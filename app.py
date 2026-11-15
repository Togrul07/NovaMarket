"""
NovaMarket — GÜCLƏNDİRİLMİŞ (secure) versiya.

Eyni funksiyalar, amma hər təhlükəsizlik boşluğu düzəldilib:
  - SQL: yalnız parametrli sorğular, ədəd parametrləri int-ə çevrilir
  - Auth: parol hash-ı (scrypt), session təmizlənir, rol yalnız server session-da
  - XSS: escape aktivdir, |safe və Markup yoxdur, CSP başlığı var
  - Command injection: shell yoxdur, IP ünvanı ipaddress ilə yoxlanılır
  - XXE: DTD/ENTITY rədd olunur, defusedxml istifadə olunur
  - SSRF: yalnız açıq ünvanlar, daxili IP-lər bloklanır, redirect yoxdur
  - Fayl yükləmə: məzmun şəkil kimi yoxlanılır, ad təsadüfidir
  - Xəta mesajları gizlidir, hücum cəhdləri log-a yazılır

İşə salmaq: SECRET_KEY mühit dəyişəni lazımdır (bax: README).
"""
import base64
import hashlib
import hmac
import io
import ipaddress
import logging
import os
import re
import socket
import struct
import time
import sqlite3
import subprocess
import urllib.parse
import urllib.request
import uuid
from functools import wraps

from defusedxml.ElementTree import fromstring as safe_xml_fromstring
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from flask import (Flask, abort, redirect, render_template, request,
                   session, url_for)
from PIL import Image
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "shop_secure.db")
AVATAR_DIR = os.path.join(BASE, "static", "uploads", "avatars")
MAX_UPLOAD = 2 * 1024 * 1024              # 2 MB
MAX_REMOTE_BYTES = 2 * 1024 * 1024
IMG_FORMATS = {"PNG": "png", "JPEG": "jpg", "GIF": "gif"}

log = logging.getLogger("novamarket")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = Flask(__name__)

_secret = os.environ.get("SECRET_KEY")
if not _secret:
    raise RuntimeError("SECRET_KEY mühit dəyişəni təyin olunmayıb. "
                       "Məs: export SECRET_KEY=$(python3 -c \"import secrets;print(secrets.token_hex(32))\")")
app.secret_key = _secret
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,          # JavaScript session cookie-ni oxuya bilməsin
    SESSION_COOKIE_SAMESITE="Lax",         # cross-site sorğularda göndərilmir
    MAX_CONTENT_LENGTH=MAX_UPLOAD,         # böyük sorğular 413 ilə rədd olunur
)

# (kateqoriya_id, ad, qiymət, köhnə_qiymət, stok, emoji, rəng, təsvir)
PRODUCTS = [
    (1, "Aurex Book 14 · Ryzen 7 · 16GB", 2199, 2499, 12, "💻", "#dfe9f7",
     "14 düymlük ultra yüngül noutbuk. 16GB RAM, 512GB SSD, gündəlik iş və təhsil üçün ideal."),
    (1, "Veloce Pro 16 · i7 · 32GB", 3299, None, 5, "💻", "#e6e0f7",
     "16 düymlük güclü noutbuk. 32GB RAM, ayrıca qrafik kart, dizayn və tədqiqat üçün."),
    (1, "Nimbus Air 13 · 8GB · 256GB", 2799, 2999, 8, "💻", "#e4f5ea",
     "Cəmi 1.2 kq çəki, gün boyu batareya ömrü və səssiz soyutma sistemi."),
    (2, "Stellar X9 · 256GB", 1399, 1599, 20, "📱", "#fbe9e4",
     "6.7 düym AMOLED ekran, 50MP əsas kamera, 5000 mAh batareya."),
    (2, "Stellar Mini · 128GB", 799, None, 30, "📱", "#f7f0dc",
     "Kompakt ölçü, bir əllə rahat istifadə. Gücləndirilmiş şüşə ekran."),
    (2, "Orbit Z Fold · 512GB", 3899, 4199, 4, "📱", "#ece6f5",
     "Qatlanan ekran, çoxtapşırıqlı iş üçün ideal. IP68 qorunma."),
    (3, "SoundCore Pro ANC", 249, 299, 40, "🎧", "#e3eef7",
     "Aktiv səs-küy ləğvi, 30 saat batareya ömrü, Hi-Res dəstəyi."),
    (3, "Bass Pulse Wireless", 129, None, 55, "🎧", "#f5e6ee",
     "Güclü bas, su keçirməz korpus, 20 saat işləmə müddəti."),
    (4, "Smart Watch S5", 399, 449, 25, "⌚", "#e8f0e2",
     "Nəbz və yuxu izləmə, GPS, 14 gün batareya."),
    (4, "USB-C Hub 7-in-1", 79, None, 60, "🔌", "#eef0f4",
     "HDMI 4K, 3 USB-A, SD kart oxuyucu, 100W power delivery."),
    (4, "RGB Mexaniki Klaviatura", 149, 179, 18, "⌨️", "#f2e8e8",
     "Hot-swap switch-lər, alüminium üst panel, RGB işıqlandırma."),
    (5, "Lumen Smart Lampa", 89, None, 35, "💡", "#fdf6dd",
     "Səsli idarəetmə, 16 milyon rəng, Wi-Fi ilə tənzimləmə."),
    (5, "Robot Süpürgə V3", 699, 799, 10, "🤖", "#e5f1f4",
     "Lazerlə xəritələmə, avtomatik boşaltma, güclü sorma gücü."),
]


# ---------------------------------------------------------------- 2FA (TOTP, RFC 6238)

LOCK_FAILS = 5            # neçə səhv kodda kilidlənir
LOCK_SECONDS = 300        # kilidlənmə müddəti (5 dəqiqə)
TRUSTED_DAYS = 30         # "bu cihaza bir daha soruşma" müddəti
trusted_ser = URLSafeTimedSerializer(app.secret_key, salt="trusted-device")


def new_b32_secret():
    return base64.b32encode(os.urandom(20)).decode()   # 160 bit təsadüfi açar


def totp_at(secret_b32, step, digits=6):
    key = base64.b32decode(secret_b32, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return f"{code:0{digits}d}"


def match_totp(secret_b32, code, after=-1):
    """Kod ±30 saniyə pəncərəsində uyğun gəlirsə, zaman addımını qaytarır.
    after: bundan kiçik və ya bərabər addımlar qəbul olunmur (təkrar istifadənin qarşısı)."""
    if not re.fullmatch(r"\d{6}", code or ""):
        return None
    now_step = int(time.time() // 30)
    for step in (now_step - 1, now_step, now_step + 1):
        if step > after and hmac.compare_digest(code, totp_at(secret_b32, step)):
            return step
    return None


def otp_uri(username, secret):
    return f"otpauth://totp/NovaMarket:{username}?secret={secret}&issuer=NovaMarket"


def twofa_enabled(username):
    return q("SELECT 1 FROM twofa WHERE username=?", (username,), one=True) is not None


def is_locked(username):
    row = q("SELECT locked_until FROM twofa_fails WHERE username=?", (username,), one=True)
    return bool(row and row["locked_until"] and row["locked_until"] > time.time())


def register_fail(username):
    row = q("SELECT fails FROM twofa_fails WHERE username=?", (username,), one=True)
    fails = (row["fails"] if row else 0) + 1
    locked_until = None
    if fails >= LOCK_FAILS:
        locked_until, fails = time.time() + LOCK_SECONDS, 0
    q("INSERT INTO twofa_fails (username, fails, locked_until) VALUES (?,?,?) "
      "ON CONFLICT(username) DO UPDATE SET fails=excluded.fails, locked_until=excluded.locked_until",
      (username, fails, locked_until), commit=True)


def clear_fails(username):
    q("DELETE FROM twofa_fails WHERE username=?", (username,), commit=True)


def trusted_device_for(username):
    """Cookie imzalanıb (itsdangerous), istifadəçiyə və müddətə bağlıdır."""
    tok = request.cookies.get("trusted_device")
    if not tok:
        return False
    try:
        return trusted_ser.loads(tok, max_age=TRUSTED_DAYS * 86400) == username
    except (BadSignature, SignatureExpired):
        return False


def complete_login(username):
    """YALNIZ parol + (lazım olsa) 2FA keçildikdən sonra çağırılır."""
    row = q("SELECT username, role FROM users WHERE username=?", (username,), one=True)
    session.clear()
    session["user"] = row["username"]
    session["role"] = row["role"]
    session["auth_time"] = int(time.time())
    return redirect(url_for("profile"))


# ---------------------------------------------------------------- DB

def q(sql, args=(), one=False, commit=False):
    """Həmişə parametrli sorğu. SQL mətni heç vaxt istifadəçi girişi ilə qurulmur."""
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute(sql, args)
        rows = cur.fetchone() if one else cur.fetchall()
        if commit:
            conn.commit()
        return rows
    finally:
        conn.close()


def init_db():
    os.makedirs(AVATAR_DIR, exist_ok=True)
    conn = sqlite3.connect(DB)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT,
            full_name TEXT, email TEXT, role TEXT DEFAULT 'user', avatar TEXT);
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY, cat_id INTEGER, name TEXT, price REAL,
            old_price REAL, stock INTEGER, emoji TEXT, image_color TEXT,
            description TEXT);
        CREATE TABLE IF NOT EXISTS twofa (
            username TEXT PRIMARY KEY, secret TEXT, last_step INTEGER DEFAULT -1);
        CREATE TABLE IF NOT EXISTS twofa_fails (
            username TEXT PRIMARY KEY, fails INTEGER, locked_until REAL);
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY, product_id INTEGER, author TEXT, text TEXT);
    """)
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        # Parollar scrypt ilə hash olunur (duzlu, yavaş hash)
        conn.executemany(
            "INSERT INTO users (username,password_hash,full_name,email,role) VALUES (?,?,?,?,?)",
            [("admin", generate_password_hash("admin123"), "Sistem Administratoru",
              "admin@novamarket.az", "admin"),
             ("alice", generate_password_hash("alice123"), "Aysel Məmmədova",
              "aysel@mail.az", "user")])
        conn.executemany("INSERT INTO categories (id,name) VALUES (?,?)",
                         [(1, "Noutbuklar"), (2, "Telefonlar"), (3, "Qulaqlıqlar"),
                          (4, "Aksesuarlar"), (5, "Ev elektronikası")])
        conn.executemany(
            "INSERT INTO products (cat_id,name,price,old_price,stock,emoji,image_color,description) "
            "VALUES (?,?,?,?,?,?,?,?)", PRODUCTS)
        conn.execute("INSERT INTO reviews (product_id,author,text) "
                     "VALUES (1,'Kamran','Çox sürətlidir, tövsiyə edirəm!')")
        conn.commit()
    conn.close()


# ---------------------------------------------------------------- Köməkçilər

def parse_int(value):
    """Yalnız tam ədəd qəbul edir, digər hər şey None qaytarır."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@app.context_processor
def inject_globals():
    cart = session.get("cart", {})
    return {"nav_cats": q("SELECT id, name FROM categories"),
            "cart_count": sum(cart.values())}


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    """Rol YALNIZ server tərəfindəki imzalanmış session-dan oxunur, cookie-dən yox."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            log.warning("Admin səhifəsinə icazəsiz cəhd: %s", request.path)
            abort(403)
        return view(*args, **kwargs)
    return wrapper


@app.after_request
def security_headers(resp):
    # CSP: inline skript yoxdur, başqa domendən skript yüklənmir. Stil üçün
    # 'unsafe-inline' saxlanılıb, çünki şablonlarda inline style atributları var.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; frame-ancestors 'none'; form-action 'self'")
    resp.headers["X-Frame-Options"] = "DENY"            # clickjacking-ə qarşı
    resp.headers["X-Content-Type-Options"] = "nosniff"  # MIME tipini təxmin etmə
    resp.headers["Referrer-Policy"] = "same-origin"
    return resp


# ---------------------------------------------------------------- Mağaza

@app.route("/")
def index():
    products = q("SELECT * FROM products ORDER BY id LIMIT 8")
    return render_template("index.html", products=products)


@app.route("/category")
def category():
    cat_id = parse_int(request.args.get("cat", "1"))
    if cat_id is None:
        log.warning("Kateqoriya üçün yanlış dəyər: %r", request.args.get("cat"))
        abort(400)
    products = q("SELECT * FROM products WHERE cat_id=?", (cat_id,))
    name_row = q("SELECT name FROM categories WHERE id=?", (cat_id,), one=True)
    heading = name_row["name"] if name_row else "Kateqoriya"
    return render_template("listing.html", heading=heading, products=products, err=None)


@app.route("/search")
def search():
    term = request.args.get("q", "")[:100]
    products = q("SELECT * FROM products WHERE name LIKE ?", (f"%{term}%",)) if term else []
    # Düz mətn kimi ötürülür, şablonda avtomatik escape olunur
    heading = f"Axtarış: {term}" if term else "Axtarış"
    return render_template("listing.html", heading=heading, products=products, err=None)


@app.route("/product")
def product():
    pid = parse_int(request.args.get("id", "0"))
    if pid is None:
        abort(400)
    p = q("SELECT * FROM products WHERE id=?", (pid,), one=True)
    if not p:
        abort(404)
    reviews = q("SELECT * FROM reviews WHERE product_id=?", (pid,))
    return render_template("product.html", p=p, reviews=reviews)


@app.route("/product/review", methods=["POST"])
def review():
    pid = parse_int(request.form.get("product_id"))
    if pid is None or not q("SELECT 1 FROM products WHERE id=?", (pid,), one=True):
        abort(400)
    author = request.form.get("author", "Qonaq")[:50]
    text = request.form.get("text", "").strip()[:1000]
    if not text:
        abort(400)
    q("INSERT INTO reviews (product_id,author,text) VALUES (?,?,?)",
      (pid, author, text), commit=True)
    return redirect(url_for("product", id=pid))


@app.route("/cart/add", methods=["POST"])
def cart_add():
    pid = parse_int(request.form.get("id"))
    if pid is None or not q("SELECT 1 FROM products WHERE id=?", (pid,), one=True):
        abort(400)
    cart = session.get("cart", {})
    key = str(pid)
    cart[key] = min(cart.get(key, 0) + 1, 20)      # hər məhsuldan maks. 20
    session["cart"] = cart
    return redirect(url_for("cart"))


@app.route("/cart")
def cart():
    items, total = [], 0.0
    for key, qty in session.get("cart", {}).items():
        p = q("SELECT * FROM products WHERE id=?", (int(key),), one=True)
        if p:
            items.append({"p": p, "qty": qty})
            total += p["price"] * qty
    return render_template("cart.html", items=items, total=total)


# ---------------------------------------------------------------- Hesab

@app.route("/login", methods=["GET", "POST"])
def login():
    err = None
    if request.method == "POST":
        u = request.form.get("username", "")[:50]
        p = request.form.get("password", "")[:200]
        row = q("SELECT id, username, role, password_hash FROM users WHERE username=?",
                (u,), one=True)
        if row and check_password_hash(row["password_hash"], p):
            if twofa_enabled(row["username"]) and not trusted_device_for(row["username"]):
                session.clear()
                # Yalnız "parol keçilib" vəziyyəti. session["user"] YOXDUR, ona görə
                # login_required və admin_required bu sessiyanı qəbul etmir.
                session["pending_user"] = row["username"]
                return redirect(url_for("twofa"))
            return complete_login(row["username"])
        log.warning("Uğursuz giriş cəhdi: %s", u)
        # Eyni mesaj: istifadəçi adının mövcudluğu bilinməsin
        err = "İstifadəçi adı və ya şifrə yanlışdır"
    return render_template("login.html", err=err)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


def profile_page(**extra):
    user = q("SELECT * FROM users WHERE username=?", (session["user"],), one=True)
    return render_template("profile.html", user=user, **extra)


@app.route("/profile")
@login_required
def profile():
    return profile_page()


def store_avatar(data):
    """Məzmunun real şəkil olduğunu yoxlayır, təsadüfi ad verir, yazır.
    Fayl adı və ya göndərilən uzantı heç vaxt istifadə olunmur."""
    if not data or len(data) > MAX_UPLOAD:
        raise ValueError("Fayl ölçüsü yanlışdır (maks. 2 MB)")
    try:
        img = Image.open(io.BytesIO(data))
        img.verify()                              # faylın həqiqətən şəkil olduğunu yoxla
        fmt = img.format
    except Exception as exc:
        raise ValueError("Fayl həqiqi şəkil deyil") from exc
    ext = IMG_FORMATS.get(fmt)
    if not ext:
        raise ValueError("Yalnız PNG, JPEG və GIF qəbul olunur")
    name = f"{uuid.uuid4().hex}.{ext}"
    with open(os.path.join(AVATAR_DIR, name), "wb") as fh:
        fh.write(data)
    return f"uploads/avatars/{name}"


@app.route("/profile/avatar", methods=["POST"])
@login_required
def avatar_upload():
    f = request.files.get("avatar")
    if not f or not f.filename:
        return profile_page(err="Fayl seçilməyib"), 400
    try:
        rel = store_avatar(f.read(MAX_UPLOAD + 1))
    except ValueError as exc:
        log.warning("Rədd olunmuş yükləmə (%s): %s", session["user"], exc)
        return profile_page(err=str(exc)), 400
    q("UPDATE users SET avatar=? WHERE username=?", (rel, session["user"]), commit=True)
    return profile_page(msg="Profil şəkli yeniləndi")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirect-ləri izləmirik: açıq yönləndirmə ilə daxili ünvana keçid olmasın."""
    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(NoRedirect)


def is_safe_url(url):
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        return False
    try:
        infos = socket.getaddrinfo(p.hostname, p.port or 80)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return False
    return True


@app.route("/profile/avatar-url", methods=["POST"])
@login_required
def avatar_url():
    url = request.form.get("url", "")[:500]
    if not is_safe_url(url):
        log.warning("SSRF cəhdi rədd edildi (%s): %s", session["user"], url)
        return profile_page(err="Bu ünvana sorğu göndərmək icazəli deyil"), 400
    try:
        with _opener.open(url, timeout=5) as r:
            data = r.read(MAX_REMOTE_BYTES + 1)
    except Exception:
        return profile_page(err="Şəkil yüklənmədi"), 400
    try:
        rel = store_avatar(data)
    except ValueError as exc:
        return profile_page(err=str(exc)), 400
    q("UPDATE users SET avatar=? WHERE username=?", (rel, session["user"]), commit=True)
    # Serverdən çəkilən məzmun heç vaxt istifadəçiyə göstərilmir
    return profile_page(msg="Şəkil yükləndi")


# ---------------------------------------------------------------- 2FA marşrutları

@app.route("/2fa", methods=["GET", "POST"])
def twofa():
    user = session.get("pending_user")
    if not user:
        return redirect(url_for("login"))
    err = None
    if request.method == "POST":
        if is_locked(user):
            log.warning("2FA kilidlənib: %s", user)
            return render_template("twofa.html", user=user, err=(
                "Çox sayda səhv cəhd. Bir neçə dəqiqə sonra yenidən cəhd edin.")), 429
        code = request.form.get("code", "").strip()
        row = q("SELECT secret, last_step FROM twofa WHERE username=?", (user,), one=True)
        step = match_totp(row["secret"], code, after=row["last_step"]) if row else None
        if step is not None:
            q("UPDATE twofa SET last_step=? WHERE username=?", (step, user), commit=True)
            clear_fails(user)
            resp = complete_login(user)
            if request.form.get("remember"):
                resp.set_cookie("trusted_device", trusted_ser.dumps(user),
                                max_age=TRUSTED_DAYS * 86400, httponly=True, samesite="Lax")
                # production-da: secure=True (yalnız HTTPS)
            return resp
        register_fail(user)
        log.warning("Səhv 2FA kodu: %s", user)
        err = "Kod yanlışdır"
    return render_template("twofa.html", err=err, user=user)


@app.route("/profile/2fa")
@login_required
def twofa_setup():
    user = session["user"]
    if twofa_enabled(user):
        return render_template("twofa_setup.html", enabled=True, secret=None, uri=None, err=None)
    secret = session.get("setup_secret")
    if not secret:
        secret = session["setup_secret"] = new_b32_secret()
    return render_template("twofa_setup.html", enabled=False, secret=secret,
                           uri=otp_uri(user, secret), err=None)


@app.route("/profile/2fa/confirm", methods=["POST"])
@login_required
def twofa_confirm():
    user = session["user"]
    secret = session.get("setup_secret")
    if not secret or twofa_enabled(user):
        return redirect(url_for("twofa_setup"))
    step = match_totp(secret, request.form.get("code", "").strip())
    if step is None:
        return render_template("twofa_setup.html", enabled=False, secret=secret,
                               uri=otp_uri(user, secret), err="Kod yanlışdır"), 400
    # Açar yalnız bu sətirdə, DB-də saxlanılır. Profil səhifəsində heç vaxt göstərilmir.
    q("INSERT INTO twofa (username, secret, last_step) VALUES (?,?,?)", (user, secret, step), commit=True)
    session.pop("setup_secret", None)
    return redirect(url_for("profile"))


# ---------------------------------------------------------------- Admin

def admin_page(**extra):
    users = q("SELECT id, username, role, email FROM users")
    products = q("SELECT id, name, price, stock FROM products")
    return render_template("admin.html", users=users, products=products, **extra)


@app.route("/admin")
@admin_required
def admin():
    return admin_page()


@app.route("/admin/ping", methods=["POST"])
@admin_required
def admin_ping():
    raw = request.form.get("host", "").strip()
    try:
        ip = ipaddress.ip_address(raw)        # yalnız düzgün IP qəbul olunur
    except ValueError:
        log.warning("Ping üçün yanlış giriş: %r", raw)
        return admin_page(ping_out="Yanlış IP ünvanı"), 400
    try:
        # Siyahı şəklində arqumentlər, shell yoxdur
        res = subprocess.run(["ping", "-c", "2", str(ip)],
                             capture_output=True, text=True, timeout=10)
        out = res.stdout + res.stderr
    except (subprocess.TimeoutExpired, OSError):
        out = "Ping icra olunmadı"
    return admin_page(ping_out=out)


@app.route("/admin/import", methods=["POST"])
@admin_required
def admin_import():
    raw = request.form.get("xml", "")[:10000]
    upper = raw.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        log.warning("XXE cəhdi rədd edildi")
        return admin_page(imp="DTD/ENTITY icazə verilmir"), 400
    try:
        root = safe_xml_fromstring(raw.encode("utf-8"))   # defusedxml: xarici entity yoxdur
    except Exception:
        return admin_page(imp="XML formatı yanlışdır"), 400
    lines = [f"{p.findtext('name')} — {p.findtext('price')}" for p in root.iter("product")]
    return admin_page(imp="\n".join(lines) or "Məhsul tapılmadı")


# ---------------------------------------------------------------- Xəta idarəetməsi

@app.errorhandler(400)
def bad_request(e):
    return "Sorğu yanlışdır", 400


@app.errorhandler(403)
def forbidden(e):
    return "Giriş qadağandır", 403


@app.errorhandler(404)
def not_found(e):
    return "Səhifə tapılmadı", 404


@app.errorhandler(500)
def server_error(e):
    log.exception("Server xətası")            # təfərrüat yalnız log-da
    return "Daxili xəta baş verdi", 500


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
