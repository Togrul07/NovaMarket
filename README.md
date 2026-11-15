# NovaMarket — SECURE (düzəldilmiş) versiya

Eyni sayt, amma bütün boşluqlar düzəldilib. Blue team üçün referansdır: red team-in payload-ları burada işləməməlidir.

## Quraşdırma

```bash
cd secure
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
python app.py
```

Windows (PowerShell) üçün:
```powershell
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
python app.py
```

`SECRET_KEY` olmadan tətbiq başlamır. Bu, kodda açarın sabit yazılmasının qarşısını alır.

Hesablar: `alice / alice123`, `admin / admin123`. Verilənlər bazası `shop_secure.db`-dir (zəif versiyanın `shop.db`-si ilə qarışmır).

## Düzəlişlərin xülasəsi

| Boşluq | Düzəliş |
|---|---|
| SQL injection | Yalnız parametrli sorğular, ədəd parametrləri `int`-ə çevrilir |
| Login bypass | `check_password_hash`, session təmizlənir, eyni xəta mesajı |
| Admin cookie | Rol yalnız server session-da, `admin_required` dekoratoru |
| Reflected / Stored XSS | Escape aktivdir, `|safe` yoxdur, CSP başlığı |
| Command injection | `subprocess.run` siyahı ilə, IP `ipaddress` ilə yoxlanılır |
| XXE | DOCTYPE/ENTITY rədd olunur, `defusedxml` istifadə olunur |
| SSRF | Yalnız http/https, daxili IP-lər bloklanır, redirect yoxdur |
| Fayl yükləmə | Məzmun şəkil kimi yoxlanılır (Pillow), ad təsadüfidir, SVG/HTML rədd olunur |
| Zəif hash / secret | scrypt hash, açar mühit dəyişənindən |
| Məlumat sızması | Xəta mesajları gizlidir, hücum cəhdləri log-a yazılır |
| Clickjacking | `X-Frame-Options: DENY`, `frame-ancestors 'none'` |

## Test

Blue team üçün: red team-in payload-larını yenidən işlədin və hər birinin 400/403 və ya escape olunmuş nəticə verdiyini yoxlayın. Əvvəlki zəif versiya ilə müqayisə üçün eyni sorğuları hər iki tətbiqə göndərin.

## Qalan məhdudiyyətlər (öyrənmək üçün)

- CSRF token yoxdur (formalarda). Flask-WTF ilə əlavə etmək olar.
- SSRF-də DNS rebinding tam bağlanmayıb. Tam həll üçün funksiyanı ləğv etmək və ya həll olunmuş IP-yə birbaşa qoşulmaq lazımdır.
- Admin rolu session-da saxlanılır. Rol dəyişəndə köhnə session etibarlı qala bilər.
