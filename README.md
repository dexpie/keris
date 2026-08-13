<div align="center">

# Keris

**Modular Web Pentest Toolkit** · *Toolkit Pengujian Keamanan Web*

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![CI](https://github.com/dexpie/keris/actions/workflows/ci.yml/badge.svg)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)
![Status](https://img.shields.io/badge/Status-Beta-yellow)

Automated black-box security testing: recon → discovery → vulnerability scanning → reporting.
*Otomasi pengujian keamanan black-box: recon → discovery → scan kerentanan → laporan.*

</div>

---

## English

> ⚠️ **Important:** Only use Keris on systems you own or have explicit written permission to test. You are responsible for how you use this tool.

### What is Keris?

Keris is a command-line toolkit that automates the workflow of a black-box web penetration test. It grew out of real engagements against production sites (Next.js/Vercel, PHP/LiteSpeed, React SPA) and turns those manual steps into repeatable, scriptable commands.

| Module | What it does |
|---|---|
| `recon` | DNS resolution, security headers audit, technology/stack detection, robots.txt & sitemap |
| `passive` | Passive recon without touching the target: subdomains via crt.sh (certificate transparency) + whois |
| `discover` | Extracts `/api/*` endpoints from JS bundles, scans for secrets (API keys, JWTs), brute-forces directories & subdomains |
| `scan` | Runs the full pipeline plus vulnerability checks: SQLi, reflected XSS, SSRF, IDOR, rate-limit, directory listing, auth bypass, CORS, open redirect, cookie flags, TLS, security.txt |
| `fuzz` | Lightweight parameter fuzzing (reflection, SQL/LFI/redirect payloads) to flag spots needing manual review |
| `jwt` | Decode JWTs and check for weak signatures, `alg:none`, algorithm confusion, missing expiry |
| `ports` | Simple TCP port scanner (common ports or a custom list) |
| `openapi` | Import OpenAPI/Swagger spec and fuzz every documented endpoint |
| `bruteforce` | Test for weak credentials on HTML login forms or basic auth |
| `platforms` | Platform-specific checks (WordPress, NextAuth, Supabase, Laravel, phpMyAdmin, Spring) |
| `project` | Self-audit local source code for vulnerability patterns — CLI-friendly and AI-agent friendly (JSON) |
| `plugins` | Runs only your custom checks against a target |
| `init` | Generates an example `keris.json` config file |

### Installation

```bash
git clone https://github.com/yourname/keris.git
cd keris
pip install -r requirements.txt
```

Or install as a package:

```bash
pip install -e .
```

### Quick Start

```bash
# Full scan: recon + discovery + vulnerability scan + markdown report
python -m keris scan https://example.com -o report.md

# Also emit JSON (great for CI) and an HTML report
python -m keris scan https://example.com -o report.md \
    --json-output report.json --html report.html

# Re-run the scan next day; block CI if anything HIGH or worse appears
python -m keris scan https://example.com --exit-on high
echo "exit code: $?"   # 0 = ok, 1 = high/critical finding, 2 = error
```

### Scanning with authentication

Many endpoints only make sense to test when logged in:

```bash
# Bearer token
python -m keris scan https://app.example.com --token eyJhbGciOi...

# Session cookie
python -m keris scan https://app.example.com --cookie "session=abc123"

# Basic auth
python -m keris scan https://admin.example.com --username admin --password hunter2

# Auto-login via HTML login form (session is captured for the whole scan)
python -m keris scan https://app.example.com --login-username admin --login-password hunter2

# Route through Burp/OWASP ZAP
python -m keris scan https://example.com --proxy http://127.0.0.1:8080
```

### Passive recon (no traffic to the target)

```bash
# Subdomains from crt.sh certificate transparency + whois info
python -m keris passive example.com -o passive.json

# Include passive recon in a full scan
python -m keris scan https://example.com --passive
```

### Configuration file

Keris reads `keris.json` from the current directory (or `~/.config/keris/keris.json`). CLI flags always win over the file. Generate a starter file with:

```bash
python -m keris init
```

```json
{
  "proxy": "http://127.0.0.1:8080",
  "timeout": 20.0,
  "retries": 1,
  "workers": 10,
  "delay": 0.2,
  "max_assets": 15,
  "insecure": false,
  "token": null,
  "cookie": null,
  "username": null,
  "password": null,
  "headers": { "X-Custom": "value" },
  "plugins_dir": "plugins",
  "login_paths": ["/login", "/signin", "/auth", "/account/login"]
}
```

### Concurrency & politeness

- `--workers N` — how many threads to use for directory/subdomain brute-force (default 10)
- `--delay SEC` — sleep between HTTP requests to stay under the radar / avoid flooding
- `--timeout SEC` — per-request timeout (default 20)
- `--retries N` — connection retries (default 1; **never** retries HTTP 5xx on purpose, so error-based SQLi isn't masked)
- `--preset fast` — shortcut for `--workers 25 --delay 0`
- `--preset stealth` — shortcut for `--workers 3 --delay 1.0`

### Output & CI niceties

```bash
# Version, plain output, everything into one directory
keris --version
python -m keris scan https://example.com --no-color --output-dir ./reports

# Parameter fuzzing in a full scan
python -m keris scan https://example.com --fuzz

# PDF report (in addition to Markdown/HTML/JSON)
python -m keris scan https://example.com --pdf report.pdf
```

### JWT analysis

```bash
python -m keris jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signature"
# exit code 1 if weak secret / alg:none / algorithm confusion is found
```

### Port scanning

```bash
python -m keris ports example.com                    # common ports
python -m keris ports example.com --ports 22,80,443 --scan-timeout 3
```

### OpenAPI / Swagger import

```bash
python -m keris openapi https://api.example.com --json-output ops.json
python -m keris openapi https://api.example.com --no-fuzz   # list only
```

### Weak login credentials

```bash
python -m keris bruteforce https://app.example.com --type auto
python -m keris bruteforce https://app.example.com --type basic
```

### Platform-specific checks

```bash
python -m keris platforms https://example.com                      # all platforms
python -m keris platforms https://example.com --names wordpress laravel
```

### Project self-audit (source code)

Scans a local project for vulnerability patterns. Works standalone or as a
tool for AI coding agents (Claude Code, Codex, etc.) that need a quick
security pass before/after changes:

```bash
python -m keris project ./myapp -o audit.md --json-output audit.json
# exit code 1 if any CRITICAL/HIGH pattern is found
```

The JSON output is agent-friendly: each finding has `file`, `line`,
`severity`, `rule`, `desc`, `snippet`, and `context`.

### Wayback history

Pulls historical URLs from archive.org's CDX API and highlights interesting
endpoints (old API paths, config files, deleted assets, hidden params):

```bash
python -m keris wayback example.com --limit 500 --json-output wayback.json
```

### DNS & email security

Checks A/AAAA/CNAME/MX/TXT/NS/SOA plus SPF, DMARC and common DKIM selectors.
Optionally resolves a subdomain list and reports which are alive:

```bash
python -m keris dns example.com --subdomains subs.txt --json-output dns.json
```

### Cloud bucket checker

Looks for public S3, GCS and Azure Blob buckets derived from the target name:

```bash
python -m keris buckets example.com --json-output buckets.json
# or check an explicit name:
python -m keris buckets example.com --name acme-backup
# or as part of a full scan:
python -m keris scan https://example.com --buckets
```

### TLS certificate analysis

Fetches the leaf certificate (expiry, issuer, SAN, serial) and probes for
weak protocols (SSLv3, TLSv1, TLSv1.1):

```bash
python -m keris tls example.com --port 443 --json-output tls.json
python -m keris scan https://example.com --tls-cert
```

### WAF detection

Fingerprints common Web Application Firewalls (Cloudflare, AWS WAF, Sucuri,
Akamai, Imperva, ModSecurity, F5, Barracuda, Fastly, Wordfence, ...) from
response headers and block-page signatures:

```bash
python -m keris waf https://example.com --json-output waf.json
python -m keris scan https://example.com --waf
```

### Hidden parameter discovery

Probes endpoints with a wordlist of common hidden parameters (`debug`,
`callback`, `admin`, `test`, ...) and flags responses that change status,
length or reflect the value:

```bash
python -m keris params https://example.com --json-output params.json
python -m keris scan https://example.com --hidden-params
```

### Export sessions (curl / Burp)

Converts scan findings into replayable `curl` commands or Burp Suite XML
items, useful to hand the exact requests to a human analyst or other tools:

```bash
python -m keris scan https://example.com --json-output out.json
python -m keris export out.json --format curl -o replay.sh
python -m keris export out.json --format burp -o session.xml
```

### Webhook notifications

Sends HIGH/CRITICAL findings to Slack, Discord or Telegram after a scan:

```bash
python -m keris scan https://example.com \
  --webhook https://hooks.slack.com/services/XXX \
  --webhook-type slack
# Discord: --webhook https://discord.com/api/webhooks/...
# Telegram: --webhook https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<ID> --webhook-type telegram
```

### Aggregated dashboard

Combines several JSON scan outputs into a single interactive HTML dashboard
with per-target tables and severity cards:

```bash
python -m keris scan https://a.example.com --json-output a.json
python -m keris scan https://b.example.com --json-output b.json
python -m keris dashboard a.json b.json -o dashboard.html
```

### Rate-limit aware scanning

The HTTP client auto-detects 429/403 block responses and applies exponential
backoff (up to `max_backoff`, default 30 s), so scans stay polite and are
less likely to get your IP banned mid-assessment.

### Plugins: add your own checks

Two kinds of plugins are loaded from `plugins_dir` (default `plugins/`):

**1. Python plugins** — a file with a `run(client, base, ctx)` function returning a list of `Finding`:

```python
# plugins/my_check.py
from keris.modules.scanner import Finding

def run(client, base, ctx):
    findings = []
    r = client.get(base + "/health", timeout=10)
    if r.status_code == 200 and "ok" not in r.text:
        findings.append(Finding(
            severity="MEDIUM",
            title="Health endpoint odd",
            endpoint=base + "/health",
            detail="Expected a 200 with 'ok' marker.",
            evidence=r.text[:200],
        ))
    return findings
```

**2. JSON plugins** — a declarative template with request rules:

```json
{
  "name": "check-backup-files",
  "severity": "MEDIUM",
  "requests": [
    {
      "method": "GET",
      "path": "/backup.zip",
      "match_status": [200],
      "not_match": ["404", "not found"]
    }
  ]
}
```

Run only plugins:

```bash
python -m keris plugins https://example.com --list
python -m keris plugins https://example.com --json-output plugins.json
```

### Scanning many targets

```bash
# targets.txt, one URL per line (blank lines and # comments ignored)
echo "https://a.example.com" >> targets.txt
echo "https://b.example.com" >> targets.txt
python -m keris scan --targets targets.txt --json-output all.json
```

### Exit codes (CI integration)

| Code | Meaning |
|---|---|
| `0` | Scan finished, nothing at or above the threshold |
| `1` | At least one finding at or above `--exit-on` (default `high`) |
| `2` | Error (bad target, exception, missing file) |

Example GitHub Actions:

```yaml
- name: Security scan
  run: |
    python -m keris scan $URL --json-output out.json --exit-on high
    echo "exit=$?" >> "$GITHUB_OUTPUT"
```

### Reports

- **Markdown** (`-o report.md`) — human-readable, mirrors the structure of a manual pentest report: executive summary, severity table, target profile, security headers, findings with evidence, recommendations.
- **HTML** (`--html report.html`) — self-contained single file, easy to share or attach to tickets.
- **JSON** (`--json-output out.json`) — machine-readable for CI, dashboards, or further processing.

### Project layout

```
keris/
├── keris/
│   ├── __main__.py        # CLI (scan / recon / passive / discover / plugins / fuzz / init / jwt / ports / openapi / bruteforce / platforms / project / wayback / dns / buckets / tls / waf / params / export / dashboard)
│   ├── payloads.py        # SQLi, XSS, SSRF payloads + secret/redirect/url/hidden params
│   ├── report.py          # Markdown report generator
│   ├── report_html.py     # Self-contained HTML report generator
│   ├── report_pdf.py      # PDF report generator (reportlab)
│   ├── report_dashboard.py# Aggregated HTML dashboard across targets
│   ├── core/
│   │   ├── http.py        # HTTP client: auth, retry, proxy (incl. SOCKS), delay/throttle + adaptive rate-limit backoff
│   │   ├── config.py      # keris.json loader
│   │   ├── logger.py      # colored logging (ASCII-safe on Windows, --no-color)
│   │   └── utils.py       # URL/path/regex helpers
│   ├── modules/
│   │   ├── recon.py       # DNS, headers, stack detection
│   │   ├── passive.py     # crt.sh subdomains + whois (no traffic to target)
│   │   ├── discovery.py   # JS endpoint extraction, secrets, brute-force
│   │   ├── scanner.py     # SQLi, XSS, SSRF, IDOR, rate-limit, listing, auth bypass, CORS, redirect, TLS, cookies
│   │   ├── fuzz.py        # lightweight parameter fuzzer
│   │   ├── params.py      # hidden parameter discovery
│   │   ├── jwt.py         # JWT decode + weak signature / alg:none / confusion checks
│   │   ├── portscan.py    # TCP port scanner
│   │   ├── openapi.py     # OpenAPI/Swagger import
│   │   ├── brute.py       # weak login credentials (form + basic auth)
│   │   ├── platforms.py   # platform-specific checks
│   │   ├── wayback.py     # archive.org CDX history
│   │   ├── dnscheck.py    # DNS + SPF/DMARC/DKIM + subdomain resolution
│   │   ├── buckets.py     # public S3/GCS/Azure bucket check
│   │   ├── tlscheck.py    # TLS certificate & weak protocol analysis
│   │   ├── waf.py         # WAF fingerprint & block-page detection
│   │   ├── export.py      # curl / Burp XML session export
│   │   ├── notify.py      # Slack/Discord/Telegram webhooks
│   │   ├── project.py     # source-code self-audit (AI-agent friendly)
│   │   ├── plugins.py     # plugin engine (Python + JSON)
│   │   └── auth.py        # auth helpers + HTML form auto-login
│   └── data/              # directory & subdomain wordlists
├── plugins/               # example plugins
├── tests/                 # pytest suite + a vulnerable demo server
├── Dockerfile             # container image
└── docker-compose.yml
```

### Docker

```bash
docker build -t keris .
docker run --rm keris scan https://example.com

# with a local output mount
docker run --rm -v "$PWD:/work" keris scan https://example.com -o /work/report.md
```

### Development

```bash
pip install -e ".[dev]"
python -m pytest tests -q

# Run against the bundled intentionally-vulnerable demo server:
python tests/demo_vuln_server.py        # listens on 127.0.0.1:8099
python -m keris scan http://127.0.0.1:8099 -o demo.md
```

### Roadmap

- [x] Recon, discovery, scanner, reporting
- [x] JSON + HTML reports, exit codes, config file, plugins, multi-target
- [x] Passive recon (crt.sh subdomains + whois)
- [x] HTML form auto-login, parameter fuzzing, concurrency presets (`--fast`, `--stealth`)
- [x] New scanners: CORS, open redirect, cookie flags, TLS, security.txt
- [x] Docker, GitHub Actions CI, SECURITY.md / CONTRIBUTING.md
- [x] JWT analysis, port scanning, OpenAPI import, weak-login brute-force, platform checks
- [x] Project self-audit (source code, AI-agent friendly)
- [ ] Rate-limit-aware scan tuning

### License

[MIT](LICENSE) — use it, learn from it, improve it. Contributions welcome.

---

## Bahasa Indonesia

> ⚠️ **Penting:** Gunakan Keris hanya pada sistem yang Anda miliki atau yang telah mendapat izin tertulis untuk diuji. Segala penggunaan adalah tanggung jawab Anda.

### Apa itu Keris?

Keris adalah toolkit baris-perintah yang mengotomatisasi alur kerja penetration test web secara black-box. Lahir dari pengalaman pengujian nyata terhadap situs produksi (Next.js/Vercel, PHP/LiteSpeed, React SPA) — semua langkah manual itu diubah menjadi perintah yang bisa diulang dan dipakai dalam script.

| Modul | Fungsinya |
|---|---|
| `recon` | Resolusi DNS, audit security headers, deteksi teknologi/stack, robots.txt & sitemap |
| `passive` | Recon pasif tanpa menyentuh target: subdomain via crt.sh (certificate transparency) + whois |
| `discover` | Ekstrak endpoint `/api/*` dari bundle JS, scan secret (API key, JWT), brute-force direktori & subdomain |
| `scan` | Menjalankan seluruh pipeline + pengecekan kerentanan: SQLi, reflected XSS, SSRF, IDOR, rate-limit, directory listing, auth bypass, CORS, open redirect, cookie flags, TLS, security.txt |
| `fuzz` | Fuzzing parameter ringan (refleksi, payload SQL/LFI/redirect) untuk menandai titik yang perlu verifikasi manual |
| `jwt` | Decode JWT & cek signature lemah, `alg:none`, algorithm confusion, tanpa expiry |
| `ports` | Port scanner TCP sederhana (port umum atau daftar custom) |
| `openapi` | Import spec OpenAPI/Swagger & fuzz semua endpoint yang terdokumentasi |
| `bruteforce` | Uji kredensial login lemah pada form HTML / basic auth |
| `platforms` | Check khusus platform (WordPress, NextAuth, Supabase, Laravel, phpMyAdmin, Spring) |
| `project` | Self-audit kode sumber lokal untuk pola kerentanan — ramah CLI & agent AI (JSON) |
| `plugins` | Menjalankan hanya check khusus yang Anda buat terhadap target |
| `init` | Membuat contoh file konfigurasi `keris.json` |

### Instalasi

```bash
git clone https://github.com/namakamu/keris.git
cd keris
pip install -r requirements.txt
```

Atau pasang sebagai paket:

```bash
pip install -e .
```

### Mulai Cepat

```bash
# Scan penuh: recon + discovery + scan kerentanan + laporan markdown
python -m keris scan https://contoh.com -o laporan.md

# Sekaligus keluarkan JSON (bagus untuk CI) dan laporan HTML
python -m keris scan https://contoh.com -o laporan.md \
    --json-output hasil.json --html hasil.html

# Jalankan ulang; blokir CI jika ada temuan HIGH ke atas
python -m keris scan https://contoh.com --exit-on high
echo "exit code: $?"   # 0 = ok, 1 = ada temuan high/critical, 2 = error
```

### Scan dengan autentikasi

Banyak endpoint baru masuk akal diuji saat sudah login:

```bash
# Bearer token
python -m keris scan https://app.contoh.com --token eyJhbGciOi...

# Session cookie
python -m keris scan https://app.contoh.com --cookie "session=abc123"

# Basic auth
python -m keris scan https://admin.contoh.com --username admin --password hunter2

# Auto-login via form HTML (sesi ditangkap untuk seluruh scan)
python -m keris scan https://app.contoh.com --login-username admin --login-password hunter2

# Lewati Burp/OWASP ZAP
python -m keris scan https://contoh.com --proxy http://127.0.0.1:8080
```

### Recon pasif (tanpa lalu lintas ke target)

```bash
# Subdomain dari crt.sh certificate transparency + info whois
python -m keris passive contoh.com -o passive.json

# Sertakan recon pasif dalam scan penuh
python -m keris scan https://contoh.com --passive
```

### File konfigurasi

Keris membaca `keris.json` dari direktori aktif (atau `~/.config/keris/keris.json`). Flag CLI selalu menang atas file. Buat file awal dengan:

```bash
python -m keris init
```

```json
{
  "proxy": "http://127.0.0.1:8080",
  "timeout": 20.0,
  "retries": 1,
  "workers": 10,
  "delay": 0.2,
  "max_assets": 15,
  "insecure": false,
  "token": null,
  "cookie": null,
  "username": null,
  "password": null,
  "headers": { "X-Custom": "value" },
  "plugins_dir": "plugins",
  "login_paths": ["/login", "/signin", "/auth", "/account/login"]
}
```

### Concurrency & kesopanan

- `--workers N` — jumlah thread untuk brute-force direktori/subdomain (default 10)
- `--delay DETIK` — jeda antar request HTTP agar tidak membebani target
- `--timeout DETIK` — timeout per request (default 20)
- `--retries N` — retry koneksi (default 1; **sengaja tidak** me-retry HTTP 5xx, supaya error-based SQLi tidak tertutupi)
- `--preset fast` — pintasan `--workers 25 --delay 0`
- `--preset stealth` — pintasan `--workers 3 --delay 1.0`

### Kemudahan output & CI

```bash
# Versi, output polos, semua laporan dalam satu direktori
keris --version
python -m keris scan https://contoh.com --no-color --output-dir ./laporan

# Fuzzing parameter dalam scan penuh
python -m keris scan https://contoh.com --fuzz

# Laporan PDF (di samping Markdown/HTML/JSON)
python -m keris scan https://contoh.com --pdf laporan.pdf
```

### Analisis JWT

```bash
python -m keris jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signature"
# exit code 1 jika ada weak secret / alg:none / algorithm confusion
```

### Port scanning

```bash
python -m keris ports contoh.com                    # port umum
python -m keris ports contoh.com --ports 22,80,443 --scan-timeout 3
```

### Import OpenAPI / Swagger

```bash
python -m keris openapi https://api.contoh.com --json-output ops.json
python -m keris openapi https://api.contoh.com --no-fuzz   # list saja
```

### Kredensial login lemah

```bash
python -m keris bruteforce https://app.contoh.com --type auto
python -m keris bruteforce https://app.contoh.com --type basic
```

### Check khusus platform

```bash
python -m keris platforms https://contoh.com                      # semua platform
python -m keris platforms https://contoh.com --names wordpress laravel
```

### Self-audit proyek (kode sumber)

Scan proyek lokal untuk pola kerentanan. Bisa dipakai mandiri atau sebagai
alat untuk agent AI (Claude Code, Codex, dll) yang butuh pemeriksaan keamanan
cepat sebelum/sesudah perubahan:

```bash
python -m keris project ./aplikasi -o audit.md --json-output audit.json
# exit code 1 jika ada pola CRITICAL/HIGH
```

Output JSON ramah agent: setiap temuan memuat `file`, `line`, `severity`,
`rule`, `desc`, `snippet`, dan `context`.

### Riwayat Wayback

Ambil URL historis dari CDX API archive.org dan tandai endpoint menarik
(path API lama, file konfigurasi, aset yang dihapus, parameter tersembunyi):

```bash
python -m keris wayback contoh.com --limit 500 --json-output wayback.json
```

### DNS & keamanan email

Periksa A/AAAA/CNAME/MX/TXT/NS/SOA plus SPF, DMARC, dan selector DKIM umum.
Opsional resolve daftar subdomain dan laporkan mana yang aktif:

```bash
python -m keris dns contoh.com --subdomains subs.txt --json-output dns.json
```

### Pengecek bucket cloud

Cari bucket S3, GCS, dan Azure Blob publik yang diturunkan dari nama target:

```bash
python -m keris buckets contoh.com --json-output buckets.json
# atau periksa nama eksplisit:
python -m keris buckets contoh.com --name acme-backup
# atau bagian dari scan lengkap:
python -m keris scan https://contoh.com --buckets
```

### Analisis sertifikat TLS

Ambil sertifikat leaf (masa berlaku, issuer, SAN, serial) dan uji protokol
lemah (SSLv3, TLSv1, TLSv1.1):

```bash
python -m keris tls contoh.com --port 443 --json-output tls.json
python -m keris scan https://contoh.com --tls-cert
```

### Deteksi WAF

Fingerprint Web Application Firewall umum (Cloudflare, AWS WAF, Sucuri,
Akamai, Imperva, ModSecurity, F5, Barracuda, Fastly, Wordfence, ...) dari
header respons dan tanda block page:

```bash
python -m keris waf https://contoh.com --json-output waf.json
python -m keris scan https://contoh.com --waf
```

### Penemuan parameter tersembunyi

Uji endpoint dengan wordlist parameter tersembunyi umum (`debug`, `callback`,
`admin`, `test`, ...) dan tandai respons yang berubah status, panjang, atau
merefleksikan nilai:

```bash
python -m keris params https://contoh.com --json-output params.json
python -m keris scan https://contoh.com --hidden-params
```

### Export sesi (curl / Burp)

Konversi temuan scan menjadi perintah `curl` atau item XML Burp Suite yang
dapat diulang — berguna untuk menyerahkan request persis kepada analis atau
alat lain:

```bash
python -m keris scan https://contoh.com --json-output out.json
python -m keris export out.json --format curl -o replay.sh
python -m keris export out.json --format burp -o sesi.xml
```

### Notifikasi webhook

Kirim temuan HIGH/CRITICAL ke Slack, Discord, atau Telegram setelah scan:

```bash
python -m keris scan https://contoh.com \
  --webhook https://hooks.slack.com/services/XXX \
  --webhook-type slack
# Discord: --webhook https://discord.com/api/webhooks/...
# Telegram: --webhook https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<ID> --webhook-type telegram
```

### Dashboard agregat

Gabungkan beberapa output JSON scan menjadi satu dashboard HTML interaktif
dengan tabel per-target dan kartu severity:

```bash
python -m keris scan https://a.contoh.com --json-output a.json
python -m keris scan https://b.contoh.com --json-output b.json
python -m keris dashboard a.json b.json -o dashboard.html
```

### Scan sadar rate-limit

Klien HTTP otomatis mendeteksi respons blokir 429/403 dan menerapkan backoff
eksponensial (hingga `max_backoff`, default 30 detik) — scan tetap sopan dan
IP Anda lebih aman dari banned di tengah pengujian.

### Plugin: tambahkan check buatan sendiri

Dua jenis plugin dimuat dari `plugins_dir` (default `plugins/`):

**1. Plugin Python** — file dengan fungsi `run(client, base, ctx)` yang mengembalikan list `Finding`:

```python
# plugins/check_saya.py
from keris.modules.scanner import Finding

def run(client, base, ctx):
    findings = []
    r = client.get(base + "/health", timeout=10)
    if r.status_code == 200 and "ok" not in r.text:
        findings.append(Finding(
            severity="MEDIUM",
            title="Endpoint health aneh",
            endpoint=base + "/health",
            detail="Harusnya 200 dengan penanda 'ok'.",
            evidence=r.text[:200],
        ))
    return findings
```

**2. Plugin JSON** — template deklaratif dengan aturan request:

```json
{
  "name": "check-backup-files",
  "severity": "MEDIUM",
  "requests": [
    {
      "method": "GET",
      "path": "/backup.zip",
      "match_status": [200],
      "not_match": ["404", "not found"]
    }
  ]
}
```

Jalankan hanya plugin:

```bash
python -m keris plugins https://contoh.com --list
python -m keris plugins https://contoh.com --json-output plugin.json
```

### Scan banyak target

```bash
# targets.txt, satu URL per baris (baris kosong dan # diabaikan)
echo "https://a.contoh.com" >> targets.txt
echo "https://b.contoh.com" >> targets.txt
python -m keris scan --targets targets.txt --json-output semua.json
```

### Kode keluar (integrasi CI)

| Kode | Arti |
|---|---|
| `0` | Scan selesai, tidak ada temuan setingkat ambang batas |
| `1` | Ada minimal satu temuan setingkat `--exit-on` (default `high`) |
| `2` | Error (target salah, exception, file hilang) |

Contoh GitHub Actions:

```yaml
- name: Security scan
  run: |
    python -m keris scan $URL --json-output out.json --exit-on high
    echo "exit=$?" >> "$GITHUB_OUTPUT"
```

### Laporan

- **Markdown** (`-o laporan.md`) — mudah dibaca, meniru struktur laporan pentest manual: ringkasan eksekutif, tabel severity, profil target, security headers, temuan beserta bukti, rekomendasi.
- **HTML** (`--html laporan.html`) — satu file mandiri, mudah dibagikan atau dilampirkan ke tiket.
- **JSON** (`--json-output hasil.json`) — bisa dibaca mesin untuk CI, dashboard, atau pengolahan lanjut.

### Struktur proyek

```
keris/
├── keris/
│   ├── __main__.py        # CLI (scan / recon / passive / discover / plugins / fuzz / init / jwt / ports / openapi / bruteforce / platforms / project / wayback / dns / buckets / tls / waf / params / export / dashboard)
│   ├── payloads.py        # payload SQLi, XSS, SSRF + pola secret + parameter redirect/url/hidden
│   ├── report.py          # generator laporan markdown
│   ├── report_html.py     # generator laporan HTML mandiri
│   ├── report_pdf.py      # generator laporan PDF (reportlab)
│   ├── report_dashboard.py# dashboard HTML agregat antar-target
│   ├── core/
│   │   ├── http.py        # klien HTTP: auth, retry, proxy (termasuk SOCKS), delay/throttle + backoff adaptif rate-limit
│   │   ├── config.py      # pemuat keris.json
│   │   ├── logger.py      # logging berwarna (aman ASCII di Windows, --no-color)
│   │   └── utils.py       # helper URL/path/regex
│   ├── modules/
│   │   ├── recon.py       # DNS, headers, deteksi stack
│   │   ├── passive.py     # subdomain crt.sh + whois (tanpa trafik ke target)
│   │   ├── discovery.py   # ekstraksi endpoint JS, secret, brute-force
│   │   ├── scanner.py     # SQLi, XSS, SSRF, IDOR, rate-limit, listing, auth bypass, CORS, redirect, TLS, cookie
│   │   ├── fuzz.py        # fuzzer parameter ringan
│   │   ├── params.py      # penemuan parameter tersembunyi
│   │   ├── jwt.py         # decode JWT + cek weak signature / alg:none / confusion
│   │   ├── portscan.py    # port scanner TCP
│   │   ├── openapi.py     # import OpenAPI/Swagger
│   │   ├── brute.py       # kredensial login lemah (form + basic auth)
│   │   ├── platforms.py   # check khusus platform
│   │   ├── wayback.py     # riwayat CDX archive.org
│   │   ├── dnscheck.py    # DNS + SPF/DMARC/DKIM + resolve subdomain
│   │   ├── buckets.py     # cek bucket S3/GCS/Azure publik
│   │   ├── tlscheck.py    # analisis sertifikat TLS & protokol lemah
│   │   ├── waf.py         # fingerprint WAF & deteksi block page
│   │   ├── export.py      # export sesi curl / Burp XML
│   │   ├── notify.py      # webhook Slack/Discord/Telegram
│   │   ├── project.py     # self-audit kode sumber (ramah agent AI)
│   │   ├── plugins.py     # engine plugin (Python + JSON)
│   │   └── auth.py        # helper auth + auto-login form HTML
│   └── data/              # wordlist direktori & subdomain
├── plugins/               # contoh plugin
├── tests/                 # suite pytest + server demo rawan
├── Dockerfile             # image kontainer
└── docker-compose.yml
```

### Docker

```bash
docker build -t keris .
docker run --rm keris scan https://contoh.com

# dengan mount direktori output lokal
docker run --rm -v "$PWD:/work" keris scan https://contoh.com -o /work/laporan.md
```

### Pengembangan

```bash
pip install -e ".[dev]"
python -m pytest tests -q

# Uji terhadap server demo yang sengaja rawan:
python tests/demo_vuln_server.py        # mendengarkan di 127.0.0.1:8099
python -m keris scan http://127.0.0.1:8099 -o demo.md
```

### Roadmap

- [x] Recon, discovery, scanner, laporan
- [x] Laporan JSON + HTML, exit codes, config file, plugin, multi-target
- [x] Recon pasif (subdomain crt.sh + whois)
- [x] Auto-login form HTML, fuzzing parameter, preset concurrency (`--fast`, `--stealth`)
- [x] Scanner baru: CORS, open redirect, cookie flags, TLS, security.txt
- [x] Docker, GitHub Actions CI, SECURITY.md / CONTRIBUTING.md
- [x] Analisis JWT, port scanning, import OpenAPI, brute-force login lemah, check platform
- [x] Self-audit proyek (kode sumber, ramah agent AI)
- [x] Riwayat Wayback, DNS & email security, cek bucket cloud, analisis TLS
- [x] Deteksi WAF, penemuan parameter tersembunyi, export curl/Burp, webhook, dashboard agregat
- [x] Penyetelan scan sadar rate-limit (backoff adaptif)

### Lisensi

[MIT](LICENSE) — silakan dipakai, dipelajari, dan dikembangkan. Kontribusi dipersilakan.
