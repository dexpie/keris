<div align="center">

# Keris

**Modular Web Pentest Toolkit** · *Toolkit Pengujian Keamanan Web*

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
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
| `discover` | Extracts `/api/*` endpoints from JS bundles, scans for secrets (API keys, JWTs), brute-forces directories & subdomains |
| `scan` | Runs the full pipeline plus vulnerability checks: SQLi, reflected XSS, SSRF, IDOR, rate-limit, directory listing, auth bypass |
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

# Route through Burp/OWASP ZAP
python -m keris scan https://example.com --proxy http://127.0.0.1:8080
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
  "plugins_dir": "plugins"
}
```

### Concurrency & politeness

- `--workers N` — how many threads to use for directory/subdomain brute-force (default 10)
- `--delay SEC` — sleep between HTTP requests to stay under the radar / avoid flooding
- `--timeout SEC` — per-request timeout (default 20)
- `--retries N` — connection retries (default 1; **never** retries HTTP 5xx on purpose, so error-based SQLi isn't masked)

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
│   ├── __main__.py        # CLI (scan / recon / discover / plugins / init)
│   ├── payloads.py        # SQLi, XSS, SSRF payloads + secret patterns + header checklist
│   ├── report.py          # Markdown report generator
│   ├── report_html.py     # Self-contained HTML report generator
│   ├── core/
│   │   ├── http.py        # HTTP client: auth, retry, proxy, delay/throttle
│   │   ├── config.py      # keris.json loader
│   │   ├── logger.py      # colored logging (ASCII-safe on Windows)
│   │   └── utils.py       # URL/path/regex helpers
│   ├── modules/
│   │   ├── recon.py       # DNS, headers, stack detection
│   │   ├── discovery.py   # JS endpoint extraction, secrets, brute-force
│   │   ├── scanner.py     # SQLi, XSS, SSRF, IDOR, rate-limit, listing, auth bypass
│   │   ├── plugins.py     # plugin engine (Python + JSON)
│   │   └── auth.py        # auth helpers
│   └── data/              # directory & subdomain wordlists
├── plugins/               # example plugins
└── tests/                 # pytest suite + a vulnerable demo server
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
- [ ] Template engine for site-specific checks (NextAuth, Supabase, WordPress)
- [ ] Passive subdomain/port enumeration
- [ ] Rate-limit-aware scan tuning
- [ ] CLI concurrency presets (`--fast`, `--stealth`)

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
| `discover` | Ekstrak endpoint `/api/*` dari bundle JS, scan secret (API key, JWT), brute-force direktori & subdomain |
| `scan` | Menjalankan seluruh pipeline + pengecekan kerentanan: SQLi, reflected XSS, SSRF, IDOR, rate-limit, directory listing, auth bypass |
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

# Lewati Burp/OWASP ZAP
python -m keris scan https://contoh.com --proxy http://127.0.0.1:8080
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
  "plugins_dir": "plugins"
}
```

### Concurrency & kesopanan

- `--workers N` — jumlah thread untuk brute-force direktori/subdomain (default 10)
- `--delay DETIK` — jeda antar request HTTP agar tidak membebani target
- `--timeout DETIK` — timeout per request (default 20)
- `--retries N` — retry koneksi (default 1; **sengaja tidak** me-retry HTTP 5xx, supaya error-based SQLi tidak tertutupi)

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
│   ├── __main__.py        # CLI (scan / recon / discover / plugins / init)
│   ├── payloads.py        # payload SQLi, XSS, SSRF + pola secret + daftar header
│   ├── report.py          # generator laporan markdown
│   ├── report_html.py     # generator laporan HTML mandiri
│   ├── core/
│   │   ├── http.py        # klien HTTP: auth, retry, proxy, delay/throttle
│   │   ├── config.py      # pemuat keris.json
│   │   ├── logger.py      # logging berwarna (aman ASCII di Windows)
│   │   └── utils.py       # helper URL/path/regex
│   ├── modules/
│   │   ├── recon.py       # DNS, headers, deteksi stack
│   │   ├── discovery.py   # ekstraksi endpoint JS, secret, brute-force
│   │   ├── scanner.py     # SQLi, XSS, SSRF, IDOR, rate-limit, listing, auth bypass
│   │   ├── plugins.py     # engine plugin (Python + JSON)
│   │   └── auth.py        # helper auth
│   └── data/              # wordlist direktori & subdomain
├── plugins/               # contoh plugin
└── tests/                 # suite pytest + server demo rawan
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
- [ ] Template engine untuk check khusus platform (NextAuth, Supabase, WordPress)
- [ ] Enumerasi subdomain/port pasif
- [ ] Penyetelan scan sadar rate-limit
- [ ] Preset concurrency CLI (`--fast`, `--stealth`)

### Lisensi

[MIT](LICENSE) — silakan dipakai, dipelajari, dan dikembangkan. Kontribusi dipersilakan.
