<div align="center">

<img src="https://img.shields.io/badge/keris-v0.3.0-3A5F8A" alt="version" />

# Keris

**Modular Web Pentest Toolkit** — *Toolkit Pengujian Keamanan Web*

Automated black-box security testing: recon → discovery → vulnerability scanning → reporting.

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![CI](https://github.com/dexpie/keris/actions/workflows/ci.yml/badge.svg)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)
![Tests](https://img.shields.io/badge/tests-86%20passed-success)

Keris is a command-line security toolkit that turns the manual workflow of a black-box web penetration test into repeatable, scriptable commands. It grew out of real engagements against production sites (Next.js/Vercel, PHP/LiteSpeed, React SPA) and is designed for pentesters, bug bounty hunters, DevOps, and AI coding agents.

**Keris adalah toolkit keamanan baris-perintah yang mengubah alur kerja manual penetration test web black-box menjadi perintah yang dapat diulang dan di-script.** Lahir dari pengalaman pengujian nyata terhadap situs produksi, dirancang untuk pentester, bug bounty hunter, DevOps, dan agent AI.

</div>

> ⚠️ **Legal / Penting:** Only use Keris on systems you own or have explicit written permission to test. Active attack modules (exploit, CVE, brute-force extended, DoS) require explicit confirmation flags. You are responsible for how you use this tool.
> **Hanya gunakan Keris pada sistem yang Anda miliki atau yang memiliki izin tertulis untuk diuji.** Modul serangan aktif (exploit, CVE, brute-force extended, DoS) wajib konfirmasi eksplisit.

---

## Table of Contents / Daftar Isi

1. [Features / Fitur](#features--fitur)
2. [Quick Start](#quick-start)
3. [Installation / Instalasi](#installation--instalasi)
4. [All Commands / Semua Perintah](#all-commands--semua-perintah)
5. [Scanning](#scanning)
6. [Authentication / Autentikasi](#authentication--autentikasi)
7. [Configuration / Konfigurasi](#configuration--konfigurasi)
8. [Active Attacks (authorized only) / Serangan Aktif](#active-attacks-authorized-only--serangan-aktif)
9. [Recon & Discovery](#recon--discovery)
10. [Vulnerability Checks / Cek Kerentanan](#vulnerability-checks--cek-kerentanan)
11. [Infrastructure Checks / Cek Infrastruktur](#infrastructure-checks--cek-infrastruktur)
12. [Reporting & Integration](#reporting--integration)
13. [Plugins](#plugins)
14. [Exit Codes (CI) / Kode Keluar](#exit-codes-ci--kode-keluar)
15. [Docker](#docker)
16. [Development / Pengembangan](#development--pengembangan)
17. [Project Layout / Struktur Proyek](#project-layout--struktur-proyek)
18. [Roadmap](#roadmap)
19. [License / Lisensi](#license--lisensi)

---

## Features / Fitur

- **Full pipeline**: one command runs recon → discovery → vulnerability scan → report (`scan`)
- **34 subcommands**: recon, passive, discover, scan, fuzz, jwt, ports, openapi, bruteforce, platforms, project, wayback, dns, buckets, tls, waf, params, hidden, crawl, graphql, takeover, smuggling, cachepoison, hostheader, websocket, jsanalysis, sensitive, retest, export, dashboard, dos, serve, plugins, init
- **Web UI (`serve`)**: paste a URL, click Scan — Keris runs the full scan in the background with live progress and downloadable MD/HTML/PDF/JSON reports
- **Active attack modules** (authorized only): SQLi/CMDI/SSTI/XSS auto-exploit, extended credential brute-force, username enumeration, CVE/PoC probes
- **Web cache poisoning & host header injection**: reflection of cacheable response headers / password-reset poisoning
- **WebSocket security**: handshake auth, Origin validation, cross-origin hijacking
- **Client-side JS analysis**: DOM XSS sinks, hidden endpoints, leaked secrets in bundles
- **Sensitive data scan**: credentials, PII, credit cards in responses
- **Retest & diff workflow**: compare old vs new scan to track remediation progress
- **CVSS v3.1 & OWASP Top 10 mapping**: every finding is scored and classified in MD/HTML/PDF reports
- **Multiple report formats**: Markdown, HTML (self-contained), PDF, JSON
- **CI friendly**: exit codes, `--json-output`, `--exit-on` threshold
- **Polite by default**: concurrency presets (`fast`, `stealth`, `aggressive`), delay, adaptive rate-limit backoff
- **Auth support**: Bearer token, cookie, basic auth, HTML form auto-login
- **Plugins**: Python or declarative JSON custom checks
- **Multi-target**: scan a whole list in one run
- **Notifications**: Slack / Discord / Telegram webhooks
- **Docker ready**: container image with compose
- **AI-agent friendly**: `project` self-audit emits JSON with file/line/severity/context

---

## Quick Start

```bash
# Full scan: recon + discovery + vulnerability scan + Markdown report
python -m keris scan https://example.com -o report.md

# Also emit JSON (great for CI) and an HTML report
python -m keris scan https://example.com -o report.md \
    --json-output report.json --html report.html

# Block CI if anything HIGH or worse appears
python -m keris scan https://example.com --exit-on high
echo "exit code: $?"   # 0 = ok, 1 = high/critical finding, 2 = error
```

### Try it locally in 30 seconds

```bash
python tests/demo_vuln_server.py        # intentionally vulnerable demo server on 127.0.0.1:8099
python -m keris scan http://127.0.0.1:8099 -o demo.md --hidden-endpoints
```

### Web UI (paste a link, scan everything)

Start the local web UI, open your browser, paste a URL, click **Scan**:

```bash
python -m keris serve                 # http://127.0.0.1:8181
python -m keris serve --port 9000     # custom port
```

- Full scan runs in the background (all extra modules on by default: cache
  poisoning, host header, WebSocket, JS analysis, sensitive data, hidden
  endpoints, fuzz, WAF, TLS, buckets, ...)
- Live progress + streaming log in the browser
- Download the finished report as **Markdown / HTML / PDF / JSON**
- One scan at a time; use **Hentikan** to stop
- Active attacks (exploit/brute/CVE) only appear after ticking "Saya punya izin
  tertulis" — keep the UI bound to `127.0.0.1`; never expose it publicly.
- **CARIKRITIKAL** button: one click runs the deepest scan (every module +
  authorized active attacks) and auto-filters results to CRITICAL/HIGH. Use the
  filter buttons to focus on any severity.
- **Uji DoS** panel: app-layer DoS resilience test (slowloris / slow POST /
  measured flood) with concurrency, duration and request caps. Requires an
  explicit written-permission checkbox (`confirmed`) — the same guard as the
  CLI's `--yes`. Non-destructive and measured; reports regenerated from
  findings (MD/HTML/PDF/JSON).

---

## Installation / Instalasi

```bash
git clone https://github.com/dexpie/keris.git
cd keris
pip install -r requirements.txt
```

Or install as a package:

```bash
pip install -e .
```

Development install (with test dependencies):

```bash
pip install -e ".[dev]"
```

Dependencies: PyYAML, PySocks, reportlab, dnspython, cryptography, certifi, requests.

---

## All Commands / Semua Perintah

| Command / Perintah | English | Bahasa Indonesia |
|---|---|---|
| `scan` | Full pipeline: recon + discovery + vuln scan + report | Pipeline lengkap: recon + discovery + scan kerentanan + laporan |
| `recon` | DNS, security headers, stack detection | Resolusi DNS, audit security headers, deteksi teknologi/stack |
| `passive` | Subdomains via crt.sh + whois (no target traffic) | Subdomain via crt.sh + whois (tanpa menyentuh target) |
| `discover` | `/api/*` extraction, secrets, directory & subdomain brute | Ekstraksi endpoint `/api/*`, secret, brute direktori & subdomain |
| `fuzz` | Lightweight parameter fuzzing | Fuzzing parameter ringan |
| `jwt` | Decode & JWT security checks | Decode & analisis keamanan token JWT |
| `ports` | TCP port scanner | Port scanner TCP |
| `openapi` | Import OpenAPI/Swagger & fuzz endpoints | Import spec OpenAPI/Swagger & fuzz endpoint |
| `bruteforce` | Weak login credentials (form/basic) | Uji kredensial login lemah (form/basic) |
| `platforms` | Platform-specific checks (WordPress, Laravel, ...) | Check khusus platform (WordPress, Laravel, ...) |
| `project` | Local source-code self-audit (AI-agent friendly) | Self-audit kode sumber lokal (ramah agent AI) |
| `wayback` | Historical URLs from archive.org CDX | URL historis dari archive.org CDX |
| `dns` | DNS & email security (MX/SPF/DMARC/DKIM) | DNS & keamanan email (MX/SPF/DMARC/DKIM) |
| `buckets` | Public S3/GCS/Azure bucket check | Cek bucket S3/GCS/Azure publik |
| `tls` | TLS certificate & weak protocol analysis | Analisis sertifikat TLS & protokol lemah |
| `waf` | WAF fingerprint & block-page detection | Fingerprint WAF & deteksi block page |
| `params` | Hidden parameter discovery | Penemuan parameter tersembunyi |
| `hidden` | Hidden endpoint discovery (admin/config/backup) | Penemuan endpoint tersembunyi (admin/config/backup) |
| `crawl` | Web crawl & attack surface map | Crawl situs & peta attack surface |
| `graphql` | GraphQL testing (introspection/batching/depth) | Testing GraphQL (introspection/batching/depth) |
| `takeover` | Subdomain takeover detection (dangling CNAME) | Deteksi subdomain takeover (CNAME menggantung) |
| `smuggling` | HTTP request smuggling (CL.TE / TE.CL) | Deteksi HTTP request smuggling (CL.TE / TE.CL) |
| `cachepoison` | Web cache poisoning (header reflection) | Deteksi web cache poisoning (refleksi header) |
| `hostheader` | Host header injection / password-reset poisoning | Deteksi host header injection / password-reset poisoning |
| `websocket` | WebSocket auth & Origin validation | Uji keamanan WebSocket (auth, Origin) |
| `jsanalysis` | Client-side JS: DOM XSS sinks, endpoints, secrets | Analisis JS client: sink DOM XSS, endpoint, secret |
| `sensitive` | Sensitive data exposure (creds/PII/cards) | Scan paparan data sensitif (kredensial/PII/kartu) |
| `retest` | Compare old vs new scan (diff) | Bandingkan scan lama vs baru (retest) |
| `export` | Findings → curl / Burp XML sessions | Temuan → sesi curl / Burp XML |
| `dashboard` | Aggregate JSON reports into HTML dashboard | Gabungkan laporan JSON menjadi dashboard HTML |
| `dos` | **Authorized only** app-layer resilience test | **Khusus berizin** uji ketahanan app-layer |
| `serve` | Local web UI: paste URL → scan → reports | Web UI lokal: tempel URL → scan → laporan |
| `plugins` | Run only your custom checks | Jalankan hanya check kustom Anda |
| `init` | Generate example `keris.json` | Buat contoh `keris.json` |

---

## Scanning

### Full scan

```bash
python -m keris scan https://example.com -o report.md
```

Optional scan switches (pick what you need):

```bash
python -m keris scan https://example.com \
  --passive          # add passive recon (crt.sh/whois)
  --fuzz             # add parameter fuzzing
  --platform-checks  # add WordPress/Laravel/... checks
  --hidden-params    # hidden parameter discovery
  --hidden-endpoints # hidden endpoint discovery (admin/config/backup)
  --waf              # WAF fingerprint
  --tls-cert         # TLS certificate analysis
  --buckets          # cloud bucket check
  --ssrf-callback https://your.collaborator.example  # confirm SSRF
```

Skip phases:

```bash
python -m keris scan https://example.com --no-discover --no-bruteforce --no-plugins
```

### Scan many targets

```bash
# targets.txt: one URL per line (blank lines and # comments ignored)
echo "https://a.example.com" >> targets.txt
echo "https://b.example.com" >> targets.txt
python -m keris scan --targets targets.txt --json-output all.json
```

### Concurrency & politeness

- `--workers N` — threads for directory/subdomain brute-force (default 10)
- `--delay SEC` — sleep between HTTP requests
- `--timeout SEC` — per-request timeout (default 20)
- `--retries N` — connection retries (default 1; **never** retries HTTP 5xx on purpose, so error-based SQLi is not masked)
- `--preset fast` — `--workers 25 --delay 0`
- `--preset stealth` — `--workers 3 --delay 1.0`
- `--preset aggressive` — `--workers 50 --delay 0` + deep fuzzing (use with care and authorization)

### Rate-limit aware scanning

The HTTP client auto-detects 429/403 block responses and applies exponential backoff (up to `max_backoff`, default 30 s), so scans stay polite and are less likely to get your IP banned mid-assessment.

---

## Authentication / Autentikasi

```bash
# Bearer token
python -m keris scan https://app.example.com --token eyJhbGciOi...

# Session cookie
python -m keris scan https://app.example.com --cookie "session=abc123"

# Basic auth
python -m keris scan https://admin.example.com --username admin --password hunter2

# Auto-login via HTML login form (session captured for the whole scan)
python -m keris scan https://app.example.com --login-username admin --login-password hunter2

# Route through Burp / OWASP ZAP
python -m keris scan https://example.com --proxy http://127.0.0.1:8080

# Disable TLS verification (self-signed / internal targets)
python -m keris scan https://internal.example.com --insecure
```

---

## Configuration / Konfigurasi

Keris reads `keris.json` from the current directory (or `~/.config/keris/keris.json`). CLI flags always win over the file. Generate a starter file:

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

---

## Active Attacks (authorized only) / Serangan Aktif

> These modules **send attack payloads** against the target. They are gated behind `--authorized` (or `--yes` for DoS). Only use them on targets you own or have written permission to test.
> **Modul ini mengirim payload serangan.** Wajib `--authorized` (atau `--yes` untuk DoS). Gunakan hanya pada target yang Anda miliki atau berizin tertulis.

### Auto-exploit injection

Confirms and exploits SQLi (boolean & time-based), command injection, SSTI, and reflected XSS:

```bash
# Single flags in a full scan
python -m keris scan https://example.com --authorized --exploit
python -m keris scan https://example.com --authorized --exploit --exploit-types sqli,xss

# Or all active modules at once
python -m keris scan https://example.com --authorized \
  --exploit --brute-extended --username-enum --exploit-cve
```

### Extended credential brute-force

Bigger credential wordlist (`--extended`, ~100 common combos) plus username enumeration on login forms:

```bash
python -m keris bruteforce https://app.example.com --authorized --extended
python -m keris bruteforce https://app.example.com --authorized --enumerate --throttle 0.2
```

### CVE / PoC probes

Checks detected platforms against known CVEs and sends PoC-style probes:

```bash
python -m keris scan https://example.com --authorized --exploit-cve
python -m keris scan https://example.com --authorized --exploit-cve --cve-platform wordpress
```

Covered platforms include WordPress, Laravel, phpMyAdmin, PHP-FPM, Spring, Struts2, Next.js, Node.js, Citrix, Apache.

### DoS resilience testing (authorized only)

An **application-layer** resilience tester — the kind of test that appears in official pentest scopes when the client asks "can the app survive this?". Deliberately **non-destructive and rate-limited**:

- `slowloris` — holds connections open with partial headers sent slowly
- `slowpost` — sends request bodies at a very low pace (RUDY style)
- `flood` — a measured, capped GET load (`--requests`)

Safety rails: low default concurrency, bounded duration, a hard request cap, and **`--yes` is mandatory** before any real load is sent. Without `--yes` Keris only does a dry-run:

```bash
# dry-run: refuses to send load without confirmation
python -m keris dos https://example.com

# authorized test — only against targets you have written permission to test
python -m keris dos https://example.com --yes \
  --type slowloris --concurrency 50 --duration 30 \
  --json-output dos.json

python -m keris dos https://example.com --yes --type flood \
  --requests 500 --concurrency 20
```

After the test Keris checks whether the service still answers normal requests and reports a `HIGH` finding if it does not — usable as an automated soak/HA check.

---

## Recon & Discovery

### Recon

```bash
python -m keris recon https://example.com -o recon.json
```

### Passive recon (no traffic to the target)

```bash
python -m keris passive example.com -o passive.json
python -m keris scan https://example.com --passive
```

### Discovery

```bash
python -m keris discover https://example.com --brute
```

### Wayback history

```bash
python -m keris wayback example.com --limit 500 --json-output wayback.json
```

### DNS & email security

```bash
python -m keris dns example.com --subdomains subs.txt --json-output dns.json
```

### Web crawl & attack surface map

```bash
python -m keris crawl https://example.com --max-pages 100 --max-depth 3 --json-output crawl.json
```

### Hidden endpoint discovery

Probes ~70 admin/internal/config/backup endpoints and classifies interesting hits (admin panel, `.env`, `.git`, backups, API specs):

```bash
python -m keris hidden https://example.com --json-output hidden.json
python -m keris hidden https://example.com --wordlist my-endpoints.txt
python -m keris scan https://example.com --hidden-endpoints
```

### Hidden parameter discovery

```bash
python -m keris params https://example.com --json-output params.json
python -m keris scan https://example.com --hidden-params
```

---

## Vulnerability Checks / Cek Kerentanan

The `scan` pipeline includes: SQLi, reflected XSS, SSRF, IDOR, rate-limit, directory listing, auth bypass, CORS, open redirect, cookie flags, TLS, security.txt.

### Parameter fuzzing

```bash
python -m keris fuzz https://example.com --json-output fuzz.json
python -m keris scan https://example.com --fuzz
```

### OpenAPI / Swagger import

```bash
python -m keris openapi https://api.example.com --json-output ops.json
python -m keris openapi https://api.example.com --no-fuzz   # list only
```

### GraphQL testing

Detects GraphQL endpoints and tests introspection, query batching, and query depth abuse:

```bash
python -m keris graphql https://example.com --json-output graphql.json
```

### HTTP request smuggling

Tests CL.TE and TE.CL smuggling patterns:

```bash
python -m keris smuggling https://example.com --json-output smuggling.json
```

### Subdomain takeover

Detects dangling CNAMEs pointing to GitHub Pages, S3, Heroku, Azure, and more:

```bash
python -m keris takeover example.com --json-output takeover.json
```

### Web cache poisoning

Probes cacheable endpoints with host-reflection headers (`X-Forwarded-Host`,
`X-Host`, ...) and flags responses that reflect the injected value AND carry
cache indicators (`Age`, `X-Cache`, CDN headers) — the recipe for stored XSS
via cache poisoning:

```bash
python -m keris cachepoison https://example.com --json-output cache.json
python -m keris cachepoison https://example.com --path /landing --path /home
python -m keris scan https://example.com --cache-poisoning
```

### Host header injection

Tests reflection of a spoofed `Host` header, with special attention to
password-reset endpoints (password-reset poisoning):

```bash
python -m keris hostheader https://example.com --json-output host.json
python -m keris hostheader https://example.com --path /reset-password
python -m keris scan https://example.com --host-header
```

### WebSocket security

Discovers WebSocket endpoints, then tests the handshake without a token and
without an `Origin` header (cross-origin WebSocket hijacking / CSWSH):

```bash
python -m keris websocket https://example.com --json-output ws.json
python -m keris scan https://example.com --websocket
```

Requires `websocket-client` (`pip install websocket-client` — already in
`requirements.txt`).

### Client-side JS analysis

Downloads the JS bundles found during discovery and scans for DOM XSS sinks
(`innerHTML`, `eval`, `document.write`, ...) fed by a source (`location.hash`,
`postMessage`, ...), hidden API endpoints, and leaked secrets:

```bash
python -m keris jsanalysis https://example.com --max-assets 20 --json-output js.json
python -m keris scan https://example.com --js-analysis
```

### Sensitive data exposure

Scans responses for leaked credentials, API keys, JWTs, emails, phone numbers
and credit cards, using context keywords to keep false positives low:

```bash
python -m keris sensitive https://example.com --endpoint /api/users
python -m keris scan https://example.com --sensitive-data
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

### JWT analysis

```bash
python -m keris jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signature"
# exit code 1 if weak secret / alg:none / algorithm confusion is found
```

### Project self-audit (source code)

Scans a local project for vulnerability patterns. Works standalone or as a tool for AI coding agents (Claude Code, Codex, etc.):

```bash
python -m keris project ./myapp -o audit.md --json-output audit.json
# exit code 1 if any CRITICAL/HIGH pattern is found
```

The JSON output is agent-friendly: each finding has `file`, `line`, `severity`, `rule`, `desc`, `snippet`, and `context`.

---

## Infrastructure Checks / Cek Infrastruktur

### Port scanning

```bash
python -m keris ports example.com                    # common ports
python -m keris ports example.com --ports 22,80,443 --scan-timeout 3
```

### Cloud bucket checker

```bash
python -m keris buckets example.com --json-output buckets.json
python -m keris buckets example.com --name acme-backup
python -m keris scan https://example.com --buckets
```

### TLS certificate analysis

```bash
python -m keris tls example.com --port 443 --json-output tls.json
python -m keris scan https://example.com --tls-cert
```

### WAF detection

```bash
python -m keris waf https://example.com --json-output waf.json
python -m keris scan https://example.com --waf
```

---

## Reporting & Integration

### Reports

- **Markdown** (`-o report.md`) — human-readable, mirrors a manual pentest report: executive summary, severity table, target profile, security headers, findings with evidence, recommendations.
- **HTML** (`--html report.html`) — self-contained single file, easy to share or attach to tickets.
- **PDF** (`--pdf report.pdf`) — printable report.
- **JSON** (`--json-output out.json`) — machine-readable for CI, dashboards, or further processing.

```bash
python -m keris scan https://example.com -o report.md --html report.html --pdf report.pdf --json-output out.json
python -m keris scan https://example.com --no-color --output-dir ./reports
```

Every finding in the Markdown/HTML/PDF reports is annotated with a **CVSS v3.1
vector + base score** and its **OWASP Top 10 (2021)** category, and the report
includes an OWASP classification summary table.

### Retest & diff workflow

Compare an old scan with a new one to track remediation progress:

```bash
python -m keris scan https://example.com --json-output jan.json
# ... team fixes findings ...
python -m keris scan https://example.com --json-output feb.json
python -m keris retest jan.json feb.json -o retest.md --json-output retest.json
```

The retest report groups findings into **fixed**, **new**, **persisting** and
**severity changed**, and prints a remediation progress percentage. Exit code
is non-zero when there are new or persisting findings — usable as a CI gate
for "has the fix landed?".

### Export sessions (curl / Burp)

```bash
python -m keris scan https://example.com --json-output out.json
python -m keris export out.json --format curl -o replay.sh
python -m keris export out.json --format burp -o session.xml
```

### Aggregated dashboard

```bash
python -m keris scan https://a.example.com --json-output a.json
python -m keris scan https://b.example.com --json-output b.json
python -m keris dashboard a.json b.json -o dashboard.html
```

### Webhook notifications

```bash
python -m keris scan https://example.com \
  --webhook https://hooks.slack.com/services/XXX \
  --webhook-type slack
# Discord: --webhook https://discord.com/api/webhooks/...
# Telegram: --webhook https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<ID> --webhook-type telegram
```

---

## Plugins

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

---

## Exit Codes (CI) / Kode Keluar

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

---

## Docker

```bash
docker build -t keris .
docker run --rm keris scan https://example.com

# with a local output mount
docker run --rm -v "$PWD:/work" keris scan https://example.com -o /work/report.md
```

---

## Development / Pengembangan

```bash
pip install -e ".[dev]"
python -m pytest tests -q
ruff check keris tests

# Run against the bundled intentionally-vulnerable demo server:
python tests/demo_vuln_server.py        # listens on 127.0.0.1:8099
python -m keris scan http://127.0.0.1:8099 -o demo.md
```

---

## Project Layout / Struktur Proyek

```
keris/
├── keris/
│   ├── __main__.py        # CLI (scan / recon / passive / discover / plugins / fuzz / init / jwt / ports / openapi / bruteforce / platforms / project / wayback / dns / buckets / tls / waf / params / hidden / crawl / graphql / takeover / smuggling / cachepoison / hostheader / websocket / jsanalysis / sensitive / retest / export / dashboard / dos / serve)
│   ├── payloads.py        # SQLi, XSS, SSRF, CMDI, SSTI payloads + secret/redirect/url/hidden params
│   ├── cvss.py            # CVSS v3.1 scoring + OWASP Top 10 mapping
│   ├── report.py          # Markdown report generator
│   ├── report_html.py     # Self-contained HTML report generator
│   ├── report_pdf.py      # PDF report generator (reportlab)
│   ├── report_dashboard.py# Aggregated HTML dashboard across targets
│   ├── ui.py              # Local web UI (http.server): paste URL → scan → reports
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
│   │   ├── fuzz.py        # lightweight parameter fuzzer (incl. CMDI/SSTI markers)
│   │   ├── params.py      # hidden parameter discovery
│   │   ├── hidden.py      # hidden endpoint discovery (admin/config/backup)
│   │   ├── crawler.py     # web crawl & attack surface map
│   │   ├── graphql.py     # GraphQL testing
│   │   ├── takeover.py    # subdomain takeover detection
│   │   ├── smuggling.py   # request smuggling (CL.TE / TE.CL)
│   │   ├── cachepoison.py # web cache poisoning (header reflection)
│   │   ├── hostheader.py  # host header injection / password-reset poisoning
│   │   ├── websocket.py   # WebSocket security (auth, Origin, CSWSH)
│   │   ├── jsanalysis.py  # client-side JS: DOM XSS sinks, endpoints, secrets
│   │   ├── sensitive.py   # sensitive data exposure scan (creds/PII/cards)
│   │   ├── retest.py      # old-vs-new scan diff & remediation tracking
│   │   ├── exploit.py     # auto-exploit: SQLi/CMDI/SSTI/XSS (authorized only)
│   │   ├── cve.py         # CVE/PoC probes for detected platforms (authorized only)
│   │   ├── jwt.py         # JWT decode + weak signature / alg:none / confusion checks
│   │   ├── portscan.py    # TCP port scanner
│   │   ├── openapi.py     # OpenAPI/Swagger import
│   │   ├── brute.py       # weak login credentials (form + basic auth, extended wordlist)
│   │   ├── platforms.py   # platform-specific checks
│   │   ├── wayback.py     # archive.org CDX history
│   │   ├── dnscheck.py    # DNS + SPF/DMARC/DKIM + subdomain resolution
│   │   ├── buckets.py     # public S3/GCS/Azure bucket check
│   │   ├── tlscheck.py    # TLS certificate & weak protocol analysis
│   │   ├── waf.py         # WAF fingerprint & block-page detection
│   │   ├── export.py      # curl / Burp XML session export
│   │   ├── notify.py      # Slack/Discord/Telegram webhooks
│   │   ├── dos.py         # app-layer DoS resilience test (authorized-only, --yes)
│   │   ├── project.py     # source-code self-audit (AI-agent friendly)
│   │   ├── plugins.py     # plugin engine (Python + JSON)
│   │   └── auth.py        # auth helpers + HTML form auto-login
│   └── data/              # directory & subdomain wordlists
├── plugins/               # example plugins
├── tests/                 # pytest suite + a vulnerable demo server
├── Dockerfile             # container image
└── docker-compose.yml
```

---

## Roadmap

- [x] Recon, discovery, scanner, reporting
- [x] JSON + HTML reports, exit codes, config file, plugins, multi-target
- [x] Passive recon (crt.sh subdomains + whois)
- [x] HTML form auto-login, parameter fuzzing, concurrency presets (`fast`, `stealth`)
- [x] New scanners: CORS, open redirect, cookie flags, TLS, security.txt
- [x] Docker, GitHub Actions CI, SECURITY.md / CONTRIBUTING.md
- [x] JWT analysis, port scanning, OpenAPI import, weak-login brute-force, platform checks
- [x] Project self-audit (source code, AI-agent friendly)
- [x] Wayback history, DNS & email security, cloud bucket check, TLS analysis
- [x] WAF detection, hidden parameter discovery, curl/Burp export, webhooks, aggregate dashboard
- [x] Rate-limit-aware scan tuning (adaptive backoff)
- [x] App-layer DoS resilience test (slowloris / slow POST / measured flood, `--yes` required)
- [x] Hidden endpoint discovery, web crawler, GraphQL testing
- [x] Subdomain takeover & HTTP request smuggling detection
- [x] Active attacks: auto-exploit injection, extended brute-force, username enumeration, CVE/PoC probes (authorized only)
- [x] Web cache poisoning & host header injection (password-reset poisoning)
- [x] WebSocket security test, client-side JS analysis (DOM XSS sinks)
- [x] Sensitive data exposure scan, retest & diff workflow
- [x] CVSS v3.1 scoring & OWASP Top 10 mapping in all report formats

---

## License / Lisensi

[MIT](LICENSE) — use it, learn from it, improve it. Contributions welcome.

**Kontribusi** dipersilakan. Lihat [CONTRIBUTING.md](CONTRIBUTING.md) dan laporkan celah keamanan via [SECURITY.md](SECURITY.md).