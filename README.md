# keris

`keris` adalah toolkit pentest web black-box dari CLI. Isi satu URL, keris
mengerjakan recon, discovery, scan kerentanan, sampai laporan dalam satu
perintah. Lahir dari pengetesan nyata ke situs produksi (Next.js/Vercel,
PHP/LiteSpeed, React SPA), jadi pilihan default-nya dibuat sopan: tidak asal
hantam target, anti kena ban.

```
    /\
   /  \
  / /\ \
 / /  \ \
 \ \__/ /
  \____/
     ||
```

> "Keris" itu belati Jawa. Kecil, tajam, dan tugasnya satu: uji apakah
> sesuatu bisa ditembus. Kalau tidak, ya tidak. Datanya tetap ada di laporan.

[![PyPI](https://img.shields.io/pypi/v/keris-toolkit?color=d4a24e&label=keris-toolkit)](https://pypi.org/project/keris-toolkit)
[![CI](https://github.com/dexpie/keris/actions/workflows/ci.yml/badge.svg)](https://github.com/dexpie/keris/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-3776AB)](https://www.python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## Isi cepat

```bash
pip install keris-toolkit        # atau: pip install -r requirements.txt

# Scan penuh: recon + discovery + kerentanan + laporan Markdown
keris scan https://example.com -o report.md

# Sekalian JSON (buat CI) dan HTML
keris scan https://example.com -o report.md \
    --json-output report.json --html report.html
```

Coba dalam 30 detik dengan server demo yang memang sengaja bocor:

```bash
python tests/demo_vuln_server.py        # 127.0.0.1:8099, penuh lubang
python -m keris scan http://127.0.0.1:8099 -o demo.md --hidden-endpoints
```

## Ada UI-nya juga

`serve` memunculkan halaman lokal di `http://127.0.0.1:8181`. Tempel link,
tekan Scan. Scan berjalan di belakang, progress dan lognya streaming ke
browser, laporan bisa diunduh dalam Markdown / HTML / PDF / JSON.

```bash
python -m keris serve
```

Dua tombol yang sering dipakai:

- **CARIKRITIKAL** - langsung menyalakan semua modul plus serangan aktif yang
  berizin, lalu memfilter hasil ke yang CRITICAL/HIGH saja.
- **Uji DoS** - tes ketahanan app-layer (slowloris / slow POST / flood
  terukur) dengan batas durasi dan request. Wajib centang izin tertulis.

Satu scan per waktu, ada tombol hentikan. UI tetap di `127.0.0.1`; jangan
pernah di-expose ke publik.

## Perintah

34 subcommand. Yang sering dipakai:

| Perintah | Kerjaannya |
|---|---|
| `scan` | Pipeline lengkap: recon + discovery + scan + laporan |
| `recon` / `passive` | DNS, security headers, stack detection; passive = crt.sh + whois tanpa menyentuh target |
| `discover` / `hidden` / `params` | Ekstraksi endpoint API, brute direktori/subdomain, cari endpoint admin/`.env`/backup, parameter tersembunyi |
| `fuzz` / `openapi` | Fuzzing parameter ringan, import spec Swagger lalu fuzz endpointnya |
| `jwt` / `ports` / `tls` / `dns` / `buckets` / `waf` | Token JWT, port scanner, TLS, email security (SPF/DMARC/DKIM), bucket S3/GCS publik, fingerprint WAF |
| `crawl` / `graphql` / `smuggling` / `takeover` | Peta attack surface, testing GraphQL, request smuggling, subdomain takeover |
| `cachepoison` / `hostheader` / `websocket` | Web cache poisoning, host header injection (termasuk password-reset poisoning), WebSocket auth & Origin |
| `jsanalysis` / `sensitive` | Sink DOM XSS + secret di bundle JS, paparan data sensitif (kredensial/PII/kartu) |
| `bruteforce` / `platforms` | Login lemah (form/basic), check khusus WordPress/Laravel/dll |
| `project` | Self-audit kode sumber lokal; output JSON ramah AI agent |
| `retest` | Diff scan lama vs baru untuk ngukur progres perbaikan |
| `export` / `dashboard` | Temuan jadi curl/Burp XML, gabung laporan JSON jadi dashboard HTML |
| `dos` | Uji ketahanan app-layer (khusus berizin, wajib `--yes`) |
| `serve` | Web UI lokal |
| `plugins` / `init` | Check kustom sendiri, contoh `keris.json` |

Semua scan default menyertakan: SQLi, XSS, SSRF, IDOR, rate-limit, directory
listing, auth bypass, CORS, open redirect, cookie flags, TLS, security.txt,
plus modul cache poisoning / host header / WebSocket / JS analysis / sensitive
/ hidden endpoints / fuzz.

## Serangan aktif

Modul berikut **mengirim payload**. Wajib `--authorized` (atau `--yes` untuk
DoS) dan hanya untuk target yang Anda miliki atau punya izin tertulis.

```bash
# Auto-exploit SQLi/CMDI/SSTI/XSS (konfirmasi + exploit otomatis)
python -m keris scan https://example.com --authorized --exploit

# Extended brute + username enumeration
python -m keris bruteforce https://app.example.com --authorized --extended

# CVE/PoC probe sesuai platform yang terdeteksi
python -m keris scan https://example.com --authorized --exploit-cve
```

## Autentikasi

Bearer token, cookie session, basic auth, sampai auto-login lewat form HTML
(sesi ditangkap untuk seluruh scan):

```bash
python -m keris scan https://app.example.com --token eyJhbGciOi...
python -m keris scan https://app.example.com --cookie "session=abc123"
python -m keris scan https://app.example.com --login-username admin --login-password hunter2
python -m keris scan https://example.com --proxy http://127.0.0.1:8080
```

## Laporan

Setiap temuan diberi **skor CVSS v3.1** (vektor + base score) dan kategori
**OWASP Top 10 (2021)**. Laporan Markdown menyerupai laporan pentest manual:
ringkasan eksekutif, tabel severitas, profil target, security headers, temuan
lengkap dengan bukti, lalu rekomendasi.

```bash
python -m keris scan https://example.com -o report.md \
    --html report.html --pdf report.pdf --json-output out.json
```

Lainnya:

- **Retest**: `keris retest jan.json feb.json -o retest.md` mengelompokkan
  temuan jadi fixed / new / persisting dan mencetak persentase progres.
  Exit code bukan nol kalau masih ada yang baru atau belum diperbaiki, jadi
  bisa jadi gerbang CI "apakah fix-nya sudah landed?".
- **Export**: temuan jadi script curl atau session Burp XML.
- **Dashboard**: gabung beberapa `--json-output` jadi satu HTML.
- **Webhook**: Slack / Discord / Telegram.
- **Exit code**: `0` bersih, `1` ada temuan >= threshold (`--exit-on`, default
  high), `2` error.

## Kebiasaan yang sudah dibangun-in

- **Sopan secara default**: preset `fast` / `stealth` / `aggressive`, delay,
  workers, dan backoff adaptif saat deteksi 429/403. Scan tidak asal ngebut
  biar IP Anda tidak kena blokir.
- **Rate-limit aware**: retry tidak pernah untuk HTTP 5xx, supaya SQLi
  berbasis error tidak tertutupi.
- **Konfigurasi via `keris.json`**: `python -m keris init` untuk contoh; flag
  CLI selalu menang atas file.

## Instalasi

```bash
pip install keris-toolkit         # cukup. semua dependensi ikut.
keris --help

# Dari source (buat development):
git clone https://github.com/dexpie/keris.git
cd keris
pip install -e ".[dev]"           # + dependensi test
```

Dependensi: PyYAML, PySocks, reportlab, dnspython, cryptography, certifi, requests, websocket-client.

Docker juga bisa:

```bash
docker build -t keris .
docker run --rm -v "$PWD:/work" keris scan https://example.com -o /work/report.md
```

## Kerja dengan Keris

```bash
python -m keris scan https://example.com --exit-on high     # CI gate
python -m keris scan --targets targets.txt --json-output all.json  # banyak target
python -m keris scan https://example.com --no-discover --no-bruteforce --no-plugins

# Development
python -m pytest tests -q
ruff check keris tests
```

## Struktur

```
keris/
├── keris/
│   ├── __main__.py        # CLI (34 subcommand)
│   ├── payloads.py        # payload SQLi/XSS/SSRF/CMDI/SSTI + daftar wordlist
│   ├── cvss.py            # CVSS v3.1 scoring + OWASP mapping
│   ├── report*.py         # Markdown / HTML / PDF / dashboard
│   ├── ui.py              # web UI lokal (http.server, tanpa dependensi)
│   ├── core/              # http client (auth, proxy, backoff), config, logger, utils
│   ├── modules/           # 30+ scanner: recon sampai dos, exploit, plugins
│   └── data/              # wordlist direktori & subdomain
├── plugins/               # contoh plugin (Python + JSON)
├── tests/                 # pytest suite + server demo yang sengaja bocor
├── Dockerfile
└── docker-compose.yml
```

## Roadmap

- [x] Pipeline scan penuh + laporan
- [x] Passive recon, form auto-login, fuzzing, preset kecepatan
- [x] JWT, port scan, OpenAPI, brute-force, platform checks
- [x] Project self-audit (untuk AI agent)
- [x] Wayback, DNS/email security, bucket cloud, TLS
- [x] WAF, hidden parameter, export curl/Burp, webhook, dashboard
- [x] DoS resilience test (authorized-only)
- [x] Hidden endpoint, crawler, GraphQL
- [x] Subdomain takeover & request smuggling
- [x] Auto-exploit + CVE probes (authorized only)
- [x] Cache poisoning, host header, WebSocket, JS analysis
- [x] Sensitive data scan, retest workflow
- [x] CVSS + OWASP di semua format laporan
- [x] Web UI dengan scan satu-klik dan uji DoS

## Catatan legal

Gunakan hanya pada sistem yang Anda miliki atau yang sudah memberi izin
tertulis. Modul serangan aktif (exploit, CVE, brute-force extended, DoS) wajib
konfirmasi eksplisit. Semua risiko ada di pemakai.

---

[MIT](LICENSE) - pakai, pelajari, perbaiki. Kontribusi dipersilakan, lihat
[CONTRIBUTING.md](CONTRIBUTING.md). Cari celah keamanan di Keris sendiri?
Lapor lewat [SECURITY.md](SECURITY.md).

Keris dibangun untuk pentester, bug bounty hunter, DevOps, dan AI coding agent
yang mau hasil konsisten tanpa harus menghafal 30 tool berbeda. Kalau ada
tanggapan atau permintaan fitur, jangan ragu.