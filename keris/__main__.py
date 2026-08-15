"""Entry point CLI untuk Keris."""

import argparse
import json
import os
import sys
from typing import List, Optional

import requests

from keris import __version__
from keris.core.http import KerisHTTP
from keris.core.logger import info, ok, warn, error, debug, severity, set_quiet
from keris.core.utils import normalize_url, urljoin, domain_from_host
from keris.core.config import KerisConfig
from keris.modules import recon as recon_module
from keris.modules import discovery as discovery_module
from keris.modules import scanner as scanner_module
from keris.modules import plugins as plugins_module
from keris.report import write_report
from keris.report_html import write_html_report

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="keris",
        description="Keris — Modular Web Pentest Toolkit",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"keris {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", help="Path ke file konfigurasi JSON (default: keris.json)")
    common.add_argument("target", nargs="?", help="URL target, mis. https://example.com")
    common.add_argument("--targets", help="File berisi daftar target (satu per baris)")
    common.add_argument("--proxy", help="Proxy HTTP (mis. http://127.0.0.1:8080)")
    common.add_argument("--timeout", type=float, help="Timeout request (detik)")
    common.add_argument("--retries", type=int, help="Jumlah retry koneksi")
    common.add_argument("--delay", type=float, help="Jeda antar request (detik)")
    common.add_argument("--preset", choices=["fast", "stealth", "aggressive"], help="Preset concurrency: fast (workers 25, delay 0) / stealth (workers 3, delay 1.0) / aggressive (workers 50, delay 0, fuzz dalam)")
    common.add_argument("--token", help="Bearer token untuk request terautentikasi")
    common.add_argument("--cookie", help="Cookie header string untuk request terautentikasi")
    common.add_argument("--username", help="Username untuk basic auth")
    common.add_argument("--password", help="Password untuk basic auth")
    common.add_argument("--login-username", help="Username untuk auto-login form")
    common.add_argument("--login-password", help="Password untuk auto-login form")
    common.add_argument("--insecure", action="store_true", help="Nonaktifkan verifikasi TLS")
    common.add_argument("--quiet", action="store_true", help="Minimal output")
    common.add_argument("--no-color", action="store_true", help="Nonaktifkan warna output")
    common.add_argument("--output-dir", help="Direktori untuk menyimpan semua laporan")
    common.add_argument("--plugins", nargs="*", default=[], help="Plugin tambahan (path .py atau .json)")

    # scan (lengkap)
    ps = sub.add_parser("scan", parents=[common], help="Scan lengkap: recon + discovery + vuln scan + laporan")
    ps.add_argument("-o", "--output", default="keris-report.md", help="File laporan markdown")
    ps.add_argument("--json-output", help="File output JSON (untuk CI)")
    ps.add_argument("--html", dest="html_output", help="File laporan HTML (self-contained)")
    ps.add_argument("--pdf", dest="pdf_output", help="File laporan PDF")
    ps.add_argument("--no-discover", action="store_true", help="Lewati discovery (endpoint/JS)")
    ps.add_argument("--no-bruteforce", action="store_true", help="Lewati brute path/subdomain")
    ps.add_argument("--no-plugins", action="store_true", help="Nonaktifkan plugin")
    ps.add_argument("--passive", action="store_true", help="Juga lakukan passive recon (crt.sh/whois)")
    ps.add_argument("--fuzz", action="store_true", help="Jalankan fuzzing parameter sederhana")
    ps.add_argument("--platform-checks", action="store_true", help="Jalankan check khusus platform (WordPress, dll)")
    ps.add_argument("--hidden-params", action="store_true", help="Jalankan hidden parameter discovery")
    ps.add_argument("--hidden-endpoints", action="store_true",
                    help="Jalankan hidden endpoint discovery (admin/internal/config/backup)")
    ps.add_argument("--waf", action="store_true", help="Deteksi WAF pada target")
    ps.add_argument("--tls-cert", action="store_true", help="Analisis sertifikat TLS")
    ps.add_argument("--buckets", action="store_true", help="Cek bucket cloud terbuka")
    ps.add_argument("--webhook", help="URL webhook untuk notifikasi temuan HIGH/CRITICAL")
    ps.add_argument("--webhook-type", choices=["auto", "slack", "discord", "telegram"], default="auto",
                    help="Jenis webhook (default: auto-detect dari URL)")
    ps.add_argument("--ssrf-callback", help="URL kolaborator (interactsh/Burp) untuk konfirmasi SSRF")
    ps.add_argument("--chain", action="store_true",
                    help="Correlation engine: gabungkan temuan rendah jadi attack chain kritis")
    ps.add_argument("--triage", action="store_true",
                    help="AI/rule-based triage: tandai false positive + tulis executive summary (butuh KERIS_LLM_API_KEY untuk AI)")
    ps.add_argument("--browser", action="store_true",
                    help="Render target dengan headless browser (Playwright): DOM XSS sink, secret di DOM, link runtime")
    ps.add_argument("--screenshot", help="Simpan screenshot bukti halaman hasil render browser (butuh --browser)")
    ps.add_argument("--ticket", choices=["github", "jira"],
                    help="Auto-ticketing: buat ticket untuk temuan >= threshold (GITHUB_TOKEN/JIRA_* env)")
    ps.add_argument("--ticket-repo", help="Repo GitHub untuk auto-ticketing, mis. owner/repo (default: KERIS_GITHUB_REPO)")
    ps.add_argument("--ticket-project", help="Project key Jira untuk auto-ticketing")
    ps.add_argument("--ticket-min", default="HIGH", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    help="Severity minimum untuk auto-ticketing (default: HIGH)")
    ps.add_argument("--hunt", action="store_true",
                    help="Jalankan credential hunting (.git, .env/backup, secret cloud) dalam scan")
    ps.add_argument("--pwn", action="store_true",
                    help="AKTIFKAN SEMUA MODUL SERANGAN: hunt + chain + triage + browser + exploit + brute + CVE sekaligus (wajib --authorized)")
    ps.add_argument("--workers", type=int, help="Jumlah worker untuk brute")
    ps.add_argument("--parallel", action="store_true",
                    help="Scan beberapa target secara paralel (butuh --targets, mempercepat batch besar)")
    ps.add_argument("--exit-on", choices=["none", "high", "medium", "low"], default="high",
                    help="Severity minimum yang menyebabkan exit code 1 (default: high)")
    # --- serangan aktif (khusus berizin, wajib --authorized) ---
    ps.add_argument("--authorized", action="store_true",
                    help="KONFIRMASI izin tertulis untuk serangan aktif (exploit/brute/CVE)")
    ps.add_argument("--exploit", action="store_true",
                    help="Auto-exploit injection: SQLi boolean/time, CMDI, SSTI, XSS (butuh --authorized)")
    ps.add_argument("--exploit-types", default="sqli,cmdi,ssti,xss",
                    help="Jenis exploit (default: sqli,cmdi,ssti,xss)")
    ps.add_argument("--exploit-kit", action="store_true",
                    help="Jalankan exploit kit (SQLi dump, LFI/RFI, upload bypass, XXE, RCE) (butuh --authorized)")
    ps.add_argument("--brute-extended", action="store_true",
                    help="Brute-force login dengan wordlist extended (butuh --authorized)")
    ps.add_argument("--username-enum", action="store_true",
                    help="Deteksi enumerasi username pada form login")
    ps.add_argument("--exploit-cve", action="store_true",
                    help="CVE/PoC probe untuk platform terdeteksi (butuh --authorized)")
    ps.add_argument("--cve-platform", help="Batasi CVE check ke platform tertentu (opsional)")
    ps.add_argument("--cache-poisoning", action="store_true",
                    help="Cek web cache poisoning (refleksi header)")
    ps.add_argument("--host-header", action="store_true",
                    help="Cek host header injection / password-reset poisoning")
    ps.add_argument("--websocket", action="store_true",
                    help="Cek keamanan endpoint WebSocket (butuh websocket-client)")
    ps.add_argument("--js-analysis", action="store_true",
                    help="Analisis bundle JS untuk DOM XSS sinks & secret")
    ps.add_argument("--ssrf", action="store_true",
                    help="Deteksi SSRF via callback listener (out-of-band) pada tiap parameter")
    ps.add_argument("--ssrf-exploit", action="store_true",
                    help="Eksploitasi SSRF: coba ambil metadata cloud + scan port internal (butuh SSRF ditemukan)")
    ps.add_argument("--sensitive-data", action="store_true",
                    help="Scan paparan data sensitif (kredensial/PII/kartu)")
    ps.add_argument("--auth-chain", action="store_true",
                    help="Setelah login form (butuh --login-username/--login-password), scan area terproteksi untuk kontrol akses & kebocoran data")
    ps.add_argument("--jwt-attack", action="store_true",
                    help="Serang token JWT yang ditemukan: crack weak secret, alg=none, forged admin, expired replay (butuh --authorized)")
    ps.add_argument("--race", action="store_true",
                    help="Uji race condition / TOCTOU pada endpoint kritis (request paralel; butuh --authorized)")
    ps.add_argument("--js-deps", action="store_true",
                    help="Cek dependency JS yang ditemukan di bundle terhadap CVE offline")
    ps.add_argument("--favicon", action="store_true",
                    help="Fingerprint teknologi via hash favicon (cara Shodan)")
    ps.add_argument("--server-cve", action="store_true",
                    help="Cek CVE untuk versi server/framework dari banner HTTP (nginx/Apache/PHP/WordPress/dll)")
    ps.add_argument("--wayback", action="store_true",
                    help="Mining URL historis dari Wayback Machine (pasif) untuk discovery aset tersembunyi")
    ps.add_argument("--race-endpoints", default=None,
                    help="Endpoint tambahan untuk uji race (koma, mis. /api/coupon,/api/topup)")

    # recon
    pr = sub.add_parser("recon", parents=[common], help="Recon saja: DNS, headers, stack")
    pr.add_argument("-o", "--output", help="Simpan hasil recon ke file JSON")
    pr.add_argument("--json-output", help="File output JSON (sama dengan -o)")

    # passive recon
    pp = sub.add_parser("passive", parents=[common], help="Passive recon: crt.sh + whois (tanpa menyentuh target)")
    pp.add_argument("-o", "--output", help="Simpan hasil ke file JSON")

    # discover
    pd = sub.add_parser("discover", parents=[common], help="Discovery saja: endpoint API, JS, secret")
    pd.add_argument("--max-assets", type=int, help="Maksimum asset JS diunduh")
    pd.add_argument("--brute", action="store_true", help="Juga jalankan brute path & subdomain")
    pd.add_argument("--workers", type=int, help="Jumlah worker untuk brute")
    pd.add_argument("--json-output", help="File output JSON hasil discovery")

    # init (buat contoh config)
    pi = sub.add_parser("init", help="Buat contoh file konfigurasi keris.json")
    pi.add_argument("-o", "--output", default="keris.json.example", help="File output")

    # plugins (daftar & jalankan plugin)
    pl = sub.add_parser("plugins", parents=[common], help="Jalankan plugin saja terhadap target")
    pl.add_argument("--list", action="store_true", help="Daftar plugin yang dimuat")
    pl.add_argument("--json-output", help="File output JSON")

    # fuzz (jalankan fuzzer parameter saja)
    pf = sub.add_parser("fuzz", parents=[common], help="Fuzzing parameter sederhana")
    pf.add_argument("--json-output", help="File output JSON")

    # jwt (decode & analisis token)
    pj = sub.add_parser("jwt", help="Decode & analisis keamanan token JWT")
    pj.add_argument("token", help="Token JWT untuk dianalisis")
    pj.add_argument("--json-output", help="File output JSON")
    pj.add_argument("--no-color", action="store_true", help="Nonaktifkan warna output")
    pj.add_argument("--quiet", action="store_true", help="Minimal output")
    pj.add_argument("--exit-on", choices=["none", "high", "medium", "low"], default="high",
                    help="Severity minimum yang menyebabkan exit code 1")

    # ports (port scanner)
    pt = sub.add_parser("ports", parents=[common], help="Port scanner TCP sederhana")
    pt.add_argument("host", help="Host / IP untuk di-scan")
    pt.add_argument("--ports", help="Daftar port dipisah koma (mis. 22,80,443). Default: port umum")
    pt.add_argument("--workers", type=int, default=20, help="Jumlah thread")
    pt.add_argument("--scan-timeout", type=float, default=2.0, dest="scan_timeout",
                    help="Timeout koneksi (detik)")
    pt.add_argument("--json-output", help="File output JSON")

    # openapi (import spec & fuzz endpoint)
    po = sub.add_parser("openapi", parents=[common], help="Import OpenAPI/Swagger & fuzz endpoint")
    po.add_argument("--json-output", help="File output JSON")
    po.add_argument("--no-fuzz", action="store_true", help="Hanya list endpoint, tanpa fuzz")

    # bruteforce (login lemah)
    pb = sub.add_parser("bruteforce", parents=[common], help="Uji kredensial login lemah (form/basic)")
    pb.add_argument("--type", choices=["auto", "form", "basic"], default="auto",
                    help="Jenis auth: auto (deteksi), form, atau basic")
    pb.add_argument("--extended", action="store_true",
                    help="Gunakan wordlist kredensial extended (butuh --authorized)")
    pb.add_argument("--enumerate", action="store_true",
                    help="Deteksi enumerasi username pada form login")
    pb.add_argument("--authorized", action="store_true",
                    help="KONFIRMASI izin tertulis untuk serangan aktif")
    pb.add_argument("--throttle", type=float, default=0.1,
                    help="Jeda antar percobaan (detik); 0 = tanpa jeda")
    pb.add_argument("--json-output", help="File output JSON")
    pb.add_argument("--exit-on", choices=["none", "high", "medium", "low"], default="high",
                    help="Severity minimum yang menyebabkan exit code 1")

    # platforms (check template platform)
    ppf = sub.add_parser("platforms", parents=[common], help="Check khusus platform (WordPress, NextAuth, dll)")
    ppf.add_argument("--names", nargs="*", help="Platform yang dicek (default: semua)")
    ppf.add_argument("--json-output", help="File output JSON")
    ppf.add_argument("--exit-on", choices=["none", "high", "medium", "low"], default="high",
                    help="Severity minimum yang menyebabkan exit code 1")

    # project (self-audit kode lokal)
    ppr = sub.add_parser("project", help="Self-audit proyek lokal untuk pola kerentanan")
    ppr.add_argument("path", help="Direktori proyek yang di-scan")
    ppr.add_argument("-o", "--output", help="File laporan markdown")
    ppr.add_argument("--json-output", help="File output JSON (ramah untuk agent AI)")
    ppr.add_argument("--no-color", action="store_true", help="Nonaktifkan warna output")
    ppr.add_argument("--quiet", action="store_true", help="Minimal output")

    # wayback (URL historis archive.org)
    pw = sub.add_parser("wayback", help="Ambil URL historis dari archive.org (Wayback CDX)")
    pw.add_argument("domain", help="Domain untuk dicari historisnya")
    pw.add_argument("--limit", type=int, default=200, help="Maksimum URL diambil")
    pw.add_argument("--json-output", help="File output JSON")
    pw.add_argument("--no-color", action="store_true", help="Nonaktifkan warna output")
    pw.add_argument("--quiet", action="store_true", help="Minimal output")

    # dns (DNS & email security check)
    pdns = sub.add_parser("dns", help="DNS check: MX, SPF, DMARC, DKIM, TXT + subdomain resolve")
    pdns.add_argument("domain", help="Domain untuk diperiksa")
    pdns.add_argument("--subdomains", help="File subdomain (satu per baris) untuk di-resolve")
    pdns.add_argument("--json-output", help="File output JSON")
    pdns.add_argument("--no-color", action="store_true", help="Nonaktifkan warna output")
    pdns.add_argument("--quiet", action="store_true", help="Minimal output")

    # subdomain enum + wildcard detection
    psub = sub.add_parser("subdomain", help="Enumerasi subdomain: crt.sh + brute + wildcard DNS detection")
    psub.add_argument("domain", help="Domain untuk di-enumerasi")
    psub.add_argument("--no-crt", action="store_true", help="Lewati crt.sh (hanya brute)")
    psub.add_argument("--wordlist", help="File wordlist subdomain (default: data/subdomains.txt)")
    psub.add_argument("--workers", type=int, default=20, help="Thread untuk brute (default 20)")
    psub.add_argument("--json-output", help="File output JSON")
    psub.add_argument("--no-color", action="store_true", help="Nonaktifkan warna output")
    psub.add_argument("--quiet", action="store_true", help="Minimal output")

    # buckets (cloud bucket checker)
    pbk = sub.add_parser("buckets", parents=[common], help="Cek bucket S3/GCS/Azure terbuka")
    pbk.add_argument("--name", help="Nama bucket spesifik (default: turunan dari target)")
    pbk.add_argument("--json-output", help="File output JSON")

    # tls (sertifikat & protokol)
    ptls = sub.add_parser("tls", parents=[common], help="Analisis sertifikat TLS & protokol lemah")
    ptls.add_argument("--port", type=int, default=443, help="Port TLS (default 443)")
    ptls.add_argument("--json-output", help="File output JSON")

    # waf (deteksi firewall aplikasi)
    pwaf = sub.add_parser("waf", parents=[common], help="Deteksi & fingerprint WAF")
    pwaf.add_argument("--json-output", help="File output JSON")

    # params (hidden parameter discovery)
    ppa = sub.add_parser("params", parents=[common], help="Hidden parameter discovery")
    ppa.add_argument("--json-output", help="File output JSON")

    # hidden (hidden endpoint discovery)
    ph = sub.add_parser("hidden", parents=[common],
                        help="Hidden endpoint discovery: admin/internal/config/backup yang ter-expose")
    ph.add_argument("--json-output", help="File output JSON")
    ph.add_argument("--wordlist", help="File tambahan endpoint kustom (satu per baris)")

    # crawl (web crawler + attack surface map)
    pc = sub.add_parser("crawl", parents=[common], help="Crawl situs & bangun peta attack surface")
    pc.add_argument("--max-pages", type=int, default=50, help="Maksimum halaman di-crawl")
    pc.add_argument("--max-depth", type=int, default=3, help="Kedalaman maksimum")
    pc.add_argument("--json-output", help="File output JSON")

    # graphql (testing)
    pgq = sub.add_parser("graphql", parents=[common], help="GraphQL testing: introspection, batching, depth abuse")
    pgq.add_argument("--json-output", help="File output JSON")

    # takeover (subdomain takeover)
    ptk = sub.add_parser("takeover", parents=[common], help="Deteksi subdomain takeover (CNAME menggantung)")
    ptk.add_argument("--json-output", help="File output JSON")

    # smuggling (request smuggling)
    psm = sub.add_parser("smuggling", parents=[common], help="Deteksi HTTP request smuggling (CL.TE/TE.CL)")
    psm.add_argument("--json-output", help="File output JSON")

    # cachepoison (web cache poisoning)
    pcache = sub.add_parser("cachepoison", parents=[common],
                            help="Deteksi web cache poisoning (refleksi header yang bisa di-cache)")
    pcache.add_argument("--path", action="append", default=[],
                        help="Path yang diuji (dapat diulang). Default: path umum cacheable")
    pcache.add_argument("--json-output", help="File output JSON")

    # hostheader (host header injection)
    phost = sub.add_parser("hostheader", parents=[common],
                           help="Deteksi host header injection / password-reset poisoning")
    phost.add_argument("--path", action="append", default=[],
                       help="Path yang diuji (dapat diulang). Default: path umum sensitif")
    phost.add_argument("--json-output", help="File output JSON")

    # websocket (keamanan WebSocket)
    pws = sub.add_parser("websocket", parents=[common],
                         help="Uji keamanan endpoint WebSocket (auth, origin, message)")
    pws.add_argument("--json-output", help="File output JSON")

    # jsanalysis (analisis bundle JS)
    pjs = sub.add_parser("jsanalysis", parents=[common],
                         help="Analisis bundle JS: DOM XSS sinks, endpoint tersembunyi, secret")
    pjs.add_argument("--max-assets", type=int, default=15, help="Maksimum asset JS dianalisis")
    pjs.add_argument("--json-output", help="File output JSON")

    # sensitive (paparan data sensitif)
    psen = sub.add_parser("sensitive", parents=[common],
                          help="Scan paparan data sensitif (kredensial/PII/kartu kredit)")
    psen.add_argument("--endpoint", action="append", default=[],
                      help="Endpoint yang diuji (dapat diulang). Default: '/' saja")
    psen.add_argument("--json-output", help="File output JSON")

    # retest (perbandingan scan lama vs baru, opsional --live untuk re-scan otomatis)
    pretest = sub.add_parser("retest", help="Bandingkan scan lama & scan baru (retest workflow)")
    pretest.add_argument("old_json", help="File hasil scan lama (JSON output Keris)")
    pretest.add_argument("new_json", nargs="?", help="File hasil scan baru (wajib jika tanpa --live)")
    pretest.add_argument("--live", action="store_true",
                        help="Re-scan target dari old_json secara langsung lalu bandingkan")
    pretest.add_argument("--authorized", action="store_true",
                        help="Tandai pengujian resmi (diperlukan untuk --live yang menyentuh target)")
    pretest.add_argument("-o", "--output", help="File laporan markdown retest")
    pretest.add_argument("--json-output", help="File output JSON diff")
    pretest.add_argument("--no-color", action="store_true", help="Nonaktifkan warna output")
    pretest.add_argument("--quiet", action="store_true", help="Minimal output")
    pretest.add_argument("--no-discover", action="store_true", help="Lewati discovery (untuk retest live)")
    pretest.add_argument("--no-bruteforce", action="store_true", help="Lewati brute path (untuk retest live)")
    pretest.add_argument("--no-plugins", action="store_true", help="Nonaktifkan plugin (untuk retest live)")
    pretest.add_argument("--workers", type=int, help="Jumlah worker untuk brute (untuk retest live)")

    # export (curl/burp session dari temuan JSON)
    pex = sub.add_parser("export", help="Export temuan JSON menjadi curl / Burp XML")
    pex.add_argument("json_file", help="File hasil scan (JSON output Keris)")
    pex.add_argument("--format", choices=["curl", "burp"], default="curl",
                     help="Format output")
    pex.add_argument("-o", "--output", help="File output (default: stdout)")

    # dashboard (gabungkan laporan)
    pdb = sub.add_parser("dashboard", help="Gabungkan beberapa laporan JSON menjadi dashboard HTML")
    pdb.add_argument("json_files", nargs="+", help="File hasil scan (JSON output Keris)")
    pdb.add_argument("-o", "--output", default="dashboard.html", help="File output HTML")
    pdb.add_argument("--no-color", action="store_true", help="Nonaktifkan warna output")
    pdb.add_argument("--quiet", action="store_true", help="Minimal output")

    # dos (app-layer resilience tester, HANYA dengan izin)
    pdo = sub.add_parser("dos", parents=[common],
                         help="Uji ketahanan app-layer (slowloris/slow POST/flood). Wajib --yes dan izin tertulis!")
    pdo.add_argument("--type", choices=["slowloris", "slowpost", "flood", "all"],
                     default="all", help="Jenis uji (default: all)")
    pdo.add_argument("--concurrency", type=int, default=10,
                     help="Jumlah koneksi/thread bersamaan (default 10)")
    pdo.add_argument("--duration", type=float, default=20.0,
                     help="Durasi uji slowloris/slow POST (detik)")
    pdo.add_argument("--requests", type=int, default=200,
                     help="Batas total request flood")
    pdo.add_argument("--port", type=int, help="Port untuk slowloris (default: dari skema URL)")
    pdo.add_argument("--yes", action="store_true",
                     help="KONFIRMASI izin tertulis untuk menjalankan beban nyata")
    pdo.add_argument("--hammer", action="store_true",
                     help="Mode berat: jalankan semua vektor serentak dengan concurrency & cap tinggi "
                          "(slowloris + slow POST + flood paralel). HANYA dengan --yes")
    pdo.add_argument("--json-output", help="File output JSON")

    # serve (Web UI lokal)
    psv = sub.add_parser("serve", help="Jalankan Web UI lokal (tempel link -> scan otomatis)")
    psv.add_argument("--host", default="127.0.0.1", help="Host untuk bind (default: localhost saja)")
    psv.add_argument("--port", type=int, default=8181, help="Port untuk UI (default: 8181)")
    psv.add_argument("--no-color", action="store_true", help="Nonaktifkan warna output")
    psv.add_argument("--quiet", action="store_true", help="Minimal output")

    # watch (continuous monitoring)
    pwa = sub.add_parser("watch", parents=[common],
                         help="Continuous monitoring: scan terjadwal + diff + alert")
    pwa.add_argument("--interval", type=int, default=3600,
                     help="Interval antar scan (detik, default 3600)")
    pwa.add_argument("--runs", type=int, default=None,
                     help="Jumlah cycle (default: terus menerus sampai Ctrl+C)")
    pwa.add_argument("--state-dir", default=".keris-watch",
                     help="Direktori state untuk menyimpan hasil scan sebelumnya")
    pwa.add_argument("--webhook", help="Webhook Slack/Discord/Telegram untuk alert temuan baru")
    pwa.add_argument("--webhook-type", choices=["auto", "slack", "discord", "telegram"], default="auto")
    pwa.add_argument("--min-severity", default="HIGH", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                     help="Severity minimum untuk alert (default: HIGH)")
    pwa.add_argument("--json-output", help="File output JSON hasil cycle terakhir")

    # tui (terminal interactive)
    ptu = sub.add_parser("tui", help="Terminal UI interaktif: scan + progress + hasil")
    ptu.add_argument("target", help="URL target")
    ptu.add_argument("--no-color", action="store_true", help="Nonaktifkan warna output")
    ptu.add_argument("--quiet", action="store_true", help="Minimal output")

    # hunt (credential hunting)
    phu = sub.add_parser("hunt", parents=[common],
                         help="Credential hunting: .git dump, .env/backup, secret cloud key")
    phu.add_argument("--json-output", help="File output JSON")
    phu.add_argument("--verify", action="store_true",
                     help="Verifikasi AWS key yang ditemukan terhadap endpoint publik AWS")
    phu.add_argument("--asset", action="append", default=[],
                     help="URL aset tambahan untuk scan secret (bisa diulang)")

    # credcheck (validate leaked credentials - authorized only)
    pcc = sub.add_parser("credcheck", parents=[common],
                         help="Validasi kredensial: coba login sungguhan (wajib izin)")
    pcc.add_argument("--creds", default=None,
                     help="Pasangan user:pass, dipisah koma (user1:pass1,user2:pass2)")
    pcc.add_argument("--creds-file", default=None,
                     help="File teks berisi satu 'user:pass' per baris")
    pcc.add_argument("--from-scan", default=None,
                     help="File JSON hasil scan/hunt sebagai sumber kredensial")
    pcc.add_argument("--auth-type", choices=["form", "basic"], default="form",
                     help="Metode login (default: form, fallback basic)")
    pcc.add_argument("--json-output", help="File output JSON")

    # exploit (exploit kit: SQLi dump, LFI/RFI, upload bypass, XXE, RCE)
    pexpl = sub.add_parser("exploit", parents=[common],
                           help="Exploit kit: SQLi dump, LFI/RFI, upload bypass, XXE, RCE (wajib --authorized)")
    pexpl.add_argument("--types", default="sqli,lfi,upload,xxe,rce",
                       help="Jenis exploit (koma): sqli,lfi,rfi,upload,xxe,rce,pivot,rebind")
    pexpl.add_argument("--callback", default=None,
                       help="URL callback (interactsh/Burp) untuk RFI/XXE blind")
    pexpl.add_argument("--max-param", type=int, default=3, dest="max_param",
                       help="Maksimum parameter per endpoint")
    pexpl.add_argument("--endpoint", action="append", default=[],
                       help="Endpoint target manual dengan query (mis. /search?id=1); dapat diulang")
    pexpl.add_argument("--authorized", action="store_true",
                       help="KONFIRMASI izin tertulis untuk eksploitasi aktif")
    pexpl.add_argument("--json-output", help="File output JSON")
    pexpl.add_argument("--exit-on", choices=["none", "high", "medium", "low"], default="high",
                       help="Severity minimum yang menyebabkan exit code 1")

    # shell (generate reverse shell payload + konfirmasi RCE)
    psh = sub.add_parser("shell", parents=[common],
                         help="Generator payload reverse shell + konfirmasi RCE read-only (wajib --authorized)")
    psh.add_argument("--lhost", help="IP mesin penyerang untuk reverse shell")
    psh.add_argument("--lport", type=int, default=4444, help="Port mesin penyerang")
    psh.add_argument("--endpoint", action="append", default=[],
                     help="Endpoint dengan param untuk konfirmasi RCE (dapat diulang)")
    psh.add_argument("--authorized", action="store_true",
                     help="KONFIRMASI izin tertulis untuk eksploitasi aktif")
    psh.add_argument("--json-output", help="File output JSON")

    # pivot (SOCKS5 tunnel via SSRF)
    ppv = sub.add_parser("pivot", parents=[common],
                         help="SOCKS5 proxy pivot via endpoint SSRF terkonfirmasi (wajib --authorized --yes)")
    ppv.add_argument("--ssrf-url", required=True,
                     help="URL parameter SSRF yang rentan (mis. http://host/fetch?url=1)")
    ppv.add_argument("--ssrf-param", required=True,
                     help="Nama parameter SSRF")
    ppv.add_argument("--bind", default="127.0.0.1", help="Host untuk bind SOCKS5")
    ppv.add_argument("--port", type=int, default=1080, help="Port SOCKS5 lokal")
    ppv.add_argument("--yes", action="store_true",
                     help="KONFIRMASI izin tertulis untuk menjalankan pivot")
    ppv.add_argument("--authorized", action="store_true",
                     help="KONFIRMASI izin tertulis untuk eksploitasi aktif")

    # rebind (DNS rebinding server)
    prb = sub.add_parser("rebind", parents=[common],
                         help="Server DNS rebinding untuk bypass SSRF (wajib --authorized --yes)")
    prb.add_argument("--domain", required=True, help="Nama domain rebinding (mis. rebind.example.com)")
    prb.add_argument("--target-ip", required=True,
                     help="IP target internal setelah flip (mis. 169.254.169.254)")
    prb.add_argument("--legit-ip", default="127.0.0.1",
                     help="IP 'sah' untuk jawaban pertama (lolos validasi)")
    prb.add_argument("--bind", default="127.0.0.1", help="Host untuk bind DNS (port 53 butuh root)")
    prb.add_argument("--port", type=int, default=53, help="Port DNS")
    prb.add_argument("--yes", action="store_true",
                     help="KONFIRMASI izin tertulis untuk menjalankan server DNS")
    prb.add_argument("--authorized", action="store_true",
                     help="KONFIRMASI izin tertulis untuk eksploitasi aktif")

    return p.parse_args(argv)


def _resolve_targets(args) -> List[str]:
    """Gunakan `target` atau `--targets` file."""
    if args.target:
        return [args.target]
    if args.targets and os.path.exists(args.targets):
        with open(args.targets, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    if args.targets:
        raise SystemExit(f"File target tidak ditemukan: {args.targets}")
    raise SystemExit("Perlu argumen target atau --targets")


def _merge_config(args) -> tuple:
    """Gabungkan config file + CLI. Kembalikan (cfg, kwargs_overrides)."""
    cfg = KerisConfig.load(getattr(args, "config", None))
    # CLI menang atas config file. Flag store_true (default False) hanya di-override
    # bila benar-benar diaktifkan lewat CLI, supaya nilai True dari config file
    # (mis. insecure/quiet) tidak ditimpa oleh default False argparse.
    overrides = {}
    for field in ("proxy", "timeout", "retries", "workers", "delay", "token", "cookie", "username", "password"):
        val = getattr(args, field, None)
        if val is not None:
            overrides[field] = val
    for field in ("insecure", "quiet"):
        val = getattr(args, field, None)
        if val is True:
            overrides[field] = True
    if getattr(args, "max_assets", None) is not None:
        overrides["max_assets"] = args.max_assets
    # preset concurrency: fast / stealth / aggressive
    preset = getattr(args, "preset", None)
    if preset == "fast":
        overrides.setdefault("workers", 25)
        overrides.setdefault("delay", 0)
    elif preset == "stealth":
        overrides.setdefault("workers", 3)
        overrides.setdefault("delay", 1.0)
    elif preset == "aggressive":
        overrides.setdefault("workers", 50)
        overrides.setdefault("delay", 0)
        # aggressive: aktifkan opsi serangan aktif otomatis bila CLI mengizinkan
        if getattr(args, "authorized", False):
            overrides.setdefault("aggressive", True)
    # gabung plugins CLI ke plugins_dir
    return cfg, overrides


def _make_client(args, cfg: KerisConfig, overrides: dict, base: str = "") -> KerisHTTP:
    token = overrides.get("token", cfg.token)
    cookie = overrides.get("cookie", cfg.cookie)
    basic = None
    uname = overrides.get("username", cfg.username)
    pwd = overrides.get("password", cfg.password)
    if uname and pwd:
        basic = (uname, pwd)
    client = KerisHTTP(
        token=token,
        cookie=cookie,
        basic_auth=basic,
        proxy=overrides.get("proxy", cfg.proxy),
        timeout=overrides.get("timeout", cfg.timeout),
        retries=overrides.get("retries", cfg.retries),
        insecure=overrides.get("insecure", cfg.insecure),
        delay=overrides.get("delay", cfg.delay),
        extra_headers=cfg.headers,
    )
    # auto-login: semua subcommand dapat memakai sesi yang sudah terautentikasi
    if base and getattr(args, "login_username", None) and getattr(args, "login_password", None):
        info("=== AUTO LOGIN ===")
        from keris.modules import auth as auth_module

        client = auth_module.auto_login(
            base, args.login_username, args.login_password,
            login_paths=cfg.login_paths or None,
            timeout=overrides.get("timeout", cfg.timeout),
        )
    return client


def _get_plugins(args, cfg: KerisConfig) -> List[dict]:
    plugins_dir = cfg.plugins_dir
    extra = list(getattr(args, "plugins", []) or [])
    return plugins_module.load_plugins(plugins_dir, extra)


def _run_scan_single(base: str, args, cfg: KerisConfig, overrides: dict, client: KerisHTTP) -> dict:
    findings = []

    # passive recon (crt.sh/whois) — opsional, tidak menyentuh target langsung
    passive = {}
    if getattr(args, "passive", False):
        info("=== PASSIVE RECON ===")
        from keris.modules import passive as passive_module

        passive = passive_module.run_passive_recon(base)

    info("=== RECON ===")
    recon = recon_module.run_recon(base, client)

    info("=== DISCOVERY ===")
    disc = {}
    if args.no_discover:
        disc = {"api_endpoints": [], "js_assets": [], "secrets": [], "secret_count": 0}
    else:
        disc = discovery_module.discover_endpoints(base, client, max_assets=overrides.get("max_assets", cfg.max_assets))
        if not args.no_bruteforce:
            stacks = discovery_module.detect_stack(recon)
            dirs = discovery_module.brute_directories(base, client, overrides.get("workers", cfg.workers), stacks)
            disc["found_dirs"] = dirs

    info("=== SCANNER ===")
    endpoints = disc.get("api_endpoints", [])[:50]
    base_clean = base.rstrip("/")

    # analisis JWT yang ditemukan di bundle JS / halaman
    from keris.modules.jwt import analyze_jwt, extract_jwts

    jwt_found = set()
    for sec in disc.get("secrets", []):
        if sec.get("type", "").lower() in ("jwt", "token"):
            for tok in extract_jwts(sec.get("match", "")):
                jwt_found.add(tok)
    for tok in jwt_found:
        for f in analyze_jwt(tok):
            findings.append(f.to_dict())
            severity(f.severity, f"JWT: {f.title}")

    # security headers & cookie flags dari respons utama
    for f in scanner_module.check_cookie_flags(recon.get("headers", {})):
        findings.append(f.to_dict())
        severity("LOW", f"Cookie tanpa flag: {f.endpoint}")

    tls_f = scanner_module.check_tls(client, base)
    if tls_f:
        findings.append(tls_f.to_dict())
        severity(tls_f.severity, tls_f.title)

    cors_f = scanner_module.check_cors(client, base)
    if cors_f:
        findings.append(cors_f.to_dict())
        severity(cors_f.severity, f"CORS: {base}")

    sec_txt = scanner_module.check_security_txt(client, base)
    if sec_txt:
        findings.append(sec_txt.to_dict())
        severity("INFO", "security.txt tidak ada")

    for d in disc.get("found_dirs", []):
        if d["status"] == 200:
            r = scanner_module.check_directory_listing(client, base + d["path"])
            if r:
                findings.append(r.to_dict())
                severity("HIGH", f"Directory listing: {base}{d['path']}")

    for ep in endpoints[:30]:
        full = base + ep
        if "?" in full:
            from urllib.parse import parse_qsl, urlparse

            params = [k for k, _ in parse_qsl(urlparse(full).query)]
            if params:
                for param in params[:3]:
                    for f in scanner_module.scan_sqli(client, full, param):
                        findings.append(f.to_dict())
                        severity("HIGH", f"SQLi pada {ep} ({param})")
                    for f in scanner_module.scan_xss(client, full, param):
                        findings.append(f.to_dict())
                        severity("MEDIUM", f"XSS potensial pada {ep} ({param})")

    # open redirect pada parameter redirect umum (untuk halaman dengan query)
    from keris.payloads import REDIRECT_PARAMS, URL_PARAMS

    for ep in endpoints[:15]:
        full = base + ep
        if "?" in full:
            from urllib.parse import parse_qsl, urlparse as _up

            qparams = [k for k, _ in parse_qsl(_up(full).query)]
            for param in REDIRECT_PARAMS:
                if param in qparams:
                    r = scanner_module.check_open_redirect(client, full, param)
                    if r:
                        findings.append(r.to_dict())
                        severity("MEDIUM", f"Open redirect: {ep} ({param})")
                    break
            # SSRF pada parameter URL umum (only GET)
            for param in URL_PARAMS:
                if param in qparams:
                    callback = getattr(args, "ssrf_callback", "") or ""
                    for f in scanner_module.scan_ssrf(client, full, param, callback_url=callback):
                        findings.append(f.to_dict())
                        severity("HIGH", f"SSRF: {ep} ({param})")
                    break

    for ep in ["/api/auth/login", "/api/auth/register", "/api/login", "/api/forgot-password"]:
        url = base_clean + ep
        f = scanner_module.check_rate_limit(client, url)
        if f:
            findings.append(f.to_dict())
            severity("LOW", f"Tanpa rate limit: {ep}")

    admin_targets = [p["path"] for p in disc.get("found_dirs", [])
                     if p["path"].strip("/") in ("admin", "dashboard", "panel")]
    for ap in admin_targets:
        f = scanner_module.check_auth_bypass(client, base + ap)
        if f:
            findings.append(f.to_dict())
            severity("HIGH", f"Auth bypass: {base}{ap}")

    # platform checks (opsional, default: nonaktif agar scan tetap cepat)
    if getattr(args, "platform_checks", False):
        from keris.modules import platforms as platforms_module

        pf = platforms_module.check_platforms(base, client)
        findings.extend(x.to_dict() for x in pf)

    # WAF detection (opsional)
    if getattr(args, "waf", False):
        from keris.modules.waf import detect_waf, waf_finding

        waf_res = detect_waf(base, client)
        wf = waf_finding(waf_res)
        if wf:
            findings.append(wf)
            severity(wf["severity"], f"{wf['title']}: {wf['endpoint']}")
        elif waf_res.get("details"):
            info("WAF tidak terdeteksi: " + "; ".join(waf_res["details"][:2]))

    # TLS certificate analysis (opsional)
    if getattr(args, "tls_cert", False):
        from keris.modules.tlscheck import check_tls_cert
        from keris.core.utils import host_from_url

        tls_host = host_from_url(base).split(":", 1)[0]
        tls_result = check_tls_cert(tls_host)
        for sev, issue in tls_result.get("issues", []):
            findings.append({
                "severity": sev, "title": "TLS certificate issue",
                "endpoint": base, "detail": issue,
                "evidence": json.dumps(tls_result.get("cert", {}), default=str)[:500],
            })

    # hidden parameter discovery (opsional)
    if getattr(args, "hidden_params", False):
        from keris.modules.params import discover_hidden_params

        hp = discover_hidden_params(base, client, endpoints[:20])
        findings.extend(x.to_dict() for x in hp)

    # hidden endpoint discovery (opsional)
    if getattr(args, "hidden_endpoints", False):
        from keris.modules.hidden import find_hidden_endpoints

        he = find_hidden_endpoints(base, client)
        findings.extend(x.to_dict() for x in he)

    # web cache poisoning (opsional)
    if getattr(args, "cache_poisoning", False):
        from keris.modules.cachepoison import check_cache_poisoning

        cpf = check_cache_poisoning(base, client)
        findings.extend(x.to_dict() for x in cpf)

    # host header injection (opsional)
    if getattr(args, "host_header", False):
        from keris.modules.hostheader import check_host_header

        hhf = check_host_header(base, client)
        findings.extend(x.to_dict() for x in hhf)

    # websocket security (opsional)
    if getattr(args, "websocket", False):
        from keris.modules.websocket import check_websocket

        wsf = check_websocket(base, client, disc.get("js_assets", []))
        findings.extend(x.to_dict() for x in wsf)

    # client-side JS analysis (opsional)
    if getattr(args, "js_analysis", False):
        from keris.modules.jsanalysis import analyze_js

        jsa = analyze_js(base, client, disc.get("js_assets", []),
                         max_assets=overrides.get("max_assets", cfg.max_assets))
        findings.extend(x.to_dict() for x in jsa["findings"])
        disc.setdefault("js_endpoints", []).extend(jsa["endpoints"])
        disc["secret_count"] = disc.get("secret_count", 0) + jsa["secret_count"]

    # sensitive data exposure (opsional)
    if getattr(args, "sensitive_data", False):
        from keris.modules.sensitive import check_sensitive

        senf = check_sensitive(base, client, endpoints[:30])
        findings.extend(x.to_dict() for x in senf)

    # cloud bucket check (opsional)
    if getattr(args, "buckets", False):
        from keris.modules import buckets as buckets_module

        bf = buckets_module.check_buckets(base, client)
        findings.extend(x.to_dict() for x in bf)

    # fuzzing parameter sederhana (opsional)
    if getattr(args, "fuzz", False):
        from keris.modules import fuzz as fuzz_module

        fuzz_results = fuzz_module.fuzz_parameters(base, client, endpoints[:20])
        findings.extend(f.to_dict() for f in fuzz_results)

    # --- serangan aktif (khusus berizin) ---
    authorized = getattr(args, "authorized", False) or bool(overrides.get("authorized"))
    # auto-exploit injection
    if getattr(args, "exploit", False):
        from keris.modules.exploit import run_exploit

        types = [t.strip() for t in getattr(args, "exploit_types", "sqli,cmdi,ssti,xss").split(",") if t.strip()]
        for f in run_exploit(base, client, endpoints[:25], types=types, authorized=authorized):
            findings.append(f.to_dict())
            severity(f.severity, f"{f.title}: {f.endpoint}")
    # exploit kit: SQLi dump, LFI/RFI, upload bypass, XXE, RCE
    if getattr(args, "exploit_kit", False):
        if not authorized:
            warn("Lewati exploit kit: butuh --authorized")
        else:
            from keris.modules.exploitkit import run_exploit_kit

            kit_findings = run_exploit_kit(
                base, client, endpoints[:25], authorized=authorized,
                callback_url=getattr(args, "ssrf_callback", None) or "",
            )
            findings.extend(f.to_dict() for f in kit_findings)
            for f in kit_findings:
                severity(f.severity, f"{f.title}: {f.endpoint}")
    # brute-force extended + enumerasi username
    if getattr(args, "brute_extended", False):
        if not authorized:
            warn("Lewati brute-force extended: butuh --authorized")
        else:
            from keris.modules import brute as brute_module

            from keris.core.config import KerisConfig as _KC
            login_paths = cfg.login_paths or []
            bf = brute_module.brute_extended(
                base, client, login_paths=login_paths,
                throttle=0.0 if overrides.get("aggressive") else 0.1)
            findings.extend(x.to_dict() for x in bf)
    if getattr(args, "username_enum", False):
        from keris.modules import brute as brute_module

        ue = brute_module.enumerate_usernames(base, client, login_paths=cfg.login_paths or [])
        findings.extend(x.to_dict() for x in ue)
    # CVE/PoC probe untuk platform terdeteksi
    if getattr(args, "exploit_cve", False):
        from keris.modules.cve import check_cve

        for f in check_cve(base, client, platform=getattr(args, "cve_platform", None),
                           authorized=authorized):
            findings.append(f.to_dict())
            severity(f.severity, f"{f.title}: {f.endpoint}")

    # credential hunting (opsional): .git, .env/backup, secret cloud
    if getattr(args, "hunt", False):
        info("=== HUNT ===")
        from keris.modules.hunt import run_hunt

        try:
            hunt_assets = disc.get("js_assets", [])[:20]
            hfindings = run_hunt(base, client, verify=getattr(args, "verify", False),
                                 extra_urls=hunt_assets)
            findings.extend(hfindings)
            for f in hfindings:
                severity(f["severity"], f"{f['title']}: {f['endpoint']}")
        except Exception as e:
            warn(f"Hunt gagal: {e}")

    # SSRF detection (opsional): callback listener out-of-band
    if getattr(args, "ssrf", False):
        info("=== SSRF ===")
        from keris.modules.ssrf import probe_ssrf

        try:
            ssrf_urls = disc.get("api_endpoints", [])[:20]
            ssrf_findings = probe_ssrf(base, client, extra_urls=ssrf_urls)
            findings.extend(ssrf_findings)
            for f in ssrf_findings:
                severity(f["severity"], f"{f['title']}: {f['endpoint']}")
            # exploit: cloud metadata + port internal via SSRF terkonfirmasi
            if ssrf_findings and getattr(args, "ssrf_exploit", False):
                from keris.modules.ssrf import exploit_ssrf

                try:
                    v = ssrf_findings[0]
                    vuln_url = v.get("vuln_url") or v.get("endpoint")
                    vuln_param = v.get("vuln_param", "")
                    if vuln_url and vuln_param:
                        ex = exploit_ssrf(base, client, vuln_url, vuln_param)
                        findings.extend(ex)
                        for f in ex:
                            severity(f["severity"], f"{f['title']}: {f['endpoint']}")
                except Exception as e:
                    warn(f"SSRF exploit gagal: {e}")
        except Exception as e:
            warn(f"SSRF probe gagal: {e}")

    # WAF detection (opsional): fingerprint WAF di awal
    # (deteksi WAF sudah dijalankan di bagian atas _run_scan_single; ini duplikat)

    # headless browser pass (opsional): render JS + DOM XSS + screenshot
    if getattr(args, "browser", False):
        info("=== BROWSER ===")
        from keris.modules.browser import browser_pass

        try:
            bfindings = browser_pass(
                base,
                screenshot=getattr(args, "screenshot", None),
                login={"url": base, "username": getattr(args, "login_username", None),
                       "password": getattr(args, "login_password", None)}
                if getattr(args, "login_username", None) else None,
            )
            findings.extend(bfindings)
            for f in bfindings:
                severity(f["severity"], f"{f['title']}: {f['endpoint']}")
        except ImportError as e:
            warn(str(e))

    # plugin
    if not args.no_plugins:
        info("=== PLUGINS ===")
        plugins = _get_plugins(args, cfg)
        if plugins:
            ctx = {"recon": recon, "discovery": disc, "passive": passive}
            plugin_findings = plugins_module.run_plugins(plugins, client, base, ctx)
            findings.extend(f.to_dict() for f in plugin_findings)
        else:
            debug("Tidak ada plugin ditemukan")

    # correlation engine: chain temuan rendah menjadi chain kritis
    if getattr(args, "chain", False) and findings:
        info("=== CORRELATION ===")
        from keris.modules.correlation import build_chains

        chains = build_chains(findings)
        for c in chains:
            findings.append(c)
            severity(c["severity"], f"{c['title']}: {c['endpoint']}")
        if chains:
            ok(f"Correlation: {len(chains)} attack chain terbentuk")

    # auto-auth chain: kredensial form -> login -> scan area terproteksi
    if getattr(args, "auth_chain", False):
        if not (getattr(args, "login_username", None) and getattr(args, "login_password", None)):
            warn("--auth-chain butuh --login-username dan --login-password; dilewati")
        else:
            try:
                from keris.modules.authchain import run_auth_chain
                res = run_auth_chain(
                    base, args.login_username, args.login_password,
                    client, login_paths=cfg.login_paths or None,
                )
                for f in res["findings"]:
                    findings.append(f.to_dict())
                    severity(f.severity, f"{f.title}: {f.endpoint}")
                if res["authed"]:
                    ok(f"Auth chain: {len(res['findings'])} temuan di area terproteksi")
            except Exception as e:
                warn(f"Auto-auth chain gagal: {e}")

    # JWT attack: crack & forge token yang ditemukan
    if getattr(args, "jwt_attack", False):
        if not getattr(args, "authorized", False):
            warn("--jwt-attack butuh --authorized; dilewati")
        else:
            from keris.modules.jwt import extract_jwts
            from keris.modules.jwtattack import run_jwt_attack
            from keris.core.logger import brutal_warning

            tok_src = []
            for sec in disc.get("secrets", []):
                tok_src.extend(extract_jwts(sec.get("match", "") or ""))
            for tok in tok_src:
                for f in run_jwt_attack(base, tok, client, endpoints=[base.rstrip("/") + "/api/me"]):
                    findings.append(f.to_dict())
                    severity(f.severity, f"{f.title}: {f.endpoint}")
            if tok_src:
                ok(f"JWT attack: {len(tok_src)} token diuji")

    # race condition / TOCTOU: request paralel ke endpoint kritis
    if getattr(args, "race", False):
        if not getattr(args, "authorized", False):
            warn("--race butuh --authorized; dilewati")
        else:
            from keris.modules.race import race_findings

            race_eps = getattr(args, "race_endpoints", None)
            eps = [e.strip() for e in (race_eps or "").split(",") if e.strip()]
            if not eps:
                eps = ["/api/vote", "/api/coupon", "/api/topup", "/api/transfer",
                       "/api/claim", "/api/redeem", "/api/register"]
            try:
                for f in race_findings(base, eps, client, concurrency=8):
                    findings.append(f.to_dict())
                    severity(f.severity, f"{f.title}: {f.endpoint}")
            except Exception as e:
                warn(f"Race condition test gagal: {e}")

    # JS dependency CVE checker
    if getattr(args, "js_deps", False):
        from keris.modules.jsdeps import check_js_dependencies

        js_texts = []
        js_urls = []
        for j in disc.get("js_assets", []) or []:
            try:
                r = client.get(urljoin(base, j), timeout=12)
                if r.status_code == 200:
                    js_texts.append(r.text)
                    js_urls.append(urljoin(base, j))
            except requests.RequestException:
                continue
        try:
            for f in check_js_dependencies(base, js_texts, urls=js_urls or None):
                findings.append(f.to_dict())
                severity(f.severity, f"{f.title}: {f.endpoint}")
        except Exception as e:
            warn(f"JS dependency CVE check gagal: {e}")

    # favicon fingerprint hash
    if getattr(args, "favicon", False):
        from keris.modules.favicon import fingerprint_findings

        try:
            html_src = ""
            try:
                r0 = client.get(base, timeout=15)
                if r0.status_code == 200:
                    html_src = r0.text or ""
            except requests.RequestException:
                pass
            for f in fingerprint_findings(base, client, html=html_src):
                findings.append(f.to_dict())
                info(f"{f.title}: {f.endpoint}")
        except Exception as e:
            warn(f"Favicon fingerprint gagal: {e}")

    # server/framework CVE (banner-based)
    if getattr(args, "server_cve", False):
        from keris.modules.servercve import scan_server_cve

        try:
            r0 = client.get(base, timeout=15)
            html_src = r0.text or ""
            headers0 = dict(r0.headers) if r0.status_code else {}
            for f in scan_server_cve(base, headers0, html=html_src):
                findings.append(f.to_dict())
                severity(f.severity, f"{f.title}: {f.endpoint}")
        except requests.RequestException as e:
            warn(f"Server CVE check gagal: {e}")
        except Exception as e:
            warn(f"Server CVE check gagal: {e}")

    # wayback mining (pasif)
    if getattr(args, "wayback", False):
        from keris.modules.wayback import mine_urls, wayback_findings

        try:
            wb = mine_urls(base)
            for f in wayback_findings(base, wb):
                findings.append(f.to_dict())
                severity(f.severity, f"{f.title}: {f.endpoint}")
        except Exception as e:
            warn(f"Wayback mining gagal: {e}")

    # webhook notifikasi untuk temuan HIGH/CRITICAL
    webhook = getattr(args, "webhook", None)
    if webhook:
        from keris.modules.notify import notify

        critical = [f for f in findings if f.get("severity", "").upper() in ("HIGH", "CRITICAL")]
        if critical:
            notify(webhook, getattr(args, "webhook_type", "auto") or "auto", base, critical)
        else:
            debug("Tidak ada temuan HIGH/CRITICAL; webhook dilewati")

    ok(f"Scan selesai: {len(findings)} temuan")
    result = {"recon": recon, "discovery": disc, "findings": findings}
    if passive:
        result["passive"] = passive
    return result


def _ensure_parent(path: str) -> None:
    """Buat direktori induk untuk path output bila belum ada."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def _write_json_output(base, findings, recon, disc, path, exec_note=None) -> None:
    """Tulis hasil scan ke file JSON."""
    _ensure_parent(path)
    payload = {
        "tool": "keris",
        "version": __version__,
        "target": base,
        "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total": len(findings),
            **{s: sum(1 for f in findings if f.get("severity", "INFO").upper() == s)
               for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")},
        },
        "risk_score": __import__("keris.modules.riskscore", fromlist=["risk_score"]).risk_score(findings),
        "recon": recon,
        "discovery": {"api_endpoints": disc.get("api_endpoints", []),
                      "js_assets": disc.get("js_assets", []),
                      "secrets": disc.get("secrets", [])},
        "findings": findings,
    }
    if exec_note:
        payload["executive_summary"] = exec_note
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    ok(f"JSON output: {path}")


def _write_outputs(base, result, args, options, cfg) -> None:
    recon, disc, findings = result["recon"], result["discovery"], result["findings"]

    # AI/rule-based triage (opsional): annotate findings + executive summary
    exec_note = None
    if getattr(args, "triage", False):
        from keris.modules.triage import triage_findings, executive_summary

        info("=== TRIAGE ===")
        findings, raw_ai = triage_findings(findings, cfg.to_dict() if hasattr(cfg, "to_dict") else {})
        result["findings"] = findings
        exec_note = executive_summary(findings, base, raw_ai)
        ok(f"Triage selesai: {len(findings)} temuan ditinjau")

    # riwayat risk score untuk trend chart di report HTML
    history = _load_history(base)
    _rs = __import__("keris.modules.riskscore", fromlist=["risk_score"]).risk_score(findings)
    history.append({"date": __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M"),
                    "grade": _rs["grade"], "score": _rs["score"], "total": len(findings)})
    _save_history(base, history)
    options = dict(options or {})
    options["history"] = history[-30:]

    if args.output:
        _ensure_parent(args.output)
        write_report(recon, disc, findings, args.output, base, options)
    if getattr(args, "html_output", None):
        _ensure_parent(args.html_output)
        write_html_report(recon, disc, findings, args.html_output, base, options)
    if getattr(args, "pdf_output", None):
        from keris.report_pdf import write_pdf_report

        _ensure_parent(args.pdf_output)
        write_pdf_report(recon, disc, findings, args.pdf_output, base, options)
        ok(f"PDF output: {args.pdf_output}")
    if getattr(args, "json_output", None):
        _write_json_output(base, findings, recon, disc, args.json_output, exec_note)

def _suffixed(path: str, slug: str) -> str:
    """Sisipkan slug sebelum ekstensi file, mis. scan.md -> scan-example_com.md."""
    if not slug:
        return path
    dot = path.rfind(".")
    if dot > path.rfind(os.sep):
        return path[:dot] + "-" + slug + path[dot:]
    return path + "-" + slug


def _history_path(base: str) -> str:
    """Path file riwayat risk score untuk target."""
    import hashlib

    key = hashlib.md5(base.encode("utf-8")).hexdigest()[:10]
    return os.path.join(os.path.expanduser("~"), ".keris", f"history-{key}.json")


def _load_history(base: str) -> List[dict]:
    p = _history_path(base)
    try:
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
    except Exception:
        pass
    return []


def _save_history(base: str, history: List[dict]) -> None:
    p = _history_path(base)
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(history[-100:], f, indent=1)
    except Exception:
        pass


def _exit_code(findings: List[dict], threshold: str) -> int:
    if threshold == "none":
        return EXIT_OK
    order = {"info": 4, "low": 3, "medium": 2, "high": 1, "critical": 0}
    min_sev = order.get(threshold, 1)
    for f in findings:
        if order.get(f.get("severity", "INFO").lower(), 4) <= min_sev:
            return EXIT_FINDINGS
    return EXIT_OK


def _cmd_scan(args, cfg, overrides) -> int:
    targets = _resolve_targets(args)
    all_results = []
    exit_codes = []

    def _scan_one(target: str):
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            result = _run_scan_single(base, args, cfg, overrides, client)
        except Exception as e:
            error(f"Scan gagal untuk {target}: {e}")
            return base, None, EXIT_ERROR
        finally:
            client.close()
        options = {"mode": "otomatis dengan Keris", "targets_file": bool(args.targets)}
        if len(targets) > 1:
            # tulis per-target ke file terpisah agar tidak saling timpa
            import re as _re

            slug = _re.sub(r"[^A-Za-z0-9._-]+", "_", base.split("//")[-1].rstrip("/"))[:60]
            options["per_target"] = True
            if args.output:
                from keris.report import write_report
                write_report(result["recon"], result["discovery"], result["findings"],
                             _suffixed(args.output, slug), base, options)
            if getattr(args, "html_output", None):
                from keris.report_html import write_html_report
                write_html_report(result["recon"], result["discovery"], result["findings"],
                                  _suffixed(args.html_output, slug), base, options)
            if getattr(args, "pdf_output", None):
                from keris.report_pdf import write_pdf_report
                _ensure_parent(_suffixed(args.pdf_output, slug))
                write_pdf_report(result["recon"], result["discovery"], result["findings"],
                                 _suffixed(args.pdf_output, slug), base, options)
            if getattr(args, "json_output", None):
                _write_json_output(base, result["findings"], result["recon"],
                                   result["discovery"], _suffixed(args.json_output, slug))
        else:
            _write_outputs(base, result, args, options, cfg)
        return base, result, _exit_code(result["findings"], getattr(args, "exit_on", "high"))

    if getattr(args, "parallel", False) and len(targets) > 1:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        info(f"Scan paralel: {len(targets)} target")
        with ThreadPoolExecutor(max_workers=min(8, len(targets))) as pool:
            futures = {pool.submit(_scan_one, t): t for t in targets}
            for fut in as_completed(futures):
                base, result, code = fut.result()
                if result is None:
                    exit_codes.append(code)
                    continue
                all_results.append(result)
                exit_codes.append(code)
    else:
        for target in targets:
            info(f"\n===== TARGET: {target} =====")
            base, result, code = _scan_one(target)
            if result is None:
                exit_codes.append(code)
                continue
            all_results.append(result)
            exit_codes.append(code)
            # auto-ticketing (opsional): temuan -> GitHub/Jira
            if getattr(args, "ticket", None):
                from keris.modules.ticketing import create_tickets

                try:
                    created = create_tickets(
                        result["findings"],
                        kind=args.ticket,
                        cfg=cfg.to_dict() if hasattr(cfg, "to_dict") else {},
                        repo=getattr(args, "ticket_repo", None),
                        project=getattr(args, "ticket_project", None),
                        min_severity=getattr(args, "ticket_min", "HIGH"),
                    )
                    ok(f"Auto-ticketing: {len(created)} tiket dibuat")
                except Exception as e:
                    error(f"Auto-ticketing gagal: {e}")

    if len(targets) > 1:
        merged = {
            "recon": {"host": f"{len(targets)} target", "stack": [], "security_headers": []},
            "discovery": {"api_endpoints": [], "js_assets": [], "secrets": []},
            "findings": [f for r in all_results for f in r["findings"]],
        }
        if args.json_output and len(targets) > 1:
            payload = {
                "tool": "keris", "version": __version__,
                "targets": targets,
                "results": all_results,
                "total_findings": len(merged["findings"]),
            }
            with open(args.json_output, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, default=str)
            ok(f"JSON multi-target: {args.json_output}")
        # laporan gabungan multi-target
        if args.output and len(targets) > 1:
            from keris.report import write_report
            write_report(merged["recon"], merged["discovery"], merged["findings"],
                         args.output, ", ".join(targets), {"mode": "multi-target paralel" if getattr(args, "parallel", False) else "multi-target"})
        if getattr(args, "html_output", None) and len(targets) > 1:
            from keris.report_html import write_html_report
            write_html_report(merged["recon"], merged["discovery"], merged["findings"],
                              args.html_output, ", ".join(targets),
                              {"mode": "multi-target paralel" if getattr(args, "parallel", False) else "multi-target"})

    # exit code terburuk
    worst = max(exit_codes) if exit_codes else EXIT_OK
    return worst


def _cmd_recon(args, cfg, overrides) -> int:
    targets = _resolve_targets(args)
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            result = recon_module.run_recon(base, client)
        finally:
            client.close()
        out = args.json_output or args.output
        if out:
            with open(out, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, default=str)
            ok(f"Hasil recon disimpan: {out}")
    return EXIT_OK


def _cmd_passive(args, cfg, overrides) -> int:
    from keris.modules import passive as passive_module

    targets = _resolve_targets(args)
    all_results = {}
    for target in targets:
        base = normalize_url(target)
        info(f"\n===== TARGET: {target} =====")
        result = passive_module.run_passive_recon(base)
        all_results[base] = result
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(all_results if len(targets) > 1 else next(iter(all_results.values())),
                      f, indent=2, default=str)
        ok(f"Hasil passive recon disimpan: {args.output}")
    return EXIT_OK


def _cmd_fuzz(args, cfg, overrides) -> int:
    from keris.modules import fuzz as fuzz_module

    targets = _resolve_targets(args)
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            disc = discovery_module.discover_endpoints(base, client, max_assets=overrides.get("max_assets", cfg.max_assets))
            info(f"Fuzz {len(disc.get('api_endpoints', []))} endpoint...")
            findings = fuzz_module.fuzz_parameters(base, client, disc.get("api_endpoints", []))
        finally:
            client.close()
        ok(f"Fuzz selesai: {len(findings)} sinyal perlu verifikasi manual")
        if args.json_output:
            with open(args.json_output, "w", encoding="utf-8") as f:
                json.dump({"target": base, "findings": [x.to_dict() for x in findings]}, f, indent=2)
            ok(f"JSON output: {args.json_output}")
    return EXIT_OK


def _cmd_discover(args, cfg, overrides) -> int:
    targets = _resolve_targets(args)
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            recon = recon_module.run_recon(base, client)
            disc = discovery_module.discover_endpoints(base, client, max_assets=overrides.get("max_assets", cfg.max_assets))
            if args.brute:
                stacks = discovery_module.detect_stack(recon)
                dirs = discovery_module.brute_directories(base, client, overrides.get("workers", cfg.workers), stacks)
                subs = discovery_module.brute_subdomains(base, client, overrides.get("workers", cfg.workers))
                disc["found_dirs"] = dirs
                disc["found_subdomains"] = subs
        finally:
            client.close()
        if disc.get("api_endpoints"):
            ok(f"Total endpoint API: {len(disc['api_endpoints'])}")
        if args.json_output:
            with open(args.json_output, "w", encoding="utf-8") as f:
                json.dump({"target": base, "recon": recon, "discovery": disc}, f, indent=2, default=str)
            ok(f"JSON output: {args.json_output}")
    return EXIT_OK


def _cmd_plugins(args, cfg, overrides) -> int:
    targets = _resolve_targets(args)
    plugins = _get_plugins(args, cfg)
    if args.list:
        ok(f"Plugin dimuat: {len(plugins)}")
        for p in plugins:
            print(f"  - {p['name']} ({p['path']})")
        return EXIT_OK
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            recon = recon_module.run_recon(base, client)
            disc = discovery_module.discover_endpoints(base, client, max_assets=overrides.get("max_assets", cfg.max_assets))
            ctx = {"recon": recon, "discovery": disc}
            findings = plugins_module.run_plugins(plugins, client, base, ctx)
        finally:
            client.close()
        if args.json_output:
            with open(args.json_output, "w", encoding="utf-8") as f:
                json.dump({"target": base, "findings": [x.to_dict() for x in findings]}, f, indent=2)
            ok(f"JSON output: {args.json_output}")
    return EXIT_OK


def _cmd_jwt(args, cfg, overrides) -> int:
    from keris.modules.jwt import analyze_jwt, decode_jwt

    token = args.token
    decoded = decode_jwt(token)
    if decoded:
        info("Header: " + json.dumps(decoded["header"], default=str))
        info("Payload: " + json.dumps(decoded["payload"], default=str))
    findings = analyze_jwt(token)
    for f in findings:
        severity(f.severity, f"{f.title}: {f.detail}")
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"token": token, "findings": [x.to_dict() for x in findings]}, f, indent=2)
        ok(f"JSON output: {args.json_output}")
    return _exit_code([x.to_dict() for x in findings], getattr(args, "exit_on", "high"))


def _cmd_ports(args, cfg, overrides) -> int:
    from keris.modules.portscan import scan_ports

    ports = None
    if getattr(args, "ports", None):
        try:
            ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
        except ValueError:
            raise SystemExit("--ports harus berupa angka dipisah koma")
    host = args.host
    if host.lower().startswith("http"):
        from urllib.parse import urlparse

        host = urlparse(host).hostname or host
    open_ports = scan_ports(host, ports, workers=args.workers, timeout=args.scan_timeout)
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"host": host, "open_ports": open_ports}, f, indent=2)
        ok(f"JSON output: {args.json_output}")
    return EXIT_OK


def _cmd_openapi(args, cfg, overrides) -> int:
    from keris.modules.openapi import extract_operations, fetch_openapi

    targets = _resolve_targets(args)
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            spec = fetch_openapi(base, client)
            if not spec:
                continue
            ops = extract_operations(spec, base)
            ok(f"Endpoint dari spec: {len(ops)}")
            if not args.no_fuzz and ops:
                from keris.modules import fuzz as fuzz_module
                from urllib.parse import urlencode

                # bangun URL GET dengan query sample dari spec
                urls = []
                for op in ops:
                    if op["method"] != "get":
                        continue
                    q_params = {p["name"]: p["value"] for p in op["params"] if p["in"] == "query"}
                    target = op["url"]
                    if q_params:
                        target += ("&" if "?" in target else "?") + urlencode(q_params)
                    urls.append(target)
                info(f"Fuzz {len(urls)} endpoint GET...")
                findings = fuzz_module.fuzz_parameters(base, client, urls)
                ok(f"Fuzz selesai: {len(findings)} sinyal perlu verifikasi manual")
            else:
                findings = []
        finally:
            client.close()
        if args.json_output:
            with open(args.json_output, "w", encoding="utf-8") as f:
                json.dump({"target": base, "operations": ops,
                           "findings": [x.to_dict() for x in findings]}, f, indent=2)
            ok(f"JSON output: {args.json_output}")
    return EXIT_OK


def _cmd_bruteforce(args, cfg, overrides) -> int:
    from keris.modules import brute as brute_module

    targets = _resolve_targets(args)
    all_findings = []
    authorized = getattr(args, "authorized", False)
    login_paths = cfg.login_paths or []

    # enumerasi username
    if getattr(args, "enumerate", False):
        for target in targets:
            base = normalize_url(target)
            client = _make_client(args, cfg, overrides, base)
            try:
                all_findings.extend(brute_module.enumerate_usernames(base, client, login_paths=login_paths))
            finally:
                client.close()

    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            atype = args.type
            if getattr(args, "extended", False):
                if not authorized:
                    warn("Lewati brute-force extended: butuh --authorized")
                else:
                    all_findings.extend(brute_module.brute_extended(
                        base, client, login_paths=login_paths,
                        throttle=getattr(args, "throttle", 0.1)))
            if atype in ("auto", "form"):
                all_findings.extend(brute_module.brute_login_form(base, client, login_paths=login_paths))
            if atype in ("auto", "basic") and not all_findings:
                all_findings.extend(brute_module.brute_login_basic(base, client))
        finally:
            client.close()
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"findings": [x.to_dict() for x in all_findings]}, f, indent=2)
        ok(f"JSON output: {args.json_output}")
    return _exit_code([x.to_dict() for x in all_findings], getattr(args, "exit_on", "high"))


def _cmd_platforms(args, cfg, overrides) -> int:
    from keris.modules import platforms as platforms_module

    targets = _resolve_targets(args)
    all_findings = []
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            all_findings.extend(platforms_module.check_platforms(base, client,
                                                                 platforms=args.names))
        finally:
            client.close()
    ok(f"Platform check selesai: {len(all_findings)} temuan")
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"findings": [x.to_dict() for x in all_findings]}, f, indent=2)
        ok(f"JSON output: {args.json_output}")
    return _exit_code([x.to_dict() for x in all_findings], getattr(args, "exit_on", "high"))


def _cmd_project(args, cfg, overrides) -> int:
    from keris.modules import project as project_module

    result = project_module.scan_project(args.path)
    findings = result["findings"]

    if args.output:
        lines = [f"# Keris Project Audit — {result['root']}", ""]
        lines.append(f"File di-scan: {result['summary']['files_scanned']} · "
                     f"Total temuan: {result['summary']['total']}")
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            lines.append(f"- {s}: {result['summary'].get(s, 0)}")
        lines.append("")
        for f in findings:
            lines.append(f"## [{f['severity']}] {f['rule']} — {f['file']}:{f['line']}")
            lines.append("")
            lines.append(f"**Deskripsi:** {f['desc']}")
            lines.append("")
            lines.append("```")
            lines.append(f['context'])
            lines.append("```")
            lines.append("")
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        ok(f"Laporan ditulis: {args.output}")

    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        ok(f"JSON output: {args.json_output}")

    # exit code: blokir bila ada critical/high
    return EXIT_FINDINGS if (result["summary"].get("CRITICAL", 0) or result["summary"].get("HIGH", 0)) else EXIT_OK


def _cmd_wayback(args, cfg, overrides) -> int:
    from keris.modules.wayback import extract_interesting, fetch_wayback_urls

    entries = fetch_wayback_urls(args.domain, limit=args.limit)
    interesting = extract_interesting(entries)
    if interesting:
        ok(f"Endpoint/file menarik: {len(interesting)}")
        for u in interesting[:40]:
            print(f"  - {u}")
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"domain": args.domain, "entries": entries,
                       "interesting": interesting}, f, indent=2, default=str)
        ok(f"JSON output: {args.json_output}")
    return EXIT_OK


def _cmd_dns(args, cfg, overrides) -> int:
    from keris.modules.dnscheck import check_dns, resolve_subdomains

    result = check_dns(args.domain)
    for sev, issue in result.get("issues", []):
        severity(sev, issue)
    if getattr(args, "subdomains", None) and os.path.exists(args.subdomains):
        with open(args.subdomains, "r", encoding="utf-8") as f:
            subs = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        active = resolve_subdomains(args.domain, subs)
        result["active_subdomains"] = active
        ok(f"Subdomain aktif: {len(active)}/{len(subs)}")
        for a in active[:40]:
            print(f"  - {a['subdomain']}.{args.domain} ({a['type']})")
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, default=str)
        ok(f"JSON output: {args.json_output}")
    return EXIT_OK


def _cmd_subdomain(args, cfg, overrides) -> int:
    from keris.modules.subenum import (
        enumerate_subdomains,
        subenum_findings,
        detect_wildcard,
    )

    domain = args.domain
    if not domain_from_host(domain):
        error(f"'{domain}' bukan domain yang valid untuk enumerasi subdomain")
        return EXIT_ERROR
    wordlist = None
    if getattr(args, "wordlist", None):
        with open(args.wordlist, "r", encoding="utf-8") as f:
            wordlist = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    else:
        from keris.modules.discovery import load_wordlist

        wordlist = load_wordlist("subdomains.txt")

    result = enumerate_subdomains(
        domain,
        wordlist=wordlist,
        use_crt=not getattr(args, "no_crt", False),
        max_workers=getattr(args, "workers", 20),
    )
    for f in subenum_findings(domain, result):
        severity(f.severity, f"{f.title}: {f.endpoint}")

    ok(f"Total subdomain: {result['count']}")
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, default=str)
        ok(f"JSON output: {args.json_output}")
    return EXIT_OK


def _cmd_buckets(args, cfg, overrides) -> int:
    from keris.modules import buckets as buckets_module

    targets = _resolve_targets(args)
    all_findings = []
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            all_findings.extend(buckets_module.check_buckets(base, client, name=args.name))
        finally:
            client.close()
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"findings": [x.to_dict() for x in all_findings]}, f, indent=2)
        ok(f"JSON output: {args.json_output}")
    return _exit_code([x.to_dict() for x in all_findings], getattr(args, "exit_on", "high"))


def _cmd_tls(args, cfg, overrides) -> int:
    from keris.modules.tlscheck import check_tls_cert
    from keris.core.utils import host_from_url

    targets = _resolve_targets(args)
    all_results = []
    for target in targets:
        base = normalize_url(target)
        netloc = host_from_url(base)
        host = netloc.split(":", 1)[0]
        port = args.port
        result = check_tls_cert(host, port=port)
        all_results.append(result)
        for sev, issue in result.get("issues", []):
            severity(sev, issue)
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump(all_results if len(all_results) > 1 else all_results[0], f, indent=2, default=str)
        ok(f"JSON output: {args.json_output}")
    return EXIT_OK


def _cmd_waf(args, cfg, overrides) -> int:
    from keris.modules.waf import detect_waf, waf_finding

    targets = _resolve_targets(args)
    all_findings = []
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            info(f"=== WAF CHECK: {base} ===")
            res = detect_waf(base, client)
            wf = waf_finding(res)
            if wf:
                all_findings.append(wf)
                severity(wf["severity"], f"{wf['title']}: {wf['endpoint']}")
            else:
                info("WAF tidak terdeteksi (tidak ada tanda tangan/blokir)")
            for d in res.get("details", []):
                debug(d)
        finally:
            client.close()
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"tool": "keris", "version": __version__,
                       "command": "waf", "findings": all_findings}, f,
                      indent=2, default=str)
        ok(f"JSON output: {args.json_output}")
    return _exit_code(all_findings, getattr(args, "exit_on", "high"))


def _cmd_params(args, cfg, overrides) -> int:
    from keris.modules.params import discover_hidden_params

    targets = _resolve_targets(args)
    all_findings = []
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            disc = discovery_module.discover_endpoints(base, client, max_assets=overrides.get("max_assets", cfg.max_assets))
            all_findings.extend(discover_hidden_params(base, client, disc.get("api_endpoints", [])))
        finally:
            client.close()
    ok(f"Hidden params selesai: {len(all_findings)} sinyal")
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"findings": [x.to_dict() for x in all_findings]}, f, indent=2)
        ok(f"JSON output: {args.json_output}")
    return EXIT_OK


def _cmd_hidden(args, cfg, overrides) -> int:
    from keris.modules.hidden import find_hidden_endpoints

    targets = _resolve_targets(args)
    all_findings = []
    extra = []
    if getattr(args, "wordlist", None) and os.path.exists(args.wordlist):
        with open(args.wordlist, "r", encoding="utf-8") as f:
            extra = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            all_findings.extend(find_hidden_endpoints(base, client, endpoints=extra))
        finally:
            client.close()
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"findings": [x.to_dict() for x in all_findings]}, f, indent=2)
        ok(f"JSON output: {args.json_output}")
    return _exit_code([x.to_dict() for x in all_findings], getattr(args, "exit_on", "high"))


def _cmd_crawl(args, cfg, overrides) -> int:
    from keris.modules.crawler import crawl, crawl_findings

    targets = _resolve_targets(args)
    all_results = []
    all_findings = []
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            result = crawl(base, client, max_pages=args.max_pages, max_depth=args.max_depth)
            all_results.append(result)
            all_findings.extend(crawl_findings(result))
        finally:
            client.close()
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"results": all_results,
                       "findings": [x.to_dict() for x in all_findings]}, f, indent=2)
        ok(f"JSON output: {args.json_output}")
    return _exit_code([x.to_dict() for x in all_findings], getattr(args, "exit_on", "high"))


def _cmd_graphql(args, cfg, overrides) -> int:
    from keris.modules.graphql import check_graphql

    targets = _resolve_targets(args)
    all_findings = []
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            all_findings.extend(check_graphql(base, client))
        finally:
            client.close()
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"findings": [x.to_dict() for x in all_findings]}, f, indent=2)
        ok(f"JSON output: {args.json_output}")
    return _exit_code([x.to_dict() for x in all_findings], getattr(args, "exit_on", "high"))


def _cmd_takeover(args, cfg, overrides) -> int:
    from keris.modules.takeover import check_takeover
    from keris.core.utils import host_from_url

    targets = _resolve_targets(args)
    all_findings = []
    for target in targets:
        base = normalize_url(target)
        host = host_from_url(base).split(":", 1)[0]
        client = _make_client(args, cfg, overrides, base)
        try:
            all_findings.extend(check_takeover(host, client))
        finally:
            client.close()
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"findings": [x.to_dict() for x in all_findings]}, f, indent=2)
        ok(f"JSON output: {args.json_output}")
    return _exit_code([x.to_dict() for x in all_findings], getattr(args, "exit_on", "high"))


def _cmd_smuggling(args, cfg, overrides) -> int:
    from keris.modules.smuggling import check_smuggling

    targets = _resolve_targets(args)
    all_findings = []
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            all_findings.extend(check_smuggling(base, client))
        finally:
            client.close()
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"findings": [x.to_dict() for x in all_findings]}, f, indent=2)
        ok(f"JSON output: {args.json_output}")
    return _exit_code([x.to_dict() for x in all_findings], getattr(args, "exit_on", "high"))


def _cmd_cachepoison(args, cfg, overrides) -> int:
    from keris.modules.cachepoison import check_cache_poisoning

    targets = _resolve_targets(args)
    all_findings = []
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            all_findings.extend(check_cache_poisoning(base, client,
                                                      paths=args.path or None))
        finally:
            client.close()
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"findings": [x.to_dict() for x in all_findings]}, f, indent=2)
        ok(f"JSON output: {args.json_output}")
    return _exit_code([x.to_dict() for x in all_findings], getattr(args, "exit_on", "high"))


def _cmd_hostheader(args, cfg, overrides) -> int:
    from keris.modules.hostheader import check_host_header

    targets = _resolve_targets(args)
    all_findings = []
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            all_findings.extend(check_host_header(base, client,
                                                  paths=args.path or None))
        finally:
            client.close()
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"findings": [x.to_dict() for x in all_findings]}, f, indent=2)
        ok(f"JSON output: {args.json_output}")
    return _exit_code([x.to_dict() for x in all_findings], getattr(args, "exit_on", "high"))


def _cmd_websocket(args, cfg, overrides) -> int:
    from keris.modules.websocket import check_websocket

    targets = _resolve_targets(args)
    all_findings = []
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            all_findings.extend(check_websocket(base, client))
        finally:
            client.close()
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"findings": [x.to_dict() for x in all_findings]}, f, indent=2)
        ok(f"JSON output: {args.json_output}")
    return _exit_code([x.to_dict() for x in all_findings], getattr(args, "exit_on", "high"))


def _cmd_jsanalysis(args, cfg, overrides) -> int:
    from keris.modules.jsanalysis import analyze_js

    targets = _resolve_targets(args)
    all_results = []
    all_findings = []
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            res = analyze_js(base, client, max_assets=args.max_assets)
            all_results.append({"target": base, "js_scanned": res["js_scanned"],
                                "endpoints": res["endpoints"],
                                "secret_count": res["secret_count"]})
            all_findings.extend(res["findings"])
        finally:
            client.close()
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"results": all_results,
                       "findings": [x.to_dict() for x in all_findings]}, f, indent=2)
        ok(f"JSON output: {args.json_output}")
    return _exit_code([x.to_dict() for x in all_findings], getattr(args, "exit_on", "high"))


def _cmd_sensitive(args, cfg, overrides) -> int:
    from keris.modules.sensitive import check_sensitive

    targets = _resolve_targets(args)
    all_findings = []
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            all_findings.extend(check_sensitive(base, client,
                                                endpoints=args.endpoint or None))
        finally:
            client.close()
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"findings": [x.to_dict() for x in all_findings]}, f, indent=2)
        ok(f"JSON output: {args.json_output}")
    return _exit_code([x.to_dict() for x in all_findings], getattr(args, "exit_on", "high"))


def _cmd_retest(args, cfg, overrides) -> int:
    from keris.modules.retest import retest

    if getattr(args, "live", False):
        if not getattr(args, "authorized", False):
            from keris.core.logger import error as _error
            _error("retest --live menyentuh target secara langsung. Wajib --authorized.")
            return EXIT_ERROR
        return _cmd_retest_live(args, cfg, overrides)

    if not args.new_json:
        from keris.core.logger import error as _error
        _error("Perlu argumen new_json, atau gunakan --live untuk re-scan otomatis.")
        return EXIT_ERROR
    diff = retest(args.old_json, args.new_json, args.output, args.json_output)
    # exit 1 bila ada temuan baru / belum diperbaiki
    if diff["summary"]["new"] or diff["summary"]["persisting"]:
        return EXIT_FINDINGS
    return EXIT_OK


def _cmd_retest_live(args, cfg, overrides) -> int:
    """Re-scan target dari old_json lalu diff; buktikan temuan sudah fixed/persist."""
    import json as _json
    from keris.modules.retest import diff_findings, generate_diff_data, _load
    from keris.core.logger import error as _error, ok as _ok, info as _info, warn as _warn

    with open(args.old_json, "r", encoding="utf-8") as f:
        old_data = _json.load(f)
    if isinstance(old_data, dict) and "results" in old_data and isinstance(old_data["results"], list):
        old_target = old_data.get("targets", [""])[0]
        old_findings = [x for r in old_data["results"] for x in r.get("findings", [])]
    elif isinstance(old_data, dict) and "target" in old_data:
        old_target = old_data.get("target", "")
        old_findings = old_data.get("findings", [])
    else:
        old_target = ""
        old_findings = old_data if isinstance(old_data, list) else []
    if not old_target:
        _error("Target tidak bisa dibaca dari old_json.")
        return EXIT_ERROR

    _info("=== LIVE RETEST ===")
    _info(f"Re-scan target: {old_target}")
    base = normalize_url(old_target)
    client = _make_client(args, cfg, overrides, base)
    try:
        new_result = _run_scan_single(base, args, cfg, overrides, client)
    except Exception as e:
        _error(f"Re-scan gagal: {e}")
        return EXIT_ERROR
    finally:
        client.close()
    new_findings = new_result["findings"]

    diff = diff_findings(old_findings, new_findings)
    s = diff["summary"]
    _ok(f"Live retest: {s['fixed']} fixed, {s['new']} new, {s['persisting']} persisting "
        f"(progres {s['progress']:.1f}%)")

    # simpan hasil scan baru agar bisa dipakai retest offline selanjutnya
    new_json_path = args.json_output.replace(".json", "-new.json") if args.json_output else None
    md_path = args.output
    if new_json_path:
        payload = {
            "tool": "keris",
            "version": __version__,
            "target": base,
            "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
            "summary": {"total": len(new_findings)},
            "findings": new_findings,
        }
        with open(new_json_path, "w", encoding="utf-8") as f:
            _json.dump(payload, f, indent=2, default=str)
        _ok(f"Hasil scan baru: {new_json_path}")
    if md_path:
        md, _ = generate_diff_data(old_target, old_findings, base, new_findings,
                                   args.old_json, new_json_path or "")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md)
        _ok(f"Laporan retest live: {md_path}")
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            _json.dump(diff, f, indent=2, default=str)
        _ok(f"JSON retest: {args.json_output}")

    if s["new"] or s["persisting"]:
        return EXIT_FINDINGS
    return EXIT_OK


def _cmd_dos(args, cfg, overrides) -> int:
    from keris.modules.dos import run_dos_test

    if not getattr(args, "yes", False):
        from keris.core.logger import error as _error

        _error("Uji DoS membutuhkan konfirmasi izin tertulis. Gunakan --yes.")
        return EXIT_ERROR

    targets = _resolve_targets(args)
    all_findings = []
    hammer = getattr(args, "hammer", False)
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            if hammer:
                # mode brutal: semua vektor serentak dengan cap tinggi
                from keris.modules.dos import run_dos_test as _run
                from keris.modules.dos import run_hammer
                from keris.modules.scanner import Finding
                from keris.core.logger import brutal_warning

                brutal_warning("HAMMER")
                warn("HAMMER mode: seluruh vektor serentak. Pastikan izin tertulis penuh.")
                results = run_hammer(
                    base, client,
                    concurrency=args.concurrency,
                    duration=args.duration,
                    total=args.requests,
                    port=getattr(args, "port", None),
                )
                for name, stats in results["vectors"].items():
                    ok(f"HAMMER {name}: {stats.get('sent', 0)} paket/request, "
                       f"{stats.get('errors', 0)} error")
                all_findings.append(Finding(
                    results["alive"] and "INFO" or "HIGH",
                    "HAMMER DoS: semua vektor serentak",
                    base,
                    "Mode brutal menjalankan slowloris + slow POST + flood secara "
                    "paralel. " + ("Layanan tetap responsif." if results["alive"]
                                   else "Layanan tidak responsif setelah hammer!"),
                    f"vectors={list(results['vectors'])}",
                ))
            else:
                all_findings.extend(run_dos_test(
                    base, client,
                    kind=args.type,
                    concurrency=args.concurrency,
                    duration=args.duration,
                    total=args.requests,
                    port=getattr(args, "port", None),
                    confirmed=True,
                ))
        finally:
            client.close()

    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"findings": [x.to_dict() for x in all_findings]}, f, indent=2)
        ok(f"JSON output: {args.json_output}")
    # exit code mengikuti temuan tertinggi (default high)
    return _exit_code([x.to_dict() for x in all_findings], getattr(args, "exit_on", "high"))


def _cmd_serve(args, cfg, overrides) -> int:
    from keris.ui import run_ui

    run_ui(host=args.host, port=args.port)
    return EXIT_OK


def _cmd_watch(args, cfg, overrides) -> int:
    from keris.modules.watch import watch_loop

    targets = _resolve_targets(args)
    state_dir = args.state_dir

    def run_scan(target: str, out_path: str) -> str:
        # Jalankan scan sebagai subproses dengan output JSON
        import subprocess
        import sys as _sys

        cmd = [_sys.executable, "-m", "keris", "scan", target,
               "--no-color", "--json-output", out_path]
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", cwd=os.getcwd())
        if r.returncode not in (0, 1):
            warn(f"Scan subprocess rc={r.returncode}: {r.stderr[-300:]}")
        return out_path

    alert_count = 0
    for target in targets:
        info(f"Watch target: {target}")
        alert_count += watch_loop(
            target, state_dir,
            run_scan=run_scan,
            interval=args.interval,
            runs=args.runs,
            webhook=args.webhook,
            webhook_type=args.webhook_type,
            min_severity=args.min_severity,
            json_output=args.json_output,
        )
    if alert_count:
        warn(f"Total cycle dengan temuan alertable: {alert_count}")
        return EXIT_FINDINGS
    return EXIT_OK


def _cmd_tui(args, cfg, overrides) -> int:
    from keris.modules.tui import run_tui

    base = normalize_url(args.target)
    outdir = os.path.join(os.getcwd(), ".keris-tui")
    os.makedirs(outdir, exist_ok=True)
    # Setiap proyek TUI menjalankan scan penuh default dengan --no-color
    cmd = [sys.executable, "-m", "keris", "scan", base, "--no-color", "-o",
           os.path.join(outdir, "report.md")]
    rc = run_tui(base, cmd)
    return rc if rc in (0, 1) else EXIT_ERROR


def _cmd_credcheck(args, cfg, overrides) -> int:
    from keris.core.logger import brutal_warning
    from keris.modules.credcheck import (
        extract_creds_from_findings,
        validate_credentials,
    )

    brutal_warning("CREDCHECK")

    creds = []
    if args.creds:
        for part in args.creds.split(","):
            if ":" in part:
                user, pw = part.split(":", 1)
                creds.append((user.strip(), pw.strip()))
    if args.creds_file:
        with open(args.creds_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and ":" in line:
                    user, pw = line.split(":", 1)
                    creds.append((user.strip(), pw.strip()))
    if args.from_scan:
        with open(args.from_scan, "r", encoding="utf-8") as f:
            data = json.load(f)
        findings = data.get("findings", data if isinstance(data, list) else [])
        creds.extend(extract_creds_from_findings(findings))

    creds = list(dict.fromkeys(creds))
    if not creds:
        error("Tidak ada kredensial. Gunakan --creds, --creds-file, atau --from-scan.")
        return EXIT_ERROR

    targets = _resolve_targets(args)
    results = []
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            results.extend(validate_credentials(
                base, creds, client=client,
                auth_type=getattr(args, "auth_type", "form")))
        finally:
            client.close()

    confirmed = [r for r in results if r["ok"]]
    for r in results:
        if r["ok"]:
            severity("HIGH", f"Kredensial VALID: {r['username']}:{r['password']} -> {r['url']}")
        else:
            debug(f"invalid: {r['username']}:{r['password']} ({r.get('status')})")

    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({
                "tool": "keris", "version": __version__,
                "command": "credcheck",
                "confirmed": confirmed,
                "total_tested": len(results),
            }, f, indent=2, default=str)
        ok(f"JSON output: {args.json_output}")

    if confirmed:
        warn(f"{len(confirmed)} kredensial VALID. Reset segera / laporkan ke pemilik target.")
        return EXIT_FINDINGS
    info(f"Tidak ada kredensial valid ({len(results)} diuji)")
    return EXIT_OK


def _cmd_hunt(args, cfg, overrides) -> int:
    from keris.modules.hunt import run_hunt

    if getattr(args, "verify", False):
        from keris.core.logger import brutal_warning

        brutal_warning("HUNT --VERIFY")

    targets = _resolve_targets(args)
    all_findings = []
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            all_findings.extend(run_hunt(base, client, verify=args.verify,
                                         extra_urls=args.asset))
        finally:
            client.close()
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({
                "tool": "keris", "version": __version__,
                "command": "hunt",
                "findings": all_findings,
            }, f, indent=2, default=str)
        ok(f"JSON output: {args.json_output}")
    return _exit_code(all_findings, getattr(args, "exit_on", "high"))


def _cmd_exploit(args, cfg, overrides) -> int:
    from keris.core.logger import brutal_warning

    brutal_warning("EXPLOIT KIT")
    targets = _resolve_targets(args)
    all_findings = []
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            from keris.modules import discovery as _disc

            disc = _disc.discover_endpoints(base, client,
                                            max_assets=overrides.get("max_assets", cfg.max_assets))
            endpoints = disc.get("api_endpoints", [])[:30]
            endpoints.extend(getattr(args, "endpoint", []))
            endpoints = [e if e.startswith("http") else base.rstrip("/") + e
                         for e in endpoints]
            from keris.modules.exploitkit import run_exploit_kit

            fnds = run_exploit_kit(
                base, client, endpoints,
                types=[t.strip() for t in args.types.split(",") if t.strip()],
                callback_url=getattr(args, "callback", None),
                authorized=bool(getattr(args, "authorized", False)),
                yes=bool(getattr(args, "yes", False)),
            )
            all_findings.extend(f.to_dict() for f in fnds)
        finally:
            client.close()
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"tool": "keris", "version": __version__,
                       "command": "exploit", "findings": all_findings},
                      f, indent=2, default=str)
        ok(f"JSON output: {args.json_output}")
    return _exit_code(all_findings, getattr(args, "exit_on", "high"))


def _cmd_shell(args, cfg, overrides) -> int:
    from keris.core.logger import brutal_warning

    brutal_warning("RCE SHELL HELPER")
    if not getattr(args, "authorized", False):
        error("--shell memerlukan --authorized.")
        return EXIT_ERROR
    from keris.modules.shell import confirm_rce

    results = []
    if getattr(args, "lhost", None):
        from keris.modules.exploitkit import print_shell_payloads

        results.append({"payloads": print_shell_payloads(args.lhost, args.lport)})
    if args.endpoint:
        targets = _resolve_targets(args)
        for target in targets:
            base = normalize_url(target)
            client = _make_client(args, cfg, overrides, base)
            try:
                fnds = confirm_rce(base, client, args.endpoint, authorized=True)
                results.append({"endpoint": base,
                                "findings": [f.to_dict() for f in fnds]})
            finally:
                client.close()
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"tool": "keris", "version": __version__,
                       "command": "shell", "results": results},
                      f, indent=2, default=str)
    return EXIT_OK


def _cmd_pivot(args, cfg, overrides) -> int:
    from keris.core.logger import brutal_warning

    brutal_warning("SOCKS5 PIVOT")
    if not getattr(args, "authorized", False) or not getattr(args, "yes", False):
        error("Pivot memerlukan --authorized DAN --yes.")
        return EXIT_ERROR
    base = normalize_url(args.target) if getattr(args, "target", None) else args.ssrf_url
    client = _make_client(args, cfg, overrides, base)
    from keris.modules.pivot import setup_pivot

    srv = setup_pivot(args.ssrf_url, args.ssrf_param, client,
                      bind=args.bind, port=args.port,
                      authorized=True, yes=True)
    if srv is None:
        client.close()
        return EXIT_ERROR
    try:
        import time as _t
        while True:
            _t.sleep(3600)
    except KeyboardInterrupt:
        ok("Pivot dihentikan")
    finally:
        srv.stop()
        client.close()
    return EXIT_OK


def _cmd_rebind(args, cfg, overrides) -> int:
    from keris.core.logger import brutal_warning

    brutal_warning("DNS REBINDING")
    if not getattr(args, "authorized", False) or not getattr(args, "yes", False):
        error("Rebind memerlukan --authorized DAN --yes.")
        return EXIT_ERROR
    base = normalize_url(args.target) if getattr(args, "target", None) else f"http://{args.domain}/"
    client = _make_client(args, cfg, overrides, base)
    from keris.modules.dnsrebind import start_rebinder

    dns = start_rebinder(args.domain, args.target_ip, legit_ip=args.legit_ip,
                         bind=args.bind, port=args.port,
                         authorized=True, yes=True)
    if dns is None:
        client.close()
        return EXIT_ERROR
    try:
        import time as _t
        while True:
            _t.sleep(3600)
    except KeyboardInterrupt:
        ok("DNS rebinding dihentikan")
    finally:
        dns.stop()
        client.close()
    return EXIT_OK


def _cmd_export(args, cfg, overrides) -> int:
    from keris.modules.export import export_requests

    with open(args.json_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    findings = data.get("findings", data if isinstance(data, list) else [])
    target = data.get("target", args.json_file)
    out = export_requests(findings, args.format, target)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        ok(f"Export ditulis: {args.output} ({args.format})")
    else:
        print(out)
    return EXIT_OK


def _cmd_dashboard(args, cfg, overrides) -> int:
    from keris.report_dashboard import build_dashboard

    results = []
    for jf in args.json_files:
        if not os.path.exists(jf):
            warn(f"File tidak ditemukan: {jf}")
            continue
        with open(jf, "r", encoding="utf-8") as f:
            data = json.load(f)
        if "findings" in data:
            results.append({"target": data.get("target", jf), "findings": data["findings"]})
        elif isinstance(data, list):
            results.append({"target": jf, "findings": data})
    if not results:
        error("Tidak ada laporan valid untuk dashboard")
        return EXIT_ERROR
    build_dashboard(results, args.output)
    ok(f"Dashboard ditulis: {args.output} ({len(results)} laporan)")
    return EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    cfg, overrides = _merge_config(args)

    if getattr(args, "no_color", False):
        from keris.core import logger as logger_mod

        logger_mod.disable_color()
    set_quiet(getattr(args, "quiet", False) or overrides.get("quiet", False))

    from keris.core.logger import brutal_warning

    # --- MODE OVERPOWERED: --pwn mengaktifkan seluruh modul serangan ---
    if args.command == "scan" and getattr(args, "pwn", False):
        if not getattr(args, "authorized", False):
            from keris.core.logger import error as _err

            _err("--pwn membutuhkan --authorized (konfirmasi izin tertulis).")
            return 2
        for _flag in ("hunt", "chain", "triage", "browser", "exploit",
                      "brute_extended", "exploit_cve", "cache_poisoning",
                      "host_header", "username_enum", "ssrf", "waf",
                      "ssrf_exploit", "jwt_attack", "race", "js_deps",
                      "favicon", "server_cve", "wayback", "exploit_kit"):
            if not hasattr(args, _flag):
                setattr(args, _flag, False)
            setattr(args, _flag, True)
        brutal_warning("PWN")

    # output-dir: semua laporan ditulis ke direktori tersebut
    if getattr(args, "output_dir", None):
        os.makedirs(args.output_dir, exist_ok=True)
        _join_output = lambda p: os.path.join(args.output_dir, os.path.basename(p))
        for attr in ("output", "json_output", "html_output", "pdf_output"):
            val = getattr(args, attr, None)
            if val:
                setattr(args, attr, _join_output(val))

    try:
        if args.command == "recon":
            return _cmd_recon(args, cfg, overrides)
        if args.command == "passive":
            return _cmd_passive(args, cfg, overrides)
        if args.command == "discover":
            return _cmd_discover(args, cfg, overrides)
        if args.command == "scan":
            return _cmd_scan(args, cfg, overrides)
        if args.command == "plugins":
            return _cmd_plugins(args, cfg, overrides)
        if args.command == "fuzz":
            return _cmd_fuzz(args, cfg, overrides)
        if args.command == "jwt":
            return _cmd_jwt(args, cfg, overrides)
        if args.command == "ports":
            return _cmd_ports(args, cfg, overrides)
        if args.command == "openapi":
            return _cmd_openapi(args, cfg, overrides)
        if args.command == "bruteforce":
            return _cmd_bruteforce(args, cfg, overrides)
        if args.command == "platforms":
            return _cmd_platforms(args, cfg, overrides)
        if args.command == "project":
            return _cmd_project(args, cfg, overrides)
        if args.command == "wayback":
            return _cmd_wayback(args, cfg, overrides)
        if args.command == "dns":
            return _cmd_dns(args, cfg, overrides)
        if args.command == "subdomain":
            return _cmd_subdomain(args, cfg, overrides)
        if args.command == "buckets":
            return _cmd_buckets(args, cfg, overrides)
        if args.command == "tls":
            return _cmd_tls(args, cfg, overrides)
        if args.command == "waf":
            return _cmd_waf(args, cfg, overrides)
        if args.command == "params":
            return _cmd_params(args, cfg, overrides)
        if args.command == "hidden":
            return _cmd_hidden(args, cfg, overrides)
        if args.command == "crawl":
            return _cmd_crawl(args, cfg, overrides)
        if args.command == "graphql":
            return _cmd_graphql(args, cfg, overrides)
        if args.command == "takeover":
            return _cmd_takeover(args, cfg, overrides)
        if args.command == "smuggling":
            return _cmd_smuggling(args, cfg, overrides)
        if args.command == "cachepoison":
            return _cmd_cachepoison(args, cfg, overrides)
        if args.command == "hostheader":
            return _cmd_hostheader(args, cfg, overrides)
        if args.command == "websocket":
            return _cmd_websocket(args, cfg, overrides)
        if args.command == "jsanalysis":
            return _cmd_jsanalysis(args, cfg, overrides)
        if args.command == "sensitive":
            return _cmd_sensitive(args, cfg, overrides)
        if args.command == "retest":
            return _cmd_retest(args, cfg, overrides)
        if args.command == "export":
            return _cmd_export(args, cfg, overrides)
        if args.command == "dashboard":
            return _cmd_dashboard(args, cfg, overrides)
        if args.command == "dos":
            return _cmd_dos(args, cfg, overrides)
        if args.command == "serve":
            return _cmd_serve(args, cfg, overrides)
        if args.command == "watch":
            return _cmd_watch(args, cfg, overrides)
        if args.command == "tui":
            return _cmd_tui(args, cfg, overrides)
        if args.command == "hunt":
            return _cmd_hunt(args, cfg, overrides)
        if args.command == "credcheck":
            return _cmd_credcheck(args, cfg, overrides)
        if args.command == "exploit":
            return _cmd_exploit(args, cfg, overrides)
        if args.command == "shell":
            return _cmd_shell(args, cfg, overrides)
        if args.command == "pivot":
            return _cmd_pivot(args, cfg, overrides)
        if args.command == "rebind":
            return _cmd_rebind(args, cfg, overrides)
        if args.command == "init":
            from keris.core.config import save_example_config

            path = save_example_config(args.output)
            ok(f"Contoh konfigurasi ditulis: {path}")
            return EXIT_OK
    except SystemExit:
        raise
    except Exception as e:
        error(f"Error: {e}")
        return EXIT_ERROR
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
