"""Entry point CLI untuk Keris."""

import argparse
import json
import os
import sys
from typing import List, Optional

from keris import __version__
from keris.core.http import KerisHTTP
from keris.core.logger import info, ok, warn, error, debug, severity, set_quiet
from keris.core.utils import normalize_url
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
    ps.add_argument("--workers", type=int, help="Jumlah worker untuk brute")
    ps.add_argument("--exit-on", choices=["none", "high", "medium", "low"], default="high",
                    help="Severity minimum yang menyebabkan exit code 1 (default: high)")
    # --- serangan aktif (khusus berizin, wajib --authorized) ---
    ps.add_argument("--authorized", action="store_true",
                    help="KONFIRMASI izin tertulis untuk serangan aktif (exploit/brute/CVE)")
    ps.add_argument("--exploit", action="store_true",
                    help="Auto-exploit injection: SQLi boolean/time, CMDI, SSTI, XSS (butuh --authorized)")
    ps.add_argument("--exploit-types", default="sqli,cmdi,ssti,xss",
                    help="Jenis exploit (default: sqli,cmdi,ssti,xss)")
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
    ps.add_argument("--sensitive-data", action="store_true",
                    help="Scan paparan data sensitif (kredensial/PII/kartu)")

    # recon
    pr = sub.add_parser("recon", parents=[common], help="Recon saja: DNS, headers, stack")
    pr.add_argument("-o", "--output", help="Simpan hasil recon ke file JSON")

    # passive recon
    pp = sub.add_parser("passive", parents=[common], help="Passive recon: crt.sh + whois (tanpa menyentuh target)")
    pp.add_argument("-o", "--output", help="Simpan hasil ke file JSON")

    # discover
    pd = sub.add_parser("discover", parents=[common], help="Discovery saja: endpoint API, JS, secret")
    pd.add_argument("--max-assets", type=int, help="Maksimum asset JS diunduh")
    pd.add_argument("--brute", action="store_true", help="Juga jalankan brute path & subdomain")
    pd.add_argument("--workers", type=int, help="Jumlah worker untuk brute")

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

    # retest (perbandingan scan lama vs baru)
    pretest = sub.add_parser("retest", help="Bandingkan scan lama & scan baru (retest workflow)")
    pretest.add_argument("old_json", help="File hasil scan lama (JSON output Keris)")
    pretest.add_argument("new_json", help="File hasil scan baru (JSON output Keris)")
    pretest.add_argument("-o", "--output", help="File laporan markdown retest")
    pretest.add_argument("--json-output", help="File output JSON diff")
    pretest.add_argument("--no-color", action="store_true", help="Nonaktifkan warna output")
    pretest.add_argument("--quiet", action="store_true", help="Minimal output")

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
    pdo.add_argument("--json-output", help="File output JSON")

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
    # CLI menang atas config file
    overrides = {}
    for field in ("proxy", "timeout", "retries", "workers", "delay", "token", "cookie", "username", "password", "insecure", "quiet"):
        val = getattr(args, field, None)
        if val is not None:
            overrides[field] = val
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


def _make_client(args, cfg: KerisConfig, overrides: dict) -> KerisHTTP:
    token = overrides.get("token", cfg.token)
    cookie = overrides.get("cookie", cfg.cookie)
    basic = None
    uname = overrides.get("username", cfg.username)
    pwd = overrides.get("password", cfg.password)
    if uname and pwd:
        basic = (uname, pwd)
    return KerisHTTP(
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


def _get_plugins(args, cfg: KerisConfig) -> List[dict]:
    plugins_dir = cfg.plugins_dir
    extra = list(getattr(args, "plugins", []) or [])
    return plugins_module.load_plugins(plugins_dir, extra)


def _run_scan_single(base: str, args, cfg: KerisConfig, overrides: dict, client: KerisHTTP) -> dict:
    findings = []

    # auto-login: ganti client jika user memberi kredensial form login
    if getattr(args, "login_username", None) and getattr(args, "login_password", None):
        info("=== AUTO LOGIN ===")
        from keris.modules import auth as auth_module

        client = auth_module.auto_login(
            base, args.login_username, args.login_password,
            login_paths=cfg.login_paths or None,
            timeout=overrides.get("timeout", cfg.timeout),
        )

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
            dirs = discovery_module.brute_directories(base, client, overrides.get("workers", cfg.workers))
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
        from keris.modules.waf import detect_waf

        waf = detect_waf(base, client)
        if waf.get("waf"):
            findings.append({
                "severity": "INFO", "title": "WAF terdeteksi",
                "endpoint": base, "detail": f"Web Application Firewall: {waf['waf']}",
                "evidence": ", ".join(waf.get("evidence", []))[:500],
            })

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


def _write_outputs(base, result, args, options, cfg) -> None:
    recon, disc, findings = result["recon"], result["discovery"], result["findings"]

    if args.output:
        write_report(recon, disc, findings, args.output, base, options)
    if getattr(args, "html_output", None):
        write_html_report(recon, disc, findings, args.html_output, base, options)
    if getattr(args, "pdf_output", None):
        from keris.report_pdf import write_pdf_report

        write_pdf_report(recon, disc, findings, args.pdf_output, base, options)
        ok(f"PDF output: {args.pdf_output}")
    if getattr(args, "json_output", None):
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
            "recon": recon,
            "discovery": {"api_endpoints": disc.get("api_endpoints", []),
                          "js_assets": disc.get("js_assets", []),
                          "secrets": disc.get("secrets", [])},
            "findings": findings,
        }
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)
        ok(f"JSON output: {args.json_output}")


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

    for target in targets:
        info(f"\n===== TARGET: {target} =====")
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides)
        try:
            result = _run_scan_single(base, args, cfg, overrides, client)
        except Exception as e:
            error(f"Scan gagal untuk {target}: {e}")
            exit_codes.append(EXIT_ERROR)
            continue
        finally:
            client.close()
        all_results.append(result)
        options = {"mode": "otomatis dengan Keris", "targets_file": bool(args.targets)}
        _write_outputs(base, result, args, options, cfg)
        exit_codes.append(_exit_code(result["findings"], getattr(args, "exit_on", "high")))

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

    # exit code terburuk
    worst = max(exit_codes) if exit_codes else EXIT_OK
    return worst


def _cmd_recon(args, cfg, overrides) -> int:
    targets = _resolve_targets(args)
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides)
        try:
            result = recon_module.run_recon(base, client)
        finally:
            client.close()
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, default=str)
            ok(f"Hasil recon disimpan: {args.output}")
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
        client = _make_client(args, cfg, overrides)
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
        client = _make_client(args, cfg, overrides)
        try:
            recon = recon_module.run_recon(base, client)
            disc = discovery_module.discover_endpoints(base, client, max_assets=overrides.get("max_assets", cfg.max_assets))
            if args.brute:
                dirs = discovery_module.brute_directories(base, client, overrides.get("workers", cfg.workers))
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
        client = _make_client(args, cfg, overrides)
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
        client = _make_client(args, cfg, overrides)
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
            client = _make_client(args, cfg, overrides)
            try:
                all_findings.extend(brute_module.enumerate_usernames(base, client, login_paths=login_paths))
            finally:
                client.close()

    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides)
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
        client = _make_client(args, cfg, overrides)
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


def _cmd_buckets(args, cfg, overrides) -> int:
    from keris.modules import buckets as buckets_module

    targets = _resolve_targets(args)
    all_findings = []
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides)
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
    from keris.modules.waf import detect_waf

    targets = _resolve_targets(args)
    all_results = []
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides)
        try:
            result = detect_waf(base, client)
        finally:
            client.close()
        all_results.append(result)
        if result["waf"]:
            ok(f"WAF: {result['waf']}")
        if result["blocked"]:
            warn("Target tampak memblokir request scan (block page)")
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump(all_results if len(all_results) > 1 else all_results[0], f, indent=2, default=str)
        ok(f"JSON output: {args.json_output}")
    return EXIT_OK


def _cmd_params(args, cfg, overrides) -> int:
    from keris.modules.params import discover_hidden_params

    targets = _resolve_targets(args)
    all_findings = []
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides)
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
        client = _make_client(args, cfg, overrides)
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
        client = _make_client(args, cfg, overrides)
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
        client = _make_client(args, cfg, overrides)
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
        client = _make_client(args, cfg, overrides)
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
        client = _make_client(args, cfg, overrides)
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
        client = _make_client(args, cfg, overrides)
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
        client = _make_client(args, cfg, overrides)
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
        client = _make_client(args, cfg, overrides)
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
        client = _make_client(args, cfg, overrides)
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
        client = _make_client(args, cfg, overrides)
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

    diff = retest(args.old_json, args.new_json, args.output, args.json_output)
    # exit 1 bila ada temuan baru / belum diperbaiki
    if diff["summary"]["new"] or diff["summary"]["persisting"]:
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
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides)
        try:
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
