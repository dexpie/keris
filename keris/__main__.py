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
    common.add_argument("--preset", choices=["fast", "stealth"], help="Preset concurrency: fast (workers 25, delay 0) / stealth (workers 3, delay 1.0)")
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
    ps.add_argument("--no-discover", action="store_true", help="Lewati discovery (endpoint/JS)")
    ps.add_argument("--no-bruteforce", action="store_true", help="Lewati brute path/subdomain")
    ps.add_argument("--no-plugins", action="store_true", help="Nonaktifkan plugin")
    ps.add_argument("--passive", action="store_true", help="Juga lakukan passive recon (crt.sh/whois)")
    ps.add_argument("--fuzz", action="store_true", help="Jalankan fuzzing parameter sederhana")
    ps.add_argument("--workers", type=int, help="Jumlah worker untuk brute")
    ps.add_argument("--exit-on", choices=["none", "high", "medium", "low"], default="high",
                    help="Severity minimum yang menyebabkan exit code 1 (default: high)")

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
    # preset concurrency: fast / stealth
    preset = getattr(args, "preset", None)
    if preset == "fast":
        overrides.setdefault("workers", 25)
        overrides.setdefault("delay", 0)
    elif preset == "stealth":
        overrides.setdefault("workers", 3)
        overrides.setdefault("delay", 1.0)
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
    from keris.payloads import REDIRECT_PARAMS

    for ep in endpoints[:15]:
        full = base + ep
        if "?" in full:
            for param in REDIRECT_PARAMS:
                if param in full:
                    r = scanner_module.check_open_redirect(client, full, param)
                    if r:
                        findings.append(r.to_dict())
                        severity("MEDIUM", f"Open redirect: {ep} ({param})")
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

    # fuzzing parameter sederhana (opsional)
    if getattr(args, "fuzz", False):
        from keris.modules import fuzz as fuzz_module

        fuzz_results = fuzz_module.fuzz_parameters(base, client, endpoints[:20])
        findings.extend(f.to_dict() for f in fuzz_results)

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
        for attr in ("output", "json_output", "html_output"):
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
