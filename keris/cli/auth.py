"""Keris CLI - AUTH commands."""

import json
import os
import sys

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

from keris.cli.common import *  # noqa: F401,F403

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
                base, creds, client=client.session,
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


def _cmd_authbypass(args, cfg, overrides) -> int:
    from keris.core.logger import brutal_warning

    brutal_warning("AUTH BYPASS")
    if not getattr(args, "authorized", False):
        error("authbypass memerlukan --authorized.")
        return EXIT_ERROR
    targets = _resolve_targets(args)
    all_findings = []
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            from keris.modules.authbypass import test_bypass
            fnds = test_bypass(base, client, endpoints=args.endpoint,
                               authorized=True)
            all_findings.extend(f.to_dict() for f in fnds)
        finally:
            client.close()
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"tool": "keris", "version": __version__,
                       "command": "authbypass", "findings": all_findings},
                      f, indent=2, default=str)
    return _exit_code(all_findings, getattr(args, "exit_on", "high"))


def _cmd_spray(args, cfg, overrides) -> int:
    from keris.core.logger import brutal_warning

    brutal_warning("PASSWORD SPRAY")
    if not getattr(args, "authorized", False):
        error("spray memerlukan --authorized.")
        return EXIT_ERROR
    usernames = []
    if args.users:
        usernames.extend(u.strip() for u in args.users.split(",") if u.strip())
    if args.users_file:
        with open(args.users_file, "r", encoding="utf-8") as f:
            usernames.extend(l.strip() for l in f if l.strip())
    passwords = None
    if args.passwords:
        passwords = [p.strip() for p in args.passwords.split(",") if p.strip()]
    if args.passwords_file:
        with open(args.passwords_file, "r", encoding="utf-8") as f:
            passwords = [l.strip() for l in f if l.strip()]
    proxies = None
    if args.proxy_file:
        with open(args.proxy_file, "r", encoding="utf-8") as f:
            proxies = [l.strip() for l in f if l.strip()]
    targets = _resolve_targets(args)
    all_findings = []
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            from keris.modules.spray import spray
            fnds = spray(base, client, usernames, passwords,
                         auth_type=args.auth_type, delay=args.spray_delay,
                         proxies=proxies, authorized=True)
            all_findings.extend(f.to_dict() for f in fnds)
        finally:
            client.close()
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"tool": "keris", "version": __version__,
                       "command": "spray", "findings": all_findings},
                      f, indent=2, default=str)
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


def _cmd_gitdump(args, cfg, overrides) -> int:
    from keris.core.logger import brutal_warning

    brutal_warning("GIT DUMP")
    if not getattr(args, "authorized", False):
        error("gitdump memerlukan --authorized.")
        return EXIT_ERROR
    targets = _resolve_targets(args)
    all_findings = []
    for target in targets:
        base = normalize_url(target)
        client = _make_client(args, cfg, overrides, base)
        try:
            from keris.modules.gitdump import dump_git
            fnds = dump_git(base, client, outdir=args.outdir,
                            max_objects=args.max_objects, authorized=True)
            all_findings.extend(f.to_dict() for f in fnds)
        finally:
            client.close()
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"tool": "keris", "version": __version__,
                       "command": "gitdump", "findings": all_findings},
                      f, indent=2, default=str)
    return _exit_code(all_findings, getattr(args, "exit_on", "high"))


def _cmd_dbdump(args, cfg, overrides) -> int:
    from keris.core.logger import brutal_warning

    brutal_warning("DATABASE DUMP")
    if not getattr(args, "authorized", False):
        error("dbdump memerlukan --authorized.")
        return EXIT_ERROR
    targets = _resolve_targets(args)
    base = normalize_url(targets[0]) if targets else ""
    client = _make_client(args, cfg, overrides, base)
    try:
        from keris.modules.dbdump import dump_db
        fnds = dump_db(base, client, args.vuln_url, args.vuln_param,
                       db=args.db, total_cols=args.cols, outdir=args.outdir,
                       max_tables=args.max_tables, max_rows=args.max_rows,
                       workers=args.workers, authorized=True)
    finally:
        client.close()
    all_findings = [f.to_dict() for f in fnds]
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"tool": "keris", "version": __version__,
                       "command": "dbdump", "findings": all_findings},
                      f, indent=2, default=str)
    return _exit_code(all_findings, getattr(args, "exit_on", "high"))


def _cmd_cloud(args, cfg, overrides) -> int:
    from keris.core.logger import brutal_warning

    brutal_warning("CLOUD TAKEOVER")
    if not getattr(args, "authorized", False):
        error("cloud memerlukan --authorized.")
        return EXIT_ERROR
    targets = _resolve_targets(args)
    base = normalize_url(targets[0]) if targets else "http://cloud/"
    client = _make_client(args, cfg, overrides, base)
    try:
        findings_in = []
        if args.from_scan:
            with open(args.from_scan, "r", encoding="utf-8") as f:
                data = json.load(f)
            findings_in = data.get("findings", data if isinstance(data, list) else [])
        from keris.modules.cloudtakeover import (check_bucket_takeover,
                                                 scan_cloud)
        out = scan_cloud(base, client, findings_in, authorized=True)
        for b in args.bucket:
            r = check_bucket_takeover(b)
            if r:
                out.append(r)
        ok(f"Cloud check selesai: {len(out)} temuan")
    finally:
        client.close()
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"tool": "keris", "version": __version__,
                       "command": "cloud", "findings": out},
                      f, indent=2, default=str)
    return _exit_code(out, getattr(args, "exit_on", "high"))


def _cmd_xsshook(args, cfg, overrides) -> int:
    from keris.core.logger import brutal_warning

    brutal_warning("XSS HOOK")
    if not getattr(args, "authorized", False) or not getattr(args, "yes", False):
        error("xsshook memerlukan --authorized DAN --yes.")
        return EXIT_ERROR
    from keris.modules.xsshook import start_hook

    srv = start_hook(host=args.bind, port=args.port, authorized=True, yes=True)
    if srv is None:
        return EXIT_ERROR
    try:
        import time as _t
        info("Menunggu korban/tes... (Ctrl+C untuk berhenti)")
        while True:
            _t.sleep(1)
            if srv.count and srv.data.get("events"):
                ev = srv.data["events"][-1]
                info(f"  CAPTURE: {ev.get('url', '?')} | cookie={str(ev.get('cookie'))[:60]}")
    except KeyboardInterrupt:
        ok(f"XSS hook berhenti; {srv.count} event tertangkap")
    finally:
        srv.stop()
    return EXIT_OK


def _cmd_k8s(args, cfg, overrides) -> int:
    from keris.core.logger import brutal_warning

    brutal_warning("KUBERNETES ATTACK")
    if not getattr(args, "authorized", False):
        error("k8s memerlukan --authorized.")
        return EXIT_ERROR
    targets = _resolve_targets(args)
    base = normalize_url(args.k8s_base) if args.k8s_base else normalize_url(targets[0])
    client = _make_client(args, cfg, overrides, base)
    try:
        from keris.modules.k8s import scan_k8s
        fnds = scan_k8s(base, client, vuln_url=args.ssrf_url,
                        vuln_param=args.ssrf_param, authorized=True)
    finally:
        client.close()
    all_findings = [f.to_dict() for f in fnds]
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"tool": "keris", "version": __version__,
                       "command": "k8s", "findings": all_findings},
                      f, indent=2, default=str)
    return _exit_code(all_findings, getattr(args, "exit_on", "high"))


def _cmd_crack(args, cfg, overrides) -> int:
    from keris.core.logger import brutal_warning

    brutal_warning("HASH CRACK")
    if not getattr(args, "authorized", False):
        error("crack memerlukan --authorized.")
        return EXIT_ERROR
    hashes = list(args.hash)
    if args.hashes_file:
        with open(args.hashes_file, "r", encoding="utf-8") as f:
            hashes.extend(l.strip() for l in f if l.strip())
    wordlist = None
    if args.wordlist:
        with open(args.wordlist, "r", encoding="utf-8") as f:
            wordlist = [l.strip() for l in f if l.strip()]
    from keris.modules.hashcrack import crack_hashes
    fnds = crack_hashes(hashes, wordlist, brute_length=args.brute_length,
                        authorized=True)
    all_findings = [f.to_dict() for f in fnds]
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({"tool": "keris", "version": __version__,
                       "command": "crack", "findings": all_findings},
                      f, indent=2, default=str)
    return _exit_code(all_findings, getattr(args, "exit_on", "high"))


