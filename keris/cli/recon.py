"""Keris CLI - RECON commands."""

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


