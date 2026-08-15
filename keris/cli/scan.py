"""Keris CLI - SCAN commands."""

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


