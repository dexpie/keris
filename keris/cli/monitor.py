"""Keris CLI - MONITOR commands."""

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

    # bangun daftar kanal alert (webhook + email SMTP + pagerduty)
    channels = []
    webhooks = list(getattr(args, "webhook", []) or [])
    types = list(getattr(args, "webhook_type", []) or [])
    if len(types) == 1:
        types = types * len(webhooks)
    for i, url in enumerate(webhooks):
        kind = types[i] if i < len(types) else "auto"
        channels.append({"url": url, "kind": kind or "auto"})
    smtp_to = ",".join(getattr(args, "smtp_to", []) or [])
    if getattr(args, "smtp_host", "") and smtp_to:
        channels.append({
            "kind": "email",
            "smtp_host": args.smtp_host,
            "smtp_port": getattr(args, "smtp_port", 587),
            "smtp_user": getattr(args, "smtp_user", ""),
            "smtp_pass": getattr(args, "smtp_pass", ""),
            "smtp_to": smtp_to,
        })
    if getattr(args, "pagerduty_key", ""):
        channels.append({"url": args.pagerduty_key, "kind": "pagerduty"})

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

    webhook_arg = webhooks[0] if webhooks else None
    webhook_type = types[0] if types else "auto"
    alert_count = 0
    for target in targets:
        info(f"Watch target: {target}")
        alert_count += watch_loop(
            target, state_dir,
            run_scan=run_scan,
            interval=args.interval,
            runs=args.runs,
            webhook=webhook_arg,
            webhook_type=webhook_type,
            min_severity=args.min_severity,
            json_output=args.json_output,
            channels=channels or None,
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


