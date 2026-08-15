"""Keris CLI - REPORT commands."""

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

def _cmd_export(args, cfg, overrides) -> int:
    from keris.modules.export import export_requests

    with open(args.json_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    findings = data.get("findings", data if isinstance(data, list) else [])
    target = data.get("target", args.json_file) if isinstance(data, dict) else args.json_file
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


