"""Keris CLI - INTERACTIVE MENU (keris menu).

Tampilkan daftar tool bernomor, user cukup memilih angka + memasukkan
target/domain/host, lalu Keris menjalankan subcommand yang sesuai.
Tool serangan aktif (dos) tetap butuh konfirmasi izin tertulis.
"""

import sys
from typing import List, Optional

from keris.cli.common import EXIT_OK, _resolve_targets
from keris.core.logger import brutal_warning, error, info, ok, warn

TOOLS = [
    {
        "name": "Scan lengkap (recon + discovery + vuln scan + laporan)",
        "need": "target",
        "hint": "URL target, mis. https://example.com",
        "build": lambda v: ["scan", v],
    },
    {
        "name": "Recon (DNS, header, stack, TLS)",
        "need": "target",
        "hint": "URL target, mis. https://example.com",
        "build": lambda v: ["recon", v],
    },
    {
        "name": "Discover (endpoint API, JS, secret)",
        "need": "target",
        "hint": "URL target, mis. https://example.com",
        "build": lambda v: ["discover", v],
    },
    {
        "name": "Fuzz parameter (intelligent)",
        "need": "target",
        "hint": "URL target, mis. https://example.com",
        "build": lambda v: ["fuzz", v],
    },
    {
        "name": "Credential hunting (.git, .env, secret)",
        "need": "target",
        "hint": "URL target, mis. https://example.com",
        "build": lambda v: ["hunt", v],
    },
    {
        "name": "Enumerasi subdomain",
        "need": "domain",
        "hint": "Domain, mis. example.com",
        "build": lambda v: ["subdomain", v],
    },
    {
        "name": "DNS check (MX, SPF, DMARC, DKIM)",
        "need": "domain",
        "hint": "Domain, mis. example.com",
        "build": lambda v: ["dns", v],
    },
    {
        "name": "Port scanner",
        "need": "host",
        "hint": "Host / IP, mis. 10.0.0.1",
        "build": lambda v: ["ports", v],
    },
    {
        "name": "Wayback (URL historis archive.org)",
        "need": "domain",
        "hint": "Domain, mis. example.com",
        "build": lambda v: ["wayback", v],
    },
    {
        "name": "HTTP mass-scan (status, title, server, redirect)",
        "need": "http_targets",
        "hint": "Target dipisah spasi (mis. https://a.com https://b.com)",
        "build": lambda v: ["http"] + v.split(),
    },
    {
        "name": "Deteksi subdomain takeover",
        "need": "target",
        "hint": "URL target, mis. https://example.com",
        "build": lambda v: ["takeover", v],
    },
    {
        "name": "SAST (analisis source/bundle + CVE dep + SBOM)",
        "need": "sast",
        "hint": "URL target ATAU direktori source lokal (kosong = list bantuan)",
        "build": lambda v: ["sast"] if not v.strip()
                           else (["sast", v.strip()]
                                 if v.strip().startswith(("http://", "https://"))
                                 else ["sast", "--dir", v.strip()]),
    },
    {
        "name": "Toolbox (encode, hash, payload, shell, wordlist, jwt...)",
        "need": "toolbox",
        "hint": "Tool (encode,hash,payload,shell,wordlist,ports,dns,jwt...), kosong = list",
        "build": lambda v: ["toolbox", "--tool", v.strip() or "list"],
    },
    {
        "name": "Uji ketahanan app-layer (DOS) — BUTUH IZIN TERTULIS",
        "need": "target",
        "hint": "URL target, mis. https://example.com",
        "active": True,
        "build": lambda v: ["dos", v, "--yes", "--authorized"],
    },
]


def _input(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        raise SystemExit(0)


def _confirm_active(name: str) -> bool:
    brutal_warning(name.upper())
    ans = _input("KONFIRMASI izin tertulis untuk serangan aktif? [y/N]: ").lower()
    return ans in ("y", "yes")


def _run_tool(tool: dict) -> Optional[List[str]]:
    """Wizard input + validasi; kembalikan argv, atau None bila batal."""
    if tool.get("active") and not _confirm_active(tool["name"]):
        warn("Dibatalkan: butuh konfirmasi izin tertulis.")
        return None
    need = tool.get("need", "target")
    if need == "toolbox":
        val = _input(f"  {tool['hint']}: ")
        return tool["build"](val)
    if need == "sast":
        val = _input(f"  {tool['hint']}: ")
        return tool["build"](val)
    val = _input(f"  {tool['hint']}: ")
    if not val:
        warn("Batal: input kosong.")
        return None
    if need == "http_targets":
        targets = [t.strip() for t in val.split() if t.strip()]
        if not targets:
            warn("Batal: butuh minimal 1 target.")
            return None
        return ["http"] + targets
    return tool["build"](val)


def _print_menu_simple() -> None:
    info("=== KERIS — MENU INTERAKTIF ===")
    info("Pilih tool dengan mengetik angkanya (0 = keluar).\n")
    for i, t in enumerate(TOOLS, start=1):
        print(f"  [{i}] {t['name']}")
    print("  [0] Keluar\n")


def _cmd_menu(args, cfg, overrides) -> int:
    """Handler `keris menu`: pilihan interaktif berbasis angka."""
    from keris.cli.main import main as _main

    while True:
        _print_menu_simple()
        raw = _input(f"Pilih [1-{len(TOOLS)}] / 0 = keluar: ")
        if raw == "0":
            ok("Sampai jumpa.")
            return 0
        if not raw.isdigit() or not (1 <= int(raw) <= len(TOOLS)):
            warn("Pilihan tidak valid.")
            continue
        tool = TOOLS[int(raw) - 1]
        info(f"\n>>> {tool['name']}")
        argv = _run_tool(tool)
        if argv is None:
            continue
        info(f"Jalankan: keris {' '.join(argv)}\n")
        code = _main(argv)
        if code:
            warn(f"Tool selesai dengan kode {code}")
        ans = _input("\nJalankan tool lain? [y/N]: ").lower()
        if ans not in ("y", "yes"):
            ok("Sampai jumpa.")
            return 0
    return 0


AUTOPILOT_STEPS = [
    {"name": "Recon", "alias": "recon", "build": lambda t: ["recon", t, "--json-output", "autopilot-recon.json"]},
    {"name": "Discover", "alias": "discover", "build": lambda t: ["discover", t, "--brute", "--json-output", "autopilot-discover.json"]},
    {"name": "Fuzz", "alias": "fuzz", "build": lambda t: ["fuzz", t, "--json-output", "autopilot-fuzz.json"]},
    {"name": "Credential hunt", "alias": "hunt", "build": lambda t: ["hunt", t, "--json-output", "autopilot-hunt.json"]},
    {"name": "Full scan + report", "alias": "scan", "build": lambda t: ["scan", t, "-o", "autopilot-report.md",
                                                                        "--html", "autopilot-report.html",
                                                                        "--json-output", "autopilot-scan.json",
                                                                        "--hidden-endpoints", "--chain"]},
]


def _cmd_autopilot(args, cfg, overrides) -> int:
    """Handler `keris autopilot`: jalankan pipeline lengkap tanpa prompt."""
    from keris.cli.main import main as _main

    targets = _resolve_targets(args)
    steps = AUTOPILOT_STEPS
    if getattr(args, "steps", ""):
        allow = [s.strip().lower() for s in args.steps.split(",") if s.strip()]
        steps = [s for s in AUTOPILOT_STEPS if s.get("alias", s["name"].lower()) in allow]
        if not steps:
            raise SystemExit("Tidak ada step yang cocok. Pilihan: " +
                             ", ".join(s.get("alias", s["name"].lower()) for s in AUTOPILOT_STEPS))
    if getattr(args, "authorized", False) and not getattr(args, "yes", False):
        raise SystemExit("autopilot --authorized juga butuh --yes (konfirmasi izin tertulis).")

    total = 0
    all_findings = []
    for target in targets:
        info(f"\n===== AUTOPILOT TARGET: {target} =====")
        for step in steps:
            info(f"\n--- STEP: {step['name']} ---")
            argv = step["build"](target)
            if getattr(args, "authorized", False):
                argv.append("--authorized")
            if getattr(args, "yes", False):
                argv.append("--yes")
            code = _main(argv)
            if code:
                warn(f"Step {step['name']} selesai dengan kode {code}")
            total += 1
            # kumpulkan temuan dari output JSON step (bila ada)
            for f in _autopilot_collect(argv):
                if f not in all_findings:
                    all_findings.append(f)

    # laporan gabungan ringkas
    if all_findings:
        from collections import Counter

        by_sev = Counter(f.get("severity", "INFO") for f in all_findings)
        info("\n===== RINGKASAN AUTOPILOT =====")
        info(f"Step dijalankan: {total} | Target: {len(targets)}")
        info("Temuan: " + ", ".join(f"{k}: {v}" for k, v in sorted(by_sev.items())))
        if getattr(args, "json_output", None):
            import json
            import os

            payload = {
                "tool": "keris", "mode": "autopilot",
                "targets": targets, "steps": total,
                "summary": dict(by_sev), "findings": all_findings,
            }
            os.makedirs(os.path.dirname(os.path.abspath(args.json_output)), exist_ok=True)
            with open(args.json_output, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, default=str)
            ok(f"JSON gabungan: {args.json_output}")
    return EXIT_OK


def _autopilot_collect(argv) -> List[dict]:
    """Ambil findings dari file JSON yang dihasilkan argv step."""
    import json
    import os

    for a in argv:
        if a.endswith(".json") and os.path.exists(a):
            try:
                with open(a, "r", encoding="utf-8") as f:
                    data = json.load(f)
                findings = data.get("findings", []) if isinstance(data, dict) else []
                return [f for f in findings if isinstance(f, dict)]
            except Exception:
                continue
    return []