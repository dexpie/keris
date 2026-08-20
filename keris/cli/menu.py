"""Keris CLI - INTERACTIVE MENU (keris menu).

Tampilkan daftar tool bernomor, user cukup memilih angka + memasukkan
target/domain/host, lalu Keris menjalankan subcommand yang sesuai.
Tool serangan aktif (dos) tetap butuh konfirmasi izin tertulis.
"""

import sys
from typing import List, Optional

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
        raw = _input("Pilih [1-13] / 0 = keluar: ")
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