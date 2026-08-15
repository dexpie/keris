"""JS dependency CVE checker: parse package.json / lockfile di bundle JS,
cocokkan versi terhadap database CVE kecil offline."""

import json
import re
from typing import Dict, List, Optional, Tuple

from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

# DB CVE kecil offline: {paket: [(versi_rentan_prefix, severity, deskripsi)]}
CVE_DB: Dict[str, List[Tuple[str, str, str]]] = {
    "lodash": [
        ("4.17.0", "HIGH", "Prototype pollution (CVE-2019-10744)"),
        ("4.17.20", "HIGH", "Command injection via template (CVE-2021-23337)"),
    ],
    "minimist": [("1.2.0", "HIGH", "Prototype pollution (CVE-2020-7598)")],
    "qs": [("6.10.2", "HIGH", "Prototype pollution (CVE-2022-24999)")],
    "node-fetch": [("2.6.6", "MEDIUM", "SSRF / cookie leak (CVE-2022-0235)")],
    "axios": [("0.21.0", "HIGH", "Server-side request forgery (CVE-2021-3749)")],
    "jquery": [("3.4.0", "MEDIUM", "XSS pada htmlPrefilter (CVE-2020-11022)")],
    "express": [("4.17.0", "MEDIUM", "Open redirect (CVE-2022-24999 / variants)")],
    "next": [("13.4.0", "HIGH", "Image Optimization SSRF / DoS (CVE-2023-46298)")],
    "next.js": [("13.4.0", "HIGH", "Image Optimization SSRF / DoS (CVE-2023-46298)")],
    "webpack": [("5.76.0", "HIGH", "DOM XSS (CVE-2023-28154)")],
    "fastify": [("4.10.0", "MEDIUM", "Content-Type confusion (CVE-2022-39288)")],
    "handlebars": [("4.7.6", "HIGH", "Prototype pollution (CVE-2021-23383)")],
    "moment": [("2.29.1", "LOW", "ReDoS (CVE-2022-24785)")],
    "underscore": [("1.13.1", "MEDIUM", "Arbitrary code execution (CVE-2021-23358)")],
    "tar": [("6.1.0", "HIGH", "Arbitrary file overwrite (CVE-2021-37701)")],
    "postcss": [("8.4.30", "LOW", "Line wrapping XSS (CVE-2023-44270)")],
    "markdown-it": [("12.3.2", "HIGH", "ReDoS (CVE-2022-21670)")],
    "shelljs": [("0.8.4", "HIGH", "Command injection (CVE-2022-0144)")],
    "dompurify": [("2.3.5", "MEDIUM", "mXSS (CVE-2021-43904)")],
    "pdfjs-dist": [("2.16.105", "HIGH", "XSS via crafted PDF (CVE-2021-36364)")],
}


def _parse_version(ver: str) -> Tuple[int, ...]:
    m = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", ver.strip().lstrip("^~v"))
    if not m:
        return (0,)
    return tuple(int(g) for g in m.groups() if g is not None)


def _vuln_for(pkg: str, ver: str) -> Optional[Tuple[str, str]]:
    """Cek versi paket vs daftar rentan. Kembalikan (severity, desc) atau None."""
    if not ver or pkg not in CVE_DB:
        return None
    cur = _parse_version(ver)
    best = None
    for limit, sev, desc in CVE_DB[pkg]:
        lim = _parse_version(limit)
        if cur and cur <= lim:
            # ambil temuan dengan severity tertinggi yang masih berlaku
            if best is None or SEV_ORDER(sev) < SEV_ORDER(best[0]):
                best = (sev, desc)
    return best


def SEV_ORDER(s: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(s, 9)


def _extract_packages(text: str) -> Dict[str, str]:
    """Ekstrak paket+versi dari konten package.json / lockfile."""
    pkgs: Dict[str, str] = {}
    try:
        data = json.loads(text)
    except Exception:
        data = None
    if isinstance(data, dict):
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            deps = data.get(section) or {}
            if isinstance(deps, dict):
                for name, ver in deps.items():
                    if isinstance(ver, str):
                        pkgs[name] = ver
    if isinstance(data, dict) and isinstance(data.get("packages"), dict):
        for path, meta in data["packages"].items():
            if path and isinstance(meta, dict) and isinstance(meta.get("version"), str):
                name = path.split("node_modules/")[-1].split("/")[0]
                pkgs.setdefault(name, meta["version"])
    return pkgs


def check_js_dependencies(base: str, js_texts: List[str],
                          client=None, urls: Optional[List[str]] = None) -> List[Finding]:
    """Cek dependency berbahaya dari konten JS (biasanya _next/static/*.js)."""
    findings: List[Finding] = []
    known_pkgs: Dict[str, str] = {}
    for text in js_texts:
        # cari blok package metadata inline (Vercel/Next bundle sering memuat "name":"x","version":"y")
        for m in re.finditer(r'"name"\s*:\s*"([A-Za-z0-9_.@/-]+)"\s*,\s*"version"\s*:\s*"([^"]+)"', text):
            name, ver = m.group(1), m.group(2)
            base_name = name.rsplit("/", 1)[-1]
            known_pkgs.setdefault(base_name, ver)
        known_pkgs.update(_extract_packages(text))

    if not known_pkgs:
        return findings

    info(f"=== JS DEPENDENCY CVE ({len(known_pkgs)} paket terdeteksi) ===")
    for name, ver in sorted(known_pkgs.items()):
        hit = _vuln_for(name, ver)
        if not hit:
            continue
        sev, desc = hit
        findings.append(Finding(
            sev, f"Dependency rentan: {name}@{ver}",
            "bundle",
            f"Library JS `{name}@{ver}` terdeteksi dan rentan terhadap CVE yang diketahui "
            f"({desc}). Perbarui ke versi aman terbaru.",
            f"paket: {name}@{ver}",
        ))
        debug(f"{sev} {name}@{ver}: {desc}")
    return findings