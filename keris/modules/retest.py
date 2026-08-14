"""Retest & diff: bandingkan hasil scan lama dengan hasil scan baru.

Membandingkan daftar temuan (by endpoint+title) lalu mengelompokkan:
- fixed: ada di scan lama, tidak ada di scan baru
- new: hanya muncul di scan baru
- persisting: ada di kedua scan (belum diperbaiki)
- changed: severity berubah

Menghasilkan laporan markdown + JSON yang bisa dipakai untuk menunjukkan
progres perbaikan ke klien / tim.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Tuple

from keris.core.logger import info, ok, warn

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _load(path: str) -> Tuple[str, List[Dict]]:
    """Baca file scan JSON Keris; kembalikan (target, findings)."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "results" in data and isinstance(data["results"], list):
        # multi-target
        findings = [x for r in data["results"] for x in r.get("findings", [])]
        target = ", ".join(data.get("targets", []))
        return target, findings
    if isinstance(data, dict) and "findings" in data:
        return data.get("target", ""), data["findings"]
    if isinstance(data, list):
        return "", data
    raise ValueError(f"Format file tidak dikenal: {path}")


def _key(f: Dict) -> Tuple[str, str]:
    """Kunci temuan: (endpoint, title) untuk perbandingan."""
    return (f.get("endpoint", "") or "", f.get("title", "") or "")


def _severity(f: Dict) -> str:
    return (f.get("severity", "INFO") or "INFO").upper()


def diff_findings(old: List[Dict], new: List[Dict]) -> Dict:
    """Bandingkan dua daftar temuan."""
    old_map = {_key(f): f for f in old}
    new_map = {_key(f): f for f in new}

    fixed, persisting, new_f = [], [], []
    for k, f in old_map.items():
        if k in new_map:
            persisting.append({"old": f, "new": new_map[k]})
        else:
            fixed.append(f)
    for k, f in new_map.items():
        if k not in old_map:
            new_f.append(f)

    changed = []
    for p in persisting:
        if _severity(p["old"]) != _severity(p["new"]):
            changed.append(p)

    persisting_clean = [p["new"] for p in persisting]
    return {
        "fixed": fixed,
        "new": new_f,
        "persisting": persisting_clean,
        "changed": changed,
        "summary": {
            "old_total": len(old),
            "new_total": len(new),
            "fixed": len(fixed),
            "new": len(new_f),
            "persisting": len(persisting_clean),
            "changed": len(changed),
            "progress": (len(fixed) / len(old) * 100) if old else 0.0,
        },
    }


def _sev_sort(fs: List[Dict]) -> List[Dict]:
    return sorted(fs, key=lambda f: SEVERITY_ORDER.get(_severity(f), 9))


def generate_diff_report(old_path: str, new_path: str) -> Tuple[str, Dict]:
    """Bandingkan dua file scan; kembalikan (markdown, data)."""
    old_target, old = _load(old_path)
    new_target, new = _load(new_path)
    diff = diff_findings(old, new)
    s = diff["summary"]

    now = datetime.utcnow().strftime("%d %B %Y, %H:%M UTC")
    lines = []
    lines.append("# Laporan Retest")
    lines.append("")
    lines.append(f"**Scan lama:** `{old_path}` ({old_target or '?'})")
    lines.append(f"**Scan baru:** `{new_path}` ({new_target or '?'})")
    lines.append(f"**Tanggal:** {now}")
    lines.append("")
    lines.append("## Ringkasan")
    lines.append("")
    lines.append(f"- Total temuan lama: **{s['old_total']}**")
    lines.append(f"- Total temuan baru: **{s['new_total']}**")
    lines.append(f"- **Fixed:** {s['fixed']}")
    lines.append(f"- **Baru muncul:** {s['new']}")
    lines.append(f"- **Belum diperbaiki:** {s['persisting']}")
    lines.append(f"- **Perubahan severity:** {s['changed']}")
    lines.append(f"- **Progres perbaikan:** {s['progress']:.1f}%")
    lines.append("")

    def _section(title: str, items: List[Dict]) -> None:
        if not items:
            return
        lines.append(f"## {title}")
        lines.append("")
        lines.append("| Severity | Lokasi | Temuan |")
        lines.append("|---|---|---|")
        for f in _sev_sort(items):
            lines.append(f"| {_severity(f)} | `{f.get('endpoint', '')}` | {f.get('title', '')} |")
        lines.append("")

    _section("Diperbaiki (Fixed)", diff["fixed"])
    _section("Baru Muncul (New)", diff["new"])
    _section("Belum Diperbaiki (Persisting)", diff["persisting"])
    _section("Perubahan Severity", [p["new"] for p in diff["changed"]])

    if not any([diff["fixed"], diff["new"], diff["persisting"]]):
        lines.append("Tidak ada temuan pada kedua scan.")
    lines.append("")
    lines.append("---")
    lines.append("*Laporan retest dihasilkan otomatis oleh Keris.*")
    lines.append("")
    return "\n".join(lines), diff


def retest(old_path: str, new_path: str, output: str, json_output: str) -> Dict:
    """Jalankan retest dan tulis laporan. Mengembalikan data diff."""
    md, diff = generate_diff_report(old_path, new_path)
    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(md)
        ok(f"Laporan retest: {output}")
    if json_output:
        with open(json_output, "w", encoding="utf-8") as f:
            json.dump(diff, f, indent=2, default=str)
        ok(f"JSON retest: {json_output}")
    s = diff["summary"]
    info(f"Retest: {s['fixed']} fixed, {s['new']} new, "
         f"{s['persisting']} persisting, progres {s['progress']:.1f}%")
    return diff
