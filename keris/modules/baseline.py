"""Baseline false-positive / accepted-risk management.

Workflow CI:
  1. Scan pertama -> scan.json
  2. Tandai temuan yang sudah dikenal/diterima -> baseline.json
     (`keris baseline create scan.json -o baseline.json`)
  3. Scan berikutnya dengan --baseline baseline.json:
     temuan yang cocok ditandai "baseline": true dan TIDAK memicu exit code 1,
     temuan baru tetap gagalkan CI.

Key baseline sengaja lebih longgar daripada fingerprint penuh (tanpa evidence)
agar perubahan kecil pada bukti tidak membuat temuan lama "muncul lagi".
"""

import hashlib
import json
from typing import Dict, List, Set, Tuple


def baseline_key(f: Dict) -> str:
    """Key stabil untuk mencocokkan temuan antar-scan (endpoint+title+detail)."""
    key = "|".join([
        str(f.get("endpoint", "")).rstrip("/"),
        str(f.get("title", "")),
        str(f.get("detail", ""))[:200],
    ])
    return hashlib.sha1(key.encode("utf-8", "replace")).hexdigest()[:16]


def load_baseline(path: str) -> Set[str]:
    """Muat baseline: file JSON hasil `baseline create`, atau daftar key teks."""
    keys: Set[str] = set()
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        keys.update(data.get("keys", []) or [])
    elif isinstance(data, list):
        keys.update(str(k) for k in data)
    return keys


def apply_baseline(findings: List[Dict], keys: Set[str]) -> Tuple[List[Dict], int]:
    """Tandai temuan yang ada di baseline.

    Kembalikan (findings, jumlah_yang_ditandai). Temuan bertanda mendapat
    field "baseline": True; tetap tampil di laporan tapi diabaikan exit code.
    """
    marked = 0
    for f in findings:
        if baseline_key(f) in keys:
            f["baseline"] = True
            marked += 1
        else:
            f.setdefault("baseline", False)
    return findings, marked


def create_from_scan(scan_json_path: str, min_severity: str = "INFO") -> Dict:
    """Buat payload baseline dari file hasil scan JSON."""
    order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    min_rank = order.get(min_severity.upper(), 0)
    with open(scan_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    findings = []
    if isinstance(data, dict):
        findings = data.get("findings", []) or []
    elif isinstance(data, list):
        findings = data
    keys = []
    for x in findings:
        if not isinstance(x, dict):
            continue
        sev = str(x.get("severity", "INFO")).upper()
        if order.get(sev, 0) >= min_rank:
            keys.append(baseline_key(x))
    return {
        "version": 1,
        "source": scan_json_path,
        "min_severity": min_severity.upper(),
        "count": len(keys),
        "keys": sorted(set(keys)),
    }
