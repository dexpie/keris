"""Portfolio risk view: agregasi banyak hasil scan jadi satu ringkasan.

Untuk laporan manajemen: peringkat target berdasarkan risk score, grade
portofolio keseluruhan, temuan paling berat, dan jenis masalah paling umum
di seluruh target.

Input: satu atau lebih file JSON hasil scan Keris (`scan --json-output ...`,
termasuk gabungan autopilot).
"""

import json
from typing import Dict, List

from keris.modules.riskscore import risk_score


def _load_scan(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "results" in data and isinstance(data["results"], list):
        # format multi-target (watch / gabungan)
        findings = [x for r in data["results"] for x in r.get("findings", [])]
        target = ", ".join(data.get("targets", []) or ["?"])
    elif isinstance(data, dict):
        findings = data.get("findings", []) or []
        target = data.get("target", path)
    else:
        findings, target = [], path
    return {"source": path, "target": str(target),
            "findings": [x for x in findings if isinstance(x, dict)]}


def build_portfolio(paths: List[str]) -> Dict:
    """Bangun agregat portofolio dari daftar file scan JSON."""
    entries = []
    for p in paths:
        s = _load_scan(p)
        s["risk"] = risk_score(s["findings"])
        entries.append(s)

    all_findings = [x for e in entries for x in e["findings"]]
    overall = risk_score(all_findings)

    # ranking target terburuk dulu (skor kecil = berbahaya)
    ranked = sorted(entries, key=lambda e: (e["risk"]["score"], -e["risk"]["total"]))

    # temuan paling berat unik (endpoint+title)
    seen = set()
    top = []
    for f in sorted(all_findings,
                    key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                                   "LOW": 3, "INFO": 4}.get(
                                       str(x.get("severity", "")).upper(), 9)):
        key = (str(f.get("endpoint", "")), str(f.get("title", "")))
        if key in seen:
            continue
        seen.add(key)
        top.append(f)

    # jenis masalah paling umum antar target (by title)
    freq: Dict[str, int] = {}
    for e in entries:
        titles = {str(x.get("title", "")) for x in e["findings"]}
        for t in titles:
            freq[t] = freq.get(t, 0) + 1
    common = sorted(freq.items(), key=lambda kv: (-kv[1], kv[0]))

    return {
        "targets": [{
            "target": e["target"], "source": e["source"],
            "grade": e["risk"]["grade"], "score": e["risk"]["score"],
            "counts": e["risk"]["counts"], "total": e["risk"]["total"],
        } for e in ranked],
        "overall": overall,
        "top_findings": top[:15],
        "common_issues": common[:10],
        "num_targets": len(entries),
    }


def render_markdown(p: Dict) -> str:
    """Render portofolio menjadi laporan markdown."""
    o = p["overall"]
    lines = [
        "# Portfolio Risk Report",
        "",
        f"**Target:** {p['num_targets']} | **Grade portofolio:** {o['grade']} "
        f"({o['score']}/100)",
        "",
        f"> {o['recommendation']}",
        "",
        "## Ringkasan per target (terburuk dulu)",
        "",
        "| Target | Grade | Skor | C | H | M | L | Total |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for t in p["targets"]:
        c = t["counts"]
        lines.append(
            f"| {t['target']} | {t['grade']} | {t['score']} | "
            f"{c.get('CRITICAL', 0)} | {c.get('HIGH', 0)} | {c.get('MEDIUM', 0)} | "
            f"{c.get('LOW', 0)} | {t['total']} |"
        )
    lines += ["", "## Temuan paling berat", ""]
    if p["top_findings"]:
        for f in p["top_findings"]:
            lines.append(f"- **[{f.get('severity')}]** {f.get('title')} — "
                         f"{f.get('endpoint', '')}")
    else:
        lines.append("- Tidak ada temuan.")
    lines += ["", "## Jenis masalah paling umum", ""]
    if p["common_issues"]:
        for title, n in p["common_issues"]:
            lines.append(f"- {title}: muncul di {n} target")
    else:
        lines.append("- Tidak ada.")
    lines.append("")
    return "\n".join(lines)
