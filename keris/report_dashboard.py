"""Dashboard agregat HTML: gabungkan banyak laporan scan JSON jadi satu halaman."""

import html
import json
import os
from typing import List, Optional

from keris import __version__


def _sev_color(sev: str) -> str:
    return {"CRITICAL": "#B00020", "HIGH": "#D32F2F", "MEDIUM": "#F57C00",
            "LOW": "#F9A825", "INFO": "#1976D2"}.get(sev.upper(), "#333")


def _row(f: dict, idx: int) -> str:
    sev = f.get("severity", "INFO").upper()
    color = _sev_color(sev)
    return (
        f"<tr>"
        f"<td>{idx}</td>"
        f"<td><span class='sev' style='background:{color}'>{sev}</span></td>"
        f"<td>{html.escape(f.get('title', ''))}</td>"
        f"<td>{html.escape(f.get('endpoint', ''))}</td>"
        f"<td class='detail'>{html.escape(f.get('detail', ''))}</td>"
        f"</tr>"
    )


def build_dashboard(results: List[dict], output: str) -> str:
    """Gabungkan hasil laporan JSON menjadi dashboard HTML interaktif.

    `results`: list dict berisi {"target", "summary", "findings"}.
    """
    total_findings = sum(len(r.get("findings", [])) for r in results)
    total_targets = len(results)

    # ringkasan severity global
    sev_global = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for r in results:
        for f in r.get("findings", []):
            s = f.get("severity", "INFO").upper()
            sev_global[s] = sev_global.get(s, 0) + 1

    cards = "".join(
        f"<div class='card'><div class='card-num'>{sev_global[s]}</div>"
        f"<div class='card-label' style='color:{_sev_color(s)}'>{s}</div></div>"
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )

    sections = []
    for ri, r in enumerate(results, 1):
        target = html.escape(r.get("target", "?"))
        findings = r.get("findings", [])
        fcnt = len(findings)
        rows = "".join(_row(f, i) for i, f in enumerate(findings, 1))
        if not rows:
            rows = "<tr><td colspan='5' class='ok'>Tidak ada temuan</td></tr>"
        sections.append(f"""
        <section>
          <h2>{ri}. {target} <span class='count'>({fcnt} temuan)</span></h2>
          <table>
            <thead><tr><th>#</th><th>Severity</th><th>Judul</th><th>Endpoint</th><th>Detail</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </section>""")

    html_doc = f"""<!DOCTYPE html>
<html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Keris Dashboard — {total_targets} target</title>
<style>
body {{ font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; background: #f5f6f8; color: #222; }}
header {{ background: #263238; color: #fff; padding: 20px 28px; }}
header h1 {{ margin: 0; font-size: 22px; }}
header p {{ margin: 4px 0 0; color: #b0bec5; font-size: 13px; }}
.cards {{ display: flex; gap: 12px; padding: 20px 28px; flex-wrap: wrap; }}
.card {{ background: #fff; border-radius: 10px; padding: 14px 22px; box-shadow: 0 1px 3px rgba(0,0,0,.1); text-align: center; min-width: 90px; }}
.card-num {{ font-size: 28px; font-weight: 700; }}
.card-label {{ font-size: 12px; letter-spacing: 1px; }}
main {{ padding: 4px 28px 40px; }}
section {{ background: #fff; border-radius: 10px; padding: 18px 22px; margin-bottom: 18px; box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
section h2 {{ margin: 0 0 10px; font-size: 17px; }}
.count {{ color: #78909c; font-weight: 400; font-size: 13px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th {{ text-align: left; background: #eceff1; padding: 8px 10px; }}
td {{ padding: 7px 10px; border-bottom: 1px solid #eceff1; vertical-align: top; }}
.sev {{ color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; white-space: nowrap; }}
.detail {{ color: #546e7a; max-width: 420px; }}
.ok {{ color: #2e7d32; text-align: center; }}
footer {{ padding: 12px 28px; color: #90a4ae; font-size: 12px; }}
</style></head><body>
<header><h1>Keris Security Dashboard</h1>
<p>{total_targets} target · {total_findings} temuan · Keris v{__version__}</p></header>
<div class="cards">{cards}</div>
<main>{''.join(sections)}</main>
<footer>Dibuat oleh Keris — laporan gabungan otomatis.</footer>
</body></html>"""

    with open(output, "w", encoding="utf-8") as f:
        f.write(html_doc)
    return output
