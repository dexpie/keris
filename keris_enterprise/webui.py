"""Web UI dashboard keris-enterprise (self-contained HTML).

Menampilkan: risk trend, ringkasan project, remediasi tracking, dan
integrasi attack path visualization (bila ada `attack_paths` di hasil).
"""

import html
import json
from typing import Dict, List


def _esc(s) -> str:
    return html.escape(str(s or ""))


def _sev_color(sev: str) -> str:
    return {"CRITICAL": "#B00020", "HIGH": "#D32F2F", "MEDIUM": "#F57C00",
            "LOW": "#F9A825", "INFO": "#1976D2"}.get(sev.upper(), "#333")


def render_dashboard(data: Dict) -> str:
    projects = data.get("projects", 0)
    results = data.get("recent_results", 0)
    findings = data.get("total_findings", 0)
    rem_open = data.get("remediations_open", 0)
    rem_total = data.get("remediations_total", 0)
    trend = data.get("trend", [])

    trend_rows = "".join(
        f"<tr><td>{_esc(t['target'])}</td><td>{t['score']}</td>"
        f"<td>{_esc(t['grade'])}</td></tr>" for t in trend[-20:])

    rem_pct = round(rem_open / rem_total * 100) if rem_total else 0

    return f"""<!DOCTYPE html>
<html lang="id"><head><meta charset="utf-8">
<title>keris-enterprise Dashboard</title>
<style>
 body {{ font-family: system-ui, sans-serif; margin: 0; background: #f4f5f7; color: #172b4d; }}
 header {{ background: #0b3d91; color: #fff; padding: 16px 24px; }}
 header h1 {{ margin: 0; font-size: 20px; }}
 main {{ padding: 24px; display: grid; grid-template-columns: repeat(auto-fit, minmax(220px,1fr)); gap: 16px; }}
 .card {{ background: #fff; border-radius: 8px; padding: 16px; box-shadow: 0 1px 3px rgba(9,30,66,.15); }}
 .card h2 {{ margin: 0 0 8px; font-size: 14px; color: #42526e; }}
 .num {{ font-size: 32px; font-weight: 700; }}
 table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
 td, th {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid #ebecf0; }}
 .bar {{ height: 10px; background: #dfe1e6; border-radius: 6px; overflow: hidden; margin-top: 6px; }}
 .bar span {{ display: block; height: 100%; background: #0b3d91; }}
</style></head><body>
<header><h1>keris-enterprise Dashboard</h1></header>
<main>
 <div class="card"><h2>Project</h2><div class="num">{projects}</div></div>
 <div class="card"><h2>Hasil Scan</h2><div class="num">{results}</div></div>
 <div class="card"><h2>Total Temuan</h2><div class="num">{findings}</div></div>
 <div class="card"><h2>Remediasi</h2><div class="num">{rem_open}/{rem_total}</div>
   <div class="bar"><span style="width:{rem_pct}%"></span></div></div>
 <div class="card"><h2>Risk Trend (20 terakhir)</h2>
   <table><tr><th>Target</th><th>Skor</th><th>Grade</th></tr>{trend_rows}</table></div>
</main>
</body></html>"""


def render_api_docs(base_url: str) -> str:
    endpoints = [
        ("POST", "/api/login", "login -> token"),
        ("GET", "/api/users", "daftar user (admin)"),
        ("GET/POST", "/api/projects", "daftar / buat project"),
        ("POST", "/api/projects/<id>/scan", "jalankan scan sekali"),
        ("GET", "/api/projects/<id>/results", "riwayat hasil scan"),
        ("GET/POST", "/api/projects/<id>/remediations", "remediasi"),
        ("GET", "/api/dashboard", "ringkasan dashboard"),
        ("POST", "/api/scheduler/start|stop", "start/stop scheduler"),
    ]
    rows = "".join(
        f"<tr><td>{m}</td><td><code>{_esc(p)}</code></td><td>{_esc(d)}</td></tr>"
        for m, p, d in endpoints)
    return f"""<!DOCTYPE html><html lang="id"><head><meta charset="utf-8">
<title>keris-enterprise API</title><style>
 body {{ font-family: system-ui, sans-serif; margin: 0; background: #f4f5f7; color:#172b4d; }}
 header {{ background: #0b3d91; color:#fff; padding:16px 24px; }}
 main {{ padding:24px; }}
 table {{ width:100%; border-collapse:collapse; background:#fff; }}
 td,th {{ text-align:left; padding:8px; border-bottom:1px solid #ebecf0; }}
</style></head><body>
<header><h1>keris-enterprise REST API</h1><p>{_esc(base_url)}</p></header>
<main><table><tr><th>Method</th><th>Endpoint</th><th>Keterangan</th></tr>{rows}</table></main>
</body></html>"""


def attack_paths_section(results: List[Dict]) -> str:
    """Bagian attack path visualization dari hasil scan."""
    out = []
    for r in results:
        ap = r.get("result", {}).get("attack_paths", []) if isinstance(r, dict) else []
        if not ap:
            continue
        out.append(f"<div class='card'><h2>Attack Path: {_esc(r.get('target'))}</h2>")
        for i, p in enumerate(ap[:3], 1):
            sev = _esc(p.get("severity", "HIGH"))
            impact = _esc(p.get("impact", ""))
            score = p.get("score", 0)
            out.append(f"<p><b>Path {i}: [{sev}] {impact} (Skor {score})</b></p>")
            out.append("<ol>")
            for s in p.get("steps", []):
                out.append(f"<li>[{_esc(s.get('severity',''))}] "
                           f"{_esc(s.get('title',''))} @ "
                           f"<code>{_esc(s.get('endpoint',''))}</code></li>")
            out.append("</ol>")
        out.append("</div>")
    return "".join(out) if out else "<p>Tidak ada attack path.</p>"