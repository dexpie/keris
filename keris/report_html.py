"""Generator laporan HTML mandiri (self-contained) dari hasil scan Keris."""

import html
import re
from datetime import datetime
from typing import Dict, List

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

SEV_COLORS = {
    "CRITICAL": "#e11d48",
    "HIGH": "#f43f5e",
    "MEDIUM": "#f59e0b",
    "LOW": "#eab308",
    "INFO": "#3b82f6",
}


def _e(s) -> str:
    return html.escape(str(s or ""))


def _parse_chain(f: Dict) -> List[dict]:
    """Parse evidence chain 'Chain terbentuk dari: [SEV] title @ endpoint; ...'."""
    ev = f.get("evidence", "") or ""
    steps = []
    body = ev
    if "Chain terbentuk dari:" in ev:
        body = ev.split("Chain terbentuk dari:", 1)[1]
    for part in body.split(";"):
        part = part.strip()
        if not part:
            continue
        m = re.match(r"^\[([A-Z]+)\]\s+(.+?)\s+@\s+(.+)$", part)
        if m:
            steps.append({"severity": m.group(1), "title": m.group(2).strip(),
                          "endpoint": m.group(3).strip()})
    return steps


def _attack_path_html(findings: List[Dict]) -> str:
    """Rendering visual attack paths dari temuan correlation (source=correlation)."""
    chains = [f for f in findings if f.get("source") == "correlation"]
    if not chains:
        return ""
    blocks = []
    for f in chains:
        steps = _parse_chain(f)
        nodes = []
        if steps:
            for i, s in enumerate(steps):
                nodes.append(
                    f'<div class="node"><span class="badge" style="background:{SEV_COLORS.get(s["severity"].upper(), "#666")}">'
                    f'{_e(s["severity"])}</span> <b>{_e(s["title"])}</b>'
                    f'<div class="node-ep">{_e(s["endpoint"])}</div></div>')
                if i < len(steps) - 1:
                    nodes.append('<div class="arrow">&#8680;</div>')
        else:
            nodes.append(f'<div class="node">{_e(f.get("endpoint", ""))}</div>')
        blocks.append(
            f'<div class="card"><div class="card-head">'
            f'<span class="badge" style="background:{SEV_COLORS.get(f.get("severity", "HIGH").upper(), "#666")}">'
            f'{_e(f.get("severity", "HIGH").upper())}</span>'
            f'<span class="card-title">{_e(f.get("title", ""))}</span></div>'
            f'<div class="path">{ "".join(nodes) }</div>'
            f'<p class="path-why">{_e(f.get("detail", ""))}</p></div>')
    return f'<h2>Attack Paths</h2><div class="paths">{ "".join(blocks) }</div>'


def _trend_html(history: List[Dict]) -> str:
    """Grafik tren risk score dari riwayat scan (options['history'])."""
    if not history:
        return ""
    rows = "".join(
        f"<div class='tr-item'><span class='tr-date'>{_e(h.get('date', ''))}</span>"
        f"<div class='tr-bar-wrap'><div class='tr-bar' style='width:{h.get('score', 0)}%' "
        f"title='{h.get('score', 0)}/100'>{_e(h.get('grade', ''))}</div></div></div>"
        for h in history
    )
    return f"""
    <h2>Progress Trend (Risk Score)</h2>
    <div class="trend">
      <div class="tr-head"><span>Scan</span><span>Score (A-F)</span></div>
      {rows}
    </div>"""


def _history_from_options(target: str, options: Dict) -> List[Dict]:
    """Ambil riwayat risk score untuk target dari options['history']."""
    hist = options.get("history") or []
    if isinstance(hist, list) and hist:
        return hist
    return []


def generate_html_report(target: str, recon: Dict, discovery: Dict, findings: List[Dict], options: Dict = None) -> str:
    options = options or {}
    now = datetime.utcnow().strftime("%d %B %Y, %H:%M UTC")

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.get("severity", "INFO").upper()] = counts.get(f.get("severity", "INFO").upper(), 0) + 1
    total = sum(counts.values())

    sev_bars = "".join(
        f'<div class="sev-row"><span class="sev-name">{s}</span>'
        f'<div class="sev-bar-wrap"><div class="sev-bar" style="width:{counts[s]/max(total,1)*100}%;background:{SEV_COLORS[s]}"></div></div>'
        f'<span class="sev-count">{counts[s]}</span></div>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )

    sec_rows = "".join(
        f"<tr><td><code>{_e(h['header'])}</code></td><td>{'&#9989;' if h['present'] else '&#10060;'}</td><td>{_e(h['desc'])}</td></tr>"
        for h in recon.get("security_headers", [])
    )

    ep_items = "".join(f"<li><code>{_e(ep)}</code></li>" for ep in discovery.get("api_endpoints", [])[:80]) or "<li>tidak ada</li>"

    secret_items = "".join(
        f"<li><b>{_e(s['type'])}</b>: <code>{_e(s['match'])}</code></li>" for s in discovery.get("secrets", [])
    ) or "<li>tidak ada</li>"

    finding_cards = ""
    for i, f in enumerate(sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO").upper(), 9)), 1):
        sev = f.get("severity", "INFO").upper()
        from keris.cvss import classify

        cvss = classify(f.get("title", ""), sev)
        finding_cards += f"""
        <div class="card">
          <div class="card-head">
            <span class="badge" style="background:{SEV_COLORS.get(sev, '#666')}">{sev}</span>
            <span class="card-title">{_e(f.get('title', ''))}</span>
          </div>
          <p class="endpoint">{_e(f.get('endpoint', ''))}</p>
          <p><span class="cvss">CVSS {cvss['score']} &middot; {_e(cvss['vector'])}</span>
             <span class="owasp">{_e(cvss['owasp_code'])} {_e(cvss['owasp_name'])}</span></p>
          <p>{_e(f.get('detail', ''))}</p>
          <pre>{_e(f.get('evidence', ''))[:1000]}</pre>
        </div>"""

    if not findings:
        finding_cards = '<div class="card"><p>No vulnerabilities detected during this scan.</p></div>'

    attack_paths = _attack_path_html(findings)

    from keris.cvss import owasp_summary

    _owasp = owasp_summary(findings)
    owasp_rows = "".join(
        f"<tr><td>{_e(r['category'])}</td><td>{r['count']}</td></tr>" for r in _owasp
    ) or "<tr><td colspan=2>Tidak ada temuan</td></tr>"

    from keris.modules.riskscore import risk_score

    _rs = risk_score(findings)
    _history = _history_from_options(target, options)
    trend_html = _trend_html(_history)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Keris Report — {_e(target)}</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background: #0f172a; color: #e2e8f0; padding: 24px; line-height: 1.6; }}
.container {{ max-width: 960px; margin: 0 auto; }}
h1 {{ font-size: 22px; margin-bottom: 4px; }}
h2 {{ font-size: 17px; margin: 28px 0 12px; color: #93c5fd; border-bottom: 1px solid #334155; padding-bottom: 6px; }}
.sub {{ color: #94a3b8; font-size: 13px; margin-bottom: 20px; }}
table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
th, td {{ text-align: left; padding: 7px 10px; border-bottom: 1px solid #1e293b; }}
th {{ color: #93c5fd; }}
code {{ background: #1e293b; padding: 2px 5px; border-radius: 4px; font-size: 12px; }}
.summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px; margin-bottom: 20px; }}
.stat {{ background: #1e293b; border-radius: 8px; padding: 14px; }}
.stat b {{ display: block; font-size: 26px; }}
.stat b.grad {{ background: linear-gradient(135deg, #d4a24e, #f0c46a); -webkit-background-clip: text; background-clip: text; color: transparent; font-size: 30px; }}
.stat span {{ font-size: 12px; color: #94a3b8; }}
.sev-row {{ display: flex; align-items: center; gap: 10px; font-size: 13px; margin: 4px 0; }}
.sev-name {{ width: 80px; }}
.sev-bar-wrap {{ flex: 1; background: #0f172a; border-radius: 4px; overflow: hidden; height: 10px; }}
.sev-bar {{ height: 10px; }}
.sev-count {{ width: 24px; text-align: right; }}
.card {{ background: #1e293b; border-radius: 8px; padding: 16px; margin-bottom: 12px; }}
.card-head {{ display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }}
.badge {{ color: #fff; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 4px; }}
.card-title {{ font-weight: 600; }}
.endpoint {{ font-family: monospace; font-size: 12px; color: #93c5fd; margin: 4px 0; }}
.cvss {{ font-size: 12px; color: #fbbf24; }}
.owasp {{ font-size: 12px; color: #a78bfa; margin-left: 12px; }}
pre {{ background: #0f172a; padding: 10px; border-radius: 6px; font-size: 11px; overflow-x: auto; margin-top: 8px; }}
ul {{ padding-left: 20px; font-size: 13px; }}
li {{ margin: 3px 0; }}
.footer {{ margin-top: 30px; font-size: 12px; color: #64748b; text-align: center; }}
.paths {{ display: flex; flex-direction: column; gap: 12px; }}
.path {{ display: flex; align-items: center; flex-wrap: wrap; gap: 8px; margin: 10px 0; }}
.node {{ background: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 8px 12px; font-size: 12px; max-width: 320px; }}
.node-ep {{ font-family: monospace; font-size: 11px; color: #93c5fd; margin-top: 2px; }}
.arrow {{ color: #fbbf24; font-size: 18px; font-weight: 700; }}
.path-why {{ font-size: 12px; color: #94a3b8; margin-top: 6px; }}
.trend {{ margin: 12px 0 20px; }}
.tr-head, .tr-item {{ display: flex; align-items: center; gap: 10px; font-size: 12px; }}
.tr-head {{ color: #94a3b8; margin-bottom: 6px; }}
.tr-date {{ width: 160px; font-family: monospace; }}
.tr-bar-wrap {{ flex: 1; background: #0f172a; border-radius: 4px; height: 18px; overflow: hidden; }}
.tr-bar {{ background: linear-gradient(90deg, #d4a24e, #f0c46a); color: #0f172a; font-size: 11px; font-weight: 700; line-height: 18px; padding-left: 6px; height: 100%; border-radius: 4px; }}
</style>
</head>
<body>
<div class="container">
  <h1>Penetration Test Report</h1>
  <div class="sub">Target: {_e(target)} &middot; Date: {now} &middot; Tool: Keris &middot; Mode: {_e(options.get('mode', 'auto'))}</div>

  <div class="summary-grid">
    <div class="stat"><b class="grad">{_e(_rs['grade'])}</b><span>Risk Score ({_e(_rs['score'])})</span></div>
    <div class="stat"><b>{total}</b><span>Findings</span></div>
    <div class="stat"><b>{counts['HIGH'] + counts['CRITICAL']}</b><span>High+Critical</span></div>
    <div class="stat"><b>{len(discovery.get('api_endpoints', []))}</b><span>API Endpoints</span></div>
    <div class="stat"><b>{discovery.get('secret_count', 0)}</b><span>Secrets</span></div>
  </div>

  <p style="font-size:13px;color:#94a3b8;margin:-8px 0 16px">{_e(_rs['recommendation'])}</p>

  {trend_html}

  <h2>Severity</h2>
  {sev_bars}

  <h2>OWASP Top 10 (2021)</h2>
  <table>
    <tr><th>Kategori</th><th>Jumlah Temuan</th></tr>
    {owasp_rows}
  </table>

  <h2>Target Profile</h2>
  <table>
    <tr><th>URL</th><td>{_e(target)}</td></tr>
    <tr><th>Host</th><td>{_e(recon.get('host', ''))}</td></tr>
    <tr><th>IP</th><td>{_e(', '.join(recon.get('ips', [])))}</td></tr>
    <tr><th>Server</th><td>{_e(recon.get('server_header', 'n/a'))}</td></tr>
    <tr><th>Status</th><td>{_e(recon.get('status_code', ''))}</td></tr>
    <tr><th>Stack</th><td>{_e(', '.join(recon.get('stack', [])))}</td></tr>
  </table>

  <h2>Security Headers</h2>
  <table>
    <tr><th>Header</th><th>Status</th><th>Note</th></tr>
    {sec_rows}
  </table>

  <h2>Discovery</h2>
  <p><b>API endpoints ({len(discovery.get('api_endpoints', []))}):</b></p>
  <ul>{ep_items}</ul>
  <p style="margin-top:12px"><b>Potential secrets ({discovery.get('secret_count', 0)}):</b></p>
  <ul>{secret_items}</ul>

  <h2>Findings</h2>
  {finding_cards}

  {attack_paths}

  <div class="footer">Generated automatically by Keris &middot; Verify any "indicated"/"potential" findings manually before acting.</div>
</div>
</body>
</html>
"""


def write_html_report(recon: Dict, discovery: Dict, findings: List[Dict], output: str, target: str, options: Dict = None) -> str:
    html_str = generate_html_report(target, recon, discovery, findings, options)
    with open(output, "w", encoding="utf-8") as f:
        f.write(html_str)
    return output
