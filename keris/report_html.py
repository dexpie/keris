"""Generator laporan HTML mandiri (self-contained) dari hasil scan Keris."""

import html
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

    from keris.cvss import owasp_summary

    _owasp = owasp_summary(findings)
    owasp_rows = "".join(
        f"<tr><td>{_e(r['category'])}</td><td>{r['count']}</td></tr>" for r in _owasp
    ) or "<tr><td colspan=2>Tidak ada temuan</td></tr>"

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
</style>
</head>
<body>
<div class="container">
  <h1>Penetration Test Report</h1>
  <div class="sub">Target: {_e(target)} &middot; Date: {now} &middot; Tool: Keris &middot; Mode: {_e(options.get('mode', 'auto'))}</div>

  <div class="summary-grid">
    <div class="stat"><b>{total}</b><span>Findings</span></div>
    <div class="stat"><b>{counts['HIGH'] + counts['CRITICAL']}</b><span>High+Critical</span></div>
    <div class="stat"><b>{len(discovery.get('api_endpoints', []))}</b><span>API Endpoints</span></div>
    <div class="stat"><b>{discovery.get('secret_count', 0)}</b><span>Secrets</span></div>
  </div>

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
