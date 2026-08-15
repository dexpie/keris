"""Generator laporan Markdown dari hasil scan Keris."""

import os
from datetime import datetime
from typing import Dict, List

from keris.core.logger import info

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _esc(text: str) -> str:
    """Escape karakter markdown berbahaya."""
    if not text:
        return ""
    return str(text).replace("|", "\\|").replace("\n", " ")


def _severity_badge(sev: str) -> str:
    sev = sev.upper()
    colors = {
        "CRITICAL": "FF0000",
        "HIGH": "FF4D4D",
        "MEDIUM": "FFA500",
        "LOW": "FFD700",
        "INFO": "4DA6FF",
    }
    return f"![{sev}](https://img.shields.io/badge/{sev}-{colors.get(sev, '999')})"


def generate_report(
    target: str,
    recon: Dict,
    discovery: Dict,
    findings: List[Dict],
    options: Dict = None,
    author: str = "Keris",
) -> str:
    """Hasilkan string laporan markdown."""
    options = options or {}
    now = datetime.utcnow().strftime("%d %B %Y, %H:%M UTC")

    lines = []
    lines.append(f"# Laporan Pengujian Keamanan — {_esc(target)}")
    lines.append("")
    lines.append(f"**Tanggal:** {now}")
    lines.append(f"**Tools:** {author}")
    lines.append(f"**Jenis:** Black-box {_esc(options.get('mode', 'otomatis'))}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Ringkasan eksekutif
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        s = f.get("severity", "INFO").upper()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    lines.append("## Ringkasan Eksekutif")
    lines.append("")
    total = sum(sev_counts.values())
    lines.append(f"Pengujian terhadap `{_esc(target)}` menemukan **{total}** temuan.")
    lines.append("")

    # Risk score A-F
    from keris.modules.riskscore import risk_score

    rs = risk_score(findings)
    lines.append(f"**Risk Score:** `{rs['grade']}` ({rs['score']}/100)")
    lines.append("")
    lines.append(f"_{rs['recommendation']}_")
    lines.append("")
    lines.append("| Severity | Jumlah |")
    lines.append("|---|---|")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"| {sev} | {sev_counts.get(sev, 0)} |")
    lines.append("")

    # Pemetaan OWASP Top 10 & CVSS
    from keris.cvss import classify, owasp_summary

    owasp_rows = owasp_summary(findings)
    if owasp_rows:
        lines.append("### Klasifikasi OWASP Top 10 (2021)")
        lines.append("")
        lines.append("| Kategori | Jumlah Temuan |")
        lines.append("|---|---|")
        for row in owasp_rows:
            lines.append(f"| {row['category']} | {row['count']} |")
        lines.append("")

    # Profil target
    lines.append("## 1. Profil Target")
    lines.append("")
    lines.append("| Item | Nilai |")
    lines.append("|---|---|")
    lines.append(f"| URL | `{_esc(target)}` |")
    lines.append(f"| Host | `{_esc(recon.get('host', ''))}` |")
    lines.append(f"| IP | `{', '.join(recon.get('ips', []))}` |")
    lines.append(f"| Server | `{_esc(recon.get('server_header', 'n/a'))}` |")
    if recon.get("status_code"):
        lines.append(f"| HTTP Status | `{recon.get('status_code')}` |")
    if recon.get("stack"):
        lines.append(f"| Stack | `{', '.join(recon.get('stack', []))}` |")
    if recon.get("has_redirect"):
        lines.append(f"| Redirect ke | `{_esc(recon.get('final_url', ''))}` |")
    lines.append("")

    # Security headers
    lines.append("## 2. Security Headers")
    lines.append("")
    lines.append("| Header | Status | Catatan |")
    lines.append("|---|---|---|")
    for h in recon.get("security_headers", []):
        status = "✔" if h["present"] else "✘"
        lines.append(f"| `{h['header']}` | {status} | {_esc(h['desc'])} |")
    lines.append("")

    # Stack
    lines.append("## 3. Stack & Teknologi")
    lines.append("")
    if recon.get("stack"):
        lines.append("Deteksi: " + ", ".join(recon["stack"]))
    else:
        lines.append("Tidak terdeteksi.")
    lines.append("")

    # Discovery
    lines.append("## 4. Discovery")
    lines.append("")
    lines.append(f"- Endpoint API unik: **{len(discovery.get('api_endpoints', []))}**")
    lines.append(f"- Asset JS terunduh: **{len(discovery.get('js_assets', []))}**")
    lines.append(f"- Secret potensial: **{discovery.get('secret_count', 0)}**")
    lines.append("")
    if discovery.get("api_endpoints"):
        lines.append("### Endpoint API")
        lines.append("")
        for ep in discovery["api_endpoints"][:60]:
            lines.append(f"- `{ep}`")
        lines.append("")
    if discovery.get("secrets"):
        lines.append("### Secret Potensial")
        lines.append("")
        for s in discovery["secrets"]:
            lines.append(f"- **{s['type']}:** `{s['match']}`")
        lines.append("")

    # Temuan
    lines.append("## 5. Temuan")
    lines.append("")
    if not findings:
        lines.append("Tidak ada temuan kerentanan yang terdeteksi pada pengujian ini.")
    else:
        lines.append("| Severity | Lokasi | Deskripsi |")
        lines.append("|---|---|---|")
        for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO").upper(), 9)):
            lines.append(f"| {_severity_badge(f.get('severity', 'INFO'))} | `{_esc(f.get('endpoint', ''))}` | {_esc(f.get('title', ''))} |")
        lines.append("")

    # Attack paths visual (hasil correlation engine)
    chains = [f for f in findings if f.get("source") == "correlation"]
    if chains:
        lines.append("## 6. Attack Paths")
        lines.append("")
        for f in sorted(chains, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "HIGH").upper(), 9)):
            lines.append(f"### [{f.get('severity', 'HIGH')}] {f.get('title', '')}")
            lines.append("")
            lines.append(f"**Tujuan akhir:** `{f.get('endpoint', '')}`")
            lines.append("")
            ev = f.get("evidence", "") or ""
            steps = [s.strip() for s in ev.replace("Chain terbentuk dari:", "").split(";") if s.strip()]
            for idx, s in enumerate(steps, 1):
                lines.append(f"{idx}. {s}")
            lines.append("")
            lines.append(f"**Mengapa kritis:** {f.get('detail', '')}")
            lines.append("")

    if findings:
        lines.append("### Detail")
        lines.append("")
        for i, f in enumerate(sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO").upper(), 9)), 1):
            lines.append(f"#### {i}. [{f.get('severity', 'INFO')}] {f.get('title', '')}")
            lines.append("")
            lines.append(f"**Lokasi:** `{f.get('endpoint', '')}`")
            lines.append("")
            cvss = classify(f.get("title", ""), f.get("severity", ""))
            lines.append(
                f"**CVSS v3.1:** {cvss['score']} (`{cvss['vector']}`) · "
                f"**OWASP:** {cvss['owasp_code']} {cvss['owasp_name']}"
            )
            lines.append("")
            lines.append(f"**Detail:** {f.get('detail', '')}")
            lines.append("")
            if f.get("evidence"):
                lines.append("**Bukti:**")
                lines.append("")
                lines.append("```")
                lines.append(f.get("evidence", "")[:1000])
                lines.append("```")
                lines.append("")

    # Rekomendasi
    from keris.modules.remediation import build_remediation_plan, remediation_markdown

    plan = build_remediation_plan(findings)
    if plan["items"]:
        lines.append(remediation_markdown(plan, target))
        lines.append("---")
        lines.append("")
    lines.append("*Laporan dihasilkan otomatis oleh Keris. Verifikasi manual disarankan untuk temuan yang berstatus 'terindikasi' atau 'potensial'.*")
    lines.append("")

    return "\n".join(lines)


def write_report(recon: Dict, discovery: Dict, findings: List[Dict], output: str, target: str, options: Dict = None) -> str:
    """Tulis laporan ke file dan kembalikan path."""
    md = generate_report(target, recon, discovery, findings, options)
    with open(output, "w", encoding="utf-8") as f:
        f.write(md)
    info(f"Laporan ditulis: {output}")
    return output
