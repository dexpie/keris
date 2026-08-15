"""Generator laporan PDF mandiri menggunakan reportlab."""

import re
from typing import List
from xml.sax.saxutils import escape as _xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

from keris import __version__

# Tag markup yang diizinkan di dalam string Paragraph reportlab.
_ALLOWED_TAGS = re.compile(
    r"</?(?:b|i|u|font|a|br)\b[^>]*>",
    re.IGNORECASE,
)


def _esc(text) -> str:
    """Escape teks agar aman untuk Paragraph reportlab, tanpa merusak tag markup kita."""
    if text is None:
        return ""
    s = str(text)
    hold = []
    def _keep(match):
        hold.append(match.group(0))
        return f"\x00{len(hold) - 1}\x00"
    s = _ALLOWED_TAGS.sub(_keep, s)
    s = _xml_escape(s)
    def _restore(match):
        return hold[int(match.group(0)[1:-1])]
    return re.sub(r"\x00\d+\x00", _restore, s)


_SEV_COLORS = {
    "CRITICAL": colors.HexColor("#B00020"),
    "HIGH": colors.HexColor("#D32F2F"),
    "MEDIUM": colors.HexColor("#F57C00"),
    "LOW": colors.HexColor("#F9A825"),
    "INFO": colors.HexColor("#1976D2"),
}


def write_pdf_report(recon: dict, disc: dict, findings: List[dict],
                     output: str, base: str, options: dict) -> None:
    """Tulis laporan PDF ke `output`."""
    doc = SimpleDocTemplate(
        output, pagesize=A4,
        rightMargin=18 * mm, leftMargin=18 * mm,
        topMargin=15 * mm, bottomMargin=15 * mm,
        title=f"Keris Report — {base}",
        author="Keris",
    )
    styles = getSampleStyleSheet()
    h1 = styles["Heading1"]
    h2 = styles["Heading2"]
    normal = ParagraphStyle(
        "body", parent=styles["Normal"], fontSize=9.5, leading=13,
        wordWrap="CJK",
    )
    small = ParagraphStyle(
        "small", parent=normal, fontSize=8.5, textColor=colors.grey,
    )

    story = []
    story.append(Paragraph("Keris Pentest Report", h1))
    story.append(Paragraph(
        f"Target: {_esc(base)}<br/>Keris v{__version__} — {_esc(options.get('mode', ''))}",
        small,
    ))
    story.append(Spacer(1, 6 * mm))

    # Ringkasan
    total = len(findings)
    sev = {s: sum(1 for f in findings if f.get("severity", "INFO").upper() == s)
           for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    story.append(Paragraph("Ringkasan", h2))
    summary_data = [["Severity", "Jumlah"],
                    ["CRITICAL", sev["CRITICAL"]],
                    ["HIGH", sev["HIGH"]],
                    ["MEDIUM", sev["MEDIUM"]],
                    ["LOW", sev["LOW"]],
                    ["INFO", sev["INFO"]],
                    ["Total", total]]
    t = Table(summary_data, colWidths=[50 * mm, 30 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263238")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cfd8dc")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eceff1")]),
    ]))
    story.append(t)
    story.append(Spacer(1, 6 * mm))

    # Host / stack
    host = recon.get("host") or base
    story.append(Paragraph(f"Target: {_esc(host)}", h2))
    story.append(Paragraph(
        f"Stack: {_esc(', '.join(recon.get('stack', [])) or 'tidak diketahui')}",
        normal,
    ))
    story.append(Spacer(1, 4 * mm))

    # Ringkasan OWASP Top 10
    from keris.cvss import owasp_summary

    owasp_rows = owasp_summary(findings)
    if owasp_rows:
        story.append(Paragraph("Klasifikasi OWASP Top 10 (2021)", h2))
        ow_data = [["Kategori", "Jumlah"]] + [[r["category"], r["count"]] for r in owasp_rows]
        ot = Table(ow_data, colWidths=[70 * mm, 30 * mm])
        ot.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263238")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cfd8dc")),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ]))
        story.append(ot)
        story.append(Spacer(1, 5 * mm))

    # Temuan
    story.append(Paragraph("Temuan", h2))
    if not findings:
        story.append(Paragraph("Tidak ada temuan.", normal))
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO").upper()
        color = _SEV_COLORS.get(sev, colors.black)
        from keris.cvss import classify

        cvss = classify(f.get("title", ""), sev)
        story.append(Paragraph(
            f"{i}. [{sev}] {_esc(f.get('title', ''))}",
            ParagraphStyle(f"f{i}", parent=normal, textColor=color,
                           fontName="Helvetica-Bold"),
        ))
        story.append(Paragraph(
            f"<b>Endpoint:</b> {_esc(f.get('endpoint', ''))}",
            small,
        ))
        story.append(Paragraph(
            f"<b>CVSS v3.1:</b> {_esc(str(cvss['score']))} ({_esc(cvss['vector'])}) &nbsp; "
            f"<b>OWASP:</b> {_esc(cvss['owasp_code'])} {_esc(cvss['owasp_name'])}",
            small,
        ))
        story.append(Paragraph(f"<b>Detail:</b> {_esc(f.get('detail', ''))}", normal))
        if f.get("evidence"):
            story.append(Paragraph(
                f"<b>Bukti:</b> <font size='8' face='Courier'>{_esc(f['evidence'][:1000])}</font>",
                normal,
            ))
        story.append(Spacer(1, 3 * mm))

    # Rekomendasi
    story.append(Paragraph("Rekomendasi", h2))
    recs = []
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if sev in ("HIGH", "CRITICAL"):
            recs.append(f"Perbaiki segera: {f.get('title', '')} — {f.get('detail', '')}")
    for r in (recs or ["Tidak ada rekomendasi otomatis."])[:10]:
        story.append(Paragraph(f"• {_esc(r)}", normal))

    doc.build(story)
