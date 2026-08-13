"""Generator laporan PDF mandiri menggunakan reportlab."""

from typing import List

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

from keris import __version__

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
        f"Target: {base}<br/>Keris v{__version__} — {options.get('mode', '')}",
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
    story.append(Paragraph(f"Target: {host}", h2))
    story.append(Paragraph(
        f"Stack: {', '.join(recon.get('stack', [])) or 'tidak diketahui'}",
        normal,
    ))
    story.append(Spacer(1, 4 * mm))

    # Temuan
    story.append(Paragraph("Temuan", h2))
    if not findings:
        story.append(Paragraph("Tidak ada temuan.", normal))
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO").upper()
        color = _SEV_COLORS.get(sev, colors.black)
        story.append(Paragraph(
            f"{i}. [{sev}] {f.get('title', '')}",
            ParagraphStyle(f"f{i}", parent=normal, textColor=color,
                           fontName="Helvetica-Bold"),
        ))
        story.append(Paragraph(
            f"<b>Endpoint:</b> {f.get('endpoint', '')}",
            small,
        ))
        story.append(Paragraph(f"<b>Detail:</b> {f.get('detail', '')}", normal))
        if f.get("evidence"):
            story.append(Paragraph(
                f"<b>Bukti:</b> <font size='8' face='Courier'>{f['evidence'][:1000]}</font>",
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
        story.append(Paragraph(f"• {r}", normal))

    doc.build(story)
