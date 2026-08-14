"""Generate promo card bergaya terminal untuk Twitter/X (1200x675)."""

import os
import sys

from PIL import Image, ImageDraw, ImageFont

W, H = 1200, 675
BG = (10, 12, 15)
CARD = (18, 22, 28)
BORDER = (46, 50, 58)
GOLD = (212, 162, 78)
FG = (226, 228, 232)
DIM = (150, 155, 165)
RED = (240, 80, 80)
GREEN = (90, 220, 130)


def _font(size, bold=False):
    p = "C:/Windows/Fonts/consolab.ttf" if bold else "C:/Windows/Fonts/consola.ttf"
    return ImageFont.truetype(p, size) if os.path.exists(p) else ImageFont.load_default()


def draw_keris(d, cx, cy, scale=1.0, color=GOLD):
    pts = [
        (0, -52), (4, -30), (10, -16), (14, -8), (22, 0), (18, 4), (10, 2),
        (6, 10), (2, 20), (0, 34), (-2, 20), (-6, 10), (-10, 2), (-18, 4),
        (-22, 0), (-14, -8), (-10, -16), (-4, -30),
    ]
    poly = [(cx + x * scale, cy + y * scale) for x, y in pts]
    d.polygon(poly, outline=color, width=3)
    d.line([(cx, cy + 34 * scale), (cx, cy + 46 * scale)], fill=color, width=3)
    d.rectangle([cx - 3 * scale, cy + 46 * scale, cx + 3 * scale, cy + 58 * scale], fill=color)


def render_card(out_path):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # panel atas
    d.rectangle([0, 0, W, 6], fill=GOLD)
    d.rectangle([70, 90, 1130, 585], fill=CARD, outline=BORDER, width=2)

    # keris emblem + nama
    draw_keris(d, 180, 190, 2.2)
    d.text((290, 120), "keris", font=_font(72, bold=True), fill=FG)
    d.text((290, 210), "WEB PENTEST TOOLKIT", font=_font(26, bold=True), fill=GOLD)

    # tagline
    d.text((290, 265), "Satu URL masuk, seluruh pekerjaan selesai.", font=_font(22), fill=FG)
    d.text((290, 300), "recon -> discovery -> vuln scan -> report", font=_font(20), fill=DIM)

    # fitur (dua kolom)
    feats = [
        ("scan --pwn", "semua modul sekaligus"),
        ("hunt", "credential hunting + .git dump"),
        ("credcheck", "bukti login valid"),
        ("dos --hammer", "slowloris + flood serentak"),
        ("chain + triage", "attack chain + AI summary"),
        ("ticketing", "auto lapor ke GitHub/Jira"),
    ]
    x0, x1 = 150, 620
    y = 350
    for i, (cmd, desc) in enumerate(feats):
        col = x0 if i % 2 == 0 else x1
        row = y + (i // 2) * 70
        d.text((col, row), cmd, font=_font(19, bold=True), fill=GREEN)
        d.text((col + 195, row), desc, font=_font(19), fill=FG)

    # baris install
    d.rectangle([70, 560, 1130, 600], fill=(24, 28, 34))
    d.text((100, 570), "$ pip install keris-toolkit", font=_font(20, bold=True), fill=GOLD)
    d.text((560, 570), "github.com/dexpie/keris", font=_font(20, bold=True), fill=FG)

    # footer warning
    d.text((70, 615), "authorized testing only - brutal tool, user bertanggung jawab penuh",
           font=_font(17), fill=RED)

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    img.save(out_path)
    print(f"saved: {out_path} ({W}x{H})")


if __name__ == "__main__":
    render_card(sys.argv[1] if len(sys.argv) > 1 else "docs/screenshots/keris_card.png")
