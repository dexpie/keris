"""Render output ANSI menjadi PNG bergaya terminal (untuk promosi).

Contoh:
    python -m keris scan http://127.0.0.1:8099 --hunt --chain --triage > scan.out 2>&1
    python tools/make_screenshot.py scan.out docs/screenshots/scan.png
"""

import os
import re
import sys

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    sys.exit("Pillow dibutuhkan: pip install pillow")

BG = (13, 15, 18)
FG = (200, 200, 200)
TITLEBAR = (24, 27, 32)
BORDER = (46, 50, 58)
PALETTE = {
    "0": (200, 200, 200),
    "1": (222, 56, 56),
    "2": (80, 200, 120),
    "3": (230, 190, 90),
    "4": (96, 160, 220),
    "5": (200, 120, 210),
    "6": (120, 200, 200),
    "7": (230, 230, 230),
    "90": (120, 120, 120),
    "91": (240, 80, 80),
    "92": (90, 220, 130),
    "93": (240, 200, 100),
    "94": (110, 175, 240),
    "95": (215, 130, 225),
    "96": (130, 215, 215),
}


def _font(size, bold=False):
    candidates = ["C:/Windows/Fonts/consolab.ttf" if bold else "C:/Windows/Fonts/consola.ttf",
                  "C:/Windows/Fonts/courbd.ttf" if bold else "C:/Windows/Fonts/cour.ttf"]
    for path in candidates:
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size)
            except Exception:
                continue
    return ImageFont.load_default()


ANSI = re.compile(r"\x1b\[([0-9;]*)m")


def parse_ansi(text):
    """Pecah teks menjadi list of (string, fg, bold)."""
    tokens = []
    fg = 0
    bold = False
    pos = 0
    for m in ANSI.finditer(text):
        if m.start() > pos:
            tokens.append((text[pos:m.start()], fg, bold))
        codes = [c for c in m.group(1).split(";") if c]
        for c in codes:
            if c == "0":
                fg, bold = 0, False
            elif c == "1":
                bold = True
            elif c.isdigit() and int(c) in (30, 31, 32, 33, 34, 35, 36, 37):
                fg = str(int(c) - 30)
            elif c.isdigit() and int(c) in (90, 91, 92, 93, 94, 95, 96, 97):
                fg = c
        pos = m.end()
    if pos < len(text):
        tokens.append((text[pos:], fg, bold))
    return tokens


def render(text, out_path, title="keris - terminal", font_size=15, pad=18):
    font = _font(font_size)
    bold_font = _font(font_size, bold=True)
    ch = font.getbbox("X")[3] - font.getbbox("X")[1] + 2

    # hitung lebar dari token terpanjang (dengan strip warna)
    lines = text.splitlines()
    lines = lines or [""]
    max_cols = 1
    for line in lines:
        plain = ANSI.sub("", line).replace("\t", "    ")
        max_cols = max(max_cols, len(plain))
    width = pad * 2 + int(max_cols * font_size * 0.6)
    height = pad * 2 + len(lines) * ch + 40

    img = Image.new("RGB", (width, height), BG)
    d = ImageDraw.Draw(img)

    # title bar
    d.rectangle([0, 0, width, 36], fill=TITLEBAR)
    d.rectangle([0, 36, width, 38], fill=BORDER)
    for i, color in enumerate((222, 56, 56, 90, 220, 130, 240, 200, 100)):
        d.ellipse([pad + i * 22, 11, pad + i * 22 + 14, 25], fill=color)
    d.text((pad + 76, 10), title, font=_font(14, bold=True), fill=(230, 230, 230))

    y = 50
    for line in lines:
        x = pad
        for token, fg, bold in parse_ansi(line):
            if not token:
                continue
            color = PALETTE.get(str(fg), FG) if fg else FG
            if bold:
                color = tuple(min(255, c + 30) for c in color)
            d.text((x, y), token, font=bold_font if bold else font, fill=color)
            x += d.textlength(token, font=bold_font if bold else font)
        y += ch

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    img.save(out_path)
    print(f"saved: {out_path} ({width}x{height})")


if __name__ == "__main__":
    src, dst = sys.argv[1], sys.argv[2]
    title = sys.argv[3] if len(sys.argv) > 3 else "keris - terminal"
    with open(src, "r", encoding="utf-8", errors="replace") as f:
        render(f.read(), dst, title=title)
