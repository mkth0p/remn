"""
The tab icons: the sidebar's mark (the letter R in the Gulax face on the accent colour), drawn
with Pillow into public/favicon.ico, favicon-32.png, favicon-192.png and apple-touch-icon.png.

    .venv\\Scripts\\python.exe frontend\\tools\\make_icons.py
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parent.parent
FONT = HERE / "public" / "fonts" / "gulax-regular.woff"
OUT = HERE / "public"
ACCENT = (27, 127, 102)  # --accent
INK = (255, 255, 255)


def mark(size: int) -> Image.Image:
    scale = 8  # draw large, shrink for smooth edges
    s = size * scale
    im = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    d.rounded_rectangle((0, 0, s - 1, s - 1), radius=int(s * 0.22), fill=ACCENT)
    font = ImageFont.truetype(str(FONT), int(s * 0.72))
    box = d.textbbox((0, 0), "R", font=font)
    w, h = box[2] - box[0], box[3] - box[1]
    d.text(((s - w) / 2 - box[0], (s - h) / 2 - box[1]), "R", font=font, fill=INK)
    return im.resize((size, size), Image.LANCZOS)


def main() -> None:
    OUT.mkdir(exist_ok=True)
    mark(32).save(OUT / "favicon-32.png", "PNG", optimize=True)
    mark(192).save(OUT / "favicon-192.png", "PNG", optimize=True)
    mark(180).save(OUT / "apple-touch-icon.png", "PNG", optimize=True)
    mark(48).save(OUT / "favicon.ico", "ICO", sizes=[(16, 16), (32, 32), (48, 48)])
    for name in ("favicon-32.png", "favicon-192.png", "apple-touch-icon.png", "favicon.ico"):
        print(name, (OUT / name).stat().st_size, "bytes")


if __name__ == "__main__":
    main()
