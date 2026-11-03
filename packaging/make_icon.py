"""Generate the NetGuardian icon (run once, committed as a binary asset).

Usage:  python packaging/make_icon.py
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"
SCALE = 4
SIZE = 256


def _font(size: int) -> ImageFont.FreeTypeFont:
    candidates = [
        Path(r"C:\Windows\Fonts\segoeuib.ttf"),
        Path(r"C:\Windows\Fonts\seguisb.ttf"),
        Path(r"C:\Windows\Fonts\arialbd.ttf"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return ImageFont.truetype(str(candidate), size)
    return ImageFont.load_default()


def build() -> Image.Image:
    canvas = Image.new("RGBA", (SIZE * SCALE, SIZE * SCALE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(canvas)
    s = SCALE

    outer = [(128 * s, 14 * s), (233 * s, 52 * s), (233 * s, 132 * s), (128 * s, 243 * s), (23 * s, 132 * s), (23 * s, 52 * s)]
    inner = [(128 * s, 30 * s), (217 * s, 62 * s), (217 * s, 128 * s), (128 * s, 224 * s), (39 * s, 128 * s), (39 * s, 62 * s)]

    draw.polygon(outer, fill=(56, 189, 248, 255))
    draw.polygon(inner, fill=(11, 18, 32, 255))

    # faint inner accent line
    accent = [(128 * s, 44 * s), (203 * s, 72 * s), (203 * s, 124 * s), (128 * s, 208 * s), (53 * s, 124 * s), (53 * s, 72 * s)]
    draw.line(accent + [accent[0]], fill=(56, 189, 248, 90), width=2 * s)

    font = _font(84 * s)
    text = "NG"
    box = draw.textbbox((0, 0), text, font=font)
    width = box[2] - box[0]
    height = box[3] - box[1]
    draw.text(
        ((SIZE * s - width) / 2 - box[0], (SIZE * s - height) / 2 - box[1] - 6 * s),
        text,
        font=font,
        fill=(248, 250, 252, 255),
    )

    # three small link nodes under the monogram
    for offset, radius in ((-40, 5), (0, 6), (40, 5)):
        cx = (128 + offset) * s
        cy = 176 * s
        draw.ellipse([cx - radius * s, cy - radius * s, cx + radius * s, cy + radius * s], fill=(56, 189, 248, 255))

    return canvas.resize((SIZE, SIZE), Image.LANCZOS)


def main() -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    image = build()
    png = ASSETS / "netguardian.png"
    ico = ASSETS / "netguardian.ico"
    image.save(png, format="PNG")
    image.save(
        ico,
        format="ICO",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    print(f"wrote {png}")
    print(f"wrote {ico}")


if __name__ == "__main__":
    main()
