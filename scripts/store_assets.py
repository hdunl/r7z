"""Renders the Microsoft Store package's logos into package/store/Assets.

    python scripts/store_assets.py

Draws the same mark as gui/src/logo.rs (a graphite tile with an orange zipper) at each
size Windows asks for, instead of scaling one bitmap, so small icons stay sharp.
"""
from pathlib import Path

from PIL import Image

TILE = (0x1B, 0x1C, 0x21)
ACCENT = (0xFF, 0x6B, 0x2C)
OUT = Path(__file__).resolve().parent.parent / "package" / "store" / "Assets"


def rounded_rect_sd(x, y, x0, y0, x1, y1, rad):
    cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
    hx, hy = (x1 - x0) / 2 - rad, (y1 - y0) / 2 - rad
    dx, dy = abs(x - cx) - hx, abs(y - cy) - hy
    ox, oy = max(dx, 0.0), max(dy, 0.0)
    return (ox * ox + oy * oy) ** 0.5 + min(max(dx, dy), 0.0) - rad


def shapes():
    v = []
    for k in range(5):
        y = 0.2 + k * 0.105
        v.append((0.36, y, 0.52, y + 0.07) if k % 2 == 0 else (0.48, y, 0.64, y + 0.07))
    v.append((0.39, 0.74, 0.61, 0.84))
    return v


def mark(size, canvas=None):
    """The mark at `size` pixels, centred on a transparent `canvas` (default: same size)."""
    canvas = canvas or size
    img = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    px = img.load()
    off = (canvas - size) / 2
    s = float(size)
    for yi in range(canvas):
        for xi in range(canvas):
            x, y = xi + 0.5 - off, yi + 0.5 - off
            tile = min(max(0.5 - rounded_rect_sd(x, y, 0, 0, s, s, s * 0.23), 0.0), 1.0)
            if tile == 0:
                continue
            m = 0.0
            for r in shapes():
                d = rounded_rect_sd(x, y, r[0] * s, r[1] * s, r[2] * s, r[3] * s, s * 0.018)
                m = max(m, min(max(0.5 - d, 0.0), 1.0))
            c = tuple(int(TILE[i] * (1 - m) + ACCENT[i] * m) for i in range(3))
            px[xi, yi] = (*c, int(tile * 255))
    return img


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    # Tiles leave a margin around the mark, as Start shows them on a plate.
    for name, size, pad in [("Square150x150Logo", 150, 0.66), ("StoreLogo", 50, 1.0)]:
        for scale in (100, 200):
            px = size * scale // 100
            mark(round(px * pad), px).save(OUT / f"{name}.scale-{scale}.png")
    for scale in (100, 200):
        px = 44 * scale // 100
        mark(px).save(OUT / f"Square44x44Logo.scale-{scale}.png")
    # Taskbar, Start list and Explorer sizes, drawn without a plate behind them.
    for t in (16, 24, 32, 48, 256):
        img = mark(t)
        img.save(OUT / f"Square44x44Logo.targetsize-{t}.png")
        img.save(OUT / f"Square44x44Logo.targetsize-{t}_altform-unplated.png")
    print("\n".join(sorted(p.name for p in OUT.iterdir())))


if __name__ == "__main__":
    main()
