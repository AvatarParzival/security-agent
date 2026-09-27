"""
generate_icon.py
Generates assets/icon.ico using Pillow — run once before building the .exe.
No external images needed.
"""
import os
from PIL import Image, ImageDraw, ImageFont

SIZES = [16, 32,48, 64, 128, 256]
OUT_DIR = os.path.join(os.path.dirname(__file__), "assets")
os.makedirs(OUT_DIR, exist_ok=True)

BG_COLOR     = (13,  17,  23,  255)   # #0d1117
ACCENT_COLOR = (35, 134,  54,  255)   # #238636  IBM green
TEXT_COLOR   = (230, 237, 243, 255)   # #e6edf3

def draw_icon(size: int) -> Image.Image:
    img  = Image.new("RGBA", (size, size), BG_COLOR)
    draw = ImageDraw.Draw(img)

    # ── Shield shape ─────────────────────────────────────────────────────────
    m  = size * 0.08          # margin
    cx = size / 2
    # Shield polygon points (normalised)
    pts = [
        (cx,          m),              # top centre
        (size - m,    size * 0.28),    # top right
        (size - m,    size * 0.62),    # mid right
        (cx,          size - m),       # bottom point
        (m,           size * 0.62),    # mid left
        (m,           size * 0.28),    # top left
    ]
    draw.polygon(pts, fill=ACCENT_COLOR)

    # ── Lock body ─────────────────────────────────────────────────────────────
    lw  = size * 0.26
    lh  = size * 0.24
    lx  = cx - lw / 2
    ly  = size * 0.52
    r   = int(max(2, size * 0.04))
    draw.rounded_rectangle([lx, ly, lx + lw, ly + lh],
                            radius=r, fill=BG_COLOR)

    # ── Lock shackle (arc) ────────────────────────────────────────────────────
    sw   = lw * 0.55
    sx   = cx - sw / 2
    sy   = ly - lw * 0.42
    thick = max(2, int(size * 0.07))
    for t in range(thick):
        draw.arc([sx + t, sy + t,
                  sx + sw - t, sy + sw * 0.9 - t],
                 start=0, end=180,
                 fill=BG_COLOR, width=1)

    # Draw shackle as filled arc trick using rectangle masks
    shackle_box = [sx, sy, sx + sw, sy + sw * 0.9]
    draw.arc(shackle_box, start=0, end=180,
             fill=BG_COLOR, width=thick)

    return img


frames = [draw_icon(s) for s in SIZES]
icon_path = os.path.join(OUT_DIR, "icon.ico")
frames[0].save(
    icon_path,
    format="ICO",
    sizes=[(s, s) for s in SIZES],
    append_images=frames[1:],
)
print(f"[OK] Icon saved to: {icon_path}")
