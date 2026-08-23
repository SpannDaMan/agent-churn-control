#!/usr/bin/env python3
"""Render the deterministic Anti-Churn store screenshot."""

from __future__ import annotations

from pathlib import Path
from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "plugins" / "agent-churn-control" / "assets"
OUT = ASSETS / "screenshot1.png"


def font(name: str, size: int) -> ImageFont.FreeTypeFont:
    path = Path("C:/Windows/Fonts") / name
    if path.exists():
        return ImageFont.truetype(str(path), size=size)
    return ImageFont.truetype("DejaVuSans.ttf", size=size)


def rounded(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], radius: int, fill: str, outline: str | None = None, width: int = 1) -> None:
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def main() -> int:
    canvas = Image.new("RGB", (1600, 1000), "#F6F9FC")
    draw = ImageDraw.Draw(canvas)
    ink = "#0F1B33"
    slate = "#5B6B7A"
    navy = "#061A5B"
    blue = "#0A6CFF"
    cyan = "#22D3EE"

    icon = Image.open(ASSETS / "logo.png").convert("RGBA")
    icon.thumbnail((150, 150), Image.Resampling.LANCZOS)
    canvas.paste(icon, (108, 92), icon)

    rounded(draw, (108, 274, 310, 318), 22, "#E6F0FF")
    draw.text((132, 282), "DEVELOPER TOOL", font=font("seguisb.ttf", 20), fill=blue)
    draw.text((108, 350), "Stop duplicate", font=font("segoeuib.ttf", 72), fill=ink)
    draw.text((108, 426), "agent work", font=font("segoeuib.ttf", 72), fill=ink)
    draw.text((108, 542), "Reuse accepted evidence.", font=font("segoeui.ttf", 32), fill=slate)
    draw.text((108, 588), "Keep changed work moving.", font=font("segoeui.ttf", 32), fill=slate)

    rounded(draw, (108, 710, 650, 790), 18, "#FFFFFF", "#D7E0EB", 2)
    draw.ellipse((138, 736, 164, 762), fill=cyan)
    draw.text((184, 730), "Local · No account · No API key · No telemetry", font=font("segoeui.ttf", 23), fill=navy)
    draw.text((108, 870), "ORBRAL", font=font("seguisb.ttf", 24), fill=navy)

    rounded(draw, (790, 90, 1492, 910), 28, "#FFFFFF", "#D7E0EB", 2)
    draw.text((850, 142), "Decision preview", font=font("segoeuib.ttf", 32), fill=ink)
    draw.text((850, 190), "One local check before another agent pass.", font=font("segoeui.ttf", 24), fill=slate)

    rows = [
        ("Run first action", "BYPASS", "No prior equivalent evidence", blue),
        ("Reuse prior evidence", "ENFORCE", "Accepted proof already exists", navy),
        ("Allow changed work", "OBSERVE", "Typed invalidation verified", cyan),
    ]
    y = 270
    for label, state, reason, color in rows:
        rounded(draw, (850, y, 1432, y + 126), 18, "#F8FAFD", "#E1E7EF", 2)
        draw.ellipse((882, y + 42, 914, y + 74), fill=color)
        draw.text((938, y + 25), label, font=font("seguisb.ttf", 27), fill=ink)
        draw.text((938, y + 66), reason, font=font("segoeui.ttf", 21), fill=slate)
        tw = draw.textbbox((0, 0), state, font=font("seguisb.ttf", 18))[2]
        rounded(draw, (1395 - tw, y + 38, 1420, y + 80), 16, "#EAF2FF")
        draw.text((1407 - tw, y + 48), state, font=font("seguisb.ttf", 18), fill=navy)
        y += 154

    rounded(draw, (850, 752, 1432, 848), 18, "#071A4A")
    draw.text((884, 775), "evidence reused  •  private receipt  •  cost unknown", font=font("consola.ttf", 18), fill="#DDEBFF")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    canvas.save(OUT, format="PNG", optimize=True)
    print(OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
