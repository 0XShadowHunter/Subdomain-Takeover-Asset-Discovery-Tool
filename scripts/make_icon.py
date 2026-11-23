"""Generate assets/icon_256.png + assets/logo.ico from the brand logo.

No third-party dependencies:
- The square render uses PowerShell/GDI+ (System.Drawing) — high-quality
  letterboxed resize onto the theme's dark background.
- The .ico container is written by hand: a Vista+ PNG-in-ICO entry (valid for
  sizes up to 256). PyInstaller consumes it with --icon.

Run:  .venv\\Scripts\\python.exe scripts\\make_icon.py
"""

from __future__ import annotations

import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOGO = ROOT / "assets" / "logo.png"
SQUARE = ROOT / "assets" / "icon_256.png"
ICO = ROOT / "assets" / "logo.ico"

SIZE = 256
# THEME["bg"] (#0b1220) — the letterbox blends into dark taskbars/docks.
BG_RGB = (11, 18, 32)

_RENDER_PS = f"""
Add-Type -AssemblyName System.Drawing
$src = [System.Drawing.Image]::FromFile('{LOGO.as_posix()}')
$bmp = New-Object System.Drawing.Bitmap {SIZE}, {SIZE}
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.InterpolationMode = 'HighQualityBicubic'
$g.Clear([System.Drawing.Color]::FromArgb(255, {BG_RGB[0]}, {BG_RGB[1]}, {BG_RGB[2]}))
$margin = 12
$scale = [Math]::Min(({SIZE} - 2 * $margin) / $src.Width, ({SIZE} - 2 * $margin) / $src.Height)
$w = [int]($src.Width * $scale)
$h = [int]($src.Height * $scale)
$g.DrawImage($src, [int](({SIZE} - $w) / 2), [int](({SIZE} - $h) / 2), $w, $h)
$bmp.Save('{SQUARE.as_posix()}', [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose()
$bmp.Dispose()
$src.Dispose()
"""


def render_square() -> None:
    subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", _RENDER_PS],
        check=True,
        timeout=60,
    )


def write_ico() -> None:
    """Wrap the 256x256 PNG in a minimal single-image ICO container."""
    png = SQUARE.read_bytes()
    # ICONDIR (reserved=0, type=1 icon, count=1) + ICONDIRENTRY:
    # width=0/height=0 mean 256; 1 plane, 32 bpp; data size + offset (6 + 16).
    icondir = struct.pack("<HHH", 0, 1, 1)
    entry = struct.pack("<BBBBHHII", 0, 0, 0, 0, 1, 32, len(png), 6 + 16)
    ICO.write_bytes(icondir + entry + png)


def main() -> int:
    if not LOGO.is_file():
        print(f"Brand logo not found: {LOGO}")
        return 1
    render_square()
    write_ico()
    print(f"Square icon: {SQUARE}")
    print(f"Windows icon: {ICO}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
