#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""meshlet tray four-state icons - 16px variant export script (stdlib only, reproducible).

Background (2026-11 tray redesign, the user-approved four-state plan):
- The 32px masters `icon-{online,degraded,offline,error}.png` are committed
  (commit e9d67d4); **this script does not touch them**. Their geometry
  constants were back-solved by per-pixel sampling and recorded in the CONST
  section below.
- The Windows tray actually renders 16px at 100% DPI: `main.rs::icon_for_state`
  now prefers the `icon-<state>-16.png` produced by this script (falling back
  to the 32px master when the file is missing).
- Known defect: when the 32px hollow ring (offline) is downscaled by the
  system to 16px, the inner hole gets clogged with anti-aliasing residue and
  no longer reads as "empty". Fix = render 16px as its own image with the hole
  hand-enlarged for 16px vision (HOLE 0.266->0.28, feather 1px->0.5px for a
  sharper edge), so the native 1:1 render never goes through downscaling.
- The error glyph at 16px uses the classic carved-out exclamation mark
  (vertical slot + detached dot); the 32px master's slot shape is too thin at
  16px (<1.5px) to read - this is an intentional hand tweak.

Usage:
    python3 gen_icons.py            # generate the 4 icon-<state>-16.png files
    python3 gen_icons.py --verify   # generate + per-pixel assertions (hole transparent / ring continuous / color purity)

The artifacts are committed to the repo; after changing a geometry constant,
re-run this script to regenerate.
"""

import struct
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent

# ── geometry and palette (units: fraction of half side, 0..0.5; back-solved from sampling the committed 32px masters) ────
OUTER_R = 13.4 / 32          # outer circle radius ≈ 0.419
HOLE = {                      # inner hole radius
    "online":   5.0 / 32,     # filled disc + centre hole
    "degraded": 5.0 / 32,     # same hole + right edge cut back
    "offline":  8.5 / 32,     # hollow ring (widened to 4.5px by hand at 16px, see OFFLINE_16_HOLE)
    "error":    0.0,          # glyph is defined by EXCL
}
# 16px hand tweak: the offline hole is half a pixel larger than the even downscale
# (8.5/32*16=4.25px), so anti-aliasing residue cannot squeeze into it; feather tightens from 1px to 0.5px.
OFFLINE_16_HOLE = 4.5 / 16
FEATHER_16 = 0.5 / 16
# degraded bevel: flat right edge dx<=FX, corners with |dy|>FX clipped by a 45° diagonal
DEGRADED_CUT = 7.6 / 32
# error carved-out exclamation mark (16px scale, units in pixels): vertical slot + detached dot
EXCL_STEM = (7.0, 9.0, 3.2, 8.6)   # x0, x1(exclusive), y0, y1
EXCL_DOT = (7.0, 9.0, 10.2, 12.2)

COLORS = {
    "online":   (0x32, 0x60, 0x72),   # dark teal (matches the 32px master sample)
    "degraded": (0xC9, 0x7B, 0x2E),   # brand amber copper
    "offline":  (0x69, 0x6F, 0x74),   # mid grey
    "error":    (0xEF, 0x44, 0x44),   # red
}
STATES = ("online", "degraded", "offline", "error")


def _fill(dist: float, boundary: float, feather: float) -> float:
    """Coverage of the distance to boundary (1 inside), linear AA."""
    if feather <= 0:
        return 1.0 if dist < boundary else 0.0
    return max(0.0, min(1.0, (boundary - dist) / feather))


def coverage(state: str, x: float, y: float, size: int) -> float:
    """Shape coverage 0..1 at pixel center (x+0.5, y+0.5)."""
    s = size
    cx, cy = s / 2.0, s / 2.0
    dx, dy = x + 0.5 - cx, y + 0.5 - cy
    dist = (dx * dx + dy * dy) ** 0.5
    feather = FEATHER_16 * s  # 0.5px @16
    hole = HOLE[state] * s    # inner hole radius (pixels)
    if state == "offline":
        hole = OFFLINE_16_HOLE * s
    alpha = _fill(dist, OUTER_R * s, feather) * (1.0 - _fill(dist, hole, feather))
    if state == "degraded":
        # Bevel: flat right edge (dx <= fx) + 45° diagonal (corners beyond fx, fy are
        # clipped), matching the 32px master's "right apex flattened" shape (per-pixel sampling gives fx=fy≈7.5px@32).
        fx = DEGRADED_CUT * s
        over_dx = dx - fx
        over_dy = abs(dy) - fx
        if over_dx > 0 and over_dy > 0:
            alpha *= _fill(over_dx + over_dy, 0.0, feather)   # diagonal
        elif over_dx > 0:
            alpha *= _fill(over_dx, 0.0, feather)             # flat edge
    if state == "error":
        # Carved-out exclamation mark: vertical slot + detached dot (alpha inverted and combined)
        x0, x1, y0, y1 = EXCL_STEM
        in_stem = x0 <= x + 0.5 < x1 and y0 <= y + 0.5 < y1
        x0, x1, y0, y1 = EXCL_DOT
        in_dot = x0 <= x + 0.5 < x1 and y0 <= y + 0.5 < y1
        if in_stem or in_dot:
            alpha = 0.0
    return alpha


def render_rgba(state: str, size: int) -> bytes:
    rgb = COLORS[state]
    out = bytearray(size * size * 4)
    for y in range(size):
        for x in range(size):
            a = round(coverage(state, x, y, size) * 255)
            if a:
                i = (y * size + x) * 4
                out[i:i + 4] = bytes(rgb) + bytes([a])
    return bytes(out)


def write_png(path: Path, size: int, rgba: bytes) -> None:
    stride = size * 4
    raw = b"".join(b"\x00" + rgba[y * stride:(y + 1) * stride] for y in range(size))

    def chunk(type_: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + type_ + data
                + struct.pack(">I", zlib.crc32(type_ + data) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
                     + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def verify(size: int) -> None:
    """Per-pixel assertions (machine check of 16px legibility)."""
    c = size / 2.0
    for state in STATES:
        rgba = render_rgba(state, size)
        # 1) colour purity: every opaque pixel must be this state's colour (no stray residue allowed)
        for y in range(size):
            for x in range(size):
                r, g, b, a = rgba[(y * size + x) * 4:(y * size + x) * 4 + 4]
                if a and (r, g, b) != COLORS[state]:
                    raise AssertionError(f"{state}: stray color at ({x},{y})")
        # 2) per-state assertions
        if state == "offline":
            # inner hole centre fully transparent (residue clogging = failure)
            for y in range(size):
                for x in range(size):
                    if ((x + 0.5 - c) ** 2 + (y + 0.5 - c) ** 2) ** 0.5 < 3.2:
                        a = rgba[(y * size + x) * 4 + 3]
                        assert a == 0, f"offline: hole filled at ({x},{y}) alpha={a}"
            # ring closure: solid ring in all 8 directions at the band midpoint r≈5.6px
            import math
            for k in range(8):
                ang = k * math.pi / 4
                x = round(c + 5.6 * math.cos(ang) - 0.5)
                y = round(c + 5.6 * math.sin(ang) - 0.5)
                a = rgba[(y * size + x) * 4 + 3]
                assert a > 128, f"offline: ring broken at dir {k} ({x},{y}) alpha={a}"
        if state == "online":
            a = rgba[(int(c) * size + int(c)) * 4 + 3]
            assert a == 0, f"online: center hole missing (alpha={a})"
        if state == "error":
            # exclamation strokes carved through (transparent pixels in both slot and dot)
            for (x0, x1, y0, y1) in (EXCL_STEM, EXCL_DOT):
                sx, sy = int(x0), int((y0 + y1) / 2)
                assert rgba[(sy * size + sx) * 4 + 3] == 0, f"error: glyph not carved at {sx},{sy}"
        if state == "degraded":
            # right edge flattened: the middle row's rightmost column is ≥2px narrower than online's
            def right_edge(name):
                row = render_rgba(name, size)[(int(c) * size) * 4:(int(c) * size + 1) * size * 4]
                return max(x for x in range(size) if row[x * 4 + 3] > 128)
            assert right_edge("degraded") <= right_edge("online") - 2, "degraded: chamfer missing"
    print(f"verify OK: {len(STATES)} states @ {size}px")


def main() -> int:
    do_verify = "--verify" in sys.argv
    size = 16
    for state in STATES:
        rgba = render_rgba(state, size)
        path = HERE / f"icon-{state}-16.png"
        write_png(path, size, rgba)
        print(f"wrote {path.name} ({path.stat().st_size} bytes)")
    if do_verify:
        verify(size)
    return 0


if __name__ == "__main__":
    sys.exit(main())
