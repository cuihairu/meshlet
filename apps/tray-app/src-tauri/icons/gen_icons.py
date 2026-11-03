#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""meshlet 托盘四态图标 · 16px 变体导出脚本（仅标准库，可复现）。

背景（2026-11 托盘重设计，用户批准的四态方案）：
- 32px 主图 `icon-{online,degraded,offline,error}.png` 已提交（commit e9d67d4），
  **本脚本不改动它们**；其几何常数经逐像素采样反向记录在下方 CONST 区。
- Windows 托盘 100% DPI 的实际显示尺寸是 16px：主循环 `main.rs::icon_for_state`
  现在优先加载本脚本产出的 `icon-<state>-16.png`（缺失时回落 32px 原图）。
- 已知缺陷：32px 空心环（offline）被系统缩小到 16px 时，内孔被抗锯齿残渣
  填塞、读不出「空」。对策 = 16px 独立成图、内孔按 16px 视觉手工放大
  （HOLE 0.266→0.28，feather 1px→0.5px 更锐），原生 1:1 渲染不再经过缩小。
- error 的字形在 16px 采用经典「挖空感叹号」（竖槽+分离点）；32px 主图的
  槽形在 16px 过细（<1.5px）不可辨，属有意的手工微调。

用法：
    python3 gen_icons.py            # 生成 4 个 icon-<state>-16.png
    python3 gen_icons.py --verify   # 生成 + 逐像素断言（内孔透明/环连续/色纯）

产物随仓库提交；改几何常数后重跑本脚本即可再生成。
"""

import struct
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent

# ── 几何与色板（单位：相对半边长 0..0.5；由已提交 32px 主图采样反推）────
OUTER_R = 13.4 / 32          # 外圆半径 ≈ 0.419
HOLE = {                      # 内孔半径
    "online":   5.0 / 32,     # 实心 + 中心圆孔
    "degraded": 5.0 / 32,     # 同孔 + 右侧削角
    "offline":  8.5 / 32,     # 空心环（16px 手工放大到 4.5px，见 OFFLINE_16_HOLE）
    "error":    0.0,          # 字形用 EXCL 定义
}
# 16px 手工微调：offline 内孔比等比缩小（8.5/32*16=4.25px）再放大半像素，
# 抗锯齿残渣挤不进孔内；feather 由 1px 收紧到 0.5px。
OFFLINE_16_HOLE = 4.5 / 16
FEATHER_16 = 0.5 / 16
# degraded 削角：右缘平边 dx<=FX，|dy|>FX 的角走 45° 斜边切掉
DEGRADED_CUT = 7.6 / 32
# error 挖空感叹号（16px 口径，单位像素）：竖槽 + 分离点
EXCL_STEM = (7.0, 9.0, 3.2, 8.6)   # x0, x1(开区间), y0, y1
EXCL_DOT = (7.0, 9.0, 10.2, 12.2)

COLORS = {
    "online":   (0x32, 0x60, 0x72),   # 深青（与 32px 主图采样一致）
    "degraded": (0xC9, 0x7B, 0x2E),   # 品牌琥珀铜
    "offline":  (0x69, 0x6F, 0x74),   # 中灰
    "error":    (0xEF, 0x44, 0x44),   # 红
}
STATES = ("online", "degraded", "offline", "error")


def _fill(dist: float, boundary: float, feather: float) -> float:
    """到边界 boundary 的覆盖率（内侧为 1），线性 AA。"""
    if feather <= 0:
        return 1.0 if dist < boundary else 0.0
    return max(0.0, min(1.0, (boundary - dist) / feather))


def coverage(state: str, x: float, y: float, size: int) -> float:
    """点 (x+0.5, y+0.5) 的形状覆盖率 0..1。"""
    s = size
    cx, cy = s / 2.0, s / 2.0
    dx, dy = x + 0.5 - cx, y + 0.5 - cy
    dist = (dx * dx + dy * dy) ** 0.5
    feather = FEATHER_16 * s  # 0.5px @16
    hole = HOLE[state] * s    # 内孔半径（像素）
    if state == "offline":
        hole = OFFLINE_16_HOLE * s
    alpha = _fill(dist, OUTER_R * s, feather) * (1.0 - _fill(dist, hole, feather))
    if state == "degraded":
        # 削角：右缘平边（dx ≤ fx）+ 45° 斜角（fx, fy 之外的角切掉），
        # 与 32px 主图「右侧顶点削平」同形（逐像素采样反推 fx=fy≈7.5px@32）。
        fx = DEGRADED_CUT * s
        over_dx = dx - fx
        over_dy = abs(dy) - fx
        if over_dx > 0 and over_dy > 0:
            alpha *= _fill(over_dx + over_dy, 0.0, feather)   # 斜角
        elif over_dx > 0:
            alpha *= _fill(over_dx, 0.0, feather)             # 平边
    if state == "error":
        # 挖空感叹号：竖槽 + 分离点（alpha 取反合并）
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
    """逐像素断言（16px 可读性的机器验证）。"""
    c = size / 2.0
    for state in STATES:
        rgba = render_rgba(state, size)
        # 1) 色纯：每个非透明像素必须是本档颜色（不许出现杂色残渣）
        for y in range(size):
            for x in range(size):
                r, g, b, a = rgba[(y * size + x) * 4:(y * size + x) * 4 + 4]
                if a and (r, g, b) != COLORS[state]:
                    raise AssertionError(f"{state}: stray color at ({x},{y})")
        # 2) 档位特有断言
        if state == "offline":
            # 内孔中心全透明（残渣填塞即失败）
            for y in range(size):
                for x in range(size):
                    if ((x + 0.5 - c) ** 2 + (y + 0.5 - c) ** 2) ** 0.5 < 3.2:
                        a = rgba[(y * size + x) * 4 + 3]
                        assert a == 0, f"offline: hole filled at ({x},{y}) alpha={a}"
            # 环闭合：8 个方向在环带中点 r≈5.6px 处都有实环
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
            # 感叹号笔画挖穿（槽+点各有透明像素）
            for (x0, x1, y0, y1) in (EXCL_STEM, EXCL_DOT):
                sx, sy = int(x0), int((y0 + y1) / 2)
                assert rgba[(sy * size + sx) * 4 + 3] == 0, f"error: glyph not carved at {sx},{sy}"
        if state == "degraded":
            # 右缘削平：中行最右像素所在列比 online 少 ≥2px
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
