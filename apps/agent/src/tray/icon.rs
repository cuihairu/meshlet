//! 图标渲染：四态轮廓几何＋状态色＋尺寸。渲染在 16/24px **原生 1:1** 进行
//! （不经过缩放，避免 gen_icons.py 记录的「32px 缩到 16px 内孔被抗锯齿残渣
//! 填塞」缺陷）；几何与色值逐项对齐已过审的四态 PNG 设计（32px 主图
//! `icon-{online,degraded,offline,error}.png` 的六边形语形＋`gen_icons.py` 的
//! 16px 可读性微调：offline 内孔放大、feather 收紧到 0.5px），不使用品牌 logo
//! 代餐——仓内 [logo.svg](../../../../logo.svg) 的主形是分层透镜多边形，细节在
//! 16px 下会糊。颜色只是第二通道，四态**轮廓互不相同**（像素探针测试钉死）。

use super::state::TrayState;

/// 图标尺寸（用户口径：16/24px 下可辨）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconSize {
    Px16,
    Px24,
}

impl IconSize {
    pub fn px(self) -> u32 {
        match self {
            IconSize::Px16 => 16,
            IconSize::Px24 => 24,
        }
    }
}

impl TrayState {
    /// 渲染为 RGBA 像素缓冲（每像素 4 字节，Y 从上到下）。
    pub fn icon_rgba(self, size: IconSize) -> (u32, u32, Vec<u8>) {
        let side = size.px() as usize;
        let mut rgba = vec![0u8; side * side * 4];
        for y in 0..side {
            for x in 0..side {
                let (dx, dy) = (
                    (x as f32 + 0.5) / side as f32 - 0.5,
                    (y as f32 + 0.5) / side as f32 - 0.5,
                );
                let alpha = (self.coverage(dx, dy, FEATHER) * 255.0) as u8;
                if alpha == 0 {
                    continue;
                }
                let (r, g, b) = rgb(self);
                let px = (y * side + x) * 4;
                rgba[px] = r;
                rgba[px + 1] = g;
                rgba[px + 2] = b;
                rgba[px + 3] = alpha;
            }
        }
        (size.px(), size.px(), rgba)
    }

    /// 形状覆盖率（0..=1）。六边形语形（尖顶正六边形，单位=全边长）：
    /// online/degraded = 螺母（外形＋内切孔），degraded 另加右缘削角；
    /// offline = 空心六边环；error = 螺母再挖有界感叹号槽（孔下延伸、底缘留实）。
    fn coverage(&self, dx: f32, dy: f32, feather: f32) -> f32 {
        let (outer, hole) = match self {
            TrayState::Offline => (OUTER_R, OFFLINE_HOLE_R),
            _ => (HEX_R, HOLE_R),
        };
        let mut alpha = hex_fill(dx, dy, outer, feather) * (1.0 - hex_fill(dx, dy, hole, feather));
        if *self == TrayState::TunnelOnly {
            // 右缘削角（gen_icons.py DEGRADED_CUT 的连续化）：|dy| ≤ CUT 段为
            // 竖直平边，|dy| > CUT 段边界按 45° 收进。此前「双超界区域恒乘 0」
            // 的分支写法切出的是直角缺口而非斜边（审核发现）。
            let cut = DEGRADED_CUT - (dy.abs() - DEGRADED_CUT).max(0.0);
            alpha *= fill(dx, cut, feather);
        }
        if *self == TrayState::TunnelDrift
            && (0.0..SLOT_BOTTOM).contains(&dy)
            && dx.abs() < SLOT_HALF
        {
            // 感叹号有界挖槽（32px 主图同形）：槽内挖空，底缘留实；硬边界挖空
            // （gen_icons.py 的挖槽即硬矩形——2px 细槽经线性 AA 只剩残影，
            // 16px 档不可辨）。
            alpha = 0.0;
        }
        alpha
    }
}

/// 状态色（第二通道；主通道是形状轮廓）。
// 2026-11 四态重设计（tray-app PNG 采样）：青 / 铜削角 / 灰环 / 红感叹号。
fn rgb(state: TrayState) -> (u8, u8, u8) {
    match state {
        TrayState::Online => (0x32, 0x60, 0x72),
        TrayState::TunnelOnly => (0xC9, 0x7B, 0x2E),
        TrayState::TunnelDrift => (0xEF, 0x44, 0x44),
        TrayState::Offline => (0x69, 0x6F, 0x74),
    }
}

/// 尖顶正六边形覆盖率：竖边（|dx| ≤ R·√3/2）与四条斜边（|dy|＋|dx|/√3 ≤ R）
/// 两个约束的覆盖率取小。
fn hex_fill(dx: f32, dy: f32, r: f32, feather: f32) -> f32 {
    let flat = fill(dx.abs(), r * SQRT_3 / 2.0, feather);
    let diag = fill(dy.abs() + dx.abs() / SQRT_3, r, feather);
    flat.min(diag)
}

// ── 已过审四态设计的渲染参数（单位=全边长 0..0.5，与 gen_icons.py 同口径）──

/// 六边形外接圆半径（尖顶正六边形，顶点朝上下；32px 主图语形）。
const HEX_R: f32 = 0.44;
/// offline 空心环的外圈半径（略小于 HEX_R，与 32px 主图一致）。
const OUTER_R: f32 = 13.4 / 32.0;
/// online/degraded/error 的内切六边形孔半径。
const HOLE_R: f32 = 5.0 / 32.0;
/// offline 空心环内孔：16px 档手工放大（gen_icons.py OFFLINE_16_HOLE 同款微调，
/// 抗锯齿残渣挤不进孔）。
const OFFLINE_HOLE_R: f32 = 4.5 / 16.0;
/// degraded 削角：右缘平边 dx ≤ CUT，|dy| > CUT 的角走 45° 斜边切掉。
const DEGRADED_CUT: f32 = 7.6 / 32.0;
/// error 感叹号挖槽：半宽与槽底（自孔心向下、止于外形内——底缘留实，32px 主图
/// 同形：槽口只开到直边带下缘，下方锥形留实）。槽上端没入内孔——任何 ≤ 孔沿的
/// 起点都渲染同一张图，「槽与孔连通」才是设计意图，故不设槽顶常数。
const SLOT_HALF: f32 = 0.06;
const SLOT_BOTTOM: f32 = 0.25;
/// 抗锯齿过渡带（全边长单位）：16px 时 0.5px、24px 时 0.75px——gen_icons.py
/// 16px 档的收紧微调按比例外推。
const FEATHER: f32 = 0.5 / 16.0;
const SQRT_3: f32 = 1.732_050_8;

/// 到边界 `boundary` 的覆盖率（dist < boundary 为内）。
fn fill(dist: f32, boundary: f32, feather: f32) -> f32 {
    ((boundary - dist) / feather).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::super::state::all_states;
    use super::*;

    /// 探针像素坐标（相对全边长比例 → 像素），用于钉死四态轮廓互不相同。
    fn probe_px(fraction: f32, size: IconSize) -> usize {
        ((fraction * size.px() as f32).round() as usize).min(size.px() as usize - 1)
    }

    fn alpha_at(state: TrayState, size: IconSize, x: usize, y: usize) -> u8 {
        let (_, _, rgba) = state.icon_rgba(size);
        rgba[(y * size.px() as usize + x) * 4 + 3]
    }

    /// 轮廓签名：中心 / 体带 / 削角带 / 挖槽带 四点。
    ///
    /// - 中心：online/degraded/error 的内切孔、offline 的环孔 → 全空。
    /// - 体带（0.68 边长处）：孔外、外界内 → 三态实心、offline 仍在环孔内。
    /// - 削角带（0.75 边长处）：degraded 已被右缘削平 → 仅它为空。
    /// - 挖槽带（中列 0.71 边长处，孔下、槽底上的槽段内）：error 的感叹号
    ///   挖槽挖空、offline 仍在环孔内 → 两态为空。
    fn signature(state: TrayState, size: IconSize) -> [bool; 4] {
        let mid = (size.px() as usize - 1) / 2;
        let points = [
            (mid, mid),
            (probe_px(0.68, size), mid),
            (probe_px(0.75, size), mid),
            (mid, probe_px(0.71, size)),
        ];
        points.map(|(x, y)| alpha_at(state, size, x, y) > 127)
    }

    #[test]
    fn tray_state_silhouettes_are_pairwise_distinct() {
        // 颜色是第二通道：形状签名逐态钉死已过审设计（commit e9d67d4 的六边形语形：
        // 螺母 / 削角螺母 / 空心环 / 挖槽感叹号），且在两个尺寸下都成立。
        let expected = [
            (TrayState::Online, [false, true, true, true]),
            (TrayState::TunnelOnly, [false, true, false, true]),
            (TrayState::TunnelDrift, [false, true, true, false]),
            (TrayState::Offline, [false, false, true, false]),
        ];
        for size in [IconSize::Px16, IconSize::Px24] {
            for (state, sig) in expected {
                assert_eq!(
                    signature(state, size),
                    sig,
                    "{state:?} silhouette drifted from the approved design at {size:?}"
                );
            }
            let states = all_states();
            let sigs: Vec<_> = states.iter().map(|s| signature(*s, size)).collect();
            for i in 0..sigs.len() {
                for j in (i + 1)..sigs.len() {
                    assert_ne!(
                        sigs[i], sigs[j],
                        "at {size:?}: {:?} and {:?} must have different silhouettes",
                        states[i], states[j]
                    );
                }
            }
        }
    }

    #[test]
    fn offline_ring_is_hollow_in_the_middle_and_closed_around() {
        for size in [IconSize::Px16, IconSize::Px24] {
            let s = size.px() as usize;
            let (_, _, rgba) = TrayState::Offline.icon_rgba(size);
            // 孔内（六边形口径，留 2px feather 余量）必须全透明——抗锯齿残渣
            // 填塞即失败（gen_icons.py --verify 同款断言）。
            for y in 0..s {
                for x in 0..s {
                    let dx = (x as f32 + 0.5) / s as f32 - 0.5;
                    let dy = (y as f32 + 0.5) / s as f32 - 0.5;
                    if hex_fill(dx, dy, OFFLINE_HOLE_R - 2.0 * FEATHER, FEATHER) > 0.0 {
                        assert_eq!(
                            rgba[(y * s + x) * 4 + 3],
                            0,
                            "offline hole filled at ({x},{y})"
                        );
                    }
                }
            }
            // 环闭合：8 个方向在环带中点都有实环。
            for k in 0..8 {
                let ang = k as f32 * std::f32::consts::FRAC_PI_4;
                let (ux, uy) = (ang.cos(), ang.sin());
                let t_in = hex_boundary_t(ux, uy, OFFLINE_HOLE_R);
                let t_out = hex_boundary_t(ux, uy, OUTER_R);
                let t_mid = (t_in + t_out) / 2.0;
                let c = s as f32 / 2.0;
                let x = ((c + ux * t_mid * s as f32 - 0.5).round() as usize).min(s - 1);
                let y = ((c + uy * t_mid * s as f32 - 0.5).round() as usize).min(s - 1);
                assert!(
                    alpha_at(TrayState::Offline, size, x, y) > 200,
                    "offline ring broken at direction {k} ({x},{y})"
                );
            }
        }
    }

    /// 沿方向 (ux, uy) 六边形边界的距离（单位=全边长）。
    fn hex_boundary_t(ux: f32, uy: f32, r: f32) -> f32 {
        let diag = r / (uy.abs() + ux.abs() / SQRT_3);
        let flat = if ux.abs() > 1e-6 {
            r * SQRT_3 / 2.0 / ux.abs()
        } else {
            f32::INFINITY
        };
        diag.min(flat)
    }

    #[test]
    fn degraded_chamfer_clips_only_the_right_edge() {
        // 削角（gen_icons.py DEGRADED_CUT 模型）：中行右缘比 online 少 ≥2px，
        // 左缘与 online 逐像素同宽——削角只发生在右缘。
        for size in [IconSize::Px16, IconSize::Px24] {
            let s = size.px() as usize;
            let mid = (s - 1) / 2;
            let online = TrayState::Online.icon_rgba(size).2;
            let degraded = TrayState::TunnelOnly.icon_rgba(size).2;
            let edge = |rgba: &[u8], from_left: bool| {
                let range: Box<dyn Iterator<Item = usize>> = if from_left {
                    Box::new(0..s)
                } else {
                    Box::new((0..s).rev())
                };
                let mut it = range;
                it.find(|x| rgba[(mid * s + x) * 4 + 3] > 127).unwrap()
            };
            assert!(
                edge(&degraded, false) + 2 <= edge(&online, false),
                "degraded mid-row right edge must sit ≥2px left of online (chamfer missing)"
            );
            assert_eq!(
                edge(&degraded, true),
                edge(&online, true),
                "chamfer must not touch the left edge"
            );
        }
    }

    #[test]
    fn degraded_chamfer_has_a_45_degree_shoulder() {
        // 斜肩两侧各取一点（削角带同一列）：|dy| ≤ CUT 段是竖直平边，其下
        // 边界按 45° 收进——直角缺口写法（恒乘 0 的分支）会让「外侧点」与
        // 「内侧点」同值或整个角消失（审核发现）。
        // 每档坐标按几何手工选定：dx ≈ 0.19~0.22 边长的削角带列。
        let cases = [
            (IconSize::Px16, 11usize, 4usize, 3usize), // (size, col, kept_row, cut_row)
            (IconSize::Px24, 16, 5, 4),
        ];
        for (size, col, kept_row, cut_row) in cases {
            assert!(
                alpha_at(TrayState::TunnelOnly, size, col, kept_row) > 127,
                "inside the 45° shoulder must stay solid ({size:?})"
            );
            assert_eq!(
                alpha_at(TrayState::TunnelOnly, size, col, cut_row),
                0,
                "outside the 45° shoulder must be cut ({size:?})"
            );
        }
    }

    #[test]
    fn error_glyph_carves_the_bounded_exclamation_slot() {
        // 有界挖槽（32px 主图同形）：孔下、槽底之间的槽段挖空；槽段侧缘之外
        // 与槽底之下（底缘留实）都是实的。offline 在该列仍处环孔内，为空。
        for size in [IconSize::Px16, IconSize::Px24] {
            let mid = (size.px() as usize - 1) / 2;
            let slot_y = probe_px(0.71, size);
            assert_eq!(
                alpha_at(TrayState::TunnelDrift, size, mid, slot_y),
                0,
                "slot must be carved at row {slot_y} ({size:?})"
            );
            // 槽侧缘之外（|dx| 超出半宽）实——钉住槽宽。
            let side_x = probe_px(0.60, size);
            assert!(
                alpha_at(TrayState::TunnelDrift, size, side_x, slot_y) > 127,
                "beside the slot must stay solid ({size:?})"
            );
            // 槽底之下实——钉住「底缘留实」（审核发现：槽不得挖穿底缘）。
            let below_y = probe_px(0.78, size);
            assert!(
                alpha_at(TrayState::TunnelDrift, size, mid, below_y) > 127,
                "slot must not cut through the bottom edge ({size:?})"
            );
            for other in [TrayState::Online, TrayState::TunnelOnly] {
                assert!(
                    alpha_at(other, size, mid, below_y) > 127,
                    "{other:?} must stay solid below the slot ({size:?})"
                );
            }
        }
    }

    #[test]
    fn design_constants_are_pinned_by_fixed_pixels_at_16px() {
        // 固定像素钉死几何常数（16px 显示档；审核发现：相对探针会随常数
        // 自适应，钉不住漂移）。每点注明钉住的参数。
        let mid = 7usize;
        let a = |state: TrayState, x: usize, y: usize| alpha_at(state, IconSize::Px16, x, y);
        let solid = |state: TrayState, x: usize, y: usize, what: &str| {
            assert!(a(state, x, y) > 127, "{what}: ({x},{y}) must be solid");
        };
        let empty = |state: TrayState, x: usize, y: usize, what: &str| {
            assert!(a(state, x, y) == 0, "{what}: ({x},{y}) must be empty");
        };
        // HEX_R=0.44：顶点方向 6.5px 实、7.5px 空（外接圆半径钉在二者之间）。
        solid(TrayState::Online, mid, 2, "HEX_R lower");
        empty(TrayState::Online, mid, 0, "HEX_R upper");
        // HOLE_R=0.156（2.5px@16）：孔内 1.5px 空、孔外 3.5px 实。
        empty(TrayState::Online, 6, mid, "HOLE_R inner");
        solid(TrayState::Online, 4, mid, "HOLE_R outer");
        // DEGRADED_CUT=0.2375（3.8px@16）：平边内 3.5px 实、平边外 5.5px 空。
        solid(TrayState::TunnelOnly, 11, mid, "CUT inner");
        empty(TrayState::TunnelOnly, 13, mid, "CUT outer");
        // SLOT_HALF=0.06（≈1px@16）、SLOT_BOTTOM=0.25（4px@16）：槽心空、
        // 槽侧 2.5px 实、槽底下 4.5px 实（底缘留实）。
        empty(TrayState::TunnelDrift, mid, 11, "slot carve");
        solid(TrayState::TunnelDrift, 9, 11, "slot half width");
        solid(
            TrayState::TunnelDrift,
            mid,
            12,
            "slot bottom keeps the edge",
        );
        // OFFLINE 环带：孔心空、环带 4.5px 实、外界外 6.5px 空。
        empty(TrayState::Offline, mid, mid, "offline hole");
        solid(TrayState::Offline, 3, mid, "offline ring band");
        empty(TrayState::Offline, 1, mid, "offline outer bound");
    }

    #[test]
    fn state_colors_match_the_approved_png_palette() {
        // 色值取自 tray-app 图标 PNG（gen_icons.py COLORS 表，与 32px 主图逐像素
        // 采样一致）；且渲染像素色纯：非透明像素只允许本档颜色。
        let palette = [
            (TrayState::Online, (0x32, 0x60, 0x72)),      // 深青
            (TrayState::TunnelOnly, (0xC9, 0x7B, 0x2E)),  // 品牌琥珀铜
            (TrayState::Offline, (0x69, 0x6F, 0x74)),     // 中灰
            (TrayState::TunnelDrift, (0xEF, 0x44, 0x44)), // 红
        ];
        for (state, expected) in palette {
            assert_eq!(rgb(state), expected, "{state:?} palette drift");
            for size in [IconSize::Px16, IconSize::Px24] {
                let (_, _, rgba) = state.icon_rgba(size);
                for px in rgba.as_chunks::<4>().0 {
                    if px[3] == 0 {
                        continue;
                    }
                    assert_eq!(
                        (px[0], px[1], px[2]),
                        expected,
                        "{state:?} stray color at {size:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn both_sizes_render() {
        for size in [IconSize::Px16, IconSize::Px24] {
            for state in all_states() {
                let (w, h, rgba) = state.icon_rgba(size);
                assert_eq!((w, h), (size.px(), size.px()));
                assert_eq!(rgba.len(), (w as usize) * (h as usize) * 4);
                // 每态至少有一个不透明像素（不是空图）。
                assert!(rgba.as_chunks::<4>().0.iter().any(|p| p[3] > 200));
            }
        }
    }
}
