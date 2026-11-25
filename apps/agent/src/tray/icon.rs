//! Icon rendering: four-state silhouette geometry + state colors + sizes. Rendering happens at
//! 16/24px **native 1:1** (no scaling, avoiding the gen_icons.py-recorded defect where "downscaling
//! 32px to 16px left the inner hole clogged by anti-aliasing residue"); geometry and colors align
//! item-by-item with the approved four-state PNG design (the hexagon language of the 32px masters
//! `icon-{online,degraded,offline,error}.png` plus `gen_icons.py`'s 16px readability tweaks: enlarged
//! offline inner hole, feather tightened to 0.5px). The brand logo is not used as a stand-in —
//! the main shape of in-repo [logo.svg](../../../../logo.svg) is a layered lens polygon whose detail blurs at 16px. Color is only a second channel; the four silhouettes are **pairwise distinct** (pinned by a pixel-probe test).

use super::state::TrayState;

/// Icon sizes (user requirement: legible at 16/24px).
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
    /// Render to an RGBA pixel buffer (4 bytes per pixel, Y top to bottom).
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

    /// Shape coverage (0..=1). Hexagon language (pointy-top regular hexagon, unit = full side length):
    /// online/degraded = nut (outline + inscribed hole), degraded adds a right-edge chamfer;
    /// offline = hollow hex ring; error = nut with a bounded exclamation slot carved out (extends below the hole, the bottom edge stays solid).
    fn coverage(&self, dx: f32, dy: f32, feather: f32) -> f32 {
        let (outer, hole) = match self {
            TrayState::Offline => (OUTER_R, OFFLINE_HOLE_R),
            _ => (HEX_R, HOLE_R),
        };
        let mut alpha = hex_fill(dx, dy, outer, feather) * (1.0 - hex_fill(dx, dy, hole, feather));
        if *self == TrayState::TunnelOnly {
            // Right-edge chamfer (a continuous version of gen_icons.py's DEGRADED_CUT): for |dy| ≤ CUT
            // the boundary is a vertical flat edge; for |dy| > CUT it recedes at 45°. The earlier
            // "multiply by 0 whenever both exceed bounds" branch cut a right-angle notch instead of a slanted edge (found in review).
            let cut = DEGRADED_CUT - (dy.abs() - DEGRADED_CUT).max(0.0);
            alpha *= fill(dx, cut, feather);
        }
        if *self == TrayState::TunnelDrift
            && (0.0..SLOT_BOTTOM).contains(&dy)
            && dx.abs() < SLOT_HALF
        {
            // Bounded exclamation slot (same shape as the 32px master): carved out inside, the bottom
            // edge stays solid; the carve uses a hard boundary (gen_icons.py's slot is a hard rectangle —
            // after linear AA a 2px slot leaves only a ghost, illegible at 16px).
            alpha = 0.0;
        }
        alpha
    }
}

/// State colors (second channel; the primary channel is the shape silhouette).
// 2026-11 four-state redesign (sampled from the tray-app PNGs): teal / copper chamfer / gray ring / red exclamation.
fn rgb(state: TrayState) -> (u8, u8, u8) {
    match state {
        TrayState::Online => (0x32, 0x60, 0x72),
        TrayState::TunnelOnly => (0xC9, 0x7B, 0x2E),
        TrayState::TunnelDrift => (0xEF, 0x44, 0x44),
        TrayState::Offline => (0x69, 0x6F, 0x74),
    }
}

/// Pointy-top regular hexagon coverage: take the smaller of the coverage from the vertical edges
/// (|dx| ≤ R·√3/2) and the four slanted edges (|dy| + |dx|/√3 ≤ R).
fn hex_fill(dx: f32, dy: f32, r: f32, feather: f32) -> f32 {
    let flat = fill(dx.abs(), r * SQRT_3 / 2.0, feather);
    let diag = fill(dy.abs() + dx.abs() / SQRT_3, r, feather);
    flat.min(diag)
}

// ── Rendering parameters of the approved four-state design (unit = full side length 0..0.5, same scale as gen_icons.py) ──

/// Hexagon circumradius (pointy-top regular hexagon, vertices up/down; 32px master language).
const HEX_R: f32 = 0.44;
/// Outer radius of the offline hollow ring (slightly below HEX_R, matching the 32px master).
const OUTER_R: f32 = 13.4 / 32.0;
/// Inscribed hexagon hole radius for online/degraded/error.
const HOLE_R: f32 = 5.0 / 32.0;
/// Offline hollow-ring inner hole: manually enlarged at 16px (same tweak as gen_icons.py's
/// OFFLINE_16_HOLE, so anti-aliasing residue cannot crowd into the hole).
const OFFLINE_HOLE_R: f32 = 4.5 / 16.0;
/// Degraded chamfer: right-edge flat for dx ≤ CUT; corners with |dy| > CUT are cut off along a 45° slant.
const DEGRADED_CUT: f32 = 7.6 / 32.0;
/// Error exclamation slot: half-width and slot bottom (down from the hole center, ending inside the
/// outline — the bottom edge stays solid, same shape as the 32px master: the slot only opens down to
/// the lower edge of the straight-side band, with the cone below left solid). The slot's top end is absorbed into the inner hole — any start ≤ the hole rim renders the same image, "slot connected to hole" is the design intent, hence no slot-top constant.
const SLOT_HALF: f32 = 0.06;
const SLOT_BOTTOM: f32 = 0.25;
/// Anti-aliasing transition band (full-side-length units): 0.5px at 16px, 0.75px at 24px — extrapolated
/// proportionally from gen_icons.py's 16px tightening tweak.
const FEATHER: f32 = 0.5 / 16.0;
const SQRT_3: f32 = 1.732_050_8;

/// Coverage up to the boundary `boundary` (dist < boundary is inside).
fn fill(dist: f32, boundary: f32, feather: f32) -> f32 {
    ((boundary - dist) / feather).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::super::state::all_states;
    use super::*;

    /// Probe pixel coordinate (fraction of full side length → pixel), used to pin the four silhouettes as pairwise distinct.
    fn probe_px(fraction: f32, size: IconSize) -> usize {
        ((fraction * size.px() as f32).round() as usize).min(size.px() as usize - 1)
    }

    fn alpha_at(state: TrayState, size: IconSize, x: usize, y: usize) -> u8 {
        let (_, _, rgba) = state.icon_rgba(size);
        rgba[(y * size.px() as usize + x) * 4 + 3]
    }

    /// Silhouette signature: four points — center / body band / chamfer band / slot band.
    ///
    /// - Center: the inscribed hole of online/degraded/error, the ring hole of offline → all empty.
    /// - Body band (0.68 of side): outside the hole, inside the outer bound → three states solid, offline still inside the ring hole.
    /// - Chamfer band (0.75 of side): degraded is already clipped by the right-edge chamfer → only it is empty.
    /// - Slot band (middle column at 0.71 of side, inside the slot segment between the hole and the
    ///   slot bottom): the exclamation slot of error is carved out and offline is still inside the ring hole → both empty.
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
        // Color is the second channel: per-state shape signatures pin the approved design (the hexagon
        // language of commit e9d67d4: nut / chamfered nut / hollow ring / slotted exclamation), holding at both sizes.
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
            // Inside the hole (hexagon scale, with a 2px feather margin) must be fully transparent —
            // any anti-aliasing residue clogging it fails (same assertion as gen_icons.py --verify).
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
            // Ring closure: at the midpoint of the ring band in all 8 directions there is solid ring.
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

    /// Distance along direction (ux, uy) to the hexagon boundary (unit = full side length).
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
        // Chamfer (gen_icons.py DEGRADED_CUT model): the mid-row right edge sits ≥2px left of online's,
        // while the left edge matches online pixel-for-pixel — the chamfer only affects the right edge.
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
        // One point on each side of the slanted shoulder (same column in the chamfer band): for |dy| ≤ CUT
        // the boundary is a vertical flat edge, below which it recedes at 45° — the right-angle-notch
        // formulation (the multiply-by-0 branch) makes the "outer point" and "inner point" equal or makes the whole corner vanish (found in review).
        // Coordinates per size chosen by hand from the geometry: a chamfer-band column at dx ≈ 0.19~0.22 of side.
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
        // Bounded slot (same shape as the 32px master): the slot segment between the hole and the slot
        // bottom is carved out; outside the slot's side edges and below the slot bottom (the bottom edge stays solid) it is solid. Offline is still inside the ring hole in this column, hence empty.
        for size in [IconSize::Px16, IconSize::Px24] {
            let mid = (size.px() as usize - 1) / 2;
            let slot_y = probe_px(0.71, size);
            assert_eq!(
                alpha_at(TrayState::TunnelDrift, size, mid, slot_y),
                0,
                "slot must be carved at row {slot_y} ({size:?})"
            );
            // Outside the slot's side edges (|dx| beyond half-width) is solid — pins the slot width.
            let side_x = probe_px(0.60, size);
            assert!(
                alpha_at(TrayState::TunnelDrift, size, side_x, slot_y) > 127,
                "beside the slot must stay solid ({size:?})"
            );
            // Below the slot bottom is solid — pins "the bottom edge stays solid" (review finding: the slot must not cut through it).
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
        // Fixed pixels pin the geometry constants (16px display size; review finding: relative probes
        // adapt along with the constants and cannot pin down drift). Each point names the parameter it pins.
        let mid = 7usize;
        let a = |state: TrayState, x: usize, y: usize| alpha_at(state, IconSize::Px16, x, y);
        let solid = |state: TrayState, x: usize, y: usize, what: &str| {
            assert!(a(state, x, y) > 127, "{what}: ({x},{y}) must be solid");
        };
        let empty = |state: TrayState, x: usize, y: usize, what: &str| {
            assert!(a(state, x, y) == 0, "{what}: ({x},{y}) must be empty");
        };
        // HEX_R=0.44: 6.5px solid and 7.5px empty along the vertex direction (the circumradius is pinned between them).
        solid(TrayState::Online, mid, 2, "HEX_R lower");
        empty(TrayState::Online, mid, 0, "HEX_R upper");
        // HOLE_R=0.156 (2.5px@16): 1.5px empty inside the hole, 3.5px solid outside it.
        empty(TrayState::Online, 6, mid, "HOLE_R inner");
        solid(TrayState::Online, 4, mid, "HOLE_R outer");
        // DEGRADED_CUT=0.2375 (3.8px@16): 3.5px solid inside the flat edge, 5.5px empty outside it.
        solid(TrayState::TunnelOnly, 11, mid, "CUT inner");
        empty(TrayState::TunnelOnly, 13, mid, "CUT outer");
        // SLOT_HALF=0.06 (≈1px@16), SLOT_BOTTOM=0.25 (4px@16): the slot center is empty,
        // 2.5px beside the slot is solid, and 4.5px below the slot bottom is solid (bottom edge stays solid).
        empty(TrayState::TunnelDrift, mid, 11, "slot carve");
        solid(TrayState::TunnelDrift, 9, 11, "slot half width");
        solid(
            TrayState::TunnelDrift,
            mid,
            12,
            "slot bottom keeps the edge",
        );
        // OFFLINE ring band: the hole center is empty, 4.5px into the band is solid, and 6.5px past the outer bound is empty.
        empty(TrayState::Offline, mid, mid, "offline hole");
        solid(TrayState::Offline, 3, mid, "offline ring band");
        empty(TrayState::Offline, 1, mid, "offline outer bound");
    }

    #[test]
    fn state_colors_match_the_approved_png_palette() {
        // Colors come from the tray-app icon PNGs (gen_icons.py COLORS table, pixel-identical to the
        // 32px masters); rendered pixels must also be color-pure: non-transparent pixels may only use the state's color.
        let palette = [
            (TrayState::Online, (0x32, 0x60, 0x72)),      // deep teal
            (TrayState::TunnelOnly, (0xC9, 0x7B, 0x2E)),  // brand amber copper
            (TrayState::Offline, (0x69, 0x6F, 0x74)),     // mid gray
            (TrayState::TunnelDrift, (0xEF, 0x44, 0x44)), // red
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
                // Each state has at least one opaque pixel (not a blank image).
                assert!(rgba.as_chunks::<4>().0.iter().any(|p| p[3] > 200));
            }
        }
    }
}
