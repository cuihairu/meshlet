//! Tray CI evidence fixture (AGENT-WIN-1/3/4): in the **same PNG format** as [TraySink]
//! (8-bit RGBA, per-row filter 0, stored deflate blocks) it produces the four-state
//! `{state}/tray/status.json + icon-16.png + icon-24.png`, for the windows-latest CI to launch
//! `meshlet-tray-host` on and capture screenshots as evidence (todo.md "CI windows-latest
//! screenshot evidence").
//!
//! Colors / shapes / tooltips are isomorphic with the production side in `apps/agent/src/tray.rs`
//! (the constants are mirrored in place, keeping the discipline of tray-host's zero data-plane
//! dependency); the CI evidence point is "the host can decode the production format and swap
//! icons with the status", not pixel-level identity (that is pinned down by the agent-side unit tests).
//!
//! Usage: `tray_fixture <out_dir>` -> creates the four state directories `<out_dir>/{online,tunnel-only,
//! tunnel-drift,offline}`.

use std::path::PathBuf;

/// Outer radius (relative to the half side) — mirrors `OUTER_R` in tray.rs.
const OUTER_R: f32 = 0.44;
/// Inner hole radius per state — mirrors `hole_of` in tray.rs.
const HOLES: [f32; 4] = [0.0, 0.16, 0.28, 0.30];
/// Half-width of the slash (drift state only) — mirrors `SLASH_HALF` in tray.rs.
const SLASH_HALF: f32 = 0.06;
/// Status colors (the brand amber copper family) — mirrors `rgb()` in tray.rs.
const COLORS: [(u8, u8, u8); 4] = [
    (201, 123, 46),
    (228, 160, 60),
    (192, 57, 43),
    (120, 130, 138),
];
/// (directory name, accessible_name, tooltip) — isomorphic with the four `TrayState` states on the agent side.
const STATES: [(&str, &str, &str); 4] = [
    (
        "online",
        "Meshlet online",
        "在线：控制通道正常，数据面与服务端期望一致（流量经 VPS 中继）",
    ),
    (
        "tunnel-only",
        "Meshlet tunnel only",
        "隧道连通但控制通道失效：本机握手新鲜，agent 上报过期",
    ),
    (
        "tunnel-drift",
        "Meshlet tunnel drift",
        "隧道异常：本地内核对象与服务端期望不一致（正在重放）",
    ),
    (
        "offline",
        "Meshlet offline",
        "已断开：无新鲜的控制通道或隧道证据",
    ),
];

fn main() {
    let out_dir = std::env::args()
        .nth(1)
        .expect("usage: tray_fixture <out_dir>");
    let out_dir = PathBuf::from(out_dir);
    for (idx, (dir, accessible, tooltip)) in STATES.iter().enumerate() {
        // Each state is a complete agent state_dir: `<out>/<state>/tray/` —
        // isomorphic with the `{state_dir}/tray` layout of TraySink::new(state_dir),
        // and tray-host consumes `<out>/<state>` directly as its state_dir argument.
        let state_dir = out_dir.join(dir);
        let tray_dir = state_dir.join("tray");
        std::fs::create_dir_all(&tray_dir).expect("create tray dir");
        for (name, size) in [("icon-16.png", 16u32), ("icon-24.png", 24)] {
            let (w, h, rgba) = silhouette_rgba(idx, size);
            std::fs::write(tray_dir.join(name), png_encode(w, h, &rgba)).expect("write icon png");
        }
        // status.json fields are isomorphic with TraySink::publish_with (state/
        // tooltip/accessible_name/icon_16/icon_24).
        // `version` / `env` are kept in sync with `TraySink::publish_with` (the local panel shows
        // the agent version and key EnvProbe items; older agents omit both, and the panel treats them as unknown / falls back).
        // `updated_at` is kept in sync with `TraySink::publish_with` (RFC3339); the local panel's
        // "current node" block shows it — without it in the fixture that row would always read "—" in the CI panel evidence.
        let body = format!(
            "{{\"state\":{accessible:?},\"tooltip\":{tooltip:?},\"accessible_name\":{accessible:?},\"icon_16\":\"icon-16.png\",\"icon_24\":\"icon-24.png\",\"updated_at\":\"2026-11-06T00:00:00Z\",\"version\":\"fixture\",\"env\":{{\"display\":null,\"wayland_display\":null,\"session_type\":null,\"session_name\":\"CI\",\"console_session\":true}}}}"
        );
        std::fs::write(tray_dir.join("status.json"), body).expect("write status.json");
        // Data sources for the local panel's other two blocks (same shape as the agent-published files): the direct-peer view +
        // the applied plan (including last_good_plan.routes). The CI panel evidence uses these to show all three blocks in full.
        std::fs::write(
            state_dir.join("direct-peers.json"),
            concat!(
                "[{\"name\":\"peer-b\",\"virtual_ipv4\":\"10.240.0.3\",",
                "\"public_key\":\"cGF1bGJrZXk=\",\"mode\":\"p2p_direct\",",
                "\"rtt_ms\":12,\"endpoint\":\"203.0.113.7:51820\",",
                "\"last_handshake_at\":null},",
                "{\"name\":\"\",\"virtual_ipv4\":\"10.240.0.4\",",
                "\"public_key\":\"cmVsYXlrZXk=\",\"mode\":\"hub_relay\",",
                "\"rtt_ms\":null,\"endpoint\":\"\",\"last_handshake_at\":null}]"
            ),
        )
        .expect("write direct-peers.json");
        std::fs::write(
            state_dir.join("applied.json"),
            concat!(
                "{\"desired_config_hash\":\"fixture\",\"tunnel_address\":\"10.240.0.2\",",
                "\"routes\":[\"10.240.0.0/16\"],\"nat_rules\":[],\"nat_owners\":[],",
                "\"applied_at\":\"2026-11-06T00:00:00Z\",",
                "\"local_public_key\":\"cHVibGlja2V5RmluZ2VycHJpbnQwMTIzNDU2Nzg5\",",
                "\"last_good_plan\":{\"desired_revision\":3,",
                "\"tunnel\":{\"address\":\"10.240.0.2\"},",
                "\"routes\":[{\"destination\":\"10.240.0.0/16\",\"interface\":\"wg-meshlet\",\"gateway\":null},",
                "{\"destination\":\"192.168.8.0/24\",\"interface\":\"wg-meshlet\",\"gateway\":\"10.240.0.3\"}],",
                "\"nat_rules\":[],\"desired_config_hash\":\"fixture\"}}"
            ),
        )
        .expect("write applied.json");
        println!("{}", state_dir.display());
    }
}

/// Renders the four-state silhouettes (solid / large-hole ring / medium-hole ring + slash / thin-hole ring).
fn silhouette_rgba(state: usize, side: u32) -> (u32, u32, Vec<u8>) {
    let side = side as usize;
    let feather = 1.0 / side as f32;
    let hole = HOLES[state];
    let mut rgba = vec![0u8; side * side * 4];
    for y in 0..side {
        for x in 0..side {
            let dx = (x as f32 + 0.5) / side as f32 - 0.5;
            let dy = (y as f32 + 0.5) / side as f32 - 0.5;
            let dist = (dx * dx + dy * dy).sqrt();
            let fill = |boundary: f32| ((boundary - dist) / feather).clamp(0.0, 1.0);
            let outside_hole = 1.0 - fill(hole);
            let mut alpha = fill(OUTER_R) * outside_hole;
            if state == 2 && dist <= OUTER_R {
                // Slash: distance from the point to the main diagonal (mirrors TunnelDrift in tray.rs).
                alpha = alpha.max(fill(SLASH_HALF));
            }
            let alpha = (alpha * 255.0) as u8;
            if alpha == 0 {
                continue;
            }
            let (r, g, b) = COLORS[state];
            let px = (y * side + x) * 4;
            rgba[px] = r;
            rgba[px + 1] = g;
            rgba[px + 2] = b;
            rgba[px + 3] = alpha;
        }
    }
    (side as u32, side as u32, rgba)
}

/// PNG encoding (stored deflate blocks) — the same format as `png_encode` in tray.rs.
fn png_encode(width: u32, height: u32, rgba: &[u8]) -> Vec<u8> {
    fn crc32(data: &[u8]) -> u32 {
        let mut table = [0u32; 256];
        for (n, slot) in table.iter_mut().enumerate() {
            let mut c = n as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *slot = c;
        }
        let mut crc = 0xFFFF_FFFFu32;
        for &byte in data {
            crc = table[((crc ^ byte as u32) & 0xff) as usize] ^ (crc >> 8);
        }
        crc ^ 0xFFFF_FFFF
    }
    fn chunk(out: &mut Vec<u8>, type_: &[u8; 4], data: &[u8]) {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(type_);
        out.extend_from_slice(data);
        out.extend_from_slice(&crc32(&[type_.as_slice(), data].concat()).to_be_bytes());
    }
    let mut out = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit RGBA, non-interlaced
    chunk(&mut out, b"IHDR", &ihdr);

    let row_len = 1 + width as usize * 4;
    let mut raw = Vec::with_capacity(row_len * height as usize);
    for y in 0..height as usize {
        raw.push(0); // filter None
        raw.extend_from_slice(&rgba[y * width as usize * 4..(y + 1) * width as usize * 4]);
    }
    // zlib: 0x78 0x01 header + a single stored block (LEN/NLEN + raw bytes) + adler32.
    let mut adler_a: u32 = 1;
    let mut adler_b: u32 = 0;
    for &byte in &raw {
        adler_a = (adler_a + byte as u32) % 65521;
        adler_b = (adler_b + adler_a) % 65521;
    }
    let mut idat = vec![0x78u8, 0x01u8];
    idat.push(0x01); // BFINAL=1, BTYPE=00 (stored)
    idat.extend_from_slice(&(raw.len() as u16).to_le_bytes());
    idat.extend_from_slice(&(!(raw.len() as u16)).to_le_bytes()); // NLEN = ~LEN (RFC 1950)
    idat.extend_from_slice(&raw);
    idat.extend_from_slice(&((adler_b << 16) | adler_a).to_be_bytes());
    chunk(&mut out, b"IDAT", &idat);
    chunk(&mut out, b"IEND", &[]);
    out
}

/// Row-format self-check (symmetric with the tray-host decoder): on failure it reports in CI
/// right there instead of letting the screenshot evidence quietly become the fallback green square.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_are_well_formed_png_with_distinct_pixels() {
        let mut first_pixels: Option<Vec<u8>> = None;
        for state in 0..4 {
            let (w, h, rgba) = silhouette_rgba(state, 24);
            let png = png_encode(w, h, &rgba);
            // PNG signature + self-consistent IHDR dimensions.
            assert_eq!(&png[..8], &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
            let ihdr_w = u32::from_be_bytes([png[16], png[17], png[18], png[19]]);
            assert_eq!(ihdr_w, 24);
            assert_eq!(rgba.len(), 24 * 24 * 4);
            // At least one non-transparent pixel per state (the icon is not empty).
            assert!(rgba.chunks(4).any(|px| px[3] != 0));
            match &first_pixels {
                None => first_pixels = Some(rgba),
                Some(first) => assert_ne!(
                    first, &rgba,
                    "four-state silhouettes must be pairwise distinct"
                ),
            }
        }
    }

    #[test]
    fn states_cover_the_four_documented_directories() {
        assert_eq!(STATES.len(), 4);
        for (dir, accessible, tooltip) in STATES {
            assert!(!dir.is_empty());
            assert!(accessible.starts_with("Meshlet "));
            assert!(!tooltip.is_empty());
        }
    }
}
