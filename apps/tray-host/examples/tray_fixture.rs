//! 托盘 CI 证据夹具（AGENT-WIN-1/3/4）：按 [TraySink] 的**同一 PNG 格式**
//! （8-bit RGBA、逐行 filter 0、stored deflate 块）产出四态
//! `{state}/tray/status.json + icon-16.png + icon-24.png`，供 windows-latest CI
//! 启动 `meshlet-tray-host` 消费、截图存证（todo.md「CI windows-latest 出
//! 截图证据」）。
//!
//! 颜色/形状/tooltip 与 `apps/agent/src/tray.rs` 生产端同构（常量就地镜像，
//! 保持 tray-host 零数据面依赖的纪律）；CI 证据点在「宿主能解码消费生产
//! 格式并随状态换图」，不在像素级一致（那由 agent 侧单测钉死）。
//!
//! 用法：`tray_fixture <out_dir>` → 生成 `<out_dir>/{online,tunnel-only,
//! tunnel-drift,offline}` 四个状态目录。

use std::path::PathBuf;

/// 外圆半径（相对半边长）— 镜像 tray.rs `OUTER_R`。
const OUTER_R: f32 = 0.44;
/// 各态内孔半径 — 镜像 tray.rs `hole_of`。
const HOLES: [f32; 4] = [0.0, 0.16, 0.28, 0.30];
/// 斜杠半宽（仅 drift 态）— 镜像 tray.rs `SLASH_HALF`。
const SLASH_HALF: f32 = 0.06;
/// 状态色（品牌 amber copper 系）— 镜像 tray.rs `rgb()`。
const COLORS: [(u8, u8, u8); 4] = [
    (201, 123, 46),
    (228, 160, 60),
    (192, 57, 43),
    (120, 130, 138),
];
/// (目录名, accessible_name, tooltip) — 与 agent 侧 `TrayState` 四态同构。
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
        let state_dir = out_dir.join(dir);
        let tray_dir = state_dir.join("tray");
        std::fs::create_dir_all(&tray_dir).expect("create tray dir");
        for (name, size) in [("icon-16.png", 16u32), ("icon-24.png", 24)] {
            let (w, h, rgba) = silhouette_rgba(idx, size);
            std::fs::write(tray_dir.join(name), png_encode(w, h, &rgba)).expect("write icon png");
        }
        // status.json 字段与 TraySink::publish_with 同构（state/tooltip/
        // accessible_name/icon_16/icon_24）。
        let body = format!(
            "{{\"state\":{accessible:?},\"tooltip\":{tooltip:?},\"accessible_name\":{accessible:?},\"icon_16\":\"icon-16.png\",\"icon_24\":\"icon-24.png\"}}",
        );
        std::fs::write(tray_dir.join("status.json"), body).expect("write status.json");
        println!("{}", state_dir.display());
    }
}

/// 四态轮廓渲染（实心 / 大孔圆环 / 中孔圆环＋斜杠 / 薄孔圆环）。
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
                // 斜杠：点到主对角线的距离（镜像 tray.rs TunnelDrift）。
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

/// PNG 编码（stored deflate 块）— 与 `tray.rs::png_encode` 同格式。
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
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit RGBA 非隔行
    chunk(&mut out, b"IHDR", &ihdr);

    let row_len = 1 + width as usize * 4;
    let mut raw = Vec::with_capacity(row_len * height as usize);
    for y in 0..height as usize {
        raw.push(0); // filter None
        raw.extend_from_slice(&rgba[y * width as usize * 4..(y + 1) * width as usize * 4]);
    }
    // zlib: 0x78 0x01 头 + 单 stored 块（LEN/NLEN + 原始字节）+ adler32。
    let mut adler_a: u32 = 1;
    let mut adler_b: u32 = 0;
    for &byte in &raw {
        adler_a = (adler_a + byte as u32) % 65521;
        adler_b = (adler_b + adler_a) % 65521;
    }
    let mut idat = vec![0x78u8, 0x01u8];
    idat.push(0x01); // BFINAL=1, BTYPE=00（stored）
    idat.extend_from_slice(&(raw.len() as u16).to_le_bytes());
    idat.extend_from_slice(&(!(raw.len() as u16)).to_le_bytes()); // NLEN = ~LEN（RFC 1950）
    idat.extend_from_slice(&raw);
    idat.extend_from_slice(&((adler_b << 16) | adler_a).to_be_bytes());
    chunk(&mut out, b"IDAT", &idat);
    chunk(&mut out, b"IEND", &[]);
    out
}

/// 行格式自检（与 tray-host 的解码器对称，出问题在 CI 就地报错而不是让
/// 截图证据悄悄变成兜底绿方块）。
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_are_well_formed_png_with_distinct_pixels() {
        let mut first_pixels: Option<Vec<u8>> = None;
        for state in 0..4 {
            let (w, h, rgba) = silhouette_rgba(state, 24);
            let png = png_encode(w, h, &rgba);
            // PNG 签名 + IHDR 尺寸自洽。
            assert_eq!(&png[..8], &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
            let ihdr_w = u32::from_be_bytes([png[16], png[17], png[18], png[19]]);
            assert_eq!(ihdr_w, 24);
            assert_eq!(rgba.len(), 24 * 24 * 4);
            // 每态至少一个非透明像素（图标不是空的）。
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
