//! 运行时系统托盘状态展示（用户 2026-10-16：「运行时需要显示对应的 icon 的吧」「系统托盘
//! icon 最好能体现状态变化」）。
//!
//! ## 纪律一：不新造状态名
//!
//! [`TrayState`] 的四态**逐一对应仓内已有枚举**，映射依据写在每个变体上：
//!
//! | 用户原话 | 托盘态 | 仓内已有枚举 |
//! |---|---|---|
//! | 在线直连 | [`TrayState::Online`] | [`meshlet_domain::presence::PresenceState::Online`] ＋ [`crate::reconcile::Reason::UpToDate`] |
//! | 中继中 | 同上 | v1 是 VPS 中心中继（ADR-002），**仓内没有「直连 / 中继」二值信号**，P2P 直连明确留 v2——所以「在线直连」与「中继中」在 v1 是**同一个真实状态**，本模块用一态表达，不伪造第二个 |
//! | 已断开 | [`TrayState::Offline`] | `PresenceState::Offline`（控制通道与隧道均无新鲜证据） |
//! | 隧道异常 | [`TrayState::TunnelDrift`] | [`crate::reconcile::Reason::KernelDrift`] ＋ [`meshlet_domain::entities::ApplyStatus::Failed`] |
//!
//! 中间还有一态 [`TrayState::TunnelOnly`] ← `PresenceState::TunnelOnly`（握手新鲜但
//! agent 上报过期）——这是仓内**真实存在**的三态之一，agent 侧对位是「本地能读到握手
//! 但心跳上报失败」，见 [`TrayState::derive`]。
//!
//! ## 纪律二/三：非静态、文本等价物、不靠颜色
//!
//! 状态变化即换图（[`TraySink::publish_with`] 内容相同则不重写，不同才落盘）；每态有
//! `tooltip`（整句说明）与 `accessible_name`（无障碍短名）。四态的**轮廓互不相同**：
//! 实心 / 大孔圆环 / 中孔圆环＋斜杠 / 薄孔圆环——颜色只是第二通道，
//! [`tray_state_silhouettes_are_pairwise_distinct`] 用像素探针钉死这一条。
//!
//! ## 纪律四：headless / CI 必须 no-op
//!
//! [`EnvProbe::from_env`] 读出桌面会话环境，[`EnvProbe::has_desktop_session`] 为 false
//! （CI、无头 VPS）时 [`TraySink::publish_with`] 直接返回
//! [`TrayWrite::Skipped`]——不写任何文件、不 panic、不让 agent 起不来。桌面探测是**注入**
//! 的纯数据，测试不需要动进程环境变量。
//!
//! ## 素材与依赖纪律
//!
//! 图标是**简单自绘形状**（圆 + 内切圆 + 斜杠），不使用品牌 logo 代餐：仓内
//! [logo.svg](../../../logo.svg) 的主形是分层透镜多边形（`viewBox="0 0 1024 1024"`），
//! 细节在 16px 下会糊，故只沿用其圆形轮廓作底形，状态信息由形状＋颜色双通道表达。
//!
//! 不引入 GUI / 托盘 crate（`tray-icon`/`tao`/`winit` 全无）：托盘宿主由桌面壳按
//! [TraySink] 写出的 PNG 自行接入（面板插件、`notify-send` 脚本等）。PNG 用内置编码器
//! （stored deflate 块）生成，零新增依赖；[`png_roundtrip_decodes_the_same_pixels`]
//! 用「解码自己写出的流」验证输出可被通用解压器还原。

use std::path::{Path, PathBuf};

use crate::reconcile::Reason;

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

/// 托盘状态：四态各对应一组仓内已有枚举，不新造状态名。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayState {
    /// 「在线直连」/「中继中」——**v1 同态**（ADR-002 全部流量经 VPS 中心中继，
    /// 仓内无直连信号，P2P 留 v2）。对应：
    /// [`PresenceState::Online`] ＋ [`Reason::UpToDate`] ＋ [`ApplyStatus::Applied`]
    /// ＋ [`DeviceStatus::Active`]。
    Online,
    /// 隧道连通但控制通道失效。对应：[`PresenceState::TunnelOnly`]
    /// （服务端口径「仅握手新鲜、agent 上报过期」）；agent 侧对位：本机 `wg show
    /// latest-handshakes` 有值，但心跳上报失败。
    TunnelOnly,
    /// 隧道异常：本地内核对象与服务端期望不一致，或重放失败。对应：
    /// [`Reason::KernelDrift`] ＋ [`ApplyStatus::Failed`]。
    TunnelDrift,
    /// 已断开：控制通道与隧道均无新鲜证据。对应 [`PresenceState::Offline`]。
    Offline,
}

impl TrayState {
    /// 由 agent 侧真实信号推导（纯函数，便于单测）：
    ///
    /// - [`Reason::KernelDrift`] → [`TrayState::TunnelDrift`]（内核漂移即「隧道异常」）
    /// - 控制通道失效 ＋ 本地读得到握手 → [`TrayState::TunnelOnly`]
    /// - 控制通道失效 ＋ 本地也读不到握手 → [`TrayState::Offline`]
    /// - 其余（含 `UpToDate` / `DesiredConfigChanged` / `NoLocalLedger`，均为**预期内**
    ///   的配置变更而非异常）→ [`TrayState::Online`]
    pub fn derive(reason: Reason, control_ok: bool, tunnel_alive: bool) -> Self {
        if reason == Reason::KernelDrift {
            return TrayState::TunnelDrift;
        }
        if !control_ok {
            return if tunnel_alive {
                TrayState::TunnelOnly
            } else {
                TrayState::Offline
            };
        }
        TrayState::Online
    }

    /// 无障碍短名（tray 图标的可访问名称；不依赖颜色）。
    pub fn accessible_name(self) -> &'static str {
        match self {
            TrayState::Online => "Meshlet online",
            TrayState::TunnelOnly => "Meshlet tunnel only",
            TrayState::TunnelDrift => "Meshlet tunnel drift",
            TrayState::Offline => "Meshlet offline",
        }
    }

    /// tooltip 正文（整句，含状态含义；与图标形状互为冗余通道）。
    pub fn tooltip(self) -> &'static str {
        match self {
            TrayState::Online => "在线：控制通道正常，数据面与服务端期望一致（流量经 VPS 中继）",
            TrayState::TunnelOnly => "隧道连通但控制通道失效：本机握手新鲜，agent 上报过期",
            TrayState::TunnelDrift => "隧道异常：本地内核对象与服务端期望不一致（正在重放）",
            TrayState::Offline => "已断开：无新鲜的控制通道或隧道证据",
        }
    }

    /// 状态色（第二通道；主通道是形状轮廓）。
    fn rgb(self) -> (u8, u8, u8) {
        match self {
            // 品牌 amber copper（`logo-copper.svg` 主色），仅用于颜色通道。
            TrayState::Online => (201, 123, 46),
            TrayState::TunnelOnly => (228, 160, 60),
            TrayState::TunnelDrift => (192, 57, 43),
            TrayState::Offline => (120, 130, 138),
        }
    }

    /// 渲染为 RGBA 像素缓冲（每像素 4 字节，Y 从上到下）。
    pub fn icon_rgba(self, size: IconSize) -> (u32, u32, Vec<u8>) {
        let side = size.px() as usize;
        let feather = 1.0 / side as f32; // ≈1px 抗锯齿
        let mut rgba = vec![0u8; side * side * 4];
        for y in 0..side {
            for x in 0..side {
                let (dx, dy) = (
                    (x as f32 + 0.5) / side as f32 - 0.5,
                    (y as f32 + 0.5) / side as f32 - 0.5,
                );
                let dist = (dx * dx + dy * dy).sqrt();
                let alpha = (self.coverage(dist, dx, dy, feather) * 255.0) as u8;
                if alpha == 0 {
                    continue;
                }
                let (r, g, b) = self.rgb();
                let px = (y * side + x) * 4;
                rgba[px] = r;
                rgba[px + 1] = g;
                rgba[px + 2] = b;
                rgba[px + 3] = alpha;
            }
        }
        (size.px(), size.px(), rgba)
    }

    /// 形状覆盖率（0..=1）：外圆内切内孔，drift 另加斜杠。
    fn coverage(&self, dist: f32, dx: f32, dy: f32, feather: f32) -> f32 {
        let outside_hole = 1.0 - fill(dist, hole_of(*self), feather);
        let mut alpha = fill(dist, OUTER_R, feather) * outside_hole;
        if *self == TrayState::TunnelDrift && dist <= OUTER_R {
            // 斜杠：|dx - dy| / √2 是点到主对角线的距离。
            alpha = alpha.max(fill((dx - dy).abs() / 2.0_f32.sqrt(), SLASH_HALF, feather));
        }
        alpha
    }
}

/// 外圆半径（相对半边长）。
const OUTER_R: f32 = 0.44;
/// 各态的内孔半径：Online 实心（0.0 = 无孔），TunnelOnly 大孔，TunnelDrift 中孔，
/// Offline 薄孔。孔越大 = 越「空」。
fn hole_of(state: TrayState) -> f32 {
    match state {
        TrayState::Online => 0.0,
        TrayState::TunnelOnly => 0.16,
        TrayState::TunnelDrift => 0.28,
        TrayState::Offline => 0.30,
    }
}
/// 斜杠半宽（仅 [`TrayState::TunnelDrift`]）。
const SLASH_HALF: f32 = 0.06;

/// 到边界 `boundary` 的覆盖率（dist < boundary 为内）。
fn fill(dist: f32, boundary: f32, feather: f32) -> f32 {
    ((boundary - dist) / feather).clamp(0.0, 1.0)
}

/// 状态 ＋ 文本等价物。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayStatus {
    pub state: TrayState,
    /// tooltip（面板悬停显示；含设备名与整句说明）。
    pub tooltip: String,
    /// 无障碍短名。
    pub accessible_name: &'static str,
}

impl TrayStatus {
    /// 带设备名与网络接口的 tooltip（tooltip 是文本等价物，不能只靠颜色）。
    pub fn new(state: TrayState, device_name: Option<&str>, interface: &str) -> Self {
        let who = device_name
            .map(|n| format!("「{n}」"))
            .unwrap_or_else(|| format!("接口 {interface}"));
        Self {
            tooltip: format!("Meshlet{who}：{}", state.tooltip()),
            state,
            accessible_name: state.accessible_name(),
        }
    }
}

/// 桌面会话探测（注入式：测试不必动进程环境变量）。
#[derive(Debug, Clone, Default)]
pub struct EnvProbe {
    /// X11 显示（`$DISPLAY`）。
    pub display: Option<String>,
    /// Wayland 显示（`$WAYLAND_DISPLAY`）。
    pub wayland_display: Option<String>,
    /// `$XDG_SESSION_TYPE`（`x11` / `wayland` / `tty` / …）。
    pub session_type: Option<String>,
}

impl EnvProbe {
    pub fn from_env() -> Self {
        Self {
            display: nonempty(var("DISPLAY")),
            wayland_display: nonempty(var("WAYLAND_DISPLAY")),
            session_type: nonempty(var("XDG_SESSION_TYPE")),
        }
    }

    /// 是否有桌面会话可挂托盘。`tty` / 空值 = headless（CI、无头 VPS）→ false。
    pub fn has_desktop_session(&self) -> bool {
        self.display.is_some()
            || self.wayland_display.is_some()
            || matches!(
                self.session_type.as_deref(),
                Some("x11") | Some("wayland") | Some("gnome") | Some("plasma")
            )
    }
}

fn nonempty(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// 一次落盘的结果（区分「跳过」「写了」「内容未变」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayWrite {
    /// headless：不写任何文件。
    Skipped,
    /// 内容未变：不重写（幂等）。
    Unchanged,
    /// 状态变化，已写新图。
    Written,
}

/// 托盘产物落盘：`{state_dir}/tray/{icon-16.png,icon-24.png,status.json}`。
///
/// headless 下 no-op（不建目录、不写文件、不 panic）。
pub struct TraySink {
    dir: PathBuf,
}

impl TraySink {
    pub fn new(state_dir: impl AsRef<Path>) -> Self {
        Self {
            dir: state_dir.as_ref().join("tray"),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// 便利入口：用真实环境探测。
    pub fn publish(&self, status: &TrayStatus) -> Result<TrayWrite, String> {
        self.publish_with(status, &EnvProbe::from_env())
    }

    /// 注入环境探测（测试与 CI 用）。
    pub fn publish_with(&self, status: &TrayStatus, env: &EnvProbe) -> Result<TrayWrite, String> {
        if !env.has_desktop_session() {
            return Ok(TrayWrite::Skipped);
        }
        // 幂等比较只看语义字段（state + tooltip）：`updated_at` 每次都会变，
        // 不参与比较，否则每轮 tick 都会重写。
        if status_unchanged(&self.dir, status) {
            return Ok(TrayWrite::Unchanged);
        }
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("create tray dir: {e}"))?;
        for size in [IconSize::Px16, IconSize::Px24] {
            let (_, _, rgba) = status.state.icon_rgba(size);
            let png = png_encode(size.px(), size.px(), &rgba);
            let name = format!("icon-{}.png", size.px());
            write_file(&self.dir.join(&name), &png).map_err(|e| format!("write {name}: {e}"))?;
        }
        let body = serde_json::json!({
            "state": status.state.accessible_name(),
            "tooltip": status.tooltip,
            "icon_16": "icon-16.png",
            "icon_24": "icon-24.png",
            "updated_at": chrono::Utc::now().to_rfc3339(),
        });
        write_file(&self.dir.join("status.json"), body.to_string().as_bytes())
            .map_err(|e| format!("write status.json: {e}"))?;
        Ok(TrayWrite::Written)
    }
}

fn read_file(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// 上一份 `status.json` 的语义字段（state + tooltip）是否与本次一致。
fn status_unchanged(dir: &Path, status: &TrayStatus) -> bool {
    read_file(&dir.join("status.json"))
        .and_then(|prev| serde_json::from_str::<serde_json::Value>(&prev).ok())
        .map(|v| {
            v.get("state").and_then(|s| s.as_str()) == Some(status.state.accessible_name())
                && v.get("tooltip").and_then(|t| t.as_str()) == Some(status.tooltip.as_str())
        })
        .unwrap_or(false)
}

fn write_file(path: &Path, body: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, body)
}

// ── PNG 编码（stored deflate 块，零依赖）──────────────────────────────────

/// 编码 RGBA 图为 PNG 字节流。压缩用 deflate **stored** 块（不压缩）：文件略大，
/// 但 16/24px 图标只有几百字节，换来零依赖与可审计的实现。
pub fn png_encode(width: u32, height: u32, rgba: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.push(8); // bit depth
    ihdr.push(6); // color type: RGBA
    ihdr.push(0); // compression method
    ihdr.push(0); // filter method
    ihdr.push(0); // interlace
    push_chunk(&mut out, b"IHDR", &ihdr);

    // 每行前置 filter byte 0（None）：PNG 的逐行滤波。
    let row_len = 1 + width as usize * 4;
    let mut raw = Vec::with_capacity(row_len * height as usize);
    for y in 0..height as usize {
        raw.push(0);
        let row = &rgba[y * width as usize * 4..(y + 1) * width as usize * 4];
        raw.extend_from_slice(row);
    }
    push_chunk(&mut out, b"IDAT", &zlib_stream(&raw));
    push_chunk(&mut out, b"IEND", &[]);
    out
}

/// zlib 容器：2 字节头 + deflate stored 块 + adler32。
fn zlib_stream(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78u8, 0x01u8]; // CM=8(deflate), FLEVEL=01
    const CHUNK: usize = 0xff00;
    let mut i = 0usize;
    loop {
        let len = data.len().saturating_sub(i).min(CHUNK);
        out.push((i + len >= data.len()) as u8); // BFINAL=bit0, BTYPE=00(stored)
        out.extend_from_slice(&(len as u16).to_le_bytes());
        out.extend_from_slice(&(len as u16).wrapping_neg().to_le_bytes());
        out.extend_from_slice(&data[i..i + len]);
        i += len;
        if i >= data.len() {
            break;
        }
    }
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

/// 解码 stored 块的 zlib 流（测试用：验证编码输出能被还原）。
#[cfg(test)]
fn zlib_decompress(stream: &[u8]) -> Option<Vec<u8>> {
    if stream.len() < 6 || stream[0] != 0x78 {
        return None;
    }
    let mut out = Vec::new();
    let mut i = 2usize;
    while i < stream.len().saturating_sub(4) {
        let last = stream[i] & 0x01 != 0;
        if stream[i] >> 1 != 0 {
            return None; // 只支持 stored 块（本模块唯一写出的形式）
        }
        i += 1;
        let len = u16::from_le_bytes([stream[i], stream[i + 1]]) as usize;
        i += 2;
        i += 2; // NLEN（!LEN）
        if i + len > stream.len() - 4 {
            return None;
        }
        out.extend_from_slice(&stream[i..i + len]);
        i += len;
        if last {
            break;
        }
    }
    Some(out)
}

fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + byte as u32) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

fn push_chunk(out: &mut Vec<u8>, type_: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(type_);
    out.extend_from_slice(data);
    let mut crc_input = Vec::with_capacity(4 + data.len());
    crc_input.extend_from_slice(type_);
    crc_input.extend_from_slice(data);
    out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xffffffff;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb88320
            } else {
                crc >> 1
            };
        }
    }
    crc ^ 0xffffffff
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshlet_domain::entities::{ApplyStatus, DeviceStatus};
    use meshlet_domain::presence::PresenceState;

    /// 探针像素坐标（相对半径 → 像素），用于钉死四态轮廓互不相同。
    fn probes(size: IconSize) -> [(usize, usize); 3] {
        let s = size.px() as usize;
        let mid = (s - 1) / 2;
        [
            (mid, mid),                                // 圆心
            ((0.70 * s as f32).round() as usize, mid), // 环带（TunnelOnly 有、Drift/Offline 空）
            ((0.86 * s as f32).floor() as usize, mid), // 外环（四态都有）
        ]
    }

    fn alpha_at(state: TrayState, size: IconSize, x: usize, y: usize) -> u8 {
        let (_, _, rgba) = state.icon_rgba(size);
        rgba[(y * size.px() as usize + x) * 4 + 3]
    }

    /// 轮廓签名：中心 / 环带 / 外环 三点。
    fn signature(state: TrayState, size: IconSize) -> [bool; 3] {
        probes(size).map(|(x, y)| alpha_at(state, size, x, y) > 127)
    }

    // ── 纪律一：状态映射到仓内已有枚举 ───────────────────────────────────

    #[test]
    fn kernel_drift_maps_to_tunnel_drift() {
        assert_eq!(
            TrayState::derive(Reason::KernelDrift, true, true),
            TrayState::TunnelDrift
        );
        // 漂移优先于心跳状态：控制通道失效时也是 TunnelDrift。
        assert_eq!(
            TrayState::derive(Reason::KernelDrift, false, false),
            TrayState::TunnelDrift
        );
    }

    #[test]
    fn control_channel_down_with_handshake_is_tunnel_only() {
        assert_eq!(
            TrayState::derive(Reason::UpToDate, false, true),
            TrayState::TunnelOnly
        );
    }

    #[test]
    fn control_channel_down_without_handshake_is_offline() {
        assert_eq!(
            TrayState::derive(Reason::UpToDate, false, false),
            TrayState::Offline
        );
    }

    #[test]
    fn expected_config_changes_stay_online() {
        // DesiredConfigChanged / NoLocalLedger 是预期内的配置变更，不是异常。
        for reason in [
            Reason::UpToDate,
            Reason::DesiredConfigChanged,
            Reason::NoLocalLedger,
        ] {
            assert_eq!(
                TrayState::derive(reason, true, true),
                TrayState::Online,
                "{reason:?} must render as Online"
            );
        }
    }

    // ── 纪律二/三：文本等价物，不靠颜色 ──────────────────────────────────

    #[test]
    fn every_state_has_a_nonempty_text_equivalent() {
        for state in states() {
            assert!(!state.accessible_name().is_empty());
            assert!(!state.tooltip().is_empty());
            let status = TrayStatus::new(state, Some("office-laptop"), "meshlet0");
            assert!(status.tooltip.contains("office-laptop"));
            assert_eq!(status.accessible_name, state.accessible_name());
        }
    }

    #[test]
    fn tooltips_are_pairwise_distinct() {
        let states = states();
        for i in 0..states.len() {
            for j in (i + 1)..states.len() {
                assert_ne!(
                    states[i].tooltip(),
                    states[j].tooltip(),
                    "{:?} and {:?} must not share a tooltip",
                    states[i],
                    states[j]
                );
                assert_ne!(states[i].accessible_name(), states[j].accessible_name());
            }
        }
    }

    #[test]
    fn tray_state_silhouettes_are_pairwise_distinct() {
        // 颜色是第二通道：形状签名本身必须互不相同，且在两个尺寸下都成立。
        for size in [IconSize::Px16, IconSize::Px24] {
            let states = states();
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
            // 四态都有外圆轮廓（不是四种空图）。
            for state in states {
                assert!(
                    signature(state, size)[2],
                    "{state:?} must render the outer ring"
                );
            }
            // 实心（Online）与「大孔圆环」（TunnelOnly）在圆心处可辨。
            assert!(signature(TrayState::Online, size)[0]);
            assert!(!signature(TrayState::TunnelOnly, size)[0]);
            // 斜杠只属于 TunnelDrift：在圆孔内、主对角线上。
            let s = size.px() as usize;
            let slash_x = (0.42 * s as f32).round() as usize;
            let slash_y = slash_x;
            assert!(alpha_at(TrayState::TunnelDrift, size, slash_x, slash_y) > 200);
            for other in [TrayState::TunnelOnly, TrayState::Offline] {
                assert!(
                    alpha_at(other, size, slash_x, slash_y) < 30,
                    "{other:?} must not render the slash"
                );
            }
        }
    }

    #[test]
    fn slash_probe_is_inside_the_tunnel_only_hole() {
        // 前置断言：斜杠探针点确实落在 TunnelOnly 的大孔里（否则上面的对比没有意义）。
        for size in [IconSize::Px16, IconSize::Px24] {
            let s = size.px() as usize;
            let x = (0.42 * s as f32).round() as usize;
            let dx = (x as f32 + 0.5) / s as f32 - 0.5;
            let dist = (2.0 * dx * dx).sqrt();
            assert!(
                dist < 0.16,
                "probe dist {dist} must be inside the 0.16 hole"
            );
        }
    }

    #[test]
    fn both_sizes_render() {
        for size in [IconSize::Px16, IconSize::Px24] {
            for state in states() {
                let (w, h, rgba) = state.icon_rgba(size);
                assert_eq!((w, h), (size.px(), size.px()));
                assert_eq!(rgba.len(), (w as usize) * (h as usize) * 4);
                // 每态至少有一个不透明像素（不是空图）。
                assert!(rgba.as_chunks::<4>().0.iter().any(|p| p[3] > 200));
            }
        }
    }

    // ── PNG 编码 ────────────────────────────────────────────────────────

    #[test]
    fn png_roundtrip_decodes_the_same_pixels() {
        for size in [IconSize::Px16, IconSize::Px24] {
            for state in states() {
                let (_, _, rgba) = state.icon_rgba(size);
                let png = png_encode(size.px(), size.px(), &rgba);
                assert!(png.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]));
                let idat = extract_chunk(&png, b"IDAT").expect("IDAT chunk");
                let raw = zlib_decompress(idat).expect("deflate stored stream");
                let row_len = 1 + size.px() as usize * 4;
                assert_eq!(raw.len(), row_len * size.px() as usize);
                for y in 0..size.px() as usize {
                    let row = &raw[y * row_len..(y + 1) * row_len];
                    assert_eq!(row[0], 0, "filter byte must be None");
                    let pixels = (row_len - 1) * y;
                    assert_eq!(&row[1..], &rgba[pixels..pixels + row_len - 1]);
                }
            }
        }
    }

    #[test]
    fn png_ihdr_carries_rgba_dimensions() {
        let png = png_encode(16, 16, &[0; 16 * 16 * 4]);
        let ihdr = extract_chunk(&png, b"IHDR").unwrap();
        assert_eq!(&ihdr[0..4], &16u32.to_be_bytes());
        assert_eq!(&ihdr[4..8], &16u32.to_be_bytes());
        assert_eq!(&ihdr[8..], &[8, 6, 0, 0, 0], "bit depth 8, color type RGBA");
        assert!(extract_chunk(&png, b"IEND").unwrap().is_empty());
    }

    #[test]
    fn crc32_matches_known_vector() {
        // "123456789" 的 CRC-32/ISO-HDLC 校验值（校验和自测）。
        assert_eq!(crc32(b"123456789"), 0xcbf43926);
        assert_eq!(crc32(&[]), 0x00000000);
    }

    #[test]
    fn adler32_matches_known_vector() {
        // 与 Python `zlib.adler32` 同值（校验和自测）。
        assert_eq!(adler32(b"123456789"), 0x091e01de);
        assert_eq!(adler32(&[]), 0x00000001);
    }

    // ── headless no-op（纪律四）─────────────────────────────────────────

    #[test]
    fn headless_publish_is_a_noop_without_touching_the_filesystem() {
        let dir = std::env::temp_dir().join("meshlet-tray-headless");
        let _ = std::fs::remove_dir_all(&dir);
        let sink = TraySink::new(&dir);
        let env = EnvProbe::default(); // 全空 = tty / CI
        assert!(!env.has_desktop_session());

        let write = sink
            .publish_with(&TrayStatus::new(TrayState::Online, None, "meshlet0"), &env)
            .expect("headless publish must not error");
        assert_eq!(write, TrayWrite::Skipped);
        assert!(
            !dir.exists(),
            "headless publish must not create the tray dir"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn writes_icons_and_status_on_a_desktop_session_then_stays_idempotent() {
        let dir = std::env::temp_dir().join("meshlet-tray-desktop");
        let _ = std::fs::remove_dir_all(&dir);
        let sink = TraySink::new(&dir);
        let env = EnvProbe {
            display: Some(":0".into()),
            ..EnvProbe::default()
        };
        assert!(env.has_desktop_session());

        let first = TrayStatus::new(TrayState::Online, Some("laptop"), "meshlet0");
        assert_eq!(
            sink.publish_with(&first, &env).expect("desktop publish"),
            TrayWrite::Written
        );
        // 同内容再发 = 不重写（幂等）。
        assert_eq!(
            sink.publish_with(&first, &env).unwrap(),
            TrayWrite::Unchanged
        );

        // 状态变化 = 换图。
        let second = TrayStatus::new(TrayState::Offline, Some("laptop"), "meshlet0");
        assert_eq!(
            sink.publish_with(&second, &env).expect("state change"),
            TrayWrite::Written
        );
        let status = std::fs::read_to_string(sink.dir().join("status.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&status).unwrap();
        assert_eq!(value["state"], "Meshlet offline");
        let updated = value["updated_at"]
            .as_str()
            .expect("updated_at must be written");
        assert!(
            chrono::DateTime::parse_from_rfc3339(updated).is_ok(),
            "updated_at must be RFC3339, got {updated}"
        );
        for name in ["icon-16.png", "icon-24.png"] {
            let bytes = std::fs::read(sink.dir().join(name)).unwrap();
            assert!(
                bytes.starts_with(&[0x89, b'P', b'N', b'G']),
                "{name} must be a PNG"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn session_type_alone_counts_as_a_desktop_session() {
        assert!(EnvProbe {
            session_type: Some("wayland".into()),
            ..EnvProbe::default()
        }
        .has_desktop_session());
        assert!(!EnvProbe {
            session_type: Some("tty".into()),
            ..EnvProbe::default()
        }
        .has_desktop_session());
    }

    // ── 辅助 ────────────────────────────────────────────────────────────

    fn states() -> [TrayState; 4] {
        [
            TrayState::Online,
            TrayState::TunnelOnly,
            TrayState::TunnelDrift,
            TrayState::Offline,
        ]
    }

    /// 按 chunk 名取数据（跳过长度与 CRC 字段）。
    fn extract_chunk<'a>(png: &'a [u8], type_: &[u8; 4]) -> Option<&'a [u8]> {
        let mut i = 8usize;
        while i + 8 <= png.len() {
            let len = u32::from_be_bytes([png[i], png[i + 1], png[i + 2], png[i + 3]]) as usize;
            let t = &png[i + 4..i + 8];
            let start = i + 8;
            if t == type_ {
                return Some(&png[start..start + len]);
            }
            i = start + len + 4;
        }
        None
    }

    /// 编译期确认映射目标都是仓内已有枚举（防漂移）。
    #[test]
    fn mapped_enums_are_the_repos_own() {
        assert_eq!(PresenceState::Online.as_str(), "online");
        assert_eq!(PresenceState::TunnelOnly.as_str(), "tunnel_only");
        assert_eq!(PresenceState::Offline.as_str(), "offline");
        assert_eq!(Reason::KernelDrift.as_str(), "kernel_drift");
        // 隧道异常态的另一个对位：应用中失败（ApplyStatus 状态机允许的迁移）。
        assert!(ApplyStatus::Applying.can_transition_to(ApplyStatus::Failed));
        assert_ne!(DeviceStatus::Active, DeviceStatus::Revoked);
    }
}
