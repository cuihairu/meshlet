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
//! `tooltip`（整句说明）与 `accessible_name`（无障碍短名）。四态的**轮廓互不相同**
//! （2026-11 托盘重设计，用户批准的四态方案，设计源
//! [apps/tray-app/src-tauri/icons](../../tray-app/src-tauri/icons/)，commit `e9d67d4`）：
//! 六边形螺母 / 右缘削角螺母 / 空心六边环 / 挖空感叹号六边形——颜色只是第二通道，
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
//! 图标是**简单自绘形状**，几何与色值逐项对齐已过审的四态 PNG 设计（32px 主图
//! `icon-{online,degraded,offline,error}.png` 的六边形语形＋`gen_icons.py` 的
//! 16px 可读性微调：offline 内孔放大、feather 收紧到 0.5px），不使用品牌 logo 代餐：
//! 仓内 [logo.svg](../../../logo.svg) 的主形是分层透镜多边形（`viewBox="0 0 1024 1024"`），
//! 细节在 16px 下会糊。状态信息由形状＋颜色双通道表达，渲染在 16/24px **原生 1:1**
//! 进行（不经过缩放，避免 gen_icons.py 记录的「32px 缩到 16px 内孔被抗锯齿残渣
//! 填塞」缺陷）。
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
            // 2026-11 四态重设计（tray-app PNG 采样）：青 / 铜削角 / 灰环 / 红感叹号。
            TrayState::Online => (0x32, 0x60, 0x72),
            TrayState::TunnelOnly => (0xC9, 0x7B, 0x2E),
            TrayState::TunnelDrift => (0xEF, 0x44, 0x44),
            TrayState::Offline => (0x69, 0x6F, 0x74),
        }
    }

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
    /// 带设备名、**本机虚拟 IP** 与网络接口的 tooltip（tooltip 是文本等价物，
    /// 不能只靠颜色）。`virtual_ip` 来自计划隧道地址（`plan.tunnel.address`，
    /// 与 `info` 命令同一链路）——用户要求托盘 tooltip / 菜单首行
    /// = 设备名 + 虚拟 IPv4 + 状态。待审批（无计划）时为 `None`。
    pub fn new(
        state: TrayState,
        device_name: Option<&str>,
        virtual_ip: Option<std::net::Ipv4Addr>,
        interface: &str,
    ) -> Self {
        let mut who = device_name
            .map(|n| format!("「{n}」"))
            .unwrap_or_else(|| format!("接口 {interface}"));
        if let Some(ip) = virtual_ip {
            who.push(' ');
            who.push_str(&ip.to_string());
        }
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
    /// Windows `%SESSIONNAME%`（`Console` / `RDP-Tcp#N`）：**本进程**处于
    /// 交互会话（用户会话 agent，`install.ps1` 的 HKCU Run 模型）。Linux 无此
    /// 变量，恒 `None`。
    pub session_name: Option<String>,
    /// Windows：机器上有活动控制台会话（`WTSGetActiveConsoleSessionId`）。
    /// 使以 SYSTEM/服务身份运行的 agent 也能为登录用户会话的托盘写状态图
    /// （托盘宿主是登录用户会话进程，状态经文件传递，见 [`TraySink`]）。
    pub console_session: bool,
}

impl EnvProbe {
    pub fn from_env() -> Self {
        Self {
            display: nonempty(var("DISPLAY")),
            wayland_display: nonempty(var("WAYLAND_DISPLAY")),
            session_type: nonempty(var("XDG_SESSION_TYPE")),
            session_name: nonempty(var("SESSIONNAME")),
            console_session: active_console_session(),
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
            || self.session_name.is_some()
            || self.console_session
    }
}

/// Windows：`WTSGetActiveConsoleSessionId() != 0xFFFFFFFF`（有活动控制台会话）。
/// 其它平台无此概念，恒 `false`。
fn active_console_session() -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;
        unsafe { WTSGetActiveConsoleSessionId() != 0xFFFF_FFFF }
    }
    #[cfg(not(windows))]
    {
        false
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
        // 幂等比较只看语义字段（state + tooltip + version + env）：
        // `updated_at` 每次都会变，不参与比较，否则每轮 tick 都会重写。
        if status_unchanged(&self.dir, status, env) {
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
            // 本地面板（tray-host `panel` 模块）的展示字段：版本 + 桌面会话探测。
            // 两者都是本进程已有的读数，不新增采集；`status_unchanged` 把它们
            // 一并比较——旧文件在升级后首次发布即补全，之后不会每轮重写。
            "version": env!("CARGO_PKG_VERSION"),
            "env": env_json(env),
        });
        write_file(&self.dir.join("status.json"), body.to_string().as_bytes())
            .map_err(|e| format!("write status.json: {e}"))?;
        Ok(TrayWrite::Written)
    }
}

fn read_file(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// EnvProbe → `status.json` 的 `env` 对象（发布与幂等比较共用同一构造，
/// 保证两边逐字段可比）。
fn env_json(env: &EnvProbe) -> serde_json::Value {
    serde_json::json!({
        "display": env.display.clone(),
        "wayland_display": env.wayland_display.clone(),
        "session_type": env.session_type.clone(),
        "session_name": env.session_name.clone(),
        "console_session": env.console_session,
    })
}

/// 上一份 `status.json` 的语义字段（state + tooltip + version + EnvProbe）是否
/// 与本次一致。
///
/// `version` / `env` 参与比较：升级前写出的旧文件在**升级后首次发布**即被补全
/// （否则 state/tooltip 未变就永远轮不到重写，本地面板会长期缺这两项）；补全后
/// 只要四者都不变就仍按幂等跳过，不会每轮 tick 重写。
fn status_unchanged(dir: &Path, status: &TrayStatus, env: &EnvProbe) -> bool {
    read_file(&dir.join("status.json"))
        .and_then(|prev| serde_json::from_str::<serde_json::Value>(&prev).ok())
        .map(|v| {
            v.get("state").and_then(|s| s.as_str()) == Some(status.state.accessible_name())
                && v.get("tooltip").and_then(|t| t.as_str()) == Some(status.tooltip.as_str())
                && v.get("version").and_then(|s| s.as_str()) == Some(env!("CARGO_PKG_VERSION"))
                && v.get("env") == Some(&env_json(env))
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
        // NLEN = LEN 的**反码**（RFC 1950 stored 块校验和）；此前误用
        // `wrapping_neg`（补码负数）恒差 1，规范解压器（如通用 zlib）会以
        // "invalid stored block lengths" 拒收整张 PNG——自研解码器不校验
        // NLEN 才一直没暴露（审核发现，tray 三连验收时以真实解压器取证）。
        out.extend_from_slice(&(!(len as u16)).to_le_bytes());
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
            let status = TrayStatus::new(
                state,
                Some("office-laptop"),
                Some("10.240.0.5".parse().unwrap()),
                "meshlet0",
            );
            assert!(status.tooltip.contains("office-laptop"));
            assert!(status.tooltip.contains("10.240.0.5"));
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

    /// ① 用户要求：托盘 tooltip / 菜单首行 = 设备名 + 虚拟 IPv4 + 状态。
    /// 虚拟 IP 从计划隧道地址注入（`plan.tunnel.address`，与 `info` 同一链路）。
    #[test]
    fn tooltip_carries_device_name_and_virtual_ip() {
        let status = TrayStatus::new(
            TrayState::Online,
            Some("office-laptop"),
            Some("10.240.0.5".parse().unwrap()),
            "meshlet0",
        );
        assert!(status
            .tooltip
            .starts_with("Meshlet「office-laptop」 10.240.0.5："));
        assert!(status.tooltip.contains("在线"));
        // 无设备名：回退接口名；无 IP（待审批）：不出现空占位。
        let no_name = TrayStatus::new(TrayState::Offline, None, None, "mesh0");
        assert!(no_name.tooltip.starts_with("Meshlet接口 mesh0："));
        assert!(!no_name.tooltip.contains("： "));
        // 无设备名但有 IP。
        let ip_only = TrayStatus::new(
            TrayState::TunnelOnly,
            None,
            Some("10.240.0.5".parse().unwrap()),
            "mesh0",
        );
        assert!(ip_only
            .tooltip
            .starts_with("Meshlet接口 mesh0 10.240.0.5："));
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
        for (state, rgb) in palette {
            assert_eq!(state.rgb(), rgb, "{state:?} palette drift");
            for size in [IconSize::Px16, IconSize::Px24] {
                let (_, _, rgba) = state.icon_rgba(size);
                for px in rgba.as_chunks::<4>().0 {
                    if px[3] == 0 {
                        continue;
                    }
                    assert_eq!(
                        (px[0], px[1], px[2]),
                        rgb,
                        "{state:?} stray color at {size:?}"
                    );
                }
            }
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

    /// NLEN 回归（审核发现）：stored 块的 NLEN 必须是 LEN 的**反码**
    /// （RFC 1950）。此前误用补码负数恒差 1，规范解压器拒收整张 PNG。
    /// 覆盖单块（< 0xff00）与多块（跨 CHUNK 边界）两种流。
    #[test]
    fn zlib_stream_nlen_is_the_ones_complement_of_len() {
        for total in [100usize, 0xff00, 0xff00 + 100] {
            let data: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
            let stream = zlib_stream(&data);
            let mut i = 2usize;
            let mut decoded = Vec::new();
            loop {
                assert_eq!(stream[i] >> 1, 0, "only stored blocks are written");
                let len = u16::from_le_bytes([stream[i + 1], stream[i + 2]]) as usize;
                let nlen = u16::from_le_bytes([stream[i + 3], stream[i + 4]]);
                assert_eq!(nlen, !(len as u16), "NLEN must be ~LEN (RFC 1950)");
                decoded.extend_from_slice(&stream[i + 5..i + 5 + len]);
                let last = stream[i] & 0x01 != 0;
                i += 5 + len;
                if last {
                    break;
                }
            }
            assert_eq!(decoded, data);
        }
    }

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
            .publish_with(
                &TrayStatus::new(TrayState::Online, None, None, "meshlet0"),
                &env,
            )
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

        let first = TrayStatus::new(TrayState::Online, Some("laptop"), None, "meshlet0");
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
        let second = TrayStatus::new(TrayState::Offline, Some("laptop"), None, "meshlet0");
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

    /// 升级回归：旧 agent 写出的 `status.json`（无 `version`/`env`）在升级后
    /// **首次发布**必须被补全——否则 state/tooltip 未变就永远轮不到重写，本地
    /// 面板会长期缺这两项；补全后仍按幂等跳过，EnvProbe 变了才再写一次。
    #[test]
    fn status_upgrade_backfills_version_and_env_without_rewriting_every_tick() {
        let dir = std::env::temp_dir().join("meshlet-tray-status-upgrade");
        let _ = std::fs::remove_dir_all(&dir);
        let sink = TraySink::new(&dir);
        let env = EnvProbe {
            display: Some(":0".into()),
            ..EnvProbe::default()
        };
        let status = TrayStatus::new(TrayState::Online, Some("laptop"), None, "meshlet0");
        std::fs::create_dir_all(sink.dir()).unwrap();
        // 旧 agent 的文件：state/tooltip 已是最新，但没有 version/env。
        let legacy = serde_json::json!({
            "state": status.state.accessible_name(),
            "tooltip": status.tooltip,
            "icon_16": "icon-16.png",
            "icon_24": "icon-24.png",
            "updated_at": "2026-11-03T00:00:00Z",
        });
        std::fs::write(sink.dir().join("status.json"), legacy.to_string()).unwrap();

        assert_eq!(
            sink.publish_with(&status, &env).expect("upgrade publish"),
            TrayWrite::Written
        );
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(sink.dir().join("status.json")).unwrap())
                .unwrap();
        assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(value["env"]["display"], ":0");
        // 补全后同内容 → 仍幂等（不会每轮 tick 重写）。
        assert_eq!(
            sink.publish_with(&status, &env).unwrap(),
            TrayWrite::Unchanged
        );
        // EnvProbe 变化 → 再写一次（比较确实覆盖 env）。
        let moved = EnvProbe {
            display: Some(":1".into()),
            ..EnvProbe::default()
        };
        assert_eq!(
            sink.publish_with(&status, &moved).unwrap(),
            TrayWrite::Written
        );
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

    /// Windows 用户会话 agent（`install.ps1` HKCU Run）：`%SESSIONNAME%`
    /// 已设置（`Console` / `RDP-Tcp#N`），必须视为有桌面会话——此前只探测
    /// X11/Wayland 变量，Windows 上恒为 headless，agent 从不写托盘 PNG，
    /// 托盘宿主永远落到 GDI 绿块（2026-10-31 验收第 7 项）。
    #[test]
    fn windows_session_name_counts_as_a_desktop_session() {
        assert!(EnvProbe {
            session_name: Some("Console".into()),
            ..EnvProbe::default()
        }
        .has_desktop_session());
        assert!(EnvProbe {
            session_name: Some("RDP-Tcp#5".into()),
            ..EnvProbe::default()
        }
        .has_desktop_session());
    }

    /// Windows SYSTEM/服务 agent（真实机 AtStartup 计划任务）：进程自身无
    /// `%SESSIONNAME%`，但机器上有活动控制台会话（用户已登录）→ 仍写托盘
    /// 状态，供登录用户会话的托盘宿主读取。无活动会话（CI、无头）→ false。
    #[test]
    fn windows_console_session_alone_counts_as_a_desktop_session() {
        assert!(EnvProbe {
            console_session: true,
            ..EnvProbe::default()
        }
        .has_desktop_session());
        assert!(!EnvProbe::default().has_desktop_session());
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
