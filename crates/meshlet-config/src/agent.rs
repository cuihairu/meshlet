//! agent 侧配置（[`AgentConfig`]）：原始 TOML schema（`Raw*`，crate 私有）、
//! 公开结构与默认值、[`AgentConfig::from_toml`] 校验；tray / upgrade /
//! dataplane / direct_connect / probe / mcp / ssh_config_sync 子配置。

use crate::ConfigError;
use serde::Deserialize;

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawDataplaneConfig {
    enabled: Option<bool>,
    interface: Option<String>,
    private_key_file: Option<String>,
    hub_endpoint: Option<String>,
    poll_interval_secs: Option<u64>,
    direct_connect: Option<RawDirectConnectConfig>,
    probe: Option<RawProbeConfig>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawDirectConnectConfig {
    enabled: Option<bool>,
    listen_port: Option<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawProbeConfig {
    enabled: Option<bool>,
    interval_secs: Option<u64>,
    window: Option<usize>,
    /// SEL-002 迟滞切换：新路径须连续 N 采样且优于现路径 ≥ margin。
    /// `margin` 以百分比给出（30 = 30%）。默认 3 / 30%。
    switch_required: Option<usize>,
    switch_margin_percent: Option<f64>,
    /// SEL-003 恢复门：直连劣化回中继后须连续 N 轮健康才切回（默认 3）。
    recovery_required: Option<usize>,
    /// SEL-003 时延劣化阈值（毫秒）：窗口 RTT 中位数 ≥ 此值判劣化回中继
    /// （默认 800，依据见 ProbeConfig::degrade_rtt_ms）。
    degrade_rtt_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawAgentConfig {
    server_url: Option<String>,
    state_dir: Option<String>,
    device_token: Option<String>,
    /// 自举码（ZeroTier 式自举注册的入口凭据）：`device_token` 缺省时用它向
    /// `POST /api/v1/device-registrations` 自举注册，批准后即转为正式设备。
    bootstrap_token: Option<String>,
    /// 自举注册时上报的设备名（同网络内唯一，跨设备/待审批申请）。
    device_name: Option<String>,
    tray: Option<RawTrayConfig>,
    upgrade: Option<RawUpgradeConfig>,
    dataplane: RawDataplaneConfig,
    ssh_config_sync: Option<RawSshConfigSyncConfig>,
    mcp: Option<RawMcpConfig>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawMcpConfig {
    enabled: Option<bool>,
    port: Option<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawSshConfigSyncConfig {
    enabled: Option<bool>,
    manage_include: Option<bool>,
    target_homes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawUpgradeConfig {
    enabled: Option<bool>,
    check_interval_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawTrayConfig {
    notifications: Option<bool>,
    status_notifier_item: Option<bool>,
}

/// Agent 配置。
#[derive(Debug, Clone, PartialEq)]
pub struct AgentConfig {
    pub server_url: String,
    pub state_dir: String,
    /// 设备凭证（enrollment 返回的 agent token，仅此一次下发）：拉取期望配置
    /// 用；`[dataplane] enabled` 且未配置时启动即报失败。
    pub device_token: Option<String>,
    /// 自举码（ZeroTier 式）：缺 `device_token` 时用它注册自身，落 Pending 等
    /// 控制中心审批。**原始凭据只写 0600 配置文件**，服务端只存摘要（§11.3）。
    pub bootstrap_token: Option<String>,
    /// 自举注册时的设备名（必须显式配置——注册名要可读，不能取默认值）。
    pub device_name: Option<String>,
    /// 桌面集成（P1/P2）：两个能力独立开关，默认均关闭。
    pub tray: TrayConfig,
    pub upgrade: UpgradeConfig,
    pub dataplane: DataplaneConfig,
    /// SSH alias 同步（`[ssh_config_sync]`）：写用户 `~/.ssh` 属敏感面，
    /// **默认全关**——`enabled` 开才写 `~/.ssh/meshlet.conf`（仅 meshlet
    /// 专用文件，不碰用户 config）；`manage_include` 开才往 `~/.ssh/config`
    /// 追加 `Include meshlet.conf`（改前备份原文件一次）；`target_homes`
    /// 显式列出目标 home 目录（空 = 仅当前运行账号自己的 home）。
    pub ssh_config_sync: SshConfigSyncConfig,
    /// MCP 本地服务（`[mcp]`）：AI 客户端经 loopback HTTP 查询本机 mesh 事实。
    /// **默认全关**——监听面默认不开，`enabled = true` 显式开启（2026-11-08）。
    pub mcp: McpConfig,
}

/// Agent 侧 MCP 服务开关（默认全关：监听面显式开启）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct McpConfig {
    /// 总开关：关 = 不监听任何端口（默认）。
    pub enabled: bool,
    /// 监听端口；`0` = 随机（实际端口写 `{state_dir}/mcp.json` 交接文件）。
    pub port: u16,
}

impl McpConfig {
    /// 关闭态（测试/默认构造用，语义与 [`Default::default`] 相同）。
    pub const OFF: Self = Self {
        enabled: false,
        port: 0,
    };
}

/// agent 侧 SSH alias 同步开关（默认全关）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SshConfigSyncConfig {
    /// 总开关：关 = 不写任何 `~/.ssh` 文件（默认）。
    pub enabled: bool,
    /// Include 行管理：开 = 检测并追加 `Include meshlet.conf` 到
    /// `~/.ssh/config`（缺失时追加、原文件先备份）。关 = 只写 fragment，
    /// 面板提示需手动加 Include。
    pub manage_include: bool,
    /// 目标 home 目录（绝对路径数组）：agent 以 root 服务运行时默认只写
    /// root 自己的 home——多账号机器配置本项后，对每个目标 home 写
    /// `<home>/.ssh/meshlet.conf`（属主钉成该 home 的属主用户、0600）、
    /// Include 追加/备份同样按目标 home 处理。空数组 = 维持「当前
    /// `$HOME` 单 home」旧语义（默认）。
    pub target_homes: Vec<std::path::PathBuf>,
}

impl SshConfigSyncConfig {
    pub const OFF: Self = Self {
        enabled: false,
        manage_include: false,
        target_homes: Vec::new(),
    };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeConfig {
    pub enabled: bool,
    pub check_interval_secs: u64,
}

impl Default for UpgradeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            check_interval_secs: 86_400,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrayConfig {
    /// Explicitly opt in to `org.freedesktop.Notifications`; no local popups by default.
    pub notifications: bool,
    /// Explicitly opt in to StatusNotifierItem registration.
    pub status_notifier_item: bool,
}

impl TrayConfig {
    pub const OFF: Self = Self {
        notifications: false,
        status_notifier_item: false,
    };
}

/// Agent 数据面配置（[ADR-007](../../docs/decisions/adr-007-linux-network-backend.md)）：
/// **默认全关**——关闭时 agent 只打印状态、不碰内核。
#[derive(Debug, Clone, PartialEq)]
pub struct DataplaneConfig {
    pub enabled: bool,
    /// 受管 WireGuard 接口名。
    pub interface: String,
    /// 本设备 WireGuard 私钥文件（本地注入，服务端永不携带——ADR-010）。
    pub private_key_file: Option<String>,
    /// hub 的可达 endpoint（`host:port`）兜底：server 未通过 `[dataplane]
    /// advertise_ip` + `listen_port` 通告时使用。
    pub hub_endpoint: Option<String>,
    /// 轮询间隔（秒）：到期向 server 拉取期望配置，有变更才重放（§10.1）。
    pub poll_interval_secs: u64,
    /// P2P 直连（§12 P2P）：agent 每帧心跳上报候选端点，数据面尝试绕过 hub
    /// 直连对端；不可达时自动回退 hub 中继。**默认开启**（批次④防火墙联动
    /// 已落地、双真机走查通过后的产品决策——直连是核心目标，hub 中继只是
    /// 兜底）：开直连会把数据面 wg 接口钉到固定监听端口并放行该 UDP 端口。
    /// 显式关闭：`[dataplane.direct_connect] enabled = false`。
    pub direct_connect: DirectConnectConfig,
    /// SEL-001 候选端点探测：对每 peer 全部候选端点发 ICMP 轻量探测，采集
    /// RTT / 丢包 / 抖动滑动窗口。**默认开启**（2026-11-13 spoke 事故后
    /// 随 direct_connect 主开关伴生开启——探测是直连安全网）；
    /// `direct_connect.enabled` 且有候选端点时才真正发探测。
    pub probe: ProbeConfig,
}

/// P2P 直连开关与 WireGuard 监听端口。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectConnectConfig {
    pub enabled: bool,
    /// 数据面 WireGuard 监听端口（直连候选端点用）：防火墙需放行该 UDP 端口。
    pub listen_port: u16,
}

impl Default for DirectConnectConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_port: 51820,
        }
    }
}

/// SEL-001 候选端点探测配置（任务书：agent 周期，默认 5s，可配）。
#[derive(Debug, Clone, PartialEq)]
pub struct ProbeConfig {
    /// 是否开启候选端点探测。默认开（2026-11-13 spoke 互断事故后从关改为开）：
    /// `direct_connect` 自 98c75fe 起默认开，探测是它的安全网——SEL-003 劣化
    /// 判定（丢包尖峰/超时 → 立即回中继）只吃探测窗口，探测关 = 直连劣化后
    /// 无限钉死黑洞（真机 2026-11-13：imac↔work5 直连在 ZT 劣化窗内 payload
    /// 全丢而握手依旧新鲜，数小时不自愈）。开关仍需 `direct_connect.enabled`
    /// 且对端有候选端点才实际发探测（无候选 = 无目标，no-op）。
    pub enabled: bool,
    /// 探测周期（秒）：默认 5s（任务书）。下限 1。
    pub interval_secs: u64,
    /// 每目标滑动窗口容量（最近 N 次探测）：SEL-002 的评分/迟滞判定在窗口上
    /// 做，过小会随单次抖动频繁翻转。默认 20。
    pub window: usize,
    /// SEL-002 迟滞切换：新路径须**连续** N 次采样（默认 3）且得分优于现路径
    /// ≥ `switch_margin` 才切换，防抖（抖动场景不切）。
    pub switch_required: usize,
    /// SEL-002 迟滞裕量（0.0..=1.0；默认 0.30 = 30%）。
    pub switch_margin: f64,
    /// SEL-003 恢复门：直连劣化回中继后须**连续** N 轮健康才允许切回（防抖）。
    /// 默认 3。
    pub recovery_required: usize,
    /// SEL-003 时延劣化阈值（毫秒）：探测窗口 RTT 中位数 ≥ 此值判直连劣化，
    /// 立即回中继。默认 800。
    ///
    /// **默认值依据**（2026-11-13 残余跟进，SEL-002 双机验收实锤）：探测传输
    /// 超时是 1000ms（Linux `ping -W 1` / Windows `ping -w 1000`）——超时的
    /// 样本记 Lost，已由丢包/超时规则兜住；800ms 恰好补上「探测成功但 RTT
    /// 深劣化」的超时前盲带（真机实录 1715ms `probe_ok` 仍钉直连数小时）。
    /// 800ms ≈ 健康网格基线（实测 8–17ms）的 50 倍，远超同网段 LAN 直连的
    /// 合理水位；此劣化程度下 hub 中继（hub 侧视野实测同窗 8–14ms）严格更优。
    /// 中位数语义 = 「连续 N 拍超阈值」（window 容量 20 @5s ≈ 持续 100s 才
    /// 命中，单点抖动不触发）；恢复仍走 recovery_required 迟滞。
    /// 注意：>1000 的取值落在探测超时之外，几乎不可达（样本已记 Lost），
    /// 配大等于关闭时延维度。
    pub degrade_rtt_ms: u64,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 5,
            window: 20,
            switch_required: 3,
            switch_margin: 0.30,
            recovery_required: 3,
            degrade_rtt_ms: 800,
        }
    }
}

impl Default for DataplaneConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: "wg0".into(),
            private_key_file: None,
            hub_endpoint: None,
            poll_interval_secs: 30,
            direct_connect: DirectConnectConfig::default(),
            probe: ProbeConfig::default(),
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server_url: "https://127.0.0.1".into(),
            state_dir: "/var/lib/meshlet".into(),
            device_token: None,
            bootstrap_token: None,
            device_name: None,
            tray: TrayConfig::default(),
            upgrade: UpgradeConfig::default(),
            dataplane: DataplaneConfig::default(),
            ssh_config_sync: SshConfigSyncConfig::OFF,
            mcp: McpConfig::default(),
        }
    }
}

impl AgentConfig {
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let raw: RawAgentConfig =
            toml::from_str(input).map_err(|e| ConfigError::Parse(e.to_string()))?;
        let default = Self::default();
        let server_url = raw.server_url.unwrap_or(default.server_url);
        if !(server_url.starts_with("http://") || server_url.starts_with("https://")) {
            return Err(ConfigError::InvalidServerUrl(server_url));
        }
        let dataplane = raw.dataplane;
        let tray = match raw.tray {
            Some(raw_tray) => TrayConfig {
                notifications: raw_tray.notifications.unwrap_or(default.tray.notifications),
                status_notifier_item: raw_tray
                    .status_notifier_item
                    .unwrap_or(default.tray.status_notifier_item),
            },
            None => default.tray,
        };
        let raw_upgrade = raw.upgrade.unwrap_or_default();
        let check_interval_secs = raw_upgrade
            .check_interval_secs
            .unwrap_or(default.upgrade.check_interval_secs);
        if check_interval_secs < 1 {
            return Err(ConfigError::InvalidUpgrade(
                "upgrade.check_interval_secs must be at least 1".into(),
            ));
        }
        let upgrade = UpgradeConfig {
            enabled: raw_upgrade.enabled.unwrap_or(default.upgrade.enabled),
            check_interval_secs,
        };
        let dp_interface = dataplane
            .interface
            .map(|s| s.trim().to_string())
            .unwrap_or(default.dataplane.interface);
        if dp_interface.is_empty() {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.interface must not be empty".into(),
            ));
        }
        let poll_interval_secs = dataplane
            .poll_interval_secs
            .unwrap_or(default.dataplane.poll_interval_secs);
        if poll_interval_secs < 1 {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.poll_interval_secs must be at least 1".into(),
            ));
        }
        let raw_dc = dataplane.direct_connect.unwrap_or_default();
        let direct_connect = DirectConnectConfig {
            enabled: raw_dc
                .enabled
                .unwrap_or(default.dataplane.direct_connect.enabled),
            listen_port: raw_dc
                .listen_port
                .unwrap_or(default.dataplane.direct_connect.listen_port),
        };
        if direct_connect.listen_port == 0 {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.direct_connect.listen_port must be 1..=65535".into(),
            ));
        }
        let raw_probe = dataplane.probe.unwrap_or_default();
        let probe = ProbeConfig {
            enabled: raw_probe.enabled.unwrap_or(default.dataplane.probe.enabled),
            interval_secs: raw_probe
                .interval_secs
                .unwrap_or(default.dataplane.probe.interval_secs),
            window: raw_probe.window.unwrap_or(default.dataplane.probe.window),
            switch_required: raw_probe
                .switch_required
                .unwrap_or(default.dataplane.probe.switch_required),
            switch_margin: raw_probe
                .switch_margin_percent
                .map(|p| p / 100.0)
                .unwrap_or(default.dataplane.probe.switch_margin),
            recovery_required: raw_probe
                .recovery_required
                .unwrap_or(default.dataplane.probe.recovery_required),
            degrade_rtt_ms: raw_probe
                .degrade_rtt_ms
                .unwrap_or(default.dataplane.probe.degrade_rtt_ms),
        };
        if probe.interval_secs < 1 {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.probe.interval_secs must be at least 1".into(),
            ));
        }
        if probe.window < 1 {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.probe.window must be at least 1".into(),
            ));
        }
        if probe.switch_required < 1 {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.probe.switch_required must be at least 1".into(),
            ));
        }
        if !(0.0..=1.0).contains(&probe.switch_margin) {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.probe.switch_margin_percent must be 0..=100".into(),
            ));
        }
        if probe.recovery_required < 1 {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.probe.recovery_required must be at least 1".into(),
            ));
        }
        if probe.degrade_rtt_ms < 1 {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.probe.degrade_rtt_ms must be at least 1".into(),
            ));
        }
        Ok(Self {
            server_url,
            state_dir: raw.state_dir.unwrap_or(default.state_dir),
            device_token: raw
                .device_token
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            bootstrap_token: raw
                .bootstrap_token
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            device_name: raw
                .device_name
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            tray,
            upgrade,
            dataplane: DataplaneConfig {
                enabled: dataplane.enabled.unwrap_or(default.dataplane.enabled),
                interface: dp_interface,
                private_key_file: dataplane.private_key_file,
                hub_endpoint: dataplane
                    .hub_endpoint
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
                poll_interval_secs,
                direct_connect,
                probe,
            },
            ssh_config_sync: match raw.ssh_config_sync {
                Some(raw_sync) => SshConfigSyncConfig {
                    enabled: raw_sync.enabled.unwrap_or(default.ssh_config_sync.enabled),
                    manage_include: raw_sync
                        .manage_include
                        .unwrap_or(default.ssh_config_sync.manage_include),
                    target_homes: raw_sync
                        .target_homes
                        // 模板缺省恒为空 = 单 home 旧语义（见结构体文档）。
                        .unwrap_or_default()
                        .into_iter()
                        .map(|s| std::path::PathBuf::from(s.trim()))
                        .filter(|p| !p.as_os_str().is_empty())
                        .collect(),
                },
                None => SshConfigSyncConfig::OFF,
            },
            mcp: match raw.mcp {
                Some(raw_mcp) => McpConfig {
                    enabled: raw_mcp.enabled.unwrap_or(default.mcp.enabled),
                    port: raw_mcp.port.unwrap_or(default.mcp.port),
                },
                None => McpConfig::default(),
            },
        })
    }
}

#[cfg(test)]
mod tests;
