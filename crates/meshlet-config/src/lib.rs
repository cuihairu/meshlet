//! meshlet-config：TOML 配置加载与校验（[存档 §4.1](../../docs/review/chatgpt-2026-10-13.md)）。
//!
//! Overlay CIDR 默认 `10.240.0.0/16` 仅为默认值，**可配置**（ADR-004）。

use meshlet_domain::Ipv4Cidr;
use serde::Deserialize;

pub const DEFAULT_OVERLAY_CIDR: &str = "10.240.0.0/16";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("parse toml: {0}")]
    Parse(String),
    #[error("invalid overlay_cidr {0:?}")]
    InvalidOverlayCidr(String),
    #[error("invalid server url {0:?} (expected http(s)://host)")]
    InvalidServerUrl(String),
    #[error("invalid tunnel_mtu {0} (1280..=65535 required: below 1280 breaks IPv6-in-tunnel and common TLS paths, §7.5)")]
    InvalidTunnelMtu(u32),
    #[error("invalid dataplane config: {0}")]
    InvalidDataPlane(String),
    #[error("invalid upgrade config: {0}")]
    InvalidUpgrade(String),
    #[error("missing required field: {0}")]
    MissingField(String),
}

/// 隧道 MTU 的合理下界：1280 是 IPv6 最小 MTU——低于它的隧道承载不了
/// IPv6-in-tunnel 与绝大多数大包路径（存档 §7.5「避免明显不合理的 MTU」）。
pub const MIN_TUNNEL_MTU: u32 = 1280;
/// 内核接口 MTU 上限。
pub const MAX_TUNNEL_MTU: u32 = 65535;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RawServerConfig {
    bind: Option<String>,
    database_path: Option<String>,
    overlay_cidr: Option<String>,
    cookie_secure: Option<bool>,
    console_dir: Option<String>,
    presence_agent_window_secs: Option<u64>,
    presence_handshake_window_secs: Option<u64>,
    backup: Option<RawBackupConfig>,
    tunnel_mtu: Option<u32>,
    dataplane: Option<RawDataPlaneConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RawBackupConfig {
    dir: Option<String>,
    auto: Option<bool>,
    interval_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RawDataPlaneConfig {
    enabled: Option<bool>,
    interface: Option<String>,
    listen_port: Option<u16>,
    private_key_file: Option<String>,
}

/// 备份配置（存档 §17.4）：只写本地路径，默认**不**自动备份。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupConfig {
    /// 备份目录。`None` = 备份未配置（`POST /system/backup` 返回 503）。
    pub dir: Option<String>,
    /// 定时自动备份开关——必须显式置 true 才开启（默认 false，§17.4
    /// 「备份 ≠ 同步」：无任何外发/云上传/遥测）。
    pub auto: bool,
    /// 自动备份间隔（秒，默认 86400）。
    pub interval_secs: u64,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            dir: None,
            auto: false,
            interval_secs: 86400,
        }
    }
}

/// 数据面配置（ADR-007）：server 进程在本机执行的 WireGuard/路由接线。
/// `enabled = false`（默认）时修订 apply 保持「确定性失败可见」（§10.3）；
/// `enabled = true` 时 apply 走 Linux 网络后端真实执行（需 NET_ADMIN）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPlaneConfig {
    /// 显式开启才接管内核（默认关闭——升级不悄悄改网络栈）。
    pub enabled: bool,
    /// 受管 WireGuard 接口名（默认 `wg0`）。后端拒绝触碰其他接口。
    pub interface: String,
    /// 隧道监听端口；`None` = 不改接口现有端口（幂等重应用）。
    pub listen_port: Option<u16>,
    /// hub 私钥文件路径（单行 base64）。服务端**不落库**私钥（ADR-010），
    /// apply 时读取；`None` = 保留接口现有私钥。首装必须提供，否则无法握手。
    pub private_key_file: Option<String>,
}

impl Default for DataPlaneConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: "wg0".to_string(),
            listen_port: None,
            private_key_file: None,
        }
    }
}

/// Server 配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    pub bind: String,
    pub database_path: String,
    pub overlay_cidr: Ipv4Cidr,
    /// 会话 Cookie 的 `Secure` 属性。生产环境（HTTPS 反代终止 TLS）必须为 true。
    pub cookie_secure: bool,
    /// Web 控制台静态文件目录（`console/dist`）。缺省不托管控制台。
    pub console_dir: Option<String>,
    /// 在线判定：agent 上报新鲜窗口（秒，默认 300）。
    pub presence_agent_window_secs: u64,
    /// 在线判定：握手新鲜窗口（秒，默认 120）。
    pub presence_handshake_window_secs: u64,
    /// 备份（存档 §17.4）：默认全关。
    pub backup: BackupConfig,
    /// 计划隧道 MTU（存档 §7.5「MTU 可配置」）：`None` = 未显式配置，agent
    /// 按 WireGuard 默认 1420 组接口。诊断（§12.7）据此解释大包/分片问题。
    pub tunnel_mtu: Option<u32>,
    /// 数据面（ADR-007）：本机 WireGuard/路由接线，默认关闭。
    pub dataplane: DataPlaneConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8080".into(),
            database_path: "meshlet.db".into(),
            overlay_cidr: DEFAULT_OVERLAY_CIDR.parse().expect("valid default cidr"),
            cookie_secure: false,
            console_dir: None,
            presence_agent_window_secs: 300,
            presence_handshake_window_secs: 120,
            backup: BackupConfig::default(),
            tunnel_mtu: None,
            dataplane: DataPlaneConfig::default(),
        }
    }
}

impl ServerConfig {
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let raw: RawServerConfig =
            toml::from_str(input).map_err(|e| ConfigError::Parse(e.to_string()))?;
        let default = Self::default();
        let overlay_cidr = match raw.overlay_cidr {
            Some(s) => s
                .parse()
                .map_err(|_| ConfigError::InvalidOverlayCidr(s.clone()))?,
            None => default.overlay_cidr,
        };
        let backup = match raw.backup {
            Some(raw_backup) => BackupConfig {
                dir: raw_backup.dir.or(default.backup.dir),
                auto: raw_backup.auto.unwrap_or(default.backup.auto),
                interval_secs: raw_backup
                    .interval_secs
                    .unwrap_or(default.backup.interval_secs)
                    .max(1),
            },
            None => default.backup,
        };
        let tunnel_mtu = match raw.tunnel_mtu {
            Some(mtu) if !(MIN_TUNNEL_MTU..=MAX_TUNNEL_MTU).contains(&mtu) => {
                return Err(ConfigError::InvalidTunnelMtu(mtu));
            }
            other => other,
        };
        let dataplane = match raw.dataplane {
            Some(raw_dp) => {
                let interface = raw_dp
                    .interface
                    .map(|s| s.trim().to_string())
                    .unwrap_or(default.dataplane.interface);
                if interface.is_empty() {
                    return Err(ConfigError::InvalidDataPlane(
                        "interface must not be empty".into(),
                    ));
                }
                if raw_dp.listen_port == Some(0) {
                    return Err(ConfigError::InvalidDataPlane(
                        "listen_port must be 1..=65535".into(),
                    ));
                }
                DataPlaneConfig {
                    enabled: raw_dp.enabled.unwrap_or(false),
                    interface,
                    listen_port: raw_dp.listen_port,
                    private_key_file: raw_dp.private_key_file,
                }
            }
            None => DataPlaneConfig::default(),
        };
        Ok(Self {
            bind: raw.bind.unwrap_or(default.bind),
            database_path: raw.database_path.unwrap_or(default.database_path),
            overlay_cidr,
            cookie_secure: raw.cookie_secure.unwrap_or(default.cookie_secure),
            console_dir: raw.console_dir.or(default.console_dir),
            presence_agent_window_secs: raw
                .presence_agent_window_secs
                .unwrap_or(default.presence_agent_window_secs),
            presence_handshake_window_secs: raw
                .presence_handshake_window_secs
                .unwrap_or(default.presence_handshake_window_secs),
            backup,
            tunnel_mtu,
            dataplane,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawDataplaneConfig {
    enabled: Option<bool>,
    interface: Option<String>,
    private_key_file: Option<String>,
    hub_endpoint: Option<String>,
    poll_interval_secs: Option<u64>,
    direct_connect: Option<RawDirectConnectConfig>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawDirectConnectConfig {
    enabled: Option<bool>,
    listen_port: Option<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// P2P 直连（§12 P2P）：agent 每轮心跳上报候选端点，数据面尝试绕过 hub
    /// 直连对端；不可达时自动回退 hub 中继。**默认开启**（数据面开启时生效）。
    pub direct_connect: DirectConnectConfig,
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

impl Default for DataplaneConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: "wg0".into(),
            private_key_file: None,
            hub_endpoint: None,
            poll_interval_secs: 30,
            direct_connect: DirectConnectConfig::default(),
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
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_defaults_use_documented_overlay() {
        let c = ServerConfig::default();
        assert_eq!(c.overlay_cidr.to_string(), "10.240.0.0/16");
        assert_eq!(c.bind, "127.0.0.1:8080");
    }

    #[test]
    fn server_config_parses_overrides() {
        let c = ServerConfig::from_toml(
            r#"
bind = "0.0.0.0:9443"
database_path = "/var/lib/meshlet/control.db"
overlay_cidr = "172.30.0.0/16"
"#,
        )
        .unwrap();
        assert_eq!(c.bind, "0.0.0.0:9443");
        assert_eq!(c.database_path, "/var/lib/meshlet/control.db");
        assert_eq!(c.overlay_cidr.to_string(), "172.30.0.0/16"); // 可配置，非协议常量
    }

    #[test]
    fn cookie_secure_defaults_false_and_parses() {
        // 本地开发默认 http（127.0.0.1）；生产部署在 HTTPS 反代后置 true（§11.4）。
        assert!(!ServerConfig::default().cookie_secure);
        let c = ServerConfig::from_toml("cookie_secure = true").unwrap();
        assert!(c.cookie_secure);
    }

    #[test]
    fn console_dir_defaults_none_and_parses() {
        assert!(ServerConfig::default().console_dir.is_none());
        let c = ServerConfig::from_toml("console_dir = \"console/dist\"").unwrap();
        assert_eq!(c.console_dir.as_deref(), Some("console/dist"));
    }

    #[test]
    fn presence_windows_default_and_parse() {
        let d = ServerConfig::default();
        assert_eq!(d.presence_agent_window_secs, 300);
        assert_eq!(d.presence_handshake_window_secs, 120);
        let c = ServerConfig::from_toml(
            "presence_agent_window_secs = 60\npresence_handshake_window_secs = 30",
        )
        .unwrap();
        assert_eq!(c.presence_agent_window_secs, 60);
        assert_eq!(c.presence_handshake_window_secs, 30);
    }

    #[test]
    fn server_config_rejects_bad_cidr() {
        let err = ServerConfig::from_toml("overlay_cidr = \"10.240.0.1/16\"").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidOverlayCidr(_)));
        let err = ServerConfig::from_toml("overlay_cidr = \"not-a-cidr\"").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidOverlayCidr(_)));
    }

    #[test]
    fn tunnel_mtu_defaults_none_and_parses_with_bounds() {
        // §7.5「MTU 可配置」：默认未配置（诊断按 WireGuard 默认 1420 解释）。
        assert_eq!(ServerConfig::default().tunnel_mtu, None);
        let c = ServerConfig::from_toml("tunnel_mtu = 1380").unwrap();
        assert_eq!(c.tunnel_mtu, Some(1380));
        // 边界：1280（IPv6 最小 MTU）与 65535 合法；之下/之上明显不合理，拒绝。
        assert_eq!(
            ServerConfig::from_toml("tunnel_mtu = 1280")
                .unwrap()
                .tunnel_mtu,
            Some(1280)
        );
        assert_eq!(
            ServerConfig::from_toml("tunnel_mtu = 65535")
                .unwrap()
                .tunnel_mtu,
            Some(65535)
        );
        for bad in [1279, 65536] {
            let err = ServerConfig::from_toml(&format!("tunnel_mtu = {bad}")).unwrap_err();
            assert!(matches!(err, ConfigError::InvalidTunnelMtu(_)), "{bad}");
        }
    }

    #[test]
    fn dataplane_defaults_off_and_parses_explicit_section() {
        // 默认不接管内核：升级不悄悄改网络栈（§10.3 接线前确定性失败可见）。
        assert!(!ServerConfig::default().dataplane.enabled);
        assert_eq!(ServerConfig::default().dataplane.interface, "wg0");

        let c = ServerConfig::from_toml(
            r#"
[dataplane]
enabled = true
interface = "mesh0"
listen_port = 51820
private_key_file = "/etc/meshlet/hub.key"
"#,
        )
        .unwrap();
        assert!(c.dataplane.enabled);
        assert_eq!(c.dataplane.interface, "mesh0");
        assert_eq!(c.dataplane.listen_port, Some(51820));
        assert_eq!(
            c.dataplane.private_key_file.as_deref(),
            Some("/etc/meshlet/hub.key")
        );

        // 只开 enabled：其余默认（接口 wg0，不动现有私钥/端口）。
        let c = ServerConfig::from_toml("[dataplane]\nenabled = true").unwrap();
        assert!(c.dataplane.enabled);
        assert_eq!(c.dataplane.interface, "wg0");
        assert_eq!(c.dataplane.listen_port, None);
    }

    #[test]
    fn dataplane_rejects_empty_interface_and_zero_port() {
        let err = ServerConfig::from_toml(
            r#"
[dataplane]
enabled = true
interface = "  "
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidDataPlane(_)));

        let err = ServerConfig::from_toml("[dataplane]\nlisten_port = 0").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidDataPlane(_)));
    }

    #[test]
    fn server_config_rejects_bad_toml() {
        assert!(matches!(
            ServerConfig::from_toml("bind = "),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn backup_defaults_completely_off() {
        // §17.4「备份 ≠ 同步」：默认无目录、不自动、无任何外发。
        let d = ServerConfig::default().backup;
        assert_eq!(d, BackupConfig::default());
        assert!(d.dir.is_none());
        assert!(!d.auto);
        assert_eq!(d.interval_secs, 86400);
        // 无 [backup] 段的配置文件同样是全关。
        assert_eq!(
            ServerConfig::from_toml("bind = \"0.0.0.0:8080\"")
                .unwrap()
                .backup,
            BackupConfig::default()
        );
    }

    #[test]
    fn backup_section_parses_with_explicit_auto_flag() {
        let c = ServerConfig::from_toml(
            r#"
[backup]
dir = "/var/lib/meshlet/backups"
auto = true
interval_secs = 3600
"#,
        )
        .unwrap();
        assert_eq!(c.backup.dir.as_deref(), Some("/var/lib/meshlet/backups"));
        assert!(c.backup.auto);
        assert_eq!(c.backup.interval_secs, 3600);

        // 只给目录不开 auto：手动备份可用，定时仍关（显式配置位）。
        let c = ServerConfig::from_toml("[backup]\ndir = \"/tmp/b\"\n").unwrap();
        assert_eq!(c.backup.dir.as_deref(), Some("/tmp/b"));
        assert!(!c.backup.auto);
        assert_eq!(c.backup.interval_secs, 86400);
    }

    #[test]
    fn agent_config_validates_url_scheme() {
        let c = AgentConfig::from_toml("server_url = \"https://vps.example.com\"").unwrap();
        assert_eq!(c.server_url, "https://vps.example.com");

        let err = AgentConfig::from_toml("server_url = \"ftp://vps.example.com\"").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidServerUrl(_)));

        // 默认值可用。
        let d = AgentConfig::from_toml("").unwrap();
        assert_eq!(d, AgentConfig::default());
    }

    #[test]
    fn agent_tray_integrations_default_off_and_parse_independently() {
        assert!(!AgentConfig::default().tray.notifications);
        assert!(!AgentConfig::default().tray.status_notifier_item);
        assert_eq!(
            AgentConfig::from_toml("").unwrap().tray,
            TrayConfig::default()
        );

        let config = AgentConfig::from_toml("[tray]\nnotifications = true\n").unwrap();
        assert!(config.tray.notifications);
        assert!(!config.tray.status_notifier_item);

        let config = AgentConfig::from_toml("[tray]\nstatus_notifier_item = true\n").unwrap();
        assert!(!config.tray.notifications);
        assert!(config.tray.status_notifier_item);
    }

    #[test]
    fn agent_dataplane_defaults_off_and_parses_explicit_section() {
        // 默认全关：agent 不碰内核（§10.3 接线前确定性失败可见）。
        let d = AgentConfig::default();
        assert!(!d.dataplane.enabled);
        assert_eq!(d.dataplane.interface, "wg0");
        assert_eq!(d.dataplane.private_key_file, None);
        assert_eq!(d.dataplane.hub_endpoint, None);
        assert_eq!(d.dataplane.poll_interval_secs, 30);

        let c = AgentConfig::from_toml(
            r#"
server_url = "https://vps.example.com"
device_token = "tok-abc"

[dataplane]
enabled = true
interface = "mesh0"
private_key_file = "/etc/meshlet/device.key"
hub_endpoint = "vps.example.com:51820"
poll_interval_secs = 10
"#,
        )
        .unwrap();
        assert_eq!(c.device_token.as_deref(), Some("tok-abc"));
        assert!(c.dataplane.enabled);
        assert_eq!(c.dataplane.interface, "mesh0");
        assert_eq!(
            c.dataplane.private_key_file.as_deref(),
            Some("/etc/meshlet/device.key")
        );
        assert_eq!(
            c.dataplane.hub_endpoint.as_deref(),
            Some("vps.example.com:51820")
        );
        assert_eq!(c.dataplane.poll_interval_secs, 10);

        let c =
            AgentConfig::from_toml("[upgrade]\nenabled = true\ncheck_interval_secs = 300").unwrap();
        assert!(c.upgrade.enabled);
        assert_eq!(c.upgrade.check_interval_secs, 300);

        let d = AgentConfig::from_toml("").unwrap();
        assert!(!d.upgrade.enabled);
        assert_eq!(d.upgrade.check_interval_secs, 86_400);

        // 只开 enabled：其余默认。
        let c = AgentConfig::from_toml("[dataplane]\nenabled = true").unwrap();
        assert!(c.dataplane.enabled);
        assert_eq!(c.dataplane.interface, "wg0");
        assert_eq!(c.dataplane.poll_interval_secs, 30);
    }

    #[test]
    fn agent_dataplane_rejects_empty_interface_and_zero_poll() {
        let err = AgentConfig::from_toml(
            r#"
[dataplane]
enabled = true
interface = "  "
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidDataPlane(_)));

        let err = AgentConfig::from_toml("[dataplane]\npoll_interval_secs = 0").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidDataPlane(_)));

        let err = AgentConfig::from_toml("[upgrade]\ncheck_interval_secs = 0").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidUpgrade(_)));
    }

    #[test]
    fn agent_direct_connect_defaults_on_and_parses_section() {
        // §12 P2P：直连是数据面的设计核心，默认开启；监听端口 51820（WireGuard 默认）。
        let d = AgentConfig::default().dataplane.direct_connect;
        assert!(d.enabled);
        assert_eq!(d.listen_port, 51820);
        // 缺 [dataplane] 段同样默认开启。
        assert!(
            AgentConfig::from_toml("")
                .unwrap()
                .dataplane
                .direct_connect
                .enabled
        );

        let c = AgentConfig::from_toml(
            r#"
[dataplane.direct_connect]
enabled = false
listen_port = 20000
"#,
        )
        .unwrap();
        assert!(!c.dataplane.direct_connect.enabled);
        assert_eq!(c.dataplane.direct_connect.listen_port, 20000);
    }

    #[test]
    fn agent_direct_connect_rejects_zero_port_and_unknown_key() {
        let err =
            AgentConfig::from_toml("[dataplane.direct_connect]\nlisten_port = 0").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidDataPlane(_)));

        let err = AgentConfig::from_toml("[dataplane.direct_connect]\nbogus = 1").unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
    }
}
