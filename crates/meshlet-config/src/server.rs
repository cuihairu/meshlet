//! hub 侧配置（[`ServerConfig`]）：原始 TOML schema（`Raw*`，crate 私有）、
//! 公开结构与默认值、[`ServerConfig::from_toml`] 校验；备份 / 数据面 /
//! SSH 别名分发。

use crate::trusted_proxy::TrustedProxyConfig;
use crate::{ConfigError, DEFAULT_OVERLAY_CIDR, MAX_TUNNEL_MTU, MIN_TUNNEL_MTU};
use meshlet_domain::Ipv4Cidr;
use serde::Deserialize;

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
    trusted_proxies: Option<Vec<String>>,
    ssh_config: Option<RawSshDistributeConfig>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawSshDistributeConfig {
    /// 按设备名（peer name）覆写 alias/user/port；未覆写的节点用默认推导。
    overrides: Option<std::collections::BTreeMap<String, RawSshHostOverride>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawSshHostOverride {
    alias: Option<String>,
    user: Option<String>,
    port: Option<u16>,
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
    /// 可信反代来源（TODO-116）：仅当请求**直接来自**这些地址/网段时才采信
    /// `X-Forwarded-For`/`X-Real-IP`（默认仅回环 127.0.0.1/::1，可配 CIDR/地址）。
    pub trusted_proxies: TrustedProxyConfig,
    /// SSH 别名分发（`[ssh_config]`）：`None` = hub 未开启分发（计划不带
    /// `ssh_config` 段，agent 回落本机默认）。**存在该段 = 显式开启**——往
    /// 节点 `~/.ssh/meshlet.conf` 分发属敏感面，与 agent 侧写盘开关（默认关）
    /// 双重把关。
    pub ssh_config: Option<SshDistributeConfig>,
}

/// hub 侧 SSH 别名分发配置（`[ssh_config]`）。`overrides` 按设备名覆写
/// alias/user/port；未覆写的节点用「主机名 > peer name」默认推导。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshDistributeConfig {
    pub overrides: std::collections::BTreeMap<String, SshHostOverride>,
}

/// 单节点覆写（`[ssh_config.overrides.<设备名>]`）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshHostOverride {
    /// 显式 Host 别名（优先级最高，覆盖主机名/peer name 推导）。
    pub alias: Option<String>,
    /// SSH 登录用户。
    pub user: Option<String>,
    /// SSH 端口。
    pub port: Option<u16>,
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
            trusted_proxies: TrustedProxyConfig::default(),
            ssh_config: None,
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
        let trusted_proxies = match raw.trusted_proxies {
            Some(entries) => TrustedProxyConfig::from_strings(entries)
                .map_err(|e| ConfigError::InvalidDataPlane(e.to_string()))?,
            None => TrustedProxyConfig::default(),
        };
        let ssh_config = raw
            .ssh_config
            .map(|raw_ssh| {
                let overrides: std::collections::BTreeMap<String, SshHostOverride> = raw_ssh
                    .overrides
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(name, o)| {
                        (
                            name,
                            SshHostOverride {
                                alias: o
                                    .alias
                                    .map(|a| a.trim().to_string())
                                    .filter(|a| !a.is_empty()),
                                user: o
                                    .user
                                    .map(|u| u.trim().to_string())
                                    .filter(|u| !u.is_empty()),
                                port: o.port,
                            },
                        )
                    })
                    .collect();
                for (name, o) in &overrides {
                    if o.port == Some(0) {
                        return Err(ConfigError::InvalidDataPlane(format!(
                            "ssh_config.overrides.{name}.port must be 1..=65535"
                        )));
                    }
                }
                Ok(SshDistributeConfig { overrides })
            })
            .transpose()?;
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
            trusted_proxies,
            ssh_config,
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
    fn trusted_proxies_default_loopback_and_parse() {
        // TODO-116：默认仅回环（nginx 同主机反代）；不可信来源不采信头部。
        let d = ServerConfig::default().trusted_proxies;
        assert!(d.is_trusted("127.0.0.1".parse().unwrap()));
        assert!(d.is_trusted("::1".parse().unwrap()));
        assert!(!d.is_trusted("203.0.113.9".parse().unwrap()));

        let c = ServerConfig::from_toml("trusted_proxies = [\"10.0.0.0/8\", \"203.0.113.10\"]")
            .unwrap();
        assert!(c.trusted_proxies.is_trusted("10.1.2.3".parse().unwrap()));
        assert!(c
            .trusted_proxies
            .is_trusted("203.0.113.10".parse().unwrap()));
        assert!(!c.trusted_proxies.is_trusted("192.168.1.1".parse().unwrap()));

        // 空列表 = 不信任任何代理（不采信任何头部）。
        let c = ServerConfig::from_toml("trusted_proxies = []").unwrap();
        assert!(!c.trusted_proxies.is_trusted("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn trusted_proxies_rejects_invalid_entry() {
        let err = ServerConfig::from_toml("trusted_proxies = [\"not-an-ip\"]").unwrap_err();
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
    fn server_ssh_config_section_parses_overrides_and_rejects_zero_port() {
        let off = ServerConfig::default();
        assert!(off.ssh_config.is_none());
        assert!(ServerConfig::from_toml("").unwrap().ssh_config.is_none());

        let on = ServerConfig::from_toml(
            r#"
[ssh_config.overrides.windows-desktop]
alias = "wd"
user = "root"
port = 2222
"#,
        )
        .unwrap()
        .ssh_config
        .expect("section presence enables distribution");
        let o = on.overrides.get("windows-desktop").expect("override row");
        assert_eq!(o.alias.as_deref(), Some("wd"));
        assert_eq!(o.user.as_deref(), Some("root"));
        assert_eq!(o.port, Some(2222));

        // 空段同样 = 开启（全部节点走默认推导）。
        let empty = ServerConfig::from_toml("[ssh_config]").unwrap().ssh_config;
        assert!(empty.is_some());
        assert!(empty.unwrap().overrides.is_empty());

        let err = ServerConfig::from_toml("[ssh_config.overrides.x]\nport = 0").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidDataPlane(_)));

        let err = ServerConfig::from_toml("[ssh_config]\nbogus = 1").unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
    }
}
