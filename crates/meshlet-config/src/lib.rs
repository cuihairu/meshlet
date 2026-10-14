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
    #[error("missing required field: {0}")]
    MissingField(String),
}

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
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RawBackupConfig {
    dir: Option<String>,
    auto: Option<bool>,
    interval_secs: Option<u64>,
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
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RawAgentConfig {
    server_url: Option<String>,
    state_dir: Option<String>,
}

/// Agent 配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    pub server_url: String,
    pub state_dir: String,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server_url: "https://127.0.0.1".into(),
            state_dir: "/var/lib/meshlet".into(),
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
        Ok(Self {
            server_url,
            state_dir: raw.state_dir.unwrap_or(default.state_dir),
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
}
