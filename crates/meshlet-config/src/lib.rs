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
}

/// Server 配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    pub bind: String,
    pub database_path: String,
    pub overlay_cidr: Ipv4Cidr,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8080".into(),
            database_path: "meshlet.db".into(),
            overlay_cidr: DEFAULT_OVERLAY_CIDR.parse().expect("valid default cidr"),
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
        Ok(Self {
            bind: raw.bind.unwrap_or(default.bind),
            database_path: raw.database_path.unwrap_or(default.database_path),
            overlay_cidr,
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
