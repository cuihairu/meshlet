//! meshlet-config: TOML config loading and validation ([archive §4.1](../../docs/review/chatgpt-2026-10-13.md)).
//!
//! The default overlay CIDR `10.240.0.0/16` is only a default and **is configurable** (ADR-004).
//!
//! Module layout: `server` (hub side: Raw schema + `ServerConfig`/`BackupConfig`/
//! `DataPlaneConfig`/SSH alias distribution), `agent` (agent side: Raw schema +
//! `AgentConfig` and the tray/upgrade/dataplane/direct_connect/probe/mcp/
//! ssh_config_sync sub-configs). The public API is re-exported at the crate root, so the
//! caller-facing `meshlet_config::Xxx` paths are unchanged.

pub mod trusted_proxy;

mod agent;
mod server;

pub use agent::{
    AgentConfig, DataplaneConfig, DirectConnectConfig, McpConfig, ProbeConfig, SshConfigSyncConfig,
    TrayConfig, TunnelBackend, UpgradeConfig,
};
pub use server::{
    BackupConfig, DataPlaneConfig, ServerConfig, SshDistributeConfig, SshHostOverride,
};
pub use trusted_proxy::{TrustedProxyConfig, TrustedProxyParseError, TrustedProxySource};

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

/// Sane lower bound for the tunnel MTU: 1280 is the IPv6 minimum MTU — below it the tunnel
/// cannot carry IPv6-in-tunnel or most large-packet paths (archive §7.5, "avoid obviously unreasonable MTUs").
pub const MIN_TUNNEL_MTU: u32 = 1280;
/// Kernel interface MTU ceiling.
pub const MAX_TUNNEL_MTU: u32 = 65535;
