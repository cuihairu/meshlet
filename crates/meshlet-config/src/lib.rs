//! meshlet-config：TOML 配置加载与校验（[存档 §4.1](../../docs/review/chatgpt-2026-10-13.md)）。
//!
//! Overlay CIDR 默认 `10.240.0.0/16` 仅为默认值，**可配置**（ADR-004）。
//!
//! 模块划分：`server`（hub 侧：Raw schema + `ServerConfig`/`BackupConfig`/
//! `DataPlaneConfig`/SSH 别名分发）、`agent`（agent 侧：Raw schema +
//! `AgentConfig` 与 tray/upgrade/dataplane/direct_connect/probe/mcp/
//! ssh_config_sync 子配置）。公开 API 经模块根 re-export，调用方
//! `meshlet_config::Xxx` 路径不变。

pub mod trusted_proxy;

mod agent;
mod server;

pub use agent::{
    AgentConfig, DataplaneConfig, DirectConnectConfig, McpConfig, ProbeConfig, SshConfigSyncConfig,
    TrayConfig, UpgradeConfig,
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

/// 隧道 MTU 的合理下界：1280 是 IPv6 最小 MTU——低于它的隧道承载不了
/// IPv6-in-tunnel 与绝大多数大包路径（存档 §7.5「避免明显不合理的 MTU」）。
pub const MIN_TUNNEL_MTU: u32 = 1280;
/// 内核接口 MTU 上限。
pub const MAX_TUNNEL_MTU: u32 = 65535;
