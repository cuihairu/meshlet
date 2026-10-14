//! meshlet-network：`NetworkBackend` 统一抽象（[存档 §15.1](../../docs/review/chatgpt-2026-10-13.md)、
//! [ADR-007](../../docs/decisions/adr-007-linux-network-backend.md)）。
//!
//! 第一版只定义抽象与数据结构；Linux 实现需要 NET_ADMIN + 网络命名空间
//! （当前开发沙箱不可用，见 TODO 卡点），Windows 实现按 ADR-008 后续接入。
//!
//! 注意：使用原生 `async fn` trait（Rust 1.75+）。原生 async trait 暂不支持
//! `dyn` 分发；如后续需要对象安全，再评估 `async-trait`（存档 §15.1 已预留该决策点）。
//!
//! [nat](nat) 模块是纯**计划**层（§9.4–§9.5）：从 Alias 映射确定性推导网关侧
//! NAT 规则；执行随数据面接线（ADR-007）。

pub mod nat;

use meshlet_domain::Ipv4Cidr;

/// Peer 配置：AllowedIPs 与目标路由一致（§7.2），不得全量指隧道。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    pub public_key: String,
    pub allowed_ips: Vec<Ipv4Cidr>,
    pub endpoint: Option<String>,
    pub persistent_keepalive_secs: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelConfig {
    /// 接口名（Linux）或隧道名（Windows）。
    pub name: String,
    pub address: std::net::Ipv4Addr,
    pub listen_port: Option<u16>,
    pub peers: Vec<PeerConfig>,
    pub mtu: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteConfig {
    pub destination: Ipv4Cidr,
    /// 下一跳接口名。
    pub interface: String,
}

/// 应用结果：**applied=false 时必须携带错误说明**，不得假装成功（§10.3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyResult {
    pub applied: bool,
    pub error: Option<String>,
}

impl ApplyResult {
    pub fn ok() -> Self {
        Self {
            applied: true,
            error: None,
        }
    }

    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            applied: false,
            error: Some(message.into()),
        }
    }
}

/// 配置版本引用（回滚目标，ADR-009）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigRevisionRef {
    pub network_id: String,
    pub revision: u64,
}

/// inspect 快照：诊断与配置协调的事实来源（§12.7、§17.3）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkSnapshot {
    pub tunnel_exists: bool,
    pub forwarding_enabled: Option<bool>,
    pub peer_count: u32,
    pub installed_routes: Vec<Ipv4Cidr>,
    pub nat_rules_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetworkError {
    #[error("operation not supported on this platform")]
    Unsupported,
    #[error("insufficient privileges: {0}")]
    InsufficientPrivileges(String),
    #[error("backend io failure: {0}")]
    Io(String),
    #[error("apply rejected: {0}")]
    ApplyRejected(String),
}

/// 统一网络后端抽象：inspect → apply → rollback。
///
/// 原生 async fn 在 trait 里无法声明 `Send` 边界；这里改用 RPITIT + `Send`
/// （Rust 1.75+），使未来能在 axum handler / `spawn_blocking` 间安全传递，
/// 不引入 `async-trait` 宏依赖。
pub trait NetworkBackend {
    fn inspect<'s>(
        &'s self,
    ) -> impl std::future::Future<Output = Result<NetworkSnapshot, NetworkError>> + Send + 's;

    fn apply_tunnel<'s>(
        &'s self,
        config: TunnelConfig,
    ) -> impl std::future::Future<Output = Result<ApplyResult, NetworkError>> + Send + 's;

    fn apply_routes<'s>(
        &'s self,
        routes: Vec<RouteConfig>,
    ) -> impl std::future::Future<Output = Result<ApplyResult, NetworkError>> + Send + 's;

    /// 回滚只允许触碰 Meshlet 自有对象（§10.3）。
    fn rollback<'s>(
        &'s self,
        revision: ConfigRevisionRef,
    ) -> impl std::future::Future<Output = Result<ApplyResult, NetworkError>> + Send + 's;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 证明 trait 可实现、可泛型分发（§15.1 概念接口落地）。
    struct DummyBackend;

    impl NetworkBackend for DummyBackend {
        async fn inspect(&self) -> Result<NetworkSnapshot, NetworkError> {
            Ok(NetworkSnapshot {
                tunnel_exists: true,
                forwarding_enabled: Some(true),
                peer_count: 2,
                installed_routes: vec!["10.240.0.0/16".parse().unwrap()],
                nat_rules_present: false,
            })
        }

        async fn apply_tunnel(&self, _config: TunnelConfig) -> Result<ApplyResult, NetworkError> {
            Ok(ApplyResult::ok())
        }

        async fn apply_routes(
            &self,
            _routes: Vec<RouteConfig>,
        ) -> Result<ApplyResult, NetworkError> {
            Ok(ApplyResult::ok())
        }

        async fn rollback(
            &self,
            _revision: ConfigRevisionRef,
        ) -> Result<ApplyResult, NetworkError> {
            Ok(ApplyResult::failed("nothing to roll back"))
        }
    }

    #[tokio::test]
    async fn backend_contract_via_generic_dispatch() {
        async fn use_backend<B: NetworkBackend>(b: &B) -> NetworkSnapshot {
            b.inspect().await.unwrap()
        }
        let snap = use_backend(&DummyBackend).await;
        assert!(snap.tunnel_exists);
        assert_eq!(snap.peer_count, 2);

        let result = DummyBackend
            .rollback(ConfigRevisionRef {
                network_id: "n".into(),
                revision: 1,
            })
            .await
            .unwrap();
        assert!(!result.applied);
        assert!(result.error.is_some());
    }

    #[test]
    fn apply_result_failure_carries_error() {
        let ok = ApplyResult::ok();
        assert!(ok.applied && ok.error.is_none());
        let bad = ApplyResult::failed("route install rejected");
        assert!(!bad.applied);
        assert_eq!(bad.error.as_deref(), Some("route install rejected"));
    }

    #[test]
    fn peer_allowed_ips_explicit() {
        // §7.2：AllowedIPs 必须与目标路由一致——类型层面强制显式列出。
        let peer = PeerConfig {
            public_key: "hub-pub".into(),
            allowed_ips: vec![
                "10.240.0.0/16".parse().unwrap(),
                "10.241.1.0/24".parse().unwrap(), // 已发布 LAN 的 alias
            ],
            endpoint: Some("203.0.113.10:51820".into()),
            persistent_keepalive_secs: Some(25),
        };
        assert_eq!(peer.allowed_ips.len(), 2);
    }
}
