//! meshlet-network：`NetworkBackend` 统一抽象（[存档 §15.1](../../docs/review/chatgpt-2026-10-13.md)、
//! [ADR-007](../../docs/decisions/adr-007-linux-network-backend.md)）。
//!
//! Linux 实现在 [linux](linux) 模块（受控执行 `ip` / `wg` / `iptables` 命令，
//! ADR-007 的降级路径先行落地，通路已在 netns 集成测试中真机验证）；
//! Windows 实现按 ADR-008 后续接入——在那之前，非 Linux 平台得到
//! [unsupported] 模块的**明确占位**（每个数据面操作显式报
//! [NetworkError::Unsupported]，绝不静默假装生效）。
//!
//! 注意：使用原生 `async fn` trait（Rust 1.75+）。原生 async trait 暂不支持
//! `dyn` 分发；如后续需要对象安全，再评估 `async-trait`（存档 §15.1 已预留该决策点）。
//!
//! [nat](nat) 模块是纯**计划**层（§9.4–§9.5）：从 Alias 映射确定性推导网关侧
//! NAT 规则；执行随数据面接线（ADR-007）。
//!
//! [windows_routes](windows_routes) / [windows_firewall](windows_firewall) /
//! [windows_service](windows_service) / [windows_tunnel](windows_tunnel) 是
//! Windows 数据面的**计划层**（ADR-008）：命令参数构造、解析与失败文本
//! 分类，Linux 上单测跑绿；执行层 `#[cfg(windows)]` 只调计划层。路由/防火
//! 墙/服务执行层已在真机验证（2026-10-16 CI runner en-US；2026-10-26 中文
//! Windows Server）；隧道执行层原语已交付，但 WireGuardNT 驱动安装后的全
//! 生命周期仍未真机验证（见 [windows_tunnel] 模块文档）。完整验收前
//! Windows 不接为 [SystemBackend]。
//!
//! 接线决策的完成状态前置审计（M5，2026-10-27）见
//! [docs/analysis/todo-completion-audit-2026-10-27.md](../../docs/analysis/todo-completion-audit-2026-10-27.md)
//! 「Focus area 3 / Windows 后端」：结论是隧道实现整体缺席，接线需新建子
//! 系统而非改这一行 `cfg`。`windows_tunnel` 计划层 + `#[cfg(windows)]` 执行
//! 层原语已于 2026-10-27 落地；`apply_tunnel` 接线与真机全生命周期仍缺席。
//!
//! [DevicePlan] 是 server → agent 的**结构化配置对象**（§16.4）：agent 只消费
//! 类型化的隧道/路由/NAT 计划，绝不执行服务端下发的任意 Shell 命令。

// 按职责分档：计划类型（plan）/ 错误（error）/ 纯解析与对账（reconcile）/
// 诊断载体（types）/ SSH alias（ssh_alias）；本文件保留模块声明、全量
// re-export、平台默认后端别名与 NetworkBackend trait。
mod error;
mod plan;
mod reconcile;
mod types;

pub use error::NetworkError;
pub use plan::{
    derive_tunnel_mtu, ApplyResult, ConfigRevisionRef, DevicePlan, NetworkSnapshot, PeerConfig,
    PeerObserved, RouteConfig, SshConfigPlan, SshHostConfig, TunnelConfig, DEFAULT_TUNNEL_MTU,
    HUB_KEEPALIVE_SECS, WG_TUNNEL_OVERHEAD_BYTES,
};
#[cfg(target_os = "windows")]
pub(crate) use reconcile::device_plan_matches;
pub(crate) use reconcile::parse_handshake_ages;
pub use reconcile::{parse_wg_dump_listen_port, parse_wg_dump_local_public_key};
pub use types::{InterfaceDiagnostic, NetworkDiagnostics, WgPeerDiagnostic};

pub mod diag;
pub mod dial;
pub mod keys;
pub mod nat;
pub mod probe;
pub mod ssh_alias;
pub mod windows_cleanup;
pub mod windows_console;
pub mod windows_elevation;
pub mod windows_firewall;
pub mod windows_routes;
pub mod windows_service;
pub mod windows_tunnel;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub mod unsupported;

/// 平台默认后端：Linux 为真实内核后端（[linux] 模块，ADR-007）。
///
/// 调用方一律经本别名构造（`SystemBackend::new()` + `with_*` 装配），平台
/// 差异收敛在这里：Linux 真实执行。
#[cfg(target_os = "linux")]
pub type SystemBackend = linux::LinuxNetworkBackend;

/// 平台默认后端（Windows）：真实 Windows 后端（[windows] 模块，ADR-008
/// tunnel-only v1 已接线；NAT-bearing 计划显式拒绝，绝不静默假装生效）。
#[cfg(target_os = "windows")]
pub type SystemBackend = windows::WindowsNetworkBackend;

/// 平台默认后端（其余平台）：[unsupported] 模块的明确占位，每个数据面操作
/// 都失败可见（`NetworkError::Unsupported`），绝不静默假装生效。
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub type SystemBackend = unsupported::UnsupportedBackend;

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
        &'s mut self,
        routes: Vec<RouteConfig>,
    ) -> impl std::future::Future<Output = Result<ApplyResult, NetworkError>> + Send + 's;

    /// 在网关侧下发 NAT 规则（计划层 [nat::NatRule] 渲染执行）。规则携带
    /// `meshlet alias {id}` 所有权注释（§12.6），[NetworkBackend::remove_nat]
    /// 按注释精确移除。
    fn apply_nat<'s>(
        &'s self,
        rules: Vec<nat::NatRule>,
        gateway_lan_addr: std::net::Ipv4Addr,
    ) -> impl std::future::Future<Output = Result<ApplyResult, NetworkError>> + Send + 's;

    /// 按所有权注释移除属于 `owner`（如 `meshlet alias al-1`）的 NAT 规则；
    /// 只触碰携带该注释的规则，绝不改写用户已有规则（ADR-007）。
    fn remove_nat<'s>(
        &'s self,
        owner: &'s str,
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
                peers: vec![
                    PeerObserved {
                        public_key: format!("{}=", "A".repeat(43)),
                        allowed_ips: vec!["10.240.0.2/32".parse().unwrap()],
                    },
                    PeerObserved {
                        public_key: format!("{}=", "B".repeat(43)),
                        allowed_ips: vec!["10.240.0.0/16".parse().unwrap()],
                    },
                ],
                installed_routes: vec!["10.240.0.0/16".parse().unwrap()],
                nat_rules: Vec::new(),
                tunnel_mtu: Some(1420),
                local_public_key: None,
                tunnel_address: None,
                tunnel_listen_port: None,
            })
        }

        async fn apply_tunnel(&self, _config: TunnelConfig) -> Result<ApplyResult, NetworkError> {
            Ok(ApplyResult::ok())
        }

        async fn apply_routes(
            &mut self,
            routes: Vec<RouteConfig>,
        ) -> Result<ApplyResult, NetworkError> {
            assert_eq!(routes.len(), 1);
            Ok(ApplyResult::ok())
        }

        async fn apply_nat(
            &self,
            rules: Vec<nat::NatRule>,
            _gateway_lan_addr: std::net::Ipv4Addr,
        ) -> Result<ApplyResult, NetworkError> {
            assert_eq!(rules.len(), 1);
            Ok(ApplyResult::ok())
        }

        async fn remove_nat(&self, _owner: &str) -> Result<ApplyResult, NetworkError> {
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
        assert_eq!(snap.peers.len(), 2);

        let mut mutable_backend = DummyBackend;
        mutable_backend
            .apply_routes(vec![RouteConfig {
                destination: "10.241.1.0/24".parse().unwrap(),
                interface: "wg0".into(),
                gateway: None,
            }])
            .await
            .unwrap();
        mutable_backend
            .apply_nat(
                vec![nat::NatRule {
                    source_cidr: None,
                    incoming_interface: None,
                    chain: nat::NatChain::Prerouting,
                    match_dest: "10.241.1.0/24".parse().unwrap(),
                    action: nat::NatAction::NetMap {
                        to: "192.168.1.0/24".parse().unwrap(),
                    },
                    owner: "meshlet alias test".into(),
                }],
                "192.168.1.1".parse().unwrap(),
            )
            .await
            .unwrap();
        mutable_backend
            .remove_nat("meshlet alias test")
            .await
            .unwrap();

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
}
