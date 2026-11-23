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
pub mod doctor;
pub mod keys;
pub mod nat;
pub mod probe;
pub mod ssh_alias;
pub mod windows_cleanup;
pub mod windows_console;
pub mod windows_elevation;
pub mod windows_firewall;
pub mod windows_probe;
pub mod windows_routes;
pub mod windows_service;
pub mod windows_tunnel;
pub mod windows_wireguard_nt;

/// boringtun 计划层（全平台编译+单测）与 macOS 后端模块（命令计划全平台、
/// `cfg(macos)` 执行器）。见 [crate::macos_wireguard_bt] 模块文档（②-3 路径
/// 决策：spawn boringtun-cli + wg.sock UAPI）。
pub mod macos;
pub mod macos_dns;
pub mod macos_privileges;
pub mod macos_wireguard_bt;

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

/// 平台默认后端（macOS）：[macos::system::MacSystemBackend]——默认占位
/// （行为与旧 [unsupported] 占位一致）+ `mac-boringtun` 数据面分派
/// （③-C 接线；`tunnel_backend` 未选时行为零变化）。
#[cfg(target_os = "macos")]
pub type SystemBackend = macos::system::MacSystemBackend;

/// 平台默认后端（其余平台）：[unsupported] 模块的明确占位，每个数据面操作
/// 都失败可见（`NetworkError::Unsupported`），绝不静默假装生效。
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
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

    /// AGENT-ISO-1：外来 overlay（ZeroTier 类）隔离**自愈**。
    ///
    /// 与 [`NetworkBackend::apply_tunnel`] 等「有变更才跑」的接口不同，本方法
    /// **每轮 reconcile 都要跑**：隔离规则可能被外部 flush，且受管隧道与外来
    /// overlay 的启动存在竞态（2026-11-23 实测 zerotier 的 ExecStartPost 早于
    /// wg-mlt 起来 0.7s，规则整批丢失 → 两条隧道互为路径、递归封装 185:1
    /// 放大）。只挂在 apply 上会漏掉「无计划变更」的轮次，规则丢了补不回来。
    ///
    /// 默认 no-op（无外来 overlay 需要隔离的平台）；Linux 实现幂等补
    /// iptables 规则。失败由调用方记日志——隔离是加固而非数据面前提，
    /// 不因它中断隧道（[`crate::diag`] / `doctor` 面负责把它报成 FAIL）。
    fn ensure_overlay_isolation(&self) -> Result<(), NetworkError> {
        Ok(())
    }

    /// AGENT-DOC-1：外来 overlay 共存体检（见 [crate::doctor]）。
    ///
    /// 默认返回 [crate::doctor::unsupported_report]——未实现的平台全项
    /// `not_assessed`，**绝不返回 PASS**（§7.5「没实现」≠「检查过没问题」）。
    /// Linux 后端覆盖为真实采集。
    fn doctor(&self) -> crate::doctor::DoctorReport {
        crate::doctor::unsupported_report()
    }
}

/// 探测本机 WireGuard 类型接口名（`ip -o link show type wireguard` 首个命中）。
///
/// CLI / MCP 都没有「受管接口名」的硬编码来源——配置里写 `wg0`、真机却叫
/// `wg-mlt` 时，按默认名读会读到空（`diag` 的 wg 段长期 `(not collected)` 就是
/// 这么来的）。按链路类型现探，读不到返回 `None` 由调用方回落默认。
#[cfg(target_os = "linux")]
pub fn detect_wireguard_interface() -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["-o", "link", "show", "type", "wireguard"])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let name = fields.get(1)?.trim_end_matches(':');
            (!name.is_empty()).then(|| name.to_string())
        })
        .next()
}

/// 非 Linux 平台暂无同款探测（wireguard-nt / boringtun 的接口枚举另走后端）。
#[cfg(not(target_os = "linux"))]
pub fn detect_wireguard_interface() -> Option<String> {
    None
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
                routes_from_peers: false,
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
