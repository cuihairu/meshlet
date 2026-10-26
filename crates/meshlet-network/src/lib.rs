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
//! [windows_routes](windows_routes) 是 Windows 路由的**计划层**（ADR-008）：
//! netsh 命令参数构造、`show route` 解析与权限失败分类，Linux 上单测跑绿；
//! 执行层 `#[cfg(windows)]` 只调计划层，**未在 Windows 上实测**（TODO #52
//! 的环境走查仍卡），实测前 Windows 不接为 [SystemBackend]。
//!
//! [DevicePlan] 是 server → agent 的**结构化配置对象**（§16.4）：agent 只消费
//! 类型化的隧道/路由/NAT 计划，绝不执行服务端下发的任意 Shell 命令。

pub mod keys;
pub mod nat;
pub mod windows_cleanup;
pub mod windows_console;
pub mod windows_elevation;
pub mod windows_firewall;
pub mod windows_routes;
pub mod windows_service;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(not(target_os = "linux"))]
pub mod unsupported;

/// 平台默认后端：Linux 为真实内核后端（[linux] 模块，ADR-007）；非 Linux
/// 为 [unsupported] 模块的明确占位（ADR-008 Windows 后端待接入）。
///
/// 调用方一律经本别名构造（`SystemBackend::new()` + `with_*` 装配），平台
/// 差异收敛在这里：Linux 真实执行，其他平台每个数据面操作都失败可见。
#[cfg(target_os = "linux")]
pub type SystemBackend = linux::LinuxNetworkBackend;

/// 平台默认后端（非 Linux）：见上方 Linux 版别的文档。
#[cfg(not(target_os = "linux"))]
pub type SystemBackend = unsupported::UnsupportedBackend;

use meshlet_domain::Ipv4Cidr;

/// Peer 配置：AllowedIPs 与目标路由一致（§7.2），不得全量指隧道。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerConfig {
    pub public_key: String,
    pub allowed_ips: Vec<Ipv4Cidr>,
    pub endpoint: Option<String>,
    pub persistent_keepalive_secs: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TunnelConfig {
    /// 接口名（Linux）或隧道名（Windows）。
    pub name: String,
    pub address: std::net::Ipv4Addr,
    /// 接口地址前缀长度（Linux 侧 `ip address replace <addr>/<prefix>`）。
    pub address_prefix: u8,
    pub listen_port: Option<u16>,
    pub peers: Vec<PeerConfig>,
    pub mtu: Option<u32>,
    /// 私钥（base64）。`None` = 保留接口现有私钥（幂等重应用）；
    /// `Some` = 以 `wg set <if> private-key` 显式设置。
    pub private_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RouteConfig {
    pub destination: Ipv4Cidr,
    /// 下一跳接口名。
    pub interface: String,
    /// 下一跳网关地址（对端设备虚拟 IP）；`None` = 直连路由。
    pub gateway: Option<std::net::Ipv4Addr>,
}

/// 设备数据面计划：服务端下发给 agent 的**结构化配置对象**（§16.4：agent 只
/// 执行类型化对象，绝不执行服务端下发的任意 Shell 命令）。
///
/// - `tunnel`：本设备隧道（私钥由 agent 本地注入，服务端永不携带——私钥不
///   出客户端，ADR-010）；
/// - `routes`：本设备经隧道转发的目的段（Overlay + 他人已发布 LAN/Alias，
///   自己本地网段不回灌）；
/// - `nat_rules`：本设备作为网关时应下发的 NAT 规则（计划层渲染，所有权
///   注释 `meshlet alias {id}`）；为空 = 非网关或映射已删；
/// - `hub_address`：hub 的 overlay 地址（服务端 IPAM 分配）——只作 agent
///   本地诊断（计划 MTU 的大包探测目标），不是内核配置的一部分；
/// - `publish`：服务发布计划（R-06，[`meshlet_publish::PublishPlan`]）：本
///   设备应绑定的 L4 转发 / HTTP 路由 / DNS 套接字与探针排程；缺省
///   （`None`，旧服务端）表示本设备无发布配置；
/// - `desired_config_hash`：本计划对应的期望配置哈希——agent 据此判断「有
///   变更才重放」（§10.1）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DevicePlan {
    #[serde(default)]
    pub desired_revision: u64,
    #[serde(default)]
    pub hub_port: Option<u16>,
    pub tunnel: TunnelConfig,
    pub routes: Vec<RouteConfig>,
    pub nat_rules: Vec<nat::NatRule>,
    /// hub overlay 地址；缺省（旧服务端）表示未知——探测随之省略。
    #[serde(default)]
    pub hub_address: Option<std::net::Ipv4Addr>,
    /// 服务发布计划；缺省（旧服务端 / 本设备无发布项）表示 `None`。
    #[serde(default)]
    pub publish: Option<meshlet_publish::PublishPlan>,
    pub desired_config_hash: String,
}

/// 隧道 MTU 缺省值（WireGuard 默认）：计划未显式配置时的有效计划值，
/// 也是大包探测的默认尺寸来源（1420 − 28 = 1392）。
pub const DEFAULT_TUNNEL_MTU: u32 = 1420;

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
///
/// 全部字段按**身份**而非**数量**采集：peer 是公钥集合、路由是带所有权标记的
/// 目的地集合、NAT 是所有权注释下的规则指纹集合。漂移判定因此能区分「少装了」
/// 与「多装了本不该在的」，且只看 Meshlet 自有对象——非本 meshlet 资源永不动。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkSnapshot {
    pub tunnel_exists: bool,
    pub forwarding_enabled: Option<bool>,
    /// 受管接口上实际存在的 WireGuard peer（公钥 + allowed-ips 原样读出）。
    pub peers: Vec<PeerObserved>,
    /// 带 Meshlet 所有权标记的路由目的地（后端只枚举标记过的对象）。
    pub installed_routes: Vec<Ipv4Cidr>,
    /// 内核中 Meshlet 所有权注释下的 NAT 规则指纹（`NatRule::signature` 同一
    /// 形状）；计划侧与内核侧据此做集合精确比对。
    pub nat_rules: Vec<String>,
    /// 隧道接口的实际 MTU 读数（`ip link show` 解析；计划显式配置 MTU
    /// 时用于漂移判定：内核读数与计划不符即重放纠回）。
    pub tunnel_mtu: Option<u32>,
}

/// 受管接口上读出的一个 WireGuard peer（身份级事实：公钥 + allowed-ips）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeerObserved {
    pub public_key: String,
    pub allowed_ips: Vec<Ipv4Cidr>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetworkError {
    #[error("operation not supported on this platform: {0}")]
    Unsupported(String),
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

    #[test]
    fn device_plan_round_trips_as_a_structured_object() {
        // §16.4：server→agent 传的是类型化对象（CIDR 序列化为 a.b.c.d/p 字符串）。
        let plan = DevicePlan {
            desired_revision: 0,
            hub_port: None,
            tunnel: TunnelConfig {
                name: "wg0".into(),
                address: "10.240.0.3".parse().unwrap(),
                address_prefix: 16,
                listen_port: None,
                peers: vec![PeerConfig {
                    public_key: "hub-pub".into(),
                    allowed_ips: vec!["10.240.0.0/16".parse().unwrap()],
                    endpoint: Some("203.0.113.10:51820".into()),
                    persistent_keepalive_secs: Some(25),
                }],
                mtu: None,
                private_key: None,
            },
            routes: vec![RouteConfig {
                destination: "10.241.1.0/24".parse().unwrap(),
                interface: "wg0".into(),
                gateway: None,
            }],
            nat_rules: vec![],
            hub_address: Some("10.240.0.1".parse().unwrap()),
            publish: None,
            desired_config_hash: "meshlet-desired-v3:ab".into(),
        };
        let value = serde_json::to_value(&plan).unwrap();
        assert_eq!(value["tunnel"]["address_prefix"], 16);
        assert_eq!(
            value["tunnel"]["peers"][0]["allowed_ips"][0],
            "10.240.0.0/16"
        );
        assert_eq!(value["routes"][0]["destination"], "10.241.1.0/24");
        let round = serde_json::from_value::<DevicePlan>(value).unwrap();
        assert_eq!(round, plan);

        // 缺 hub_address 的计划仍能解析（旧服务端下发的计划向前兼容）。
        let without_hub = serde_json::json!({
            "tunnel": plan.tunnel,
            "routes": [],
            "nat_rules": [],
            "desired_config_hash": "h",
        });
        let old: DevicePlan = serde_json::from_value(without_hub).unwrap();
        assert_eq!(old.hub_address, None);
    }

    #[test]
    fn device_plan_rejects_a_non_canonical_cidr() {
        // 反序列化同样走校验：主机位非零的网段不是合法计划输入（§6.1）。
        let plan = DevicePlan {
            desired_revision: 0,
            hub_port: None,
            tunnel: TunnelConfig {
                name: "wg0".into(),
                address: "10.240.0.3".parse().unwrap(),
                address_prefix: 16,
                listen_port: None,
                peers: vec![],
                mtu: None,
                private_key: None,
            },
            routes: vec![RouteConfig {
                destination: "10.240.0.0/16".parse().unwrap(),
                interface: "wg0".into(),
                gateway: None,
            }],
            nat_rules: vec![],
            hub_address: None,
            publish: None,
            desired_config_hash: "h".into(),
        };
        let mut value = serde_json::to_value(&plan).unwrap();
        value["routes"][0]["destination"] = serde_json::Value::String("10.240.0.1/16".into());
        assert!(
            serde_json::from_value::<DevicePlan>(value).is_err(),
            "host bits set must be rejected"
        );
    }
}
