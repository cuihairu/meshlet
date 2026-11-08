//! 计划层类型（从 lib.rs 拆出）：server → agent 的结构化配置对象、快照载体
//! 与应用结果；纯数据 + 派生，无 IO。

use crate::nat;
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

/// SSH 别名同步单条主机（hub 下发的 SSH config 分发段，`ssh_config`）。
///
/// 每个网络内 Active 节点一条；agent 据此渲染 `~/.ssh/meshlet.conf` 的
/// `Host <alias>` 块。alias 来源三级：hub 显式覆写 > 节点真实主机名 >
/// meshlet peer name（`alias_source` 如实标注来源，面板/文档同口径）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SshHostConfig {
    /// meshlet peer name（与控制台设备名一致，日志/排障锚点）。
    pub name: String,
    /// SSH Host 别名（已 sanitize 成合法 Host 字符）。
    pub alias: String,
    /// 对端 overlay VIP（`HostName`）。
    pub address: std::net::Ipv4Addr,
    /// SSH 端口；`None` = agent 用默认 22。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// SSH 登录用户；`None` = 不下发（用本地 ssh 默认）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// alias 来源（`hub-config` / `hostname` / `peer-name`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias_source: Option<String>,
}

/// SSH config 分发段（hub 侧显式开启才出现在计划里）：网络内全部 Active
/// 节点的别名表。缺省（旧服务端 / hub 未开启）表示 hub 未下发——agent 用
/// 本机默认（主机名 + 自身 overlay VIP + 22）自生成单条。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SshConfigPlan {
    pub hosts: Vec<SshHostConfig>,
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
    /// SSH 别名分发段（`ssh_config`）：hub 显式开启才携带。缺省不序列化
    /// （`skip_serializing_if`）——旧服务端计划的哈希不变，升级不触发全网
    /// 无谓重放。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_config: Option<SshConfigPlan>,
    pub desired_config_hash: String,
}

/// 隧道 MTU 缺省值（WireGuard 默认）：计划未显式配置时的有效计划值，也是
/// 大包探测的尺寸来源之一（1420 − 28 = 1392）。
pub const DEFAULT_TUNNEL_MTU: u32 = 1420;

/// WireGuard 隧道对底层网络的 IPv4 封装开销（字节）：外层 IPv4 头 20B +
/// UDP 头 8B + WireGuard 数据通道头/标签 52B ≈ 80B（IPv6 外层为 80B + 20B，
/// 取更保守的 80B 与 WireGuard 文档惯例一致）。
pub const WG_TUNNEL_OVERHEAD_BYTES: u32 = 80;

/// SEL-003 hub 兜底：hub peer 的 persistent-keepalive（秒）。hub 是中继的生命线，
/// 掉 keepalive 会让 hub 端看不到本设备（NAT 映射过期），直连回退后无处可回。
/// agent 在 reconcile 里对 hub peer 强制取 max(计划值, 此值)，保证「永不掉」。
pub const HUB_KEEPALIVE_SECS: u32 = 25;

/// 由底层接口 MTU 推导隧道 MTU（lane/dataplane-speed）：`underlay − 80`，
/// 下限 1280（IPv6 最小 MTU，低于它 IPv6-in-tunnel 与常见 TLS 路径直接断，
/// 与 meshlet-config 的 `MIN_TUNNEL_MTU` 同源）。
///
/// - 底层 1500（标准以太网）→ 1420，与 [`DEFAULT_TUNNEL_MTU`] 相同——默认
///   行为不变，**不是保守值**，是 1500 底层的正确值；
/// - 底层 9000（jumbo）→ 8920，实测（netns 基线，见 docs/guide/performance）
///   单流吞吐 1.5 → 8.5 Gbps；
/// - 底层 1492（PPPoE）→ 1412，比默认 1420 更贴合真路径。
///
/// 这是**推导辅助**，不是自动下发：服务端 `tunnel_mtu` 计划仍是唯一内核
/// 权威（漂移纠回按计划执行）。agent 只把它用于大包探测载荷（§7.5 证据），
/// 运维据此在服务端配置里钉一个显式 `tunnel_mtu`。
pub fn derive_tunnel_mtu(underlay_mtu: u32) -> u32 {
    underlay_mtu
        .saturating_sub(WG_TUNNEL_OVERHEAD_BYTES)
        .max(1280)
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
    /// 受管接口的本机公钥指纹（`wg show dump` 接口行第 2 列，44 字符
    /// base64）。漂移判定据此识别「peer 恰与计划一致但本机私钥被换」的
    /// 手动隧道（todo.md Windows 部署发现第二项）；读不到 → `None`
    /// （证据缺失不判，不进重放死循环）。
    pub local_public_key: Option<String>,
    /// 受管接口适配器的实际 IPv4 地址。漂移判定比对计划地址——手动隧道
    /// 换了地址也必须重放纠回；读不到 → `None`（证据缺失不判）。
    pub tunnel_address: Option<std::net::Ipv4Addr>,
    /// 受管接口的 WireGuard 实际监听端口（`wg show dump` 接口行第 3 列）。
    /// 直连开启时计划钉住固定端口（`plan.tunnel.listen_port`）——实际端口
    /// 与计划不符必须判不匹配（否则对端按上报端口发包，本机收不到，
    /// 打洞静默失败）；读不到 → `None`（证据缺失不判，不进重放死循环）。
    pub tunnel_listen_port: Option<u16>,
}

/// 受管接口上读出的一个 WireGuard peer（身份级事实：公钥 + allowed-ips）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeerObserved {
    pub public_key: String,
    pub allowed_ips: Vec<Ipv4Cidr>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_tunnel_mtu_tracks_the_underlay_with_floor() {
        assert_eq!(derive_tunnel_mtu(1500), 1420); // 以太网：默认值 = 正确值
        assert_eq!(derive_tunnel_mtu(9000), 8920); // jumbo underlay
        assert_eq!(derive_tunnel_mtu(1492), 1412); // PPPoE
        assert_eq!(derive_tunnel_mtu(1300), 1280); // 下限钳制
        assert_eq!(derive_tunnel_mtu(0), 1280); // 读数异常也不产生 0/回绕
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
            ssh_config: None,
            desired_config_hash: "meshlet-desired-v3:ab".into(),
        };
        let value = serde_json::to_value(&plan).unwrap();
        assert_eq!(value["tunnel"]["address_prefix"], 16);
        assert_eq!(
            value["tunnel"]["peers"][0]["allowed_ips"][0],
            "10.240.0.0/16"
        );
        assert_eq!(value["routes"][0]["destination"], "10.241.1.0/24");
        // 缺省（旧服务端 / hub 未开启）不携带 ssh_config：计划序列化不新增
        // 字段，旧服务端下发的哈希不变——升级不触发全网无谓重放。
        assert!(value.get("ssh_config").is_none());
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
            ssh_config: None,
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
