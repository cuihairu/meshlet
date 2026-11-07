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

/// 解析 `wg show <if> latest-handshakes` 输出（每行 `公钥 握手unix时间 距今秒`）：
/// 公钥 → 距今秒数。第三列优先（WireGuard 自己算好的年龄）；缺第三列时按
/// `now - 握手时间` 兜底。握手时间为 0（从未握手）的 peer 不在输出里——
/// 调用方按「无读数」处理（§12 `classify_probe` 的 Unknown/Unhealthy 之别）。
///
/// 放在本 crate 根（而非 [linux] 模块）：双平台共享的**纯解析逻辑**，
/// Windows 执行层（`windows` 模块，`#[cfg(windows)]`）与 Linux 执行层各取
/// 所需——解析本身不依赖平台，二进制格式两侧一致。
pub(crate) fn parse_handshake_ages(
    text: &str,
    now_secs: u64,
) -> std::collections::BTreeMap<String, u64> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let key = fields.next()?;
            // 公钥 44 字符 base64 且以 `=` 结尾（与 dump 行解析同一判据）。
            if key.len() != 44 || !key.ends_with('=') {
                return None;
            }
            let ts: u64 = fields.next()?.parse().ok()?;
            if ts == 0 {
                return None;
            }
            let age = fields
                .next()
                .and_then(|ago| ago.parse::<u64>().ok())
                .unwrap_or_else(|| now_secs.saturating_sub(ts));
            Some((key.to_string(), age))
        })
        .collect()
}

pub mod diag;
pub mod dial;
pub mod keys;
pub mod nat;
pub mod probe;
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

/// 平台默认后端：Linux 为真实内核后端（[linux] 模块，ADR-007）；非 Linux
/// 为 [unsupported] 模块的明确占位（ADR-008 Windows 后端待接入）。
///
/// 调用方一律经本别名构造（`SystemBackend::new()` + `with_*` 装配），平台
/// 差异收敛在这里：Linux 真实执行，其他平台每个数据面操作都失败可见。
#[cfg(target_os = "linux")]
pub type SystemBackend = linux::LinuxNetworkBackend;

/// 平台默认后端（非 Linux）：见上方 Linux 版别的文档。
#[cfg(target_os = "windows")]
pub type SystemBackend = windows::WindowsNetworkBackend;

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
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

/// SSH alias 解析（hub 与 agent 共用同一实现，两端口径不漂移）。
pub mod ssh_alias {
    /// SSH Host 别名三级来源解析：hub 显式覆写 > 节点真实主机名 >
    /// meshlet peer name。返回的 alias 已 sanitize，来源字符串与计划/面板同口径。
    pub fn resolve_alias(
        peer_name: &str,
        hostname: Option<&str>,
        hub_override: Option<&str>,
    ) -> (String, &'static str) {
        match hub_override.map(str::trim).filter(|s| !s.is_empty()) {
            Some(alias) => (sanitize_alias(alias), "hub-config"),
            None => match hostname.map(str::trim).filter(|s| !s.is_empty()) {
                Some(hostname) => (sanitize_alias(hostname), "hostname"),
                None => (sanitize_alias(peer_name), "peer-name"),
            },
        }
    }

    /// SSH Host 别名 sanitize：保留大小写，允许 `A-Za-z0-9._-`；其余字符转连
    /// 字符，空名兜底 `node`。hub 与 agent 同一规则，保证下发段可直接渲染。
    pub fn sanitize_alias(name: &str) -> String {
        let cleaned: String = name
            .trim()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        if cleaned.is_empty() {
            "node".to_string()
        } else {
            cleaned
        }
    }
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

/// 解析 `wg show <if> dump` 接口行的本机公钥指纹（字段 1；字段 0 是私钥，
/// 绝不外传）。Linux `wg` 与 Windows `wg.exe` 同一 dump 格式，共享本解析。
/// 公钥按身份校验（44 字符 base64、`=` 结尾）——残行/占位文本不臆造指纹。
pub fn parse_wg_dump_local_public_key(dump: &str) -> Option<String> {
    let header = dump.lines().next()?;
    let public_key = header.split_whitespace().nth(1)?;
    if public_key.len() != 44 || !public_key.ends_with('=') {
        return None;
    }
    Some(public_key.to_string())
}

/// 解析 `wg show <if> dump` 接口行的实际监听端口（字段 2）。Linux `wg` 与
/// Windows `wg.exe` 同一 dump 格式，共享本解析；解析不出（空/残行）→
/// `None`（调用方按证据缺失处理，不判漂移）。
pub fn parse_wg_dump_listen_port(dump: &str) -> Option<u16> {
    dump.lines().next()?.split_whitespace().nth(2)?.parse().ok()
}

/// 网络诊断信息面（R-DIAG，2026-11-01 用户令）：agent 本地路由表 / 接口
/// 清单 / wg-mlt 读数三类快照的**结构化**载体。agent 采集（[NetworkBackend]
/// 各平台实现，Linux 复用既有 `ip route` / `wg show dump` 解析器，不重写），
/// 随心跳上报服务端；控制台诊断页与 CLI `meshlet agent diag` 据此展示。
///
/// 纪律与 [NetworkSnapshot] 同源：读不到的真实状态按 `None` / 空数组上报
/// （证据缺失可见），绝不臆测默认值。
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct NetworkDiagnostics {
    /// 采集时刻（agent 本地 ISO-8601）；`None` = 采集未完成。
    pub collected_at: Option<String>,
    /// 全表路由（Linux `ip route show table all` 原文 / Windows `route print`）。
    /// 原文保留以便与真实路由表逐行对照；空 = 未取到。
    pub route_table: Vec<String>,
    /// 接口清单（名称 + IPv4 地址/前缀 + 状态 + MTU）。
    pub interfaces: Vec<InterfaceDiagnostic>,
    /// wg-mlt 接口读数（`wg show dump` 解析；每行一个 peer）。
    pub wg: Vec<WgPeerDiagnostic>,
}

/// 单条接口诊断（R-DIAG「接口清单：含地址/状态/MTU」）。
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct InterfaceDiagnostic {
    pub name: String,
    /// IPv4 地址（点分）；无 IPv4 地址留空串。
    pub ipv4: String,
    /// 前缀长度（0–32）；未取到留空。
    pub prefix: Option<u8>,
    /// `up` / `down` / `unknown`（Linux 按 `ip link` 的 UP flag，Windows 按
    /// `Get-NetIPConfiguration` 的 InterfaceOperationalStatus）。
    pub state: String,
    /// 接口 MTU（字节）；`None` = 未取到。
    pub mtu: Option<u32>,
}

/// 单条 wg-mlt 接口读数（R-DIAG「wg show：peer/握手/流量」）。
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct WgPeerDiagnostic {
    pub public_key: String,
    /// 对端 endpoint（`ip:port`）；空 = 未配置。
    pub endpoint: String,
    /// 对端 AllowedIPs（逗号分隔 CIDR 字符串）。
    pub allowed_ips: String,
    /// 最近握手时间（Unix 秒）；0 = 从未握手。
    pub last_handshake: u64,
    /// 累计接收字节（`transfer-rx`）。
    pub rx_bytes: u64,
    /// 累计发送字节（`transfer-tx`）。
    pub tx_bytes: u64,
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

/// 计划与内核快照逐项对账（纯函数，无 IO，Linux 本机可测）。
///
/// 供 Windows 后端 `device_plan_matches_sync` 使用（Linux 有内联的更强实现）；
/// 把「隧道在但配置已漂移」从「误判一致」中分辨出来：
/// ① 每个计划 peer 公钥必须存在于快照 peers（子集方向）；
/// ①a. 每个计划 peer 的 `allowed_ips` 必须与快照读回的 allowed-ips 精确一致
///    （顺序无关；与 Linux 同职责实现的身份级判定对齐）；
/// ② 快照里每个 peer 必须是计划 peer 或 `extra_peer_keys`（无未受管漂移；
///    `extra_peer_keys` 是直连保留等允许存在的额外 peer）；
/// ③ 每个计划路由 `destination` 必须在 `installed_routes`（CIDR 精确匹配）；
/// ④ 计划显式指定 MTU 则须与快照 `tunnel_mtu` 一致；
/// ⑤ 隧道不存在（`tunnel_exists=false`）→ 不匹配；
/// ⑥ 适配器实际地址读数存在且与计划地址不同 → 不匹配（手动换址的隧道）。
///
/// 调用方是 `#[cfg(windows)]` 的 `WindowsNetworkBackend`，故非 Windows 目标
/// 上本函数保持可编译（含单测）但无调用方——按仓内惯例以 cfg_attr 豁免
/// dead_code，让 Linux 本机能跑这些对账单测。
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn device_plan_matches(
    plan: &DevicePlan,
    extra_peer_keys: &std::collections::BTreeSet<String>,
    snapshot: &NetworkSnapshot,
) -> bool {
    if !snapshot.tunnel_exists {
        return false;
    }
    for peer in &plan.tunnel.peers {
        if !snapshot.peers.iter().any(|p| {
            p.public_key == peer.public_key
                // 集合语义：wg dump 读回的 CIDR 顺序不稳定，按集合比较。
                && p.allowed_ips.len() == peer.allowed_ips.len()
                && peer
                    .allowed_ips
                    .iter()
                    .all(|cidr| p.allowed_ips.contains(cidr))
        }) {
            return false;
        }
    }
    for p in &snapshot.peers {
        if plan
            .tunnel
            .peers
            .iter()
            .any(|pp| pp.public_key == p.public_key)
        {
            continue;
        }
        if extra_peer_keys.contains(&p.public_key) {
            continue;
        }
        return false;
    }
    for route in &plan.routes {
        if !snapshot.installed_routes.contains(&route.destination) {
            return false;
        }
    }
    if let Some(mtu) = plan.tunnel.mtu {
        if snapshot.tunnel_mtu != Some(mtu) {
            return false;
        }
    }
    // ⑥ 适配器实际地址：读数存在且与计划不符 → 手动换址，必须判不匹配。
    //    读数缺失（None）不判——证据缺失不假装一致，也不进重放死循环。
    if let Some(actual) = snapshot.tunnel_address {
        if actual != plan.tunnel.address {
            return false;
        }
    }
    // ⑦ 实际监听端口：直连钉住的固定端口与内核读数不符（手动 `wg set
    //    listen-port` / 半应用状态）→ 判不匹配，重放纠回。读数缺失不判。
    if let Some(port) = plan.tunnel.listen_port {
        if let Some(actual) = snapshot.tunnel_listen_port {
            if actual != port {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod device_plan_matches_tests {
    use super::*;
    use std::collections::BTreeSet;

    fn peer(key: &str) -> PeerConfig {
        PeerConfig {
            public_key: key.into(),
            allowed_ips: vec!["10.240.0.5/32".parse().unwrap()],
            endpoint: None,
            persistent_keepalive_secs: None,
        }
    }

    fn plan(peers: &[&str], routes: &[&str], mtu: Option<u32>) -> DevicePlan {
        DevicePlan {
            desired_revision: 1,
            hub_port: None,
            tunnel: TunnelConfig {
                name: "Meshlet".into(),
                address: "10.240.0.1".parse().unwrap(),
                address_prefix: 16,
                listen_port: None,
                peers: peers.iter().map(|p| peer(p)).collect(),
                mtu,
                private_key: None,
            },
            routes: routes
                .iter()
                .map(|r| RouteConfig {
                    destination: r.parse().unwrap(),
                    interface: "Meshlet".into(),
                    gateway: None,
                })
                .collect(),
            nat_rules: Vec::new(),
            hub_address: None,
            publish: None,
            ssh_config: None,
            desired_config_hash: "h".into(),
        }
    }

    fn snapshot(
        tunnel_exists: bool,
        peers: &[&str],
        routes: &[&str],
        mtu: Option<u32>,
    ) -> NetworkSnapshot {
        NetworkSnapshot {
            tunnel_exists,
            forwarding_enabled: None,
            peers: peers
                .iter()
                .map(|k| PeerObserved {
                    public_key: (*k).into(),
                    allowed_ips: vec!["10.240.0.5/32".parse().unwrap()],
                })
                .collect(),
            installed_routes: routes.iter().map(|r| r.parse().unwrap()).collect(),
            nat_rules: Vec::new(),
            tunnel_mtu: mtu,
            local_public_key: None,
            tunnel_address: None,
            tunnel_listen_port: None,
        }
    }

    fn empty_extra() -> BTreeSet<String> {
        BTreeSet::new()
    }

    #[test]
    fn adapter_address_mismatch_reads_as_not_matching() {
        // 手动把隧道地址改了（peer/路由/MTU 全一致）→ 必须判不匹配；
        // 读数缺失（None）不判。
        let p = plan(&["pk-a"], &["10.240.0.0/24"], None);
        let mut moved = snapshot(true, &["pk-a"], &["10.240.0.0/24"], None);
        moved.tunnel_address = Some("10.240.0.99".parse().unwrap());
        assert!(!device_plan_matches(&p, &empty_extra(), &moved));
        let mut matching = snapshot(true, &["pk-a"], &["10.240.0.0/24"], None);
        matching.tunnel_address = Some(p.tunnel.address);
        assert!(device_plan_matches(&p, &empty_extra(), &matching));
    }

    #[test]
    fn all_match_true() {
        let p = plan(&["pk-a", "pk-b"], &["10.240.0.0/24"], Some(1420));
        let s = snapshot(true, &["pk-a", "pk-b"], &["10.240.0.0/24"], Some(1420));
        assert!(device_plan_matches(&p, &empty_extra(), &s));
    }

    #[test]
    fn pinned_listen_port_mismatch_reads_as_not_matching() {
        // 直连钉住的固定端口与内核读数不符（手动 wg set listen-port /
        // 半应用）→ 必须判不匹配，重放纠回；读数缺失（None）不判。
        let mut p = plan(&["pk-a"], &["10.240.0.0/24"], None);
        p.tunnel.listen_port = Some(51820);
        let mut drifted = snapshot(true, &["pk-a"], &["10.240.0.0/24"], None);
        drifted.tunnel_listen_port = Some(60736);
        assert!(!device_plan_matches(&p, &empty_extra(), &drifted));
        let mut matching = snapshot(true, &["pk-a"], &["10.240.0.0/24"], None);
        matching.tunnel_listen_port = Some(51820);
        assert!(device_plan_matches(&p, &empty_extra(), &matching));
        // 证据缺失不判（不进重放死循环）。
        let mut unreadable = snapshot(true, &["pk-a"], &["10.240.0.0/24"], None);
        unreadable.tunnel_listen_port = None;
        assert!(device_plan_matches(&p, &empty_extra(), &unreadable));
    }

    #[test]
    fn wg_dump_listen_port_parses_interface_line() {
        // 接口行形状：私钥 本机公钥 监听端口 …
        let dump = format!("{} {} 51820\n", "x".repeat(32), "A".repeat(43) + "=");
        assert_eq!(crate::parse_wg_dump_listen_port(&dump), Some(51820));
        let no_port = format!("{} {}\n", "x".repeat(32), "A".repeat(43) + "=");
        assert_eq!(crate::parse_wg_dump_listen_port(&no_port), None);
        assert_eq!(crate::parse_wg_dump_listen_port(""), None);
        let junk = format!("{} {} not-a-port\n", "x".repeat(32), "A".repeat(43) + "=");
        assert_eq!(crate::parse_wg_dump_listen_port(&junk), None);
    }

    #[test]
    fn missing_plan_peer_false() {
        // 计划有 pk-c，快照缺 → 漂移。
        let p = plan(&["pk-a", "pk-c"], &[], None);
        let s = snapshot(true, &["pk-a"], &[], None);
        assert!(!device_plan_matches(&p, &empty_extra(), &s));
    }

    #[test]
    fn drifted_peer_false_but_extra_allowed_true() {
        // 快照多出 pk-x：不在计划也不在 extra → 未受管漂移。
        let p = plan(&["pk-a"], &[], None);
        let s = snapshot(true, &["pk-a", "pk-x"], &[], None);
        assert!(!device_plan_matches(&p, &empty_extra(), &s));
        // extra_peer_keys 放行 pk-x → 一致。
        let mut extra = empty_extra();
        extra.insert("pk-x".into());
        assert!(device_plan_matches(&p, &extra, &s));
    }

    #[test]
    fn drifted_peer_allowed_ips_false() {
        // 计划 peer 存在但内核 allowed-ips 已漂移（如被外部 wg set 改过）
        // → 必须判定不匹配以触发重放纠回。
        let p = plan(&["pk-a"], &[], None);
        let mut s = snapshot(true, &["pk-a"], &[], None);
        s.peers[0].allowed_ips = vec!["10.240.0.6/32".parse().unwrap()];
        assert!(!device_plan_matches(&p, &empty_extra(), &s));
    }

    #[test]
    fn missing_route_false() {
        // 计划路由 10.240.0.0/24 未安装 → 漂移。
        let p = plan(&[], &["10.240.0.0/24"], None);
        let s = snapshot(true, &[], &["192.168.1.0/24"], None);
        assert!(!device_plan_matches(&p, &empty_extra(), &s));
    }

    #[test]
    fn mtu_drift_false() {
        // 计划显式 1420，内核读数 1300 → 漂移。
        let p = plan(&[], &[], Some(1420));
        let s = snapshot(true, &[], &[], Some(1300));
        assert!(!device_plan_matches(&p, &empty_extra(), &s));
    }

    #[test]
    fn tunnel_not_exists_false() {
        let p = plan(&["pk-a"], &["10.240.0.0/24"], Some(1420));
        let s = snapshot(false, &[], &[], None);
        assert!(!device_plan_matches(&p, &empty_extra(), &s));
    }

    #[test]
    fn no_planned_mtu_skips_mtu_check() {
        // 计划未指定 MTU → 不比对，仅其余项判定。
        let p = plan(&["pk-a"], &["10.240.0.0/24"], None);
        let s = snapshot(true, &["pk-a"], &["10.240.0.0/24"], Some(1300));
        assert!(device_plan_matches(&p, &empty_extra(), &s));
    }
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

    #[test]
    fn derived_tunnel_mtu_tracks_the_underlay_with_floor() {
        assert_eq!(derive_tunnel_mtu(1500), 1420); // 以太网：默认值 = 正确值
        assert_eq!(derive_tunnel_mtu(9000), 8920); // jumbo underlay
        assert_eq!(derive_tunnel_mtu(1492), 1412); // PPPoE
        assert_eq!(derive_tunnel_mtu(1300), 1280); // 下限钳制
        assert_eq!(derive_tunnel_mtu(0), 1280); // 读数异常也不产生 0/回绕
    }

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

    #[test]
    fn ssh_alias_prefers_hub_override_then_hostname_then_peer_name() {
        // 三级来源如实标注：hub 显式覆写 > 节点真实主机名 > peer name。
        let (alias, source) = ssh_alias::resolve_alias("win", Some("DESKTOP"), Some("wd"));
        assert_eq!((alias.as_str(), source), ("wd", "hub-config"));

        let (alias, source) = ssh_alias::resolve_alias("win", Some("DESKTOP"), None);
        assert_eq!((alias.as_str(), source), ("DESKTOP", "hostname"));

        let (alias, source) = ssh_alias::resolve_alias("win", None, None);
        assert_eq!((alias.as_str(), source), ("win", "peer-name"));

        // 空串/空白覆写与主机名都回落；非法字符 sanitize。
        let (alias, source) = ssh_alias::resolve_alias("win", Some("  "), Some("  "));
        assert_eq!((alias.as_str(), source), ("win", "peer-name"));
        let (alias, source) = ssh_alias::resolve_alias("win", Some("My PC"), None);
        assert_eq!((alias.as_str(), source), ("My-PC", "hostname"));
        assert_eq!(ssh_alias::sanitize_alias("  "), "node");
    }

    /// 本机公钥指纹解析（BUG② 修复的读数端）：接口行字段 1；私钥（字段 0）
    /// 绝不返回；残行 / 占位文本 / 空表 → None。
    #[test]
    fn wg_dump_local_public_key_reads_field_one_and_validates_shape() {
        let key = format!("{}=", "K".repeat(43));
        let dump = format!("some-private-key\t{key}\t51820\t0\n");
        assert_eq!(parse_wg_dump_local_public_key(&dump), Some(key.clone()));
        // 接口行在前、peer 行在后：只看首行。
        let with_peer =
            format!("{dump}PEER-KEY-PLACEHOLDER\t\tendpoint\t10.240.0.2/32\t0\t0\t0\t0\n");
        assert_eq!(parse_wg_dump_local_public_key(&with_peer), Some(key));
        // 空表 / 残行 / 非法形状。
        assert_eq!(parse_wg_dump_local_public_key(""), None);
        assert_eq!(parse_wg_dump_local_public_key("only-private-key\n"), None);
        assert_eq!(
            parse_wg_dump_local_public_key("priv\tPLACEHOLDER\t51820\t0\n"),
            None
        );
    }
}
