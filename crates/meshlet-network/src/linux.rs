//! Linux 数据面实现（[ADR-007](../../docs/decisions/adr-007-linux-network-backend.md)）：
//! 受控执行 `ip` / `wg` / `iptables` 系统命令（ADR-007 的受控降级路径，
//! Netlink/nftables 化留待其重评估条件触发）。
//!
//! 所有命令都经 [LinuxNetworkBackend::run] 以参数数组执行（无 shell 拼接，
//! §4.3 禁止项）；每个可写操作都幂等（`replace`/`-C` 探测/`peer remove`
//! 对账），保证重复应用同一修订结果一致（§10.3）。
//!
//! 命令面坑位（netns 集成测试真机验证，见 `tests/wg_forwarding.rs` 头注）：
//! - `wg set` 的 private-key 与 peer 必须**分两次**调用（合并调用会静默丢 peer）；
//! - `wg setconf` 在本环境触发 fopen EPERM，只用 `wg set`；
//! - peer 的 endpoint 指向对端 **netns 侧** 地址（宿主侧 veth 地址会让握手
//!   对错端口）；
//! - 回滚只删 Meshlet 自有对象：所有权标记为 iptables 注释（`meshlet alias
//!   {id}` / `meshlet tunnel`）与「本后端的隧道接口上的对象」，绝不触碰
//!   系统路由与用户已有规则（§10.3、ADR-007）。
//!
//! `netns` / `sudo` 两个字段是测试钩子：生产以特权进程直连宿主网络栈
//! （`netns=None, sudo=false`）；集成测试在无特权 runner 上用 `sudo -n` 进
//! 入 netns 操作（`with_netns(..).with_sudo()`）。

mod backend;
mod operations;
mod parser;

/// iptables 所有权注释前缀：nat 规则带 `meshlet alias {id}`（§12.6），filter
/// 的 FORWARD 放行规则带 `meshlet tunnel`——回滚/清理只按注释精确定位。
pub const MESHLET_NAT_COMMENT_PREFIX: &str = "meshlet alias";
pub const MESHLET_FILTER_COMMENT: &str = "meshlet tunnel";
/// Routing-protocol number used as Meshlet's route ownership marker.
pub const MESHLET_ROUTE_PROTO: &str = "198";

/// 宿主防火墙放行动作（AGENT-FW-2）。
///
/// 背景：Linux 宿主若启用 ufw/firewalld，其默认 INPUT 策略可能挡 mesh 接口
/// 的 ICMP/业务流量（与 Windows Public 档挡 ICMP 同源）。检测到管理器活跃
/// 时自动放行 mesh 接口流量，幂等。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostFirewallAction {
    /// `ufw allow in on <if>`：放行接口入向。
    UfwAllowInOn { interface: String },
    /// `firewall-cmd --zone=trusted --add-interface=<if>`：接口入 trusted 区
    /// （全放行）。运行时配置；agent 每次 apply 重探，重启后对账恢复。
    FirewalldTrustedInterface { interface: String },
    /// `ufw allow in proto udp to any port <p>`：放行直连 UDP 端口（§12.4）。
    /// 直连 peer 经 LAN/公网接口到达本机 wg 监听端口，接口级放行（wg0）不
    /// 覆盖，必须按端口开。
    UfwAllowPort { port: u16 },
    /// `firewall-cmd --zone=trusted --add-port=<p>/udp`：同上（firewalld）。
    FirewalldAllowPort { port: u16 },
}

/// 纯规划（AGENT-FW-2，跨平台单测）：给定 ufw/firewalld 活跃态与规则现状，
/// 产出放行动作。全幂等——已放行 → 空计划；管理器未活跃 → 不动作。
pub fn host_firewall_allow_actions(
    ufw_active: bool,
    ufw_interface_allowed: bool,
    firewalld_active: bool,
    firewalld_interface_allowed: bool,
    interface: &str,
) -> Vec<HostFirewallAction> {
    let mut actions = Vec::new();
    if ufw_active && !ufw_interface_allowed {
        actions.push(HostFirewallAction::UfwAllowInOn {
            interface: interface.into(),
        });
    }
    if firewalld_active && !firewalld_interface_allowed {
        actions.push(HostFirewallAction::FirewalldTrustedInterface {
            interface: interface.into(),
        });
    }
    actions
}

/// 纯规划（§12.4 防火墙联动，跨平台单测）：直连 UDP 端口的宿主放行计划。
/// 全幂等——已放行 → 空计划；管理器未活跃 → 不动作。直连 peer 的入向流量
/// 经 LAN/公网接口到达，接口级放行不覆盖，须按端口开。
pub fn direct_udp_firewall_allow_actions(
    ufw_active: bool,
    ufw_port_allowed: bool,
    firewalld_active: bool,
    firewalld_port_allowed: bool,
    port: u16,
) -> Vec<HostFirewallAction> {
    let mut actions = Vec::new();
    if ufw_active && !ufw_port_allowed {
        actions.push(HostFirewallAction::UfwAllowPort { port });
    }
    if firewalld_active && !firewalld_port_allowed {
        actions.push(HostFirewallAction::FirewalldAllowPort { port });
    }
    actions
}

/// 外来 overlay 隔离规则的 iptables 所有权注释（AGENT-ISO-1）：回滚/清理按
/// 注释精确定位，与 [MESHLET_FILTER_COMMENT] 同一纪律（§10.3）。
pub const MESHLET_ISOLATION_COMMENT: &str = "meshlet foreign-overlay isolation";

/// 外来 overlay 的守护进程用户名（`id -u` 取 uid 的对象）。
pub const FOREIGN_OVERLAY_USER: &str = "zerotier-one";

/// 外来 overlay 主协议的知名源端口（ZeroTier 为 9993）。
pub const FOREIGN_OVERLAY_WELLKNOWN_PORT: u16 = 9993;

/// 外来 overlay 隔离规则（AGENT-ISO-1）。
///
/// 一条规则 = 目标链 + 规则主体；`-C`（探测）与 `-I`（插入）共用 `spec`，
/// 执行侧只需换动词。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayIsolationRule {
    /// 目标链（`OUTPUT` / `INPUT`）。
    pub chain: String,
    /// 规则主体（不含 `iptables`、`-t`、链名与插入位置）。
    pub spec: Vec<String>,
}

/// 外来 overlay（ZeroTier 类）的身份输入（AGENT-ISO-1）。
///
/// 读不到的字段为 `None` / 空——**不臆测**（§7.5）：对端不存在时不编造 uid
/// 或端口，对应规则直接缺席。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ForeignOverlay {
    /// 对方守护进程的 uid（`id -u <user>`）。`None` = 用户不存在 / 读取失败。
    pub uid: Option<u32>,
    /// 对方主套接字的本地 UDP 监听端口（ZeroTier 重启会变，须每次现读）。
    pub local_ports: Vec<u16>,
    /// 对方主协议的知名源端口（ZeroTier 为 9993）。
    pub wellknown_port: u16,
}

/// 纯规划（AGENT-ISO-1，跨平台单测）：产出「外来 overlay 不得借道 meshlet
/// 隧道」的期望规则。
///
/// 递归封装的成因是两条隧道**互为路径**：meshlet 的 WG endpoint 落在 ZeroTier
/// 网段（出向借道），ZeroTier 又把 meshlet overlay 学成对端路径（入向借道）。
/// 任一方向被切断即不成环，本函数给出双向规则：
///
/// 1. `OUTPUT -o <if> -m owner --uid-owner <uid>`：对方进程不得往 meshlet
///    隧道发包（切断出向，硬保证）；
/// 2. `INPUT -i <if> -p udp --dport <port>`：对方套接字不得从 meshlet 隧道
///    收包（其 overlay 路径随之过期，回落公网路径）；
/// 3. `INPUT -i <if> -p udp --sport <wellknown>`：对方协议不得从 meshlet
///    隧道进本机（拦截对端借道进来的同款包）。
///
/// `interface` 为空、或 `foreign` 未给出任何身份 → 空计划（不臆测）。
/// 全部规则带 [MESHLET_ISOLATION_COMMENT] 所有权标记。
pub fn overlay_isolation_rules(
    interface: &str,
    foreign: &ForeignOverlay,
) -> Vec<OverlayIsolationRule> {
    if interface.is_empty() {
        return Vec::new();
    }
    let mut rules = Vec::new();
    if let Some(uid) = foreign.uid {
        rules.push(OverlayIsolationRule {
            chain: "OUTPUT".into(),
            spec: vec![
                "-o".into(),
                interface.into(),
                "-m".into(),
                "owner".into(),
                "--uid-owner".into(),
                uid.to_string(),
                "-m".into(),
                "comment".into(),
                "--comment".into(),
                MESHLET_ISOLATION_COMMENT.into(),
                "-j".into(),
                "DROP".into(),
            ],
        });
    }
    for port in &foreign.local_ports {
        rules.push(OverlayIsolationRule {
            chain: "INPUT".into(),
            spec: vec![
                "-i".into(),
                interface.into(),
                "-p".into(),
                "udp".into(),
                "--dport".into(),
                port.to_string(),
                "-m".into(),
                "comment".into(),
                "--comment".into(),
                MESHLET_ISOLATION_COMMENT.into(),
                "-j".into(),
                "DROP".into(),
            ],
        });
    }
    if foreign.wellknown_port > 0 {
        rules.push(OverlayIsolationRule {
            chain: "INPUT".into(),
            spec: vec![
                "-i".into(),
                interface.into(),
                "-p".into(),
                "udp".into(),
                "--sport".into(),
                foreign.wellknown_port.to_string(),
                "-m".into(),
                "comment".into(),
                "--comment".into(),
                MESHLET_ISOLATION_COMMENT.into(),
                "-j".into(),
                "DROP".into(),
            ],
        });
    }
    rules
}

/// `ss -H -ulnp` → 某进程名的本地 UDP 监听端口（去重升序，纯解析）。
///
/// 行形如（列序：State Recv-Q Send-Q **Local** Peer Process）：
/// `UNCONN 0 0 10.240.0.4%wg-mlt:63614 0.0.0.0:* users:(("zerotier-one",pid=1579,fd=25))`
///
/// 取**第 4 列**（本地地址）末段端口——地址可能带 `%接口` 作用域后缀，
/// `rsplit(':')` 取末段即可剥掉。仅收含 `needle`（进程名）的行；`users:` 列
/// 需要读他人进程的权限（root 才有），缺失不影响按行内进程名过滤。
pub fn parse_ss_udp_listen_ports(output: &str, needle: &str) -> Vec<u16> {
    let mut ports: Vec<u16> = output
        .lines()
        .filter(|line| line.contains(needle))
        .filter_map(|line| {
            let local = line.split_whitespace().nth(3)?;
            let port = local.rsplit(':').next()?;
            port.parse::<u16>().ok()
        })
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

pub(crate) use parser::{
    chrono_now_iso, enforced_tunnel_mtu, foreign_route_line, is_lan_interface, mtu_matches_planned,
    parse_default_route_interface, parse_ip_octet_addrs, parse_ip_octet_subnets, parse_link_mtu,
    parse_wg_dump_diag_line, route_source,
};

pub use backend::LinuxNetworkBackend;
pub use parser::{parse_ping_rtt_ms, run_ping_rtt};

#[cfg(test)]
mod tests;
