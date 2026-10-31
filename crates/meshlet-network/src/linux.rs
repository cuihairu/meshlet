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

use std::collections::BTreeMap;
use std::net::SocketAddrV4;
use std::process::{Command, Output, Stdio};

use meshlet_domain::Ipv4Cidr;
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::str::FromStr;

use crate::nat::{NatAction, NatChain, NatRule};
use crate::{
    ApplyResult, ConfigRevisionRef, DevicePlan, NetworkBackend, NetworkError, NetworkSnapshot,
    PeerObserved, RouteConfig, TunnelConfig, DEFAULT_TUNNEL_MTU,
};

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

/// 从 `ip link show <if>` 输出解析实际 MTU 读数（首行形如
/// `3: wg0: <...> mtu 1420 qdisc noqueue ...`）。读不到 `mtu` 字段或无法
/// 解析时返回 `None`——调用方按「读数不可得」处理，不臆测默认值。
fn parse_link_mtu(link_show: &str) -> Option<u32> {
    let mut tokens = link_show.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "mtu" {
            return tokens.next().and_then(|v| v.parse().ok());
        }
    }
    None
}

/// 从 `ip -4 -o addr show` 输出解析 `(接口, IPv4 地址)` 对（仅 `inet` 行）。
/// 形如 `2: eth0    inet 192.168.1.50/24 ...`（`-o` 单行每地址一行）。
fn parse_ip_octet_addrs(output: &str) -> Vec<(String, Ipv4Addr)> {
    output
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 || fields[2] != "inet" {
                return None;
            }
            let ifname = fields[1].to_string();
            let addr: Ipv4Addr = fields[3].split('/').next()?.parse().ok()?;
            Some((ifname, addr))
        })
        .collect()
}

/// 同 [`parse_ip_octet_addrs`]，但保留前缀长度（`192.168.1.50/24` → 网段）。
/// 仅解析合法网段（前缀 0–32）；解析失败的行跳过（调用方按「该子网不可知」
/// 处理，不臆造）。
fn parse_ip_octet_subnets(output: &str) -> Vec<(String, meshlet_domain::Ipv4Cidr)> {
    output
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 || fields[2] != "inet" {
                return None;
            }
            let ifname = fields[1].to_string();
            // 接口地址形如 `10.98.0.20/24`——主机位恒非零，不能用
            // `Ipv4Cidr::from_str`（其要求规范化网络地址）；按「地址+前缀」
            // 掩出所属网段（`10.98.0.0/24`）。
            let (addr, prefix) = fields[3].split_once('/')?;
            let addr: std::net::Ipv4Addr = addr.parse().ok()?;
            let prefix: u8 = prefix.parse().ok()?;
            let subnet = meshlet_domain::Ipv4Cidr::from_host_address(addr, prefix).ok()?;
            Some((ifname, subnet))
        })
        .collect()
}

/// 候选 LAN 接口：排除回环、受管隧道，以及容器/虚拟化/vpn 等不会承载
/// 对端直连的虚拟接口（`docker*`/`br-*`/`veth*`/`virbr*`/`vmbr*`/
/// `tailscale*`/`wg*`）。
fn is_lan_interface(ifname: &str, wg_interface: &str) -> bool {
    if ifname == "lo" || ifname == wg_interface {
        return false;
    }
    for prefix in ["docker", "br-", "veth", "virbr", "vmbr", "tailscale", "wg"] {
        if ifname.starts_with(prefix) {
            return false;
        }
    }
    true
}

/// The MTU the agent enforces. An unset plan value means the WireGuard default
/// ([`DEFAULT_TUNNEL_MTU`]), not "leave the interface alone" — see
/// [`mtu_matches_planned`].
fn enforced_tunnel_mtu(planned: Option<u32>) -> u32 {
    planned.unwrap_or(DEFAULT_TUNNEL_MTU)
}

/// Readback half of MTU convergence: true only when the interface carries the
/// MTU the plan intends. The default is enforced like an explicit value, so an
/// interface left at a higher MTU (by an older plan or a manual `ip link set`)
/// is seen as drifted on the next reconcile instead of matching the plan.
fn mtu_matches_planned(link_show: &str, planned: Option<u32>) -> bool {
    parse_link_mtu(link_show) == Some(enforced_tunnel_mtu(planned))
}

/// 解析 `wg show <if> latest-handshakes` 输出（每行 `公钥 握手unix时间 距今秒`）：
/// 公钥 → 距今秒数。第三列优先（WireGuard 自己算好的年龄）；缺第三列时按
/// `now - 握手时间` 兜底。握手时间为 0（从未握手）的 peer 不在输出里——
/// 调用方按「无读数」处理（§12 `classify_probe` 的 Unknown/Unhealthy 之别）。
fn parse_handshake_ages(text: &str, now_secs: u64) -> BTreeMap<String, u64> {
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

/// Kernel-selected source for the actual destination, not an address inside its prefix.
fn route_source(route_get: &str, tunnel: &str) -> Option<Ipv4Addr> {
    let fields: Vec<_> = route_get.split_whitespace().collect();
    if matches!(
        fields.first().copied(),
        Some("local" | "broadcast" | "unreachable" | "blackhole" | "prohibit")
    ) {
        return None;
    }
    let dev = fields.windows(2).find(|p| p[0] == "dev")?[1];
    if dev == tunnel || dev == "lo" {
        return None;
    }
    let source: Ipv4Addr = fields.windows(2).find(|p| p[0] == "src")?[1].parse().ok()?;
    (!source.is_unspecified() && !source.is_loopback()).then_some(source)
}

/// §18.3：判读 `ip route show exact <dst>` 的一行是否为「不经受管接口的
/// 外来路由」。返回 `Some(行原文)` 表示冲突——目标前缀已被指往别的路径，
/// `ip route replace` 会静默接管它，必须改为显式拒绝；`None` 表示经受管
/// 接口的既有路由（Meshlet 自有对象，幂等改写属正常计划变更）。解析不出
/// `dev` 的行（blackhole / 输出格式变化）按冲突处理——fail closed，不放过
/// 未知对象。
fn foreign_route_line(line: &str, interface: &str) -> Option<String> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    match tokens
        .iter()
        .position(|t| *t == "dev")
        .and_then(|i| tokens.get(i + 1))
    {
        Some(dev) if *dev == interface => None,
        _ => Some(line.trim().to_string()),
    }
}

/// Linux 网络后端：命令执行器 + 对账式幂等应用。
pub struct LinuxNetworkBackend {
    /// 测试钩子：命令在此 netns 内执行（`ip netns exec <ns> ...`）。
    netns: Option<String>,
    /// 测试钩子：每条命令前缀 `sudo -n`（无特权集成测试用）。
    sudo: bool,
    /// 受管隧道接口名（默认 `wg0`）。
    interface: String,
}

impl LinuxNetworkBackend {
    pub fn new() -> Self {
        Self {
            netns: None,
            sudo: false,
            interface: "wg0".to_string(),
        }
    }

    /// 测试钩子：在指定网络命名空间内执行命令。
    pub fn with_netns(mut self, netns: impl Into<String>) -> Self {
        self.netns = Some(netns.into());
        self
    }

    /// 测试钩子：以 `sudo -n` 前缀执行每条命令。
    pub fn with_sudo(mut self) -> Self {
        self.sudo = true;
        self
    }

    /// 受管接口名（默认 `wg0`）。
    pub fn with_interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = interface.into();
        self
    }

    /// 命令前缀（sudo / netns 测试钩子展开在这之后统一处理）。
    fn command_prefix(&self) -> Vec<&str> {
        let mut prefix: Vec<&str> = Vec::with_capacity(6);
        if self.sudo {
            prefix.extend(["sudo", "-n"]);
        }
        if let Some(ns) = &self.netns {
            prefix.extend(["ip", "netns", "exec", ns.as_str()]);
        }
        prefix
    }

    /// 执行一条命令。非零退出返回携带 stderr 的 [NetworkError::Io]
    /// （不静默、不假装成功）。
    fn run(&self, argv: &[&str]) -> Result<Output, NetworkError> {
        let mut full = self.command_prefix();
        full.extend_from_slice(argv);

        let out = Command::new(full[0])
            .args(&full[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| NetworkError::Io(format!("spawn {}: {e}", full.join(" "))))?;
        Self::check(&out, &full)
    }

    /// `bash -c <script>` + 管道 stdin（私钥下发专用路径）。私钥经 stdin
    /// 传递，不进 argv/命令行（`ps` 不可见）。
    fn run_bash_stdin(&self, script: &str, input: &str) -> Result<Output, NetworkError> {
        use std::io::Write;
        let mut full = self.command_prefix();
        full.extend(["bash", "-c"]);
        let mut child = Command::new(full[0])
            .args(&full[1..])
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| NetworkError::Io(format!("spawn {}: {e}", full.join(" "))))?;
        child
            .stdin
            .as_mut()
            .expect("piped stdin")
            .write_all(input.as_bytes())
            .map_err(|e| NetworkError::Io(format!("stdin write: {e}")))?;
        let out = child
            .wait_with_output()
            .map_err(|e| NetworkError::Io(format!("wait: {e}")))?;
        Self::check(&out, &full)
    }

    fn check(out: &Output, full: &[&str]) -> Result<Output, NetworkError> {
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let detail = if err.is_empty() { stdout } else { err };
            return Err(NetworkError::Io(format!(
                "{} exited {}: {}",
                full.join(" "),
                out.status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".to_string()),
                detail
            )));
        }
        Ok(out.clone())
    }

    /// `wg show <if> peers` 输出（每行一个公钥）。
    fn existing_peers(&self) -> Result<Vec<String>, NetworkError> {
        Ok(self
            .peers_on_interface()?
            .into_iter()
            .map(|peer| peer.public_key)
            .collect())
    }

    /// `wg show <if> dump` 的 peer 行 → 身份级读数（公钥 + allowed-ips）。
    /// 漂移判定按**身份集合**而非条数：多一个不该在的 peer、某 peer 的
    /// allowed-ips 被改宽，都与「少一个 peer」同样必须重放纠回。
    fn peers_on_interface(&self) -> Result<Vec<PeerObserved>, NetworkError> {
        let dump = self.run(&["wg", "show", &self.interface, "dump"])?;
        let body = String::from_utf8_lossy(&dump.stdout);
        Ok(body
            .lines()
            .skip(1) // 首行是本机（private_key 起头），其后每行一个 peer。
            .filter_map(Self::parse_peer_dump_line)
            .collect())
    }

    /// 单行 peer dump 解析（`pubkey presharedkey endpoint allowed-ips …`，
    /// allowed-ips 逗号分隔、可为空）。纯函数，单测直接覆盖。
    fn parse_peer_dump_line(line: &str) -> Option<PeerObserved> {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // 公钥固定为 44 字符 base64（32 字节 curve25519）且以 `=` 结尾：
        // 空行 / 残行 / 占位串不臆造 peer。
        let public_key = fields.first()?;
        if public_key.len() != 44 || !public_key.ends_with('=') {
            return None;
        }
        let public_key = public_key.to_string();
        let allowed_ips = fields
            .get(3)
            .unwrap_or(&"")
            .split(',')
            .filter_map(|c| c.trim().parse().ok())
            .collect();
        Some(PeerObserved {
            public_key,
            allowed_ips,
        })
    }

    /// 对账式 peer 下发：目标集之外的 peer 显式移除（撤销即失效，§11.5）。
    ///
    /// `keep_keys` 是 P2P 直连对端（§12）：它们由 agent 的直连管理器单独
    /// 增删（`set_direct_peer_sync` / `remove_peer_sync`），不属于服务端计划。
    /// 计划重放时把它们当「保留集」，**只不删**、不重刷——避免与服务端期望
    /// 哈希无关的直连态在每次配置变更时被冲掉。
    fn reconcile_peers(
        &self,
        config: &TunnelConfig,
        keep_keys: &BTreeSet<String>,
    ) -> Result<(), NetworkError> {
        let existing = self.existing_peers()?;
        for peer in &config.peers {
            let allowed = peer
                .allowed_ips
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let mut args: Vec<String> = vec![
                "wg".into(),
                "set".into(),
                self.interface.clone(),
                "peer".into(),
                peer.public_key.clone(),
                "allowed-ips".into(),
                allowed,
            ];
            if let Some(ep) = &peer.endpoint {
                args.extend(["endpoint".into(), ep.clone()]);
            }
            if let Some(ka) = peer.persistent_keepalive_secs {
                args.extend(["persistent-keepalive".into(), ka.to_string()]);
            }
            let argv: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            self.run(&argv)?;
        }
        for key in existing {
            if config.peers.iter().any(|p| p.public_key == key) {
                continue;
            }
            if keep_keys.contains(&key) {
                continue;
            }
            self.run(&["wg", "set", &self.interface, "peer", &key, "remove"])?;
        }
        Ok(())
    }

    /// 各对端最近一次握手距今秒数（`wg show <if> latest-handshakes`）：
    /// 公钥 → 距今秒数。从未握手的 peer 不在输出里（WireGuard 输出 0，
    /// 这里按「无读数」跳过）。P2P 健康探测用（§12）。
    pub fn handshake_ages_sync(&self) -> Result<BTreeMap<String, u64>, NetworkError> {
        let out = self.run(&["wg", "show", &self.interface, "latest-handshakes"])?;
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Ok(parse_handshake_ages(
            &String::from_utf8_lossy(&out.stdout),
            now_secs,
        ))
    }

    /// 直连 peer 下发（P2P，§12）：`allowed-ips` 只写对端 overlay `/32` +
    /// `endpoint`（直连地址）+ `persistent-keepalive`（既开 NAT 打洞的洞，
    /// 也是健康探测的心跳）。幂等：重复调用结果一致。
    ///
    /// `/32` 最长前缀匹配天然优先于 hub peer 的整段路由，故不触碰 hub 配置
    /// 也能把流量引到直连路径。
    pub fn set_direct_peer_sync(
        &self,
        public_key: &str,
        allowed_ips: &[Ipv4Cidr],
        endpoint: SocketAddrV4,
        persistent_keepalive_secs: u32,
    ) -> Result<(), NetworkError> {
        let allowed = allowed_ips
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let endpoint = endpoint.to_string();
        let keepalive = persistent_keepalive_secs.to_string();
        self.run(&[
            "wg",
            "set",
            &self.interface,
            "peer",
            public_key,
            "allowed-ips",
            &allowed,
            "endpoint",
            &endpoint,
            "persistent-keepalive",
            &keepalive,
        ])?;
        Ok(())
    }

    /// 移除直连 peer（回退 hub，§12）：`wg set <if> peer <key> remove`。
    /// 幂等：不存在也成功（WireGuard 对缺失 peer 的 remove 是 no-op）。
    pub fn remove_peer_sync(&self, public_key: &str) -> Result<(), NetworkError> {
        self.run(&["wg", "set", &self.interface, "peer", public_key, "remove"])?;
        Ok(())
    }

    /// `ip -4 route show dev <if> proto <marker>` → successful Meshlet route
    /// destinations. The routing protocol marker is the route-side ownership
    /// tag: unlike `proto kernel` connected routes, these objects can be
    /// enumerated safely even after the local agent ledger is lost.
    fn routes_on_interface(&self) -> Result<Vec<Ipv4Cidr>, NetworkError> {
        let out = self.run(&[
            "ip",
            "-4",
            "route",
            "show",
            "dev",
            &self.interface,
            "proto",
            MESHLET_ROUTE_PROTO,
        ])?;
        let mut dsts = Vec::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let mut fields = line.split_whitespace();
            let dst = fields.next().unwrap_or("");
            if dst.is_empty() || dst == "default" {
                continue;
            }
            let cidr = match dst.parse::<std::net::Ipv4Addr>() {
                Ok(addr) => {
                    let prefix = fields
                        .next()
                        .and_then(|spec| spec.strip_prefix('/'))
                        .and_then(|prefix| prefix.parse().ok())
                        .unwrap_or(32);
                    Ipv4Cidr::new(addr, prefix)
                }
                Err(_) => Ipv4Cidr::from_str(dst),
            };
            let cidr = match cidr {
                Ok(cidr) => cidr,
                Err(_) => return Err(NetworkError::Io(format!("unparsable route line: {line}"))),
            };
            dsts.push(cidr);
        }
        Ok(dsts)
    }

    /// 带引号的 iptables `-S` 输出分词（注释含空格，需保留为单 token）。
    fn split_iptables_line(line: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut cur = String::new();
        let mut in_quotes = false;
        for ch in line.chars() {
            match ch {
                '"' => in_quotes = !in_quotes,
                ' ' if !in_quotes => {
                    if !cur.is_empty() {
                        tokens.push(std::mem::take(&mut cur));
                    }
                }
                _ => cur.push(ch),
            }
        }
        if !cur.is_empty() {
            tokens.push(cur);
        }
        tokens
    }

    /// nat 表 PREROUTING/POSTROUTING 中携带指定所有权注释的规则（回滚与
    /// remove_nat 共用定位逻辑）。`owner=None` = 全部 `meshlet alias` 前缀。
    /// 返回删除用参数（`-A` 已换成 `-D`）。
    fn meshlet_nat_rules(&self, owner: Option<&str>) -> Result<Vec<Vec<String>>, NetworkError> {
        let mut deletions = Vec::new();
        for chain in [NatChain::Prerouting, NatChain::Postrouting] {
            deletions.extend(self.meshlet_nat_rules_in(chain, owner)?);
        }
        Ok(deletions)
    }

    /// 单条链上的 Meshlet 所有权规则（[meshlet_nat_rules] 的链级拆分）。
    fn meshlet_nat_rules_in(
        &self,
        chain: NatChain,
        owner: Option<&str>,
    ) -> Result<Vec<Vec<String>>, NetworkError> {
        let out = self.run(&["iptables", "-t", "nat", "-S", chain.as_str()])?;
        let mut deletions = Vec::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if let Some(del) = Self::meshlet_rule_deletion(line, owner) {
                deletions.push(del);
            }
        }
        Ok(deletions)
    }

    /// 单行 `-A CHAIN ...` 若为匹配的 Meshlet 所有权规则，返回其删除参数
    /// （`-A` 换成 `-D`）；否则 `None`。纯函数，单测直接覆盖。
    fn meshlet_rule_deletion(line: &str, owner: Option<&str>) -> Option<Vec<String>> {
        let tokens = Self::split_iptables_line(line);
        if tokens.len() < 2 || tokens[0] != "-A" {
            return None;
        }
        let comment = tokens
            .iter()
            .position(|t| t == "--comment")
            .and_then(|i| tokens.get(i + 1))?;
        let matches = match owner {
            Some(o) => *comment == o,
            None => comment.starts_with(MESHLET_NAT_COMMENT_PREFIX),
        };
        if !matches {
            return None;
        }
        let mut del = vec!["-D".to_string(), tokens[1].clone()];
        del.extend(tokens[2..].iter().cloned());
        Some(del)
    }
}

impl LinuxNetworkBackend {
    /// 同步检查快照（inspect 的命令核心；服务端同步 backend 直接调用）。
    pub fn inspect_sync(&self) -> Result<NetworkSnapshot, NetworkError> {
        let link = self.run(&["ip", "link", "show", &self.interface]).ok();
        let tunnel_exists = link.is_some();
        let tunnel_mtu = link
            .as_ref()
            .and_then(|out| parse_link_mtu(&String::from_utf8_lossy(&out.stdout)));
        let forwarding_enabled = self
            .run(&["sysctl", "-n", "net.ipv4.ip_forward"])
            .ok()
            .and_then(|out| match String::from_utf8_lossy(&out.stdout).trim() {
                "1" => Some(true),
                "0" => Some(false),
                _ => None,
            });
        let peers = if tunnel_exists {
            self.peers_on_interface()?
        } else {
            Vec::new()
        };
        let installed_routes = if tunnel_exists {
            self.routes_on_interface()?
        } else {
            Vec::new()
        };
        let nat_rules = self.meshlet_nat_signatures_sync()?;
        Ok(NetworkSnapshot {
            tunnel_exists,
            forwarding_enabled,
            peers,
            installed_routes,
            nat_rules,
            tunnel_mtu,
        })
    }

    /// 枚举本机 RFC1918 局域网地址（§12 P2P 直连候选上报）：`ip -4 -o addr
    /// show` 里过滤回环、受管隧道与容器/虚拟接口。命令失败返回错误，由调用方
    /// 决定是否仍上报（候选为空）。
    pub fn lan_addresses_sync(&self) -> Result<Vec<Ipv4Addr>, NetworkError> {
        let out = self.run(&["ip", "-4", "-o", "addr", "show"])?;
        let mut addrs: Vec<Ipv4Addr> = parse_ip_octet_addrs(&String::from_utf8_lossy(&out.stdout))
            .into_iter()
            .filter(|(ifname, _)| is_lan_interface(ifname, &self.interface))
            .map(|(_, addr)| addr)
            .filter(|addr| meshlet_domain::is_private_ip(*addr))
            .collect();
        addrs.sort_unstable();
        addrs.dedup();
        Ok(addrs)
    }

    /// 枚举本机 RFC1918 局域网**子网**（§12 P2P 同网段判定）：与
    /// [`lan_addresses_sync`] 同一来源，但保留前缀长度——「对端 LAN 候选是否
    /// 落在本机子网内」需要网段而不是单个地址。
    pub fn lan_subnets_sync(&self) -> Result<Vec<meshlet_domain::Ipv4Cidr>, NetworkError> {
        let out = self.run(&["ip", "-4", "-o", "addr", "show"])?;
        let mut subnets: Vec<meshlet_domain::Ipv4Cidr> =
            parse_ip_octet_subnets(&String::from_utf8_lossy(&out.stdout))
                .into_iter()
                .filter(|(ifname, _)| is_lan_interface(ifname, &self.interface))
                .map(|(_, subnet)| subnet)
                .filter(|subnet| meshlet_domain::is_private_ip(subnet.network()))
                .collect();
        subnets.sort();
        subnets.dedup();
        Ok(subnets)
    }

    /// Remove only this hub interface and its isolation rules; gateways own NAT.
    pub fn clear_hub_sync(&self) -> Result<(), NetworkError> {
        let chain = format!("MLT_{}", self.interface);
        for table_chain in ["INPUT", "FORWARD"] {
            let out = self.run(&["iptables", "-S", table_chain])?;
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let tokens = Self::split_iptables_line(line);
                if tokens.first().map(String::as_str) != Some("-A") {
                    continue;
                }
                let owned = tokens
                    .windows(2)
                    .any(|p| (p[0] == "-j" || p[0] == "--comment") && p[1] == chain)
                    || (tokens
                        .windows(2)
                        .any(|p| (p[0] == "-i" || p[0] == "-o") && p[1] == self.interface)
                        && tokens
                            .windows(2)
                            .any(|p| p[0] == "--comment" && p[1] == MESHLET_FILTER_COMMENT));
                if owned {
                    let mut argv = vec!["iptables", "-D"];
                    argv.extend(tokens[1..].iter().map(String::as_str));
                    self.run(&argv)?;
                }
            }
        }
        if self.run(&["iptables", "-S", &chain]).is_ok() {
            self.run(&["iptables", "-F", &chain])?;
            self.run(&["iptables", "-X", &chain])?;
        }
        if self.run(&["ip", "link", "show", &self.interface]).is_ok() {
            self.run(&["ip", "link", "del", &self.interface])?;
        }
        Ok(())
    }

    /// Hub traffic can only be forwarded between peers of this network.
    pub fn isolate_hub_sync(&self, address: Ipv4Addr) -> Result<(), NetworkError> {
        let chain = format!("MLT_{}", self.interface);
        if self.run(&["iptables", "-S", &chain]).is_err() {
            self.run(&["iptables", "-N", &chain])?;
        }
        let out = self.run(&["iptables", "-S", &chain])?;
        let text = String::from_utf8_lossy(&out.stdout);
        let actual: Vec<_> = text
            .lines()
            .filter(|line| line.starts_with("-A "))
            .collect();
        let accept = format!(
            "-A {chain} -i {} -o {} -j ACCEPT",
            self.interface, self.interface
        );
        let drop = format!("-A {chain} -j DROP");
        if actual != [accept.as_str(), drop.as_str()] {
            // Install a fail-closed pair before discarding a drifted rule set.
            self.run(&["iptables", "-I", &chain, "1", "-j", "DROP"])?;
            self.run(&[
                "iptables",
                "-I",
                &chain,
                "1",
                "-i",
                &self.interface,
                "-o",
                &self.interface,
                "-j",
                "ACCEPT",
            ])?;
            for _ in actual {
                self.run(&["iptables", "-D", &chain, "3"])?;
            }
        }
        for dir in ["-i", "-o"] {
            let mut args = vec![
                "iptables",
                "-C",
                "FORWARD",
                dir,
                &self.interface,
                "-j",
                &chain,
            ];
            if self.run(&args).is_err() {
                args[1] = "-I";
                self.run(&args)?;
            }
        }
        let address = address.to_string();
        let mut args = vec![
            "iptables",
            "-C",
            "INPUT",
            "-i",
            &self.interface,
            "!",
            "-d",
            &address,
            "-m",
            "comment",
            "--comment",
            &chain,
            "-j",
            "DROP",
        ];
        if self.run(&args).is_err() {
            args[1] = "-I";
            self.run(&args)?;
        }
        Ok(())
    }

    /// Read back each planned object; counts alone do not prove convergence.
    ///
    /// `extra_peer_keys` 是 P2P 直连对端公钥集（§12）：它们由 agent 直连管理
    /// 器单独增删，**不属于**服务端计划——读回时按「额外允许的 peer」容忍
    /// （只认存在、不严格核其 allowed-ips，直连态由管理器自己收敛），绝不让
    /// 直连 peer 的存在被判成「计划未收敛」而反复重放。
    pub fn device_plan_matches_sync(
        &self,
        plan: &DevicePlan,
        extra_peer_keys: &BTreeSet<String>,
    ) -> Result<bool, NetworkError> {
        let addresses = self.run(&["ip", "-4", "-o", "addr", "show", "dev", &self.interface])?;
        let expected = format!("{}/{}", plan.tunnel.address, plan.tunnel.address_prefix);
        if !String::from_utf8_lossy(&addresses.stdout)
            .split_whitespace()
            .any(|v| v == expected)
        {
            return Ok(false);
        }
        let link = self.run(&["ip", "link", "show", &self.interface])?;
        let link_text = String::from_utf8_lossy(&link.stdout);
        if !link_text
            .split(['<', '>'])
            .nth(1)
            .is_some_and(|flags| flags.split(',').any(|f| f == "UP"))
        {
            return Ok(false);
        }
        if !mtu_matches_planned(&link_text, plan.tunnel.mtu) {
            return Ok(false);
        }
        let dump = self.run(&["wg", "show", &self.interface, "dump"])?;
        let body = String::from_utf8_lossy(&dump.stdout);
        let header: Vec<_> = body
            .lines()
            .next()
            .unwrap_or("")
            .split_whitespace()
            .collect();
        if let Some(port) = plan.tunnel.listen_port {
            if header.get(2).and_then(|s| s.parse::<u16>().ok()) != Some(port) {
                return Ok(false);
            }
        }
        if let Some(key) = &plan.tunnel.private_key {
            if header.get(1).copied() != Some(self.public_key_from_private(key)?.as_str()) {
                return Ok(false);
            }
        }
        let peers: Vec<_> = body.lines().skip(1).collect();
        // 每个计划 peer 必须存在且 allowed-ips 精确匹配（身份级，非计数）。
        for peer in &plan.tunnel.peers {
            let Some(line) = peers
                .iter()
                .find(|line| line.split_whitespace().next() == Some(peer.public_key.as_str()))
            else {
                return Ok(false);
            };
            let fields: Vec<_> = line.split_whitespace().collect();
            let actual: std::collections::BTreeSet<_> =
                fields.get(3).unwrap_or(&"").split(',').collect();
            let wanted: Vec<_> = peer.allowed_ips.iter().map(ToString::to_string).collect();
            if actual != wanted.iter().map(String::as_str).collect() {
                return Ok(false);
            }
        }
        // 受管接口上不得有既非计划、也非直连保留的 peer（未受管对象 → 漂移）。
        for line in &peers {
            let key = line.split_whitespace().next().unwrap_or("");
            if plan.tunnel.peers.iter().any(|p| p.public_key == key) {
                continue;
            }
            if extra_peer_keys.contains(key) {
                continue;
            }
            return Ok(false);
        }
        for route in &plan.routes {
            let out = self.run(&[
                "ip",
                "-4",
                "route",
                "show",
                "exact",
                &route.destination.to_string(),
            ])?;
            let text = String::from_utf8_lossy(&out.stdout);
            let dev = format!("dev {}", route.interface);
            let via = route.gateway.map(|g| format!("via {g}"));
            if !text
                .lines()
                .any(|line| line.contains(&dev) && via.as_ref().is_none_or(|v| line.contains(v)))
            {
                return Ok(false);
            }
        }
        for dir in ["-i", "-o"] {
            if self
                .run(&[
                    "iptables",
                    "-C",
                    "FORWARD",
                    dir,
                    &self.interface,
                    "-m",
                    "comment",
                    "--comment",
                    MESHLET_FILTER_COMMENT,
                    "-j",
                    "ACCEPT",
                ])
                .is_err()
            {
                return Ok(false);
            }
        }
        for rule in &plan.nat_rules {
            let addr = match rule.action {
                NatAction::NetMap { .. } => Ipv4Addr::UNSPECIFIED,
                NatAction::SnatToGatewayLan => self.lan_source_for(rule.match_dest)?,
            };
            if !self.nat_rule_matches(rule, addr) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// 大包探测（§7.5）：以 DF 位（`ping -M do`）向 `target` 发一个载荷
    /// `payload` 字节的 ICMP echo——成功即路径可承载「payload + 28B」（IP
    /// 头 20B + ICMP 头 8B）的数据报。只读诊断，不写任何内核状态；ping
    /// 不可用或无应答返回 `false`（证据按「未证实」处理，不臆测）。
    pub fn mtu_probe_sync(&self, target: std::net::Ipv4Addr, payload: u32) -> bool {
        match self.run(&[
            "ping",
            "-c",
            "1",
            "-W",
            "2",
            "-M",
            "do",
            "-s",
            &payload.to_string(),
            &target.to_string(),
        ]) {
            Ok(out) => out.status.success(),
            Err(_) => false,
        }
    }

    /// 同步隧道应用（[NetworkBackend::apply_tunnel] 的命令核心）。
    ///
    /// `keep_keys`：P2P 直连对端公钥集（§12）——计划重放时保留它们，不冲掉。
    pub fn apply_tunnel_sync(
        &self,
        config: &TunnelConfig,
        keep_keys: &BTreeSet<String>,
    ) -> Result<ApplyResult, NetworkError> {
        let ifname = config.name.clone();
        if ifname.is_empty()
            || ifname.len() > 15
            || !ifname
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            return Err(NetworkError::ApplyRejected("invalid interface name".into()));
        }
        if ifname != self.interface {
            return Err(NetworkError::ApplyRejected(format!(
                "tunnel name {ifname} is not the managed interface {}",
                self.interface
            )));
        }
        // 接口存在则复用，不存在则创建（幂等）。
        if self.run(&["ip", "link", "show", &ifname]).is_err() {
            self.run(&["ip", "link", "add", &ifname, "type", "wireguard"])?;
        }
        self.run(&[
            "ip",
            "address",
            "replace",
            &format!("{}/{}", config.address, config.address_prefix),
            "dev",
            &ifname,
        ])?;
        // 未配置的 MTU 也按默认值落盘（不是「不动」）：接口停在更高的 MTU
        // 时若不收敛回默认，下面 `device_plan_matches_sync` 的读回（同样按
        // 默认值比较）会一直判漂移，大包探测也持续失败。默认值与显式值
        // 一视同仁。
        let mtu = enforced_tunnel_mtu(config.mtu);
        self.run(&["ip", "link", "set", &ifname, "mtu", &mtu.to_string()])?;
        self.run(&["ip", "link", "set", &ifname, "up"])?;
        if let Some(key) = &config.private_key {
            // 本环境 wg 工具 fopen 普通路径与 /dev/stdin 均报 EPERM（同
            // setconf 坑位），仅 bash 进程替换的 /dev/fd 管道可读——经
            // `<(cat)` + 管道 stdin 下发，私钥不进 argv、不落盘。
            self.run_bash_stdin(
                &format!("wg set {ifname} private-key <(cat)"),
                &format!("{key}\n"),
            )?;
        }
        if let Some(port) = config.listen_port {
            self.run(&["wg", "set", &ifname, "listen-port", &port.to_string()])?;
        }
        // key 与 peer 分两次 set（合并调用会静默丢 peer，真机实测坑位）。
        self.reconcile_peers(config, keep_keys)?;
        Ok(ApplyResult::ok())
    }

    /// 同步路由/ip_forward/FORWARD 应用（[NetworkBackend::apply_routes] 核心）。
    pub fn apply_routes_sync(
        &mut self,
        routes: &[RouteConfig],
    ) -> Result<ApplyResult, NetworkError> {
        // §18.3 冲突预检：目标前缀已有指向其他接口的路由时显式拒绝——
        // `ip route replace` 会静默接管外来路由，这里改为点名冲突对象并
        // 拒绝，且拒绝发生在任何内核状态（sysctl/iptables）改动之前。
        for route in routes {
            if let Some(line) = self.foreign_route_conflict(&route.destination, &route.interface)? {
                return Err(NetworkError::ApplyRejected(format!(
                    "route {} already exists on another path ({}): meshlet does not take over foreign routes",
                    route.destination, line
                )));
            }
        }
        let forwarding = self.run(&["sysctl", "-n", "net.ipv4.ip_forward"])?;
        if String::from_utf8_lossy(&forwarding.stdout).trim() != "1" {
            self.run(&["sysctl", "-w", "net.ipv4.ip_forward=1"])?;
        }
        // FORWARD 放行：进出受管隧道接口的流量（注释标记所有权，回滚可精确定位）。
        for dir in ["-i", "-o"] {
            let probe = vec![
                "iptables",
                "-C",
                "FORWARD",
                dir,
                self.interface.as_str(),
                "-m",
                "comment",
                "--comment",
                MESHLET_FILTER_COMMENT,
                "-j",
                "ACCEPT",
            ];
            if self.run(&probe).is_err() {
                let mut add = probe.clone();
                add[1] = "-A";
                self.run(&add)?;
            }
        }
        for existing in self.routes_on_interface()? {
            if !routes.iter().any(|r| r.destination == existing) {
                self.run(&[
                    "ip",
                    "route",
                    "del",
                    &existing.to_string(),
                    "dev",
                    &self.interface,
                    "proto",
                    MESHLET_ROUTE_PROTO,
                ])?;
            }
        }
        for route in routes {
            let mut args: Vec<String> = vec![
                "ip".into(),
                "route".into(),
                "replace".into(),
                route.destination.to_string(),
            ];
            if let Some(gw) = route.gateway {
                args.extend(["via".into(), gw.to_string()]);
            }
            args.extend(["dev".into(), route.interface.clone()]);
            args.extend(["proto".into(), MESHLET_ROUTE_PROTO.into()]);
            let argv: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            self.run(&argv)?;
        }
        Ok(ApplyResult::ok())
    }

    /// §18.3 冲突预检：`ip route show exact <dst>` 有任何一行指向非受管
    /// 接口即冲突，返回该行原文供拒绝信息点名。无既有路由或全部经受管
    /// 接口（Meshlet 自有对象，幂等改写属正常计划变更）则返回 None。
    fn foreign_route_conflict(
        &self,
        destination: &Ipv4Cidr,
        interface: &str,
    ) -> Result<Option<String>, NetworkError> {
        let out = self.run(&["ip", "route", "show", "exact", &destination.to_string()])?;
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Some(conflict) = foreign_route_line(line, interface) {
                return Ok(Some(conflict));
            }
        }
        Ok(None)
    }

    /// 同步 NAT 规则下发（[NetworkBackend::apply_nat] 的命令核心）。
    pub fn apply_nat_sync(
        &self,
        rules: &[NatRule],
        gateway_lan_addr: Ipv4Addr,
    ) -> Result<ApplyResult, NetworkError> {
        for rule in rules {
            // nat.rs 渲染不含程序与前缀（`-t nat` 之外的部分），这里补全。
            let mut args = vec!["iptables".to_string(), "-t".to_string(), "nat".to_string()];
            args.extend(rule.iptables_args(gateway_lan_addr));
            // -C 探测（-A 换成 -C），已存在则跳过——幂等下发。
            let probe: Vec<&str> = args
                .iter()
                .enumerate()
                .map(|(i, s)| if i == 3 { "-C" } else { s.as_str() })
                .collect();
            if self.run(&probe).is_err() {
                let apply_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                self.run(&apply_args)?;
            }
        }
        Ok(ApplyResult::ok())
    }

    /// 同步按所有权注释移除 NAT 规则（[NetworkBackend::remove_nat] 核心）。
    pub fn remove_nat_sync(&self, owner: &str) -> Result<ApplyResult, NetworkError> {
        for del_args in self.meshlet_nat_rules(Some(owner))? {
            let mut full = vec!["iptables".to_string(), "-t".to_string(), "nat".to_string()];
            full.extend(del_args);
            let args: Vec<&str> = full.iter().map(|s| s.as_str()).collect();
            self.run(&args)?;
        }
        Ok(ApplyResult::ok())
    }

    /// Enumerate NAT ownership units that currently exist in the kernel.
    pub fn meshlet_nat_owners_sync(&self) -> Result<Vec<String>, NetworkError> {
        let owners = self
            .meshlet_nat_rules(None)?
            .into_iter()
            .filter_map(|tokens| {
                let index = tokens.iter().position(|token| token == "--comment")? + 1;
                tokens.get(index).cloned()
            })
            .collect::<BTreeSet<String>>()
            .into_iter()
            .collect();
        Ok(owners)
    }

    /// Meshlet 所有权注释下的 NAT 规则身份指纹集合（`NatRule::signature` 同一
    /// 形状，去重排序）。集合只含 Meshlet 自有规则——注释前缀过滤在前，非本
    /// meshlet 规则在此处即已被排除，因此该集合的集合比对绝不会把用户规则
    /// 误判为漂移。
    pub fn meshlet_nat_signatures_sync(&self) -> Result<Vec<String>, NetworkError> {
        let signatures = self
            .meshlet_nat_rules(None)?
            .into_iter()
            .filter_map(|tokens| {
                // 删除参数形如 `-D CHAIN -d … -j … --comment …`。
                let [_, chain, args @ ..] = tokens.as_slice() else {
                    return None;
                };
                Self::nat_rule_signature_from_iptables(chain, args)
            })
            .collect::<BTreeSet<String>>()
            .into_iter()
            .collect();
        Ok(signatures)
    }

    /// 按身份指纹移除「有 Meshlet 所有权注释、但不在计划里」的 NAT 规则
    /// （M2）：计划侧与内核侧产出同一指纹，集合差集即多余对象。非本 meshlet
    /// 规则（注释不符）进不了该枚举，永不被触碰。
    ///
    /// 认了所有权却认不出形状的规则在此不删——那是异常而非匹配失败，交给
    /// 整单元清理路径（`remove_nat_sync` 按所有权）处置。
    pub fn remove_stale_nat_rules_sync(
        &self,
        planned: &[String],
    ) -> Result<ApplyResult, NetworkError> {
        let keep: BTreeSet<&str> = planned.iter().map(String::as_str).collect();
        for del_args in self.meshlet_nat_rules(None)? {
            let [_, chain, args @ ..] = del_args.as_slice() else {
                continue;
            };
            let Some(signature) = Self::nat_rule_signature_from_iptables(chain, args) else {
                continue;
            };
            if keep.contains(signature.as_str()) {
                continue;
            }
            let mut full = vec!["iptables".to_string(), "-t".to_string(), "nat".to_string()];
            full.extend(del_args);
            let args: Vec<&str> = full.iter().map(|s| s.as_str()).collect();
            self.run(&args)?;
        }
        Ok(ApplyResult::ok())
    }

    /// 单行 iptables 规则的删除参数 → 身份指纹。形状必须与
    /// [`NatRule::signature`] 逐字节一致（两侧据此做集合比对），且只接受
    /// 本网关渲染器会产出的两种动作：`NETMAP --to <cidr>` 与 `SNAT`。
    /// 无法识别的规则形状返回 `None`——按注释认领了却不认得，属异常而非匹配
    /// 失败，交由所有权清理路径处置（`remove_nat_sync` 按注释精确移除）。
    fn nat_rule_signature_from_iptables(chain: &str, args: &[String]) -> Option<String> {
        let mut match_dest = String::new();
        let mut source = String::new();
        let mut interface = String::new();
        let mut action = String::new();
        let mut owner = String::new();
        let mut i = 0;
        while i < args.len() {
            let flag = args[i].as_str();
            let value = args.get(i + 1).map(String::as_str).unwrap_or("");
            match flag {
                "-d" => match_dest = value.to_string(),
                "-s" => source = value.to_string(),
                "-i" | "-o" => interface = value.to_string(),
                "-j" => {
                    let target = args.get(i + 1).cloned().unwrap_or_default();
                    // `-S` 输出里 `--to` / `--to-source` 的值是**下一个 token**
                    // （`split_iptables_line` 已按空白切开）：两个 token 都要
                    // 消费，否则 NETMAP 的网段会被漏读成空串。
                    let (to, extra) = if matches!(
                        args.get(i + 2).map(String::as_str),
                        Some("--to") | Some("--to-source")
                    ) {
                        (args.get(i + 3).cloned().unwrap_or_default(), 3)
                    } else {
                        (String::new(), 1)
                    };
                    action = if target == "NETMAP" {
                        format!("net_map:{to}")
                    } else if target == "SNAT" {
                        "snat_to_gateway_lan".to_string()
                    } else {
                        return None;
                    };
                    i += extra; // 循环末尾的 +1 再跳过剩余位置
                }
                "-m" | "--comment" if flag == "--comment" => {
                    owner = value.to_string();
                }
                _ => {}
            }
            i += 1;
        }
        if action.is_empty() || owner.is_empty() || match_dest.is_empty() {
            return None;
        }
        Some(format!(
            "{}|{}|{}|{}|{}|{}",
            chain,
            match_dest,
            action,
            owner,
            if source.is_empty() {
                "none".to_string()
            } else {
                source
            },
            if interface.is_empty() {
                "none".to_string()
            } else {
                interface
            },
        ))
    }

    /// Remove Meshlet-marked routes that are absent from the desired plan.
    ///
    /// The managed-interface route marker is deliberately narrow: connected,
    /// static and manually installed paths (including unmarked paths on the
    /// managed interface) are foreign and are never deleted.
    pub fn remove_stale_meshlet_routes_sync(
        &self,
        routes: &[RouteConfig],
    ) -> Result<ApplyResult, NetworkError> {
        if self.run(&["ip", "link", "show", &self.interface]).is_err() {
            return Ok(ApplyResult::ok());
        }
        let desired: BTreeSet<_> = routes.iter().map(|route| route.destination).collect();
        for existing in self.routes_on_interface()? {
            if desired.contains(&existing) {
                continue;
            }
            self.run(&[
                "ip",
                "route",
                "del",
                &existing.to_string(),
                "dev",
                &self.interface,
                "proto",
                MESHLET_ROUTE_PROTO,
            ])?;
        }
        Ok(ApplyResult::ok())
    }

    /// 私钥 → 公钥（`wg pubkey`，密钥走 stdin、不进 argv）。服务端据此填充
    /// 下发给设备的 hub peer 公钥，无需额外持久化公钥（ADR-010）。
    pub fn public_key_from_private(&self, private_key: &str) -> Result<String, NetworkError> {
        // `wg pubkey` 从 stdin 读私钥（不像 `wg set private-key` 那样走 argv）。
        let out = self.run_bash_stdin("wg pubkey", &format!("{private_key}\n"))?;
        let key = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if key.is_empty() {
            return Err(NetworkError::Io("wg pubkey returned an empty key".into()));
        }
        Ok(key)
    }

    /// Resolve the route-selected LAN source, including /32 targets and routed LANs.
    /// Reject missing routes, local destinations and routes back into our own tunnel.
    pub fn lan_source_for(&self, target: Ipv4Cidr) -> Result<Ipv4Addr, NetworkError> {
        let out = self.run(&["ip", "-4", "route", "get", &target.network().to_string()])?;
        let text = String::from_utf8_lossy(&out.stdout);
        route_source(&text, &self.interface).ok_or_else(|| {
            NetworkError::ApplyRejected(format!(
                "no usable LAN egress/source for {target}: route get={text:?}"
            ))
        })
    }

    fn nat_rule_matches(&self, rule: &NatRule, source: Ipv4Addr) -> bool {
        let mut args = rule.iptables_args(source);
        args[0] = "-C".into();
        let mut argv = vec!["iptables", "-t", "nat"];
        argv.extend(args.iter().map(String::as_str));
        self.run(&argv).is_ok()
    }

    /// 设备数据面计划的同步应用入口：agent（§16.4 结构化配置对象）与测试共
    /// 用同一条执行路径。失败即报错，绝不返回「已应用」。
    ///
    /// - `private_key` = 本设备本地私钥（服务端不携带）；
    /// - `gateway_lan_addr` = `Some` 显式给定 SNAT 源地址；`None` = 从本机
    ///   到每个目标的实际路由解析；显式地址也须与读回使用的内核选择一致。
    ///   没有 SNAT 规则时无需解析源地址。
    pub fn apply_device_plan_sync(
        &mut self,
        plan: &DevicePlan,
        private_key: Option<String>,
        gateway_lan_addr: Option<Ipv4Addr>,
        keep_keys: &BTreeSet<String>,
    ) -> Result<(), NetworkError> {
        let mut tunnel = plan.tunnel.clone();
        tunnel.private_key = private_key;
        let tunnel_result = self.apply_tunnel_sync(&tunnel, keep_keys)?;
        if !tunnel_result.applied {
            return Err(NetworkError::ApplyRejected(
                tunnel_result.error.unwrap_or_default(),
            ));
        }
        let routes_result = self.apply_routes_sync(&plan.routes)?;
        if !routes_result.applied {
            return Err(NetworkError::ApplyRejected(
                routes_result.error.unwrap_or_default(),
            ));
        }
        // AGENT-FW-2：宿主 ufw/firewalld 活跃时自动放行 mesh 接口流量（幂等；
        // 探测失败按「未活跃」处理，放行失败显式报错——不假装生效）。netns
        // 测试钩子不跑此步，避免污染宿主防火墙。
        self.ensure_host_firewall_sync()?;
        // §12.4 防火墙联动：直连开启（计划携带 listen_port——agent 只在
        // direct_connect.enabled 时改写）→ 自动放行直连 UDP 端口。直连 peer
        // 经 LAN/公网接口到达，接口级放行不覆盖，须按端口开。
        if let Some(port) = plan.tunnel.listen_port {
            self.ensure_direct_udp_firewall_sync(port)?;
        }
        if plan.nat_rules.is_empty() {
            return Ok(());
        }
        // Resolve all sources before adding any NAT, so an unreachable target does
        // not leave a partial NETMAP-only unit. Apply and readback share this lookup.
        let sources: Vec<_> = plan
            .nat_rules
            .iter()
            .map(|rule| match rule.action {
                NatAction::NetMap { .. } => Ok(Ipv4Addr::UNSPECIFIED),
                NatAction::SnatToGatewayLan => {
                    let source = self.lan_source_for(rule.match_dest)?;
                    if gateway_lan_addr.is_some_and(|explicit| explicit != source) {
                        return Err(NetworkError::ApplyRejected(format!(
                            "explicit gateway address does not match route source {source} for {}",
                            rule.match_dest
                        )));
                    }
                    Ok(source)
                }
            })
            .collect::<Result<_, NetworkError>>()?;
        // A changed egress source must replace the old owner's SNAT, not append a
        // shadowed rule that passes -C while packets still use the obsolete source.
        let mut reset_owners = std::collections::BTreeSet::new();
        for (rule, source) in plan.nat_rules.iter().zip(&sources) {
            if !self.nat_rule_matches(rule, *source) {
                reset_owners.insert(rule.owner.as_str());
            }
        }
        for owner in reset_owners {
            self.remove_nat_sync(owner)?;
        }
        for (rule, source) in plan.nat_rules.iter().zip(sources) {
            let result = self.apply_nat_sync(std::slice::from_ref(rule), source)?;
            if !result.applied {
                return Err(NetworkError::ApplyRejected(
                    result.error.unwrap_or_default(),
                ));
            }
        }
        // 计划外的 Meshlet 自有规则按身份指纹清理（M2）：`apply_nat_sync` 只增
        // 不删，改名前后的旧指纹、半途失败的中间态会永远留在表里；按指纹
        // 差集清掉，非本 meshlet 规则不在该枚举内、永不被触碰。
        let planned_signatures: Vec<String> =
            plan.nat_rules.iter().map(|rule| rule.signature()).collect();
        let stale = self.remove_stale_nat_rules_sync(&planned_signatures)?;
        if !stale.applied {
            return Err(NetworkError::ApplyRejected(stale.error.unwrap_or_default()));
        }
        Ok(())
    }

    #[cfg(test)]
    fn snat_target_cidr(rules: &[NatRule]) -> Option<Ipv4Cidr> {
        rules.iter().find_map(|rule| match rule.action {
            NatAction::SnatToGatewayLan => Some(rule.match_dest),
            _ => None,
        })
    }

    /// 探测宿主防火墙管理器并产出放行计划（AGENT-FW-2）。
    ///
    /// 命令缺失/未活跃一律按「未活跃」处理（no-op）；探测失败不阻断数据面
    /// 应用——放行是增益而非前提。
    fn host_firewall_allow_plan(&self) -> Vec<HostFirewallAction> {
        let (ufw_active, ufw_allowed) = match self.run(&["ufw", "status"]) {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
                (
                    text.contains("status: active"),
                    text.contains(&format!("on {}", self.interface)),
                )
            }
            // `ufw` 未安装（spawn 失败）→ 不活跃。
            Err(_) => (false, false),
        };
        let firewalld_active = matches!(
            self.run(&["firewall-cmd", "--state"]),
            Ok(out) if String::from_utf8_lossy(&out.stdout).trim() == "running"
        );
        let firewalld_allowed = matches!(
            self.run(&[
                "firewall-cmd",
                "--zone=trusted",
                &format!("--query-interface={}", self.interface),
            ]),
            Ok(out) if String::from_utf8_lossy(&out.stdout).trim() == "yes"
        );
        host_firewall_allow_actions(
            ufw_active,
            ufw_allowed,
            firewalld_active,
            firewalld_allowed,
            &self.interface,
        )
    }

    /// 执行宿主防火墙放行（AGENT-FW-2）。测试 netns 钩子下跳过——探测经
    /// `ip netns exec` 仍能读到宿主 ufw 状态文件，若真放行会改宿主防火墙。
    fn ensure_host_firewall_sync(&self) -> Result<(), NetworkError> {
        if self.netns.is_some() {
            return Ok(());
        }
        for action in self.host_firewall_allow_plan() {
            match action {
                HostFirewallAction::UfwAllowInOn { interface } => {
                    self.run(&["ufw", "allow", "in", "on", &interface])?;
                }
                HostFirewallAction::FirewalldTrustedInterface { interface } => {
                    self.run(&[
                        "firewall-cmd",
                        "--zone=trusted",
                        &format!("--add-interface={interface}"),
                    ])?;
                }
                // 端口类动作走直连专用路径（§12.4），接口放行里不可能出现。
                HostFirewallAction::UfwAllowPort { .. }
                | HostFirewallAction::FirewalldAllowPort { .. } => {}
            }
        }
        Ok(())
    }

    /// 探测宿主防火墙管理器并产出直连 UDP 端口放行计划（§12.4）。
    ///
    /// 命令缺失/未活跃一律按「未活跃」处理（no-op）；探测失败不阻断数据面
    /// 应用——放行是增益而非前提（同 [host_firewall_allow_plan]）。
    fn host_direct_udp_allow_plan(&self, port: u16) -> Vec<HostFirewallAction> {
        let (ufw_active, ufw_port_allowed) = match self.run(&["ufw", "status"]) {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
                (
                    text.contains("status: active"),
                    text.contains(&format!("{port}/udp")),
                )
            }
            // `ufw` 未安装（spawn 失败）→ 不活跃。
            Err(_) => (false, false),
        };
        let firewalld_active = matches!(
            self.run(&["firewall-cmd", "--state"]),
            Ok(out) if String::from_utf8_lossy(&out.stdout).trim() == "running"
        );
        let firewalld_port_allowed = matches!(
            self.run(&["firewall-cmd", "--query-port", &format!("{port}/udp")]),
            Ok(out) if String::from_utf8_lossy(&out.stdout).trim() == "yes"
        );
        direct_udp_firewall_allow_actions(
            ufw_active,
            ufw_port_allowed,
            firewalld_active,
            firewalld_port_allowed,
            port,
        )
    }

    /// 执行直连 UDP 端口放行（§12.4）。netns 钩子下跳过（同
    /// [ensure_host_firewall_sync]）；直连关闭时端口规则保留无害（只开一个
    /// UDP 端口），幂等重复执行。失败显式报错——不假装生效。
    fn ensure_direct_udp_firewall_sync(&self, port: u16) -> Result<(), NetworkError> {
        if self.netns.is_some() {
            return Ok(());
        }
        for action in self.host_direct_udp_allow_plan(port) {
            match action {
                HostFirewallAction::UfwAllowPort { port } => {
                    // `ufw allow 51820/udp`：规范形式（ufw status 同形展示）。
                    self.run(&["ufw", "allow", &format!("{port}/udp")])?;
                }
                HostFirewallAction::FirewalldAllowPort { port } => {
                    self.run(&[
                        "firewall-cmd",
                        "--zone=trusted",
                        "--add-port",
                        &format!("{port}/udp"),
                    ])?;
                }
                HostFirewallAction::UfwAllowInOn { .. }
                | HostFirewallAction::FirewalldTrustedInterface { .. } => {}
            }
        }
        Ok(())
    }

    /// 同步回滚（[NetworkBackend::rollback] 的命令核心）。
    pub fn rollback_sync(&self) -> Result<ApplyResult, NetworkError> {
        // §10.3：只删 Meshlet 自有对象——本后端拥有的隧道接口上的全部数据面
        // 对象（nat 规则 / FORWARD 放行 / 隧道路由 / peer），保留接口、地址与
        // 系统级 ip_forward（属系统状态，不动用户既有配置）。
        // Gateway NAT cleanup requires exact owner ids from its local ledger.
        // A hub rollback must never sweep the machine-wide NAT table.
        let out = self.run(&["iptables", "-S", "FORWARD"])?;
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let tokens = Self::split_iptables_line(line);
            if tokens.len() < 2 || tokens[0] != "-A" {
                continue;
            }
            let owned = tokens
                .iter()
                .position(|t| t == "--comment")
                .and_then(|i| tokens.get(i + 1))
                .is_some_and(|c| *c == MESHLET_FILTER_COMMENT);
            if owned
                && tokens
                    .windows(2)
                    .any(|pair| (pair[0] == "-i" || pair[0] == "-o") && pair[1] == self.interface)
            {
                let mut del = vec!["iptables".to_string(), "-D".to_string(), tokens[1].clone()];
                del.extend(tokens[2..].iter().cloned());
                let args: Vec<&str> = del.iter().map(|s| s.as_str()).collect();
                self.run(&args)?;
            }
        }
        for cidr in self.routes_on_interface()? {
            self.run(&[
                "ip",
                "route",
                "del",
                &cidr.to_string(),
                "dev",
                &self.interface,
            ])?;
        }
        for key in self.existing_peers()? {
            self.run(&["wg", "set", &self.interface, "peer", &key, "remove"])?;
        }
        Ok(ApplyResult::ok())
    }
}

impl NetworkBackend for LinuxNetworkBackend {
    async fn inspect(&self) -> Result<NetworkSnapshot, NetworkError> {
        self.inspect_sync()
    }

    async fn apply_tunnel(&self, config: TunnelConfig) -> Result<ApplyResult, NetworkError> {
        // trait 面无直连保留集语义（trait 是旧接口，直连只走 sync 面）。
        self.apply_tunnel_sync(&config, &BTreeSet::new())
    }

    async fn apply_routes(
        &mut self,
        routes: Vec<RouteConfig>,
    ) -> Result<ApplyResult, NetworkError> {
        self.apply_routes_sync(&routes)
    }

    async fn apply_nat(
        &self,
        rules: Vec<NatRule>,
        gateway_lan_addr: Ipv4Addr,
    ) -> Result<ApplyResult, NetworkError> {
        self.apply_nat_sync(&rules, gateway_lan_addr)
    }

    async fn remove_nat<'s>(&'s self, owner: &'s str) -> Result<ApplyResult, NetworkError> {
        self.remove_nat_sync(owner)
    }

    async fn rollback(&self, _revision: ConfigRevisionRef) -> Result<ApplyResult, NetworkError> {
        self.rollback_sync()
    }
}

impl Default for LinuxNetworkBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::{NatAction, NatChain, NatRule};

    #[test]
    fn ip_octet_subnets_mask_interface_host_bits_into_the_lan_subnet() {
        // `ip -4 -o addr show` 的地址带主机位（接口地址不是网络地址）——
        // 回归：按规范化 CIDR 解析曾整行失败，LAN 枚举恒为空，直连永不
        // 触发（netns 真机测试抓到）。
        let output = "1: lo    inet 127.0.0.1/8 scope host lo\\\n\
                      2: wg0    inet 10.240.0.2/24 scope global wg0\\\n\
                      18623: eth0    inet 10.98.0.20/24 brd 10.98.0.255 scope global eth0\\\n";
        let subnets = parse_ip_octet_subnets(output);
        assert_eq!(subnets.len(), 3, "every addr line parses, host bits masked");
        assert_eq!(subnets[0].1.to_string(), "127.0.0.0/8");
        assert_eq!(subnets[1].1.to_string(), "10.240.0.0/24");
        assert_eq!(subnets[2].0, "eth0");
        assert_eq!(subnets[2].1.to_string(), "10.98.0.0/24");

        // 与 lan_subnets_sync 同一口径的过滤：lo/受管隧道出局、非私网出局
        // → 只剩 eth0 的网段。
        let lan: Vec<String> = subnets
            .iter()
            .filter(|(ifname, _)| is_lan_interface(ifname, "wg0"))
            .map(|(_, subnet)| subnet)
            .filter(|subnet| meshlet_domain::is_private_ip(subnet.network()))
            .map(|subnet| subnet.to_string())
            .collect();
        assert_eq!(lan, vec!["10.98.0.0/24"]);

        // 前缀越界/非地址的行被跳过，不 panic。
        assert!(parse_ip_octet_subnets("3: eth1 inet 1.2.3.4/99 x\n").is_empty());
        assert!(parse_ip_octet_subnets("3: eth1 inet junk/24 x\n").is_empty());
    }

    #[test]
    fn handshake_ages_parses_peer_lines_and_skips_never_handshaked() {
        // 标准三列：公钥 握手时间 距今秒。
        let pk_a = "A".repeat(43) + "=";
        let pk_b = "B".repeat(43) + "=";
        // 从未握手的 peer：握手时间戳为 0（WireGuard 语义），非「距今 0 秒」。
        let text = format!("{pk_a} 1750000000 12\n{pk_b} 0 0\nnot-a-key 1750000000 5\n");
        let ages = parse_handshake_ages(&text, 1750000060);
        assert_eq!(ages.len(), 1, "zero-handshake and junk lines are skipped");
        assert_eq!(ages.get(&pk_a), Some(&12));

        // 缺第三列：按 now - 握手时间兜底。
        let two_col = format!("{pk_b} 1750000000\n");
        let ages = parse_handshake_ages(&two_col, 1750000060);
        assert_eq!(ages.get(&pk_b), Some(&60));
    }

    #[test]
    fn mtu_readback_enforces_the_default_like_an_explicit_value() {
        let link_at = |mtu: u32| {
            format!(
                "523: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu {mtu} qdisc noqueue state UNKNOWN"
            )
        };
        // Unset plan means the default 1420: an interface left higher by an old
        // plan must read as drifted (regression: the check used to be skipped
        // entirely for unset plans, so 1480 never converged back).
        assert!(!mtu_matches_planned(&link_at(1480), None));
        assert!(mtu_matches_planned(&link_at(1420), None));
        assert!(mtu_matches_planned(&link_at(1420), Some(1420)));
        // An explicit plan value must match exactly, higher or lower.
        assert!(!mtu_matches_planned(&link_at(1420), Some(1380)));
        assert!(mtu_matches_planned(&link_at(1380), Some(1380)));
        // A missing/unparseable mtu field never counts as a match.
        assert!(!mtu_matches_planned(
            "523: wg0: <POINTOPOINT,NOARP,UP> qdisc noqueue state UNKNOWN",
            None
        ));
        assert_eq!(enforced_tunnel_mtu(None), DEFAULT_TUNNEL_MTU);
        assert_eq!(enforced_tunnel_mtu(Some(1380)), 1380);
    }

    #[test]
    fn route_source_uses_kernel_selection_and_rejects_unsafe_egress() {
        assert_eq!(
            route_source("192.168.1.5 dev eth0 src 192.168.1.1 uid 0\n cache", "wg0"),
            Some("192.168.1.1".parse().unwrap())
        );
        assert_eq!(
            route_source(
                "192.168.2.5 via 192.168.1.2 dev eth0 src 192.168.1.9",
                "wg0"
            ),
            Some("192.168.1.9".parse().unwrap())
        );
        for output in [
            "192.168.1.5 dev wg0 src 10.240.0.2",
            "local 192.168.1.1 dev lo src 192.168.1.1",
            "broadcast 192.168.1.255 dev eth0 src 192.168.1.1",
            "unreachable 192.168.1.5",
            "blackhole 192.168.1.5",
            "192.168.1.5 dev eth0",
            "192.168.1.5 src 192.168.1.1",
            "192.168.1.5 dev eth0 src bad",
            "",
        ] {
            assert_eq!(route_source(output, "wg0"), None, "{output}");
        }
    }

    #[test]
    fn parses_ip_octet_addr_output_and_filters_non_lan() {
        let out = "\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: eth0    inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0\\       valid_lft forever preferred_lft forever
2: eth0    inet 10.0.0.5/16 scope global eth0\\       valid_lft forever preferred_lft forever
3: wg0    inet 10.240.0.2/32 scope global wg0\\       valid_lft forever preferred_lft forever
4: docker0    inet 172.17.0.1/16 scope global docker0\\       valid_lft forever preferred_lft forever
5: br-1234    inet 172.18.0.1/16 scope global br-1234\\       valid_lft forever preferred_lft forever
";
        let parsed = parse_ip_octet_addrs(out);
        let addrs: Vec<Ipv4Addr> = parsed
            .iter()
            .filter(|(ifname, _)| is_lan_interface(ifname, "wg0"))
            .map(|(_, addr)| *addr)
            .collect();
        // eth0 两条 RFC1918 保留；lo/wg0/docker0/br-* 全部排除。
        assert_eq!(
            addrs,
            vec![
                "192.168.1.50".parse::<Ipv4Addr>().unwrap(),
                "10.0.0.5".parse().unwrap()
            ]
        );
        assert!(!is_lan_interface("lo", "wg0"));
        assert!(!is_lan_interface("wg0", "wg0"));
        assert!(!is_lan_interface("wg9", "wg0")); // 其它 wg 接口同样排除
        assert!(is_lan_interface("eth0", "wg0"));
        assert!(is_lan_interface("enp2s0", "wg0"));
    }

    #[test]
    fn split_iptables_line_keeps_quoted_comment_as_one_token() {
        let line = "-A PREROUTING -d 10.241.1.0/24 -j NETMAP --to 192.168.1.0/24 \
            -m comment --comment \"meshlet alias al-1\"";
        let tokens = LinuxNetworkBackend::split_iptables_line(line);
        assert_eq!(tokens[0], "-A");
        assert_eq!(tokens[1], "PREROUTING");
        let idx = tokens.iter().position(|t| t == "--comment").unwrap();
        assert_eq!(tokens[idx + 1], "meshlet alias al-1");
    }

    #[test]
    fn meshlet_rule_deletion_matches_ownership_comment() {
        let line = "-A POSTROUTING -d 192.168.1.0/24 -j SNAT --to-source 192.168.1.1 \
            -m comment --comment \"meshlet alias al-1\"";
        let del = LinuxNetworkBackend::meshlet_rule_deletion(line, None).unwrap();
        assert_eq!(del[0], "-D");
        assert_eq!(del[1], "POSTROUTING");
        assert_eq!(del[2], "-d");

        // 精确 owner 匹配：al-1 的规则不被 al-2 的清理命中。
        assert!(
            LinuxNetworkBackend::meshlet_rule_deletion(line, Some("meshlet alias al-2")).is_none()
        );
        assert!(
            LinuxNetworkBackend::meshlet_rule_deletion(line, Some("meshlet alias al-1")).is_some()
        );

        // 非 Meshlet 规则（无注释 / 用户注释）不命中。
        assert!(LinuxNetworkBackend::meshlet_rule_deletion(
            "-A PREROUTING -d 203.0.113.0/24 -j ACCEPT -m comment --comment \"user rule\"",
            None
        )
        .is_none());
        assert!(LinuxNetworkBackend::meshlet_rule_deletion(
            "-A PREROUTING -d 10.241.1.0/24 -j NETMAP --to 192.168.1.0/24",
            None
        )
        .is_none());
        // 非规则行（注释头 / 链声明）不命中。
        assert!(
            LinuxNetworkBackend::meshlet_rule_deletion(":PREROUTING ACCEPT [0:0]", None).is_none()
        );
    }

    #[test]
    fn parse_link_mtu_reads_the_first_mtu_field() {
        let link_show = "7: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1380 \
            qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n\
            \x20   link/none";
        assert_eq!(parse_link_mtu(link_show), Some(1380));

        // 读数不可得（缺字段 / 非数字）时按 None 处理，不臆测默认值。
        assert_eq!(
            parse_link_mtu("7: wg0: <...> state UNKNOWN\n link/none"),
            None
        );
        assert_eq!(parse_link_mtu("7: wg0: mtu junk qdisc"), None);
    }

    #[test]
    fn nat_apply_probes_with_the_same_rule_shape() {
        // apply_nat_sync 组装 `iptables -t nat <args>`；-C 探测与 -A 下发只差
        // flag 位（index 3），保证探测与实际规则形状一致。
        let rule = NatRule {
            source_cidr: None,
            incoming_interface: None,
            chain: NatChain::Prerouting,
            match_dest: "10.241.1.0/24".parse().unwrap(),
            action: NatAction::NetMap {
                to: "192.168.1.0/24".parse().unwrap(),
            },
            owner: "meshlet alias al-1".into(),
        };
        let mut args = vec!["iptables".to_string(), "-t".to_string(), "nat".to_string()];
        args.extend(rule.iptables_args(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(args[3], "-A");
        let probe: Vec<&str> = args
            .iter()
            .enumerate()
            .map(|(i, s)| if i == 3 { "-C" } else { s.as_str() })
            .collect();
        assert_eq!(probe[3], "-C");
        assert_eq!(probe[..3], args[..3]);
        assert_eq!(probe[4..], args[4..]);
    }

    #[tokio::test]
    async fn foreign_tunnel_name_is_rejected() {
        // 后端只受管自己的接口：拒绝别的隧道名（防误操作系统接口）。
        let backend = LinuxNetworkBackend::new();
        let config = TunnelConfig {
            name: "wg-user".into(),
            address: Ipv4Addr::new(10, 240, 0, 1),
            address_prefix: 24,
            listen_port: None,
            peers: vec![],
            mtu: None,
            private_key: None,
        };
        let result = backend.apply_tunnel(config).await;
        assert!(matches!(result, Err(NetworkError::ApplyRejected(_))));
    }

    #[test]
    fn snat_target_cidr_picks_only_the_controlled_snat_rule() {
        use crate::nat::{alias_nat_rules, NatChain};
        use meshlet_domain::{AliasMappingId, LanRouteId, NetworkId, TranslationMode};

        let mapping = meshlet_domain::AliasMapping::new(
            AliasMappingId("al-9".into()),
            NetworkId("net-1".into()),
            LanRouteId("rt-9".into()),
            "10.241.9.0/24".parse().unwrap(),
            "192.168.9.0/24".parse().unwrap(),
            TranslationMode::DnatSnat,
        )
        .unwrap();
        let rules = alias_nat_rules(&mapping);
        // 计划含两条：DNAT 匹配 alias，SNAT 匹配 target（真实 LAN 段）。
        assert_eq!(
            LinuxNetworkBackend::snat_target_cidr(&rules),
            Some("192.168.9.0/24".parse().unwrap())
        );

        // dnat_only 计划无 SNAT 规则——网关 LAN 地址不适用（§9.5）。
        let dnat_only: Vec<NatRule> = rules
            .iter()
            .filter(|r| r.chain == NatChain::Prerouting)
            .cloned()
            .collect();
        assert!(LinuxNetworkBackend::snat_target_cidr(&dnat_only).is_none());
    }

    #[test]
    fn foreign_route_line_flags_routes_on_other_paths() {
        // Marked routes on the managed interface remain Meshlet-owned even
        // when their proto appears in exact output; other-interface paths are
        // conflicts and are named verbatim.
        let via = "10.244.0.0/24 via 10.99.0.1 dev eth0";
        assert_eq!(foreign_route_line(via, "wg0").as_deref(), Some(via));
        assert_eq!(
            foreign_route_line("10.244.0.0/24 dev eth0", "wg0").as_deref(),
            Some("10.244.0.0/24 dev eth0")
        );

        // 经受管接口：Meshlet 自有对象，幂等改写不冲突。
        assert!(foreign_route_line("10.241.1.0/24 via 10.240.0.4 dev wg0", "wg0").is_none());
    }

    #[test]
    fn foreign_route_line_fails_closed_without_a_dev_field() {
        // blackhole / 输出格式变化：解析不出 dev 即按冲突处理，不放过
        // 未知对象（fail closed）。
        assert_eq!(
            foreign_route_line("blackhole 10.244.0.0/24", "wg0").as_deref(),
            Some("blackhole 10.244.0.0/24")
        );
        assert!(foreign_route_line("10.244.0.0/24", "wg0").is_some());
    }

    #[test]
    fn connected_route_line_is_not_a_conflict_on_its_own_interface() {
        // connected 路由（proto kernel，地址自带）：dev 字段在 exact 输出
        // 里照常出现，经受管接口则不算冲突。
        let line = "10.240.0.0/24 proto kernel scope link src 10.240.0.1 dev wg0";
        assert!(foreign_route_line(line, "wg0").is_none());
    }

    #[test]
    fn peer_dump_line_yields_identity_not_a_count() {
        // dump 行序：pubkey presharedkey endpoint allowed-ips …（endpoint
        // none、allowed-ips 空串是未握手 peer 的常态）。allowed-ips 用逗号
        // 连接且**不带空格**（`wg show dump` 的实测输出）。
        let key = "B".repeat(43) + "=";
        let peer = LinuxNetworkBackend::parse_peer_dump_line(&format!(
            "{key} (none) 10.240.0.3:16190 10.240.0.3/32,10.241.1.0/24 0 0 0 0"
        ))
        .unwrap();
        assert_eq!(peer.public_key, key);
        assert_eq!(
            peer.allowed_ips,
            vec![
                "10.240.0.3/32".parse::<Ipv4Cidr>().unwrap(),
                "10.241.1.0/24".parse::<Ipv4Cidr>().unwrap(),
            ]
        );

        // 未握手 / 未放行任何前缀的 peer：allowed-ips 为空是合法状态，
        // 不等于「少了一条 peer」。
        let none = LinuxNetworkBackend::parse_peer_dump_line(&format!(
            "{key} (none) (none) (none) 0 0 0 0"
        ))
        .unwrap();
        assert!(none.allowed_ips.is_empty());

        // 缺 44 字符公钥的残行不产 peer（不臆造身份）。
        assert!(LinuxNetworkBackend::parse_peer_dump_line("(none) 10.240.0.3/32 0 0 0").is_none());
        assert!(LinuxNetworkBackend::parse_peer_dump_line("tooshort").is_none());
    }

    #[test]
    fn nat_signature_round_trips_through_kernel_rendering() {
        // 计划侧指纹必须能从内核渲染出的 iptables 参数读回同值——两侧据此
        // 做集合精确比对，形状不一致就等于看不见漂移。用 `-S` 的字段顺序
        // （`-s` 在 `-d` 前、`-m comment` 在 `-j` 前）而非 `iptables_args`
        // 的顺序，证明解析与字段顺序无关。
        let rules = [
            NatRule {
                source_cidr: Some("10.240.0.0/16".parse().unwrap()),
                incoming_interface: Some("wg0".into()),
                chain: NatChain::Prerouting,
                match_dest: "10.241.1.0/24".parse().unwrap(),
                action: NatAction::NetMap {
                    to: "192.168.1.0/24".parse().unwrap(),
                },
                owner: "meshlet alias al-2".into(),
            },
            // POSTROUTING 不渲染 `-i`：`incoming_interface` 对它是惰性元数据，
            // 两侧都必须按 `none` 对齐（曾因此把在表内的 SNAT 规则误判为多余）。
            NatRule {
                source_cidr: Some("10.240.0.0/16".parse().unwrap()),
                incoming_interface: Some("wg0".into()),
                chain: NatChain::Postrouting,
                match_dest: "192.168.1.0/24".parse().unwrap(),
                action: NatAction::SnatToGatewayLan,
                owner: "meshlet alias al-2".into(),
            },
        ];
        for rule in &rules {
            let rendered = rule.iptables_args("192.168.1.1".parse().unwrap());
            let kernel: Vec<String> = rendered
                .iter()
                .map(|arg| {
                    if arg == "-A" {
                        "-D".to_string()
                    } else {
                        arg.clone()
                    }
                })
                .collect();
            let [_, chain, rest @ ..] = kernel.as_slice() else {
                panic!("malformed rendering: {rendered:?}")
            };
            let signature = LinuxNetworkBackend::nat_rule_signature_from_iptables(chain, rest)
                .unwrap_or_else(|| panic!("unparsable rendering: {rendered:?}"));
            assert_eq!(signature, rule.signature(), "plan vs kernel fingerprint");
        }
    }

    #[test]
    fn nat_signature_rejects_shapes_the_renderer_never_emits() {
        // 认了 Meshlet 所有权、形状却超出本网关渲染器产出的范围 → 不产指纹：
        // 既不冒充计划内规则，也不会被差集清理误删（交由整单元清理路径处置）。
        let unparsable = [
            (
                "POSTROUTING",
                vec![
                    "-d".to_string(),
                    "203.0.113.0/24".into(),
                    "-j".into(),
                    "MASQUERADE".into(),
                    "-m".into(),
                    "comment".into(),
                    "--comment".into(),
                    "meshlet alias al-9".into(),
                ],
            ),
            (
                "POSTROUTING",
                vec![
                    "-d".to_string(),
                    "203.0.113.0/24".into(),
                    "-j".into(),
                    "SNAT".into(),
                    "--to-source".into(),
                    "192.168.1.1".into(),
                ],
            ),
            (
                "PREROUTING",
                vec![
                    "-j".to_string(),
                    "NETMAP".into(),
                    "--to".into(),
                    "192.168.1.0/24".into(),
                    "--comment".into(),
                    "meshlet alias al-9".into(),
                ],
            ),
        ];
        for (chain, args) in unparsable {
            assert!(
                LinuxNetworkBackend::nat_rule_signature_from_iptables(chain, &args).is_none(),
                "{chain} {args:?}"
            );
        }

        // 非 Meshlet 注释的规则带进来的也是它自己的注释：指纹永远撞不上计划
        // 侧的任何指纹，所以差集清理碰不到它。
        let foreign = vec![
            "-d".to_string(),
            "10.0.0.0/24".into(),
            "-j".into(),
            "SNAT".into(),
            "--to-source".into(),
            "192.168.1.1".into(),
            "-m".into(),
            "comment".into(),
            "--comment".into(),
            "user rule".into(),
        ];
        let signature =
            LinuxNetworkBackend::nat_rule_signature_from_iptables("POSTROUTING", &foreign).unwrap();
        assert!(signature.contains("|user rule|"));
    }

    #[test]
    fn host_firewall_plan_is_idempotent_and_manager_gated() {
        // 管理器都未活跃 → 不动作（放行规则存不存在都不影响）。
        assert!(host_firewall_allow_actions(false, false, false, false, "wg0").is_empty());
        assert!(host_firewall_allow_actions(false, true, false, true, "wg0").is_empty());

        // ufw 活跃且接口已放行 → 只补 firewalld 侧（若有）。
        assert_eq!(
            host_firewall_allow_actions(true, true, false, false, "wg0"),
            vec![]
        );
        assert_eq!(
            host_firewall_allow_actions(true, false, false, false, "wg0"),
            vec![HostFirewallAction::UfwAllowInOn {
                interface: "wg0".into()
            }]
        );

        // firewalld 活跃且接口未入 trusted → 补 trusted 接口。
        assert_eq!(
            host_firewall_allow_actions(false, false, true, false, "wg0"),
            vec![HostFirewallAction::FirewalldTrustedInterface {
                interface: "wg0".into()
            }]
        );

        // 双管理器都活跃且都未放行 → 两条动作，顺序确定（ufw 在前）。
        assert_eq!(
            host_firewall_allow_actions(true, false, true, false, "wg0"),
            vec![
                HostFirewallAction::UfwAllowInOn {
                    interface: "wg0".into()
                },
                HostFirewallAction::FirewalldTrustedInterface {
                    interface: "wg0".into()
                },
            ]
        );
    }

    #[test]
    fn direct_udp_firewall_plan_is_idempotent_and_manager_gated() {
        // 管理器未活跃 → 不动作；已放行 → 不动作（幂等）。
        assert!(direct_udp_firewall_allow_actions(false, false, false, false, 51820).is_empty());
        assert!(direct_udp_firewall_allow_actions(true, true, false, false, 51820).is_empty());
        assert!(direct_udp_firewall_allow_actions(false, false, true, true, 51820).is_empty());

        // ufw 活跃且端口未放行 → 按端口开。
        assert_eq!(
            direct_udp_firewall_allow_actions(true, false, false, false, 51820),
            vec![HostFirewallAction::UfwAllowPort { port: 51820 }]
        );

        // firewalld 活跃且端口未放行 → trusted 端口开。
        assert_eq!(
            direct_udp_firewall_allow_actions(false, false, true, false, 51820),
            vec![HostFirewallAction::FirewalldAllowPort { port: 51820 }]
        );

        // 双管理器都活跃且都未放行 → 两条，顺序确定（ufw 在前）。
        assert_eq!(
            direct_udp_firewall_allow_actions(true, false, true, false, 20000),
            vec![
                HostFirewallAction::UfwAllowPort { port: 20000 },
                HostFirewallAction::FirewalldAllowPort { port: 20000 },
            ]
        );
    }

    #[test]
    fn ufw_status_port_line_detects_direct_udp_allow() {
        // `ufw status` 的端口行是 `51820/udp ALLOW IN Anywhere`；放行后
        // contains("{port}/udp") 命中，plan 不再补规则（幂等）。
        let allowed = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n51820/udp                 ALLOW IN    Anywhere\n";
        assert!(allowed.to_lowercase().contains("51820/udp"));
        let not_allowed = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW IN    Anywhere\n";
        assert!(!not_allowed.to_lowercase().contains("51820/udp"));
    }
}
