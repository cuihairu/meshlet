use crate::{WgPeerDiagnostic, DEFAULT_TUNNEL_MTU};
use meshlet_domain::Ipv4Cidr;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

/// 从 `ip link show <if>` 输出解析实际 MTU 读数（首行形如
/// `3: wg0: <...> mtu 1420 qdisc noqueue ...`）。读不到 `mtu` 字段或无法
/// 解析时返回 `None`——调用方按「读数不可得」处理，不臆测默认值。
pub(crate) fn parse_link_mtu(link_show: &str) -> Option<u32> {
    let mut tokens = link_show.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "mtu" {
            return tokens.next().and_then(|v| v.parse().ok());
        }
    }
    None
}

/// 从 `ip -4 route show default` 解析默认路由出接口（首行形如
/// `default via 10.0.0.1 dev ens18 proto dhcp ...`）。解析不出 `dev` 时返回
/// `None`——调用方按「读数不可得」处理，不臆测接口名。
pub(crate) fn parse_default_route_interface(route_show: &str) -> Option<String> {
    let line = route_show.lines().next()?;
    let mut tokens = line.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "dev" {
            return tokens.next().map(str::to_string);
        }
    }
    None
}

/// 从 `ip -4 -o addr show` 输出解析 `(接口, IPv4 地址)` 对（仅 `inet` 行）。
/// 形如 `2: eth0    inet 192.168.1.50/24 ...`（`-o` 单行每地址一行）。
pub(crate) fn parse_ip_octet_addrs(output: &str) -> Vec<(String, Ipv4Addr)> {
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
pub(crate) fn parse_ip_octet_subnets(output: &str) -> Vec<(String, Ipv4Cidr)> {
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
pub(crate) fn is_lan_interface(ifname: &str, wg_interface: &str) -> bool {
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
pub(crate) fn enforced_tunnel_mtu(planned: Option<u32>) -> u32 {
    planned.unwrap_or(DEFAULT_TUNNEL_MTU)
}

/// Readback half of MTU convergence: true only when the interface carries the
/// MTU the plan intends. The default is enforced like an explicit value, so an
/// interface left at a higher MTU (by an older plan or a manual `ip link set`)
/// is seen as drifted on the next reconcile instead of matching the plan.
pub(crate) fn mtu_matches_planned(link_show: &str, planned: Option<u32>) -> bool {
    parse_link_mtu(link_show) == Some(enforced_tunnel_mtu(planned))
}

/// 当前 UTC 时刻的 ISO-8601 字符串（秒精度，`Z` 后缀）——诊断采集时刻。
/// 不引 chrono（meshlet-network 是纯命令执行层）；用 `date` 命令读取本机
/// UTC 时间，失败回退 `SystemTime` 的纪元秒格式化（仅作采集时刻展示）。
pub(crate) fn chrono_now_iso() -> String {
    if let Ok(out) = std::process::Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            let text = text.trim();
            if !text.is_empty() {
                return text.to_string();
            }
        }
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

/// 从 `ping` 输出解析首个 RTT（毫秒）。支持 `time=12.3 ms` 与 `time<1 ms`
///（Linux iputils 的超小延迟表示）；无读数返回 `None`。
///
/// `pub`（非 `pub(crate)`）：探测层（[`crate::probe`]）与 netns 集成测试
/// （`tests/probe_netns.rs`）都直接复用本解析器。
pub fn parse_ping_rtt_ms(text: &str) -> Option<u128> {
    let start = text.find("time")?;
    let rest = &text[start + 4..];
    let digit_start = rest.find(|c: char| c.is_ascii_digit())?;
    let value = &rest[digit_start..];
    let end = value
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(value.len());
    value[..end].parse::<f64>().ok().map(|v| v.round() as u128)
}

/// SEL-001 探测层传输：不经后端（无 sudo / netns 前缀）直接 `ping -c 1
/// -W 1` 实测 ICMP RTT（毫秒）。agent 探测线程以本函数探测候选端点 IP
///（候选是普通单播地址，从 agent 进程可达即可，无需经 wg 接口）。
/// 超时 1s——探测是高频轻量操作，2s 的诊断级等待会拖慢探测线程。
pub fn run_ping_rtt(target: Ipv4Addr) -> Option<u128> {
    let out = Command::new("ping")
        .args(["-c", "1", "-W", "1", &target.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .ok()?;
    parse_ping_rtt_ms(&String::from_utf8_lossy(&out.stdout))
}

/// 解析 `wg show <if> dump` 的 peer 行为诊断读数（纯函数，Linux 本机可测）。
/// 空白分隔：`pubkey preshared endpoint allowed-ips latest-handshake rx tx
/// keepalive`；与 Linux 现有 peer dump 解析器同一公钥判据，缺列按 0/空补。
pub(crate) fn parse_wg_dump_diag_line(line: &str) -> Option<WgPeerDiagnostic> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let public_key = fields.first()?;
    if public_key.len() != 44 || !public_key.ends_with('=') {
        return None;
    }
    let endpoint = fields.get(2).unwrap_or(&"").to_string();
    let allowed_ips = fields.get(3).unwrap_or(&"").to_string();
    let last_handshake: u64 = fields.get(4).and_then(|v| v.parse().ok()).unwrap_or(0);
    let rx_bytes: u64 = fields.get(5).and_then(|v| v.parse().ok()).unwrap_or(0);
    let tx_bytes: u64 = fields.get(6).and_then(|v| v.parse().ok()).unwrap_or(0);
    Some(WgPeerDiagnostic {
        public_key: public_key.to_string(),
        endpoint,
        allowed_ips,
        last_handshake,
        rx_bytes,
        tx_bytes,
    })
}

/// Kernel-selected source for the actual destination, not an address inside its prefix.
pub(crate) fn route_source(route_get: &str, tunnel: &str) -> Option<Ipv4Addr> {
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
pub(crate) fn foreign_route_line(line: &str, interface: &str) -> Option<String> {
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
