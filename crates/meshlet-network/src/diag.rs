//! R-DIAG 诊断快照：路由表 / 接口清单 / wg 接口读数三类只读采集。
//!
//! 类型与纯解析层跨平台共享（Linux 本机单测）；各平台后端（[crate::linux] /
//! [crate::windows]）负责取数——Linux `ip route` / `ip -o link` / `ip -o addr`
//! / `wg show dump`，Windows `route print` / `netsh interface ipv4` /
//! `wg.exe show dump`。**只读诊断**：不写任何内核状态，失败按该段缺失记录
//! （[DiagSnapshot::errors]），绝不臆测（§7.5 同纪律）。
//!
//! 复用既有解析惯例而非重写：wg dump 字段布局与
//! [crate::windows_tunnel::parse_wg_dump_peers] 同一套（制表符分隔，
//! fields[0] 公钥 / fields[3] allowed-ips，本模块在此之上扩展 endpoint /
//! 握手 / 流量）；`ip route` 目的地解析与 [crate::linux] 的
//! `routes_on_interface` 同一套 token 扫掠。链路 MTU 复用
//! [crate::linux::parse_link_mtu] 的「`mtu` 后一 token」判据。

use meshlet_domain::Ipv4Cidr;

/// 一条 IPv4 路由表目（全表，非仅受管接口）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiagRoute {
    /// 目的地（`default` 或 CIDR / 单地址 / 特殊类型行如 `blackhole 10.0.0.0/8`）。
    pub destination: String,
    /// 下一跳网关（`via`）；无网关（直连 / on-link）为 `None`。
    pub via: Option<String>,
    /// 出接口名（`dev`）。读不到（特殊路由）为 `None`。
    pub dev: Option<String>,
    /// 路由协议标记（`proto`；`None` = 未标注）。
    pub proto: Option<String>,
    /// 路由 metric。
    pub metric: Option<String>,
}

/// 接口清单原始行（`ip -o link` / `netsh interface ipv4` 两平台的共同形状）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkRow {
    pub name: String,
    /// 接口管理态（Linux `UP`/`DOWN`；Windows `connected`/`disconnected` 原样）。
    pub state: Option<String>,
    pub mtu: Option<u32>,
}

/// 一个网络接口的清单条目（名称 / 状态 / MTU / 地址）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiagInterface {
    pub name: String,
    pub state: Option<String>,
    pub mtu: Option<u32>,
    /// 接口上的 IPv4 地址（带前缀，如 `10.240.0.2/16`）。
    pub addrs: Vec<String>,
    /// 是否 meshlet 受管隧道接口。
    pub managed: bool,
}

/// wg 接口读数（单 peer）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiagWgPeer {
    pub public_key: String,
    /// 当前 endpoint（`ip:port`）；`None` = 未配置 / 未握手。
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<Ipv4Cidr>,
    /// 最近握手距今秒数；`None` = 从未握手（或读数缺失）。
    pub latest_handshake_age_secs: Option<u64>,
    pub transfer_rx: Option<u64>,
    pub transfer_tx: Option<u64>,
}

/// wg 受管接口整体读数。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiagWg {
    pub interface: String,
    pub listen_port: Option<u16>,
    pub mtu: Option<u32>,
    pub peers: Vec<DiagWgPeer>,
}

/// 三类快照的聚合（agent 采集 → 心跳上报 → console / CLI 展示）。
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct DiagSnapshot {
    /// 采集时刻（unix 秒）。
    pub collected_at_secs: u64,
    pub routes: Vec<DiagRoute>,
    pub interfaces: Vec<DiagInterface>,
    /// `None` = 受管 wg 接口当前不可读（未创建 / 读数失败）。
    pub wg: Option<DiagWg>,
    /// 各段采集失败的说明（空 = 全部成功）。
    pub errors: Vec<String>,
}

/// `ip -4 route show`（全表）→ 路由条目。
///
/// 行形如 `default via 192.168.1.1 dev eth0 proto dhcp metric 100`、
/// `10.240.0.0/16 dev wg0 scope link src 10.240.0.2`、
/// `blackhole 10.99.0.0/8 proto static`。首个 token 是目的地（特殊路由类型
/// 为 `类型 目的地` 两 token）；其后是 `key value` 对，取 via/dev/proto/metric。
pub fn parse_ip_route_table(output: &str) -> Vec<DiagRoute> {
    const ROUTE_TYPES: &[&str] = &[
        "blackhole",
        "unreachable",
        "prohibit",
        "throw",
        "local",
        "broadcast",
        "multicast",
        "anycast",
        "nat",
    ];
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let mut tokens = line.split_whitespace();
            let first = tokens.next()?;
            let mut destination = first.to_string();
            if ROUTE_TYPES.contains(&first) {
                destination.push(' ');
                destination.push_str(tokens.next()?);
            }
            let mut via = None;
            let mut dev = None;
            let mut proto = None;
            let mut metric = None;
            let mut rest = tokens.peekable();
            while let Some(key) = rest.next() {
                let value = rest.peek().copied();
                match key {
                    "via" => via = value.map(str::to_string),
                    "dev" => dev = value.map(str::to_string),
                    "proto" => proto = value.map(str::to_string),
                    "metric" => metric = value.map(str::to_string),
                    _ => {}
                }
                if matches!(key, "via" | "dev" | "proto" | "metric") {
                    rest.next();
                }
            }
            Some(DiagRoute {
                destination,
                via,
                dev,
                proto,
                metric,
            })
        })
        .collect()
}

/// `ip -o link show` → 接口原始行（名称 / 状态 / MTU）。
///
/// 行形如 `2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel
/// state UP mode DEFAULT ...`。名称 = 第二 token 去尾冒号；MTU 复用
/// 「`mtu` 后一 token」判据（与 [crate::linux::parse_link_mtu] 同一惯例）；
/// 状态 = `state` 后一 token（读不到 → `None`）。
pub fn parse_ip_o_link(output: &str) -> Vec<LinkRow> {
    output
        .lines()
        .filter_map(|line| {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() < 3 || !tokens[0].ends_with(':') {
                return None;
            }
            let name = tokens[1].trim_end_matches(':').to_string();
            if name.is_empty() {
                return None;
            }
            let mut state = None;
            let mut mtu = None;
            let mut it = tokens.iter().skip(2).peekable();
            while let Some(&key) = it.next() {
                if key == "mtu" {
                    mtu = it.next().and_then(|v| v.parse().ok());
                } else if key == "state" {
                    state = it.next().map(|v| v.to_string());
                }
            }
            Some(LinkRow { name, state, mtu })
        })
        .collect()
}

/// `ip -4 -o addr show` → `(接口, "地址/前缀")` 对（仅 `inet` 行）。
///
/// 行形如 `2: eth0    inet 192.168.1.50/24 brd 192.168.1.255 scope global
/// dynamic eth0`。与 [crate::linux::parse_ip_octet_addrs] 同一判据
/// （fields[2] == "inet"），保留前缀长度。
pub fn parse_ip_o_addr(output: &str) -> Vec<(String, String)> {
    output
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 || fields[2] != "inet" {
                return None;
            }
            let ifname = fields[1].to_string();
            let addr = fields[3].to_string();
            Some((ifname, addr))
        })
        .collect()
}

/// 把接口原始行与地址对合并成清单条目（纯函数，单测覆盖）。
///
/// 每个 `LinkRow` 一条；无 `LinkRow` 但有地址的接口（`ip -o link` 读不到时
/// 兜底）也产出一条（state/mtu 均 `None`）。`managed` = 名称等于受管接口。
pub fn assemble_interfaces(
    links: &[LinkRow],
    addrs: &[(String, String)],
    managed_interface: &str,
) -> Vec<DiagInterface> {
    let mut by_name: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for (name, addr) in addrs {
        by_name.entry(name.clone()).or_default().push(addr.clone());
    }
    let mut names: std::collections::BTreeSet<String> =
        links.iter().map(|l| l.name.clone()).collect();
    names.extend(by_name.keys().cloned());
    names
        .into_iter()
        .map(|name| {
            let link = links.iter().find(|l| l.name == name);
            DiagInterface {
                name: name.clone(),
                state: link.and_then(|l| l.state.clone()),
                mtu: link.and_then(|l| l.mtu),
                addrs: by_name.remove(&name).unwrap_or_default(),
                managed: name == managed_interface,
            }
        })
        .collect()
}

/// `wg show <if> dump`（或 `wg.exe show <name> dump`）→ `(listen_port, peers)`。
///
/// 官方 dump 为制表符分隔：首行 `private-key public-key listen-port fwmark`，
/// 其后每行 `public-key preshared-key endpoint allowed-ips latest-handshake
/// transfer-rx transfer-tx keepalive`。字段布局与
/// [crate::windows_tunnel::parse_wg_dump_peers] 同一套（fields[0] 公钥 /
/// fields[3] allowed-ips），此处扩展 fields[2] endpoint / fields[4] 握手 /
/// fields[5..7] 流量。未设值为 `(none)` / `off` / 空。握手时间 0（从未握手）
/// 按 `None`（调用方按「无读数」处理，不臆造）。
pub fn parse_wg_dump(dump: &str, now_secs: u64) -> (Option<u16>, Vec<DiagWgPeer>) {
    let mut listen_port = None;
    let mut peers = Vec::new();
    for (idx, line) in dump.lines().enumerate() {
        let fields: Vec<&str> = line.split('\t').collect();
        if idx == 0 {
            listen_port = fields
                .get(2)
                .map(|s| s.trim())
                .and_then(|s| s.parse::<u16>().ok());
            continue;
        }
        if fields.len() < 4 {
            continue;
        }
        let public_key = fields[0].trim();
        if public_key.len() != 44 || !public_key.ends_with('=') {
            continue;
        }
        let endpoint = fields
            .get(2)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && *s != "(none)" && *s != "off")
            .map(str::to_string);
        let allowed_ips = fields[3]
            .split(',')
            .filter_map(|c| c.trim().parse::<Ipv4Cidr>().ok())
            .collect();
        let handshake_ts = fields
            .get(4)
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|ts| *ts > 0);
        let latest_handshake_age_secs = handshake_ts.map(|ts| now_secs.saturating_sub(ts));
        let transfer_rx = fields.get(5).and_then(|s| s.trim().parse::<u64>().ok());
        let transfer_tx = fields.get(6).and_then(|s| s.trim().parse::<u64>().ok());
        peers.push(DiagWgPeer {
            public_key: public_key.to_string(),
            endpoint,
            allowed_ips,
            latest_handshake_age_secs,
            transfer_rx,
            transfer_tx,
        });
    }
    (listen_port, peers)
}

/// `route print -4` 的活动路由段 → 路由条目（Windows）。
///
/// 段形如（en-US 稳定布局）：
/// ```text
/// Active Routes:
/// Network Destination        Netmask          Gateway       Interface  Metric
///          0.0.0.0          0.0.0.0     192.168.1.1    192.168.1.50     25
///       10.240.0.0      255.255.0.0       On-link         10.240.0.2    291
/// ```
/// 列位置无关，按空白切 5 列（目的地 / 掩码 / 网关 / 接口 / metric）。
/// `0.0.0.0/0.0.0.0` → `default`；网关 `On-link` → `None`；`dev` 是接口
/// 地址（调用方再映射为接口名）。遇 `===` 结束段。
pub fn parse_route_print(output: &str) -> Vec<DiagRoute> {
    let mut active = false;
    let mut routes = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("Active Routes:") {
            active = true;
            continue;
        }
        if !active {
            continue;
        }
        if line.starts_with('=') || line.starts_with("Persistent Routes:") {
            break;
        }
        if line.starts_with("Network Destination") {
            continue; // 表头
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        let (dst, mask) = (fields[0], fields[1]);
        let destination = if dst == "0.0.0.0" && mask == "0.0.0.0" {
            "default".to_string()
        } else if let Some(prefix) = netmask_prefix(mask) {
            format!("{dst}/{prefix}")
        } else {
            dst.to_string()
        };
        let via = match fields[2] {
            "On-link" | "on-link" => None,
            gw => Some(gw.to_string()),
        };
        routes.push(DiagRoute {
            destination,
            via,
            dev: Some(fields[3].to_string()),
            proto: None,
            metric: Some(fields[4].to_string()),
        });
    }
    routes
}

/// 点分十进制掩码 → 前缀长度（仅连续掩码，如 `255.255.0.0` → 16）。
fn netmask_prefix(mask: &str) -> Option<u8> {
    let octets: [u8; 4] = mask
        .split('.')
        .map(|o| o.parse::<u8>().ok())
        .collect::<Option<Vec<_>>>()?
        .try_into()
        .ok()?;
    let v = u32::from_be_bytes(octets);
    let ones = v.leading_ones();
    (ones + v.trailing_zeros() == 32).then_some(ones as u8)
}

/// `netsh interface ipv4 show interfaces` → 接口原始行。
///
/// 行形如 ` 12          25        1420  connected     WireGuard`；前 4 列
/// （索引 / metric / MTU / 状态）+ 其余为名称。表头与分隔行（`Idx`/`---`）
/// 跳过。
pub fn parse_netsh_interfaces(output: &str) -> Vec<LinkRow> {
    output
        .lines()
        .filter_map(|line| {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() < 5 || tokens[0] == "Idx" || tokens[0].starts_with('-') {
                return None;
            }
            let mtu = tokens[2].parse::<u32>().ok();
            let state = Some(tokens[3].to_string());
            let name = tokens[4..].join(" ");
            if name.is_empty() {
                return None;
            }
            Some(LinkRow { name, state, mtu })
        })
        .collect()
}

/// `netsh interface ipv4 show config` → 每接口的 IPv4 地址列表。
///
/// 段形如 `Configuration for interface "WireGuard"` 下含 `IP Address: 10.240.0.2`
/// 行（`Subnet Prefix:` 单独一行，地址不带前缀——Windows 侧接口地址前缀由
/// 该接口的 `Subnet Prefix` 行给出，此处只取地址本身，展示时与路由表互证）。
pub fn parse_netsh_config_addrs(output: &str) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    let mut current: Option<usize> = None;
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Configuration for interface \"") {
            let name = rest.trim_end_matches('"').to_string();
            out.push((name, Vec::new()));
            current = Some(out.len() - 1);
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("IP Address:") {
            let addr = rest.trim();
            if let Some(idx) = current {
                if !addr.is_empty() {
                    out[idx].1.push(addr.to_string());
                }
            }
        }
    }
    out
}

/// 从 `ping` 输出解析首个往返时延（毫秒，四舍五入）。
///
/// 兼容 iputils（`time=0.512 ms`，小数带空格）与 Windows（`time=1ms` /
/// `时间=1ms`，整数不带空格）——统一取「数字后可选空格 + `ms`」首次出现。
/// 取到子毫秒按四舍五入成整毫秒（RTT 展示与对账粒度）。
pub fn parse_ping_rtt_ms(output: &str) -> Option<u64> {
    let bytes = output.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        let int_part: f64 = output[start..i].parse().ok()?;
        let mut value = int_part;
        if i < bytes.len() && bytes[i] == b'.' {
            let mut j = i + 1;
            let frac_start = j;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j > frac_start {
                value = output[start..j].parse().ok()?;
                i = j;
            }
        }
        let mut j = i;
        while j < bytes.len() && bytes[j] == b' ' {
            j += 1;
        }
        if j + 1 < bytes.len() && bytes[j] == b'm' && bytes[j + 1] == b's' {
            return Some(value.round() as u64);
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> &'static str {
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    }

    #[test]
    fn ip_route_table_full_parse() {
        let out = "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n\
                   10.240.0.0/16 dev wg0 scope link src 10.240.0.2\n\
                   192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.50 metric 100\n\
                   blackhole 10.99.0.0/8 proto static metric 200";
        let routes = parse_ip_route_table(out);
        assert_eq!(routes.len(), 4);
        assert_eq!(routes[0].destination, "default");
        assert_eq!(routes[0].via.as_deref(), Some("192.168.1.1"));
        assert_eq!(routes[0].dev.as_deref(), Some("eth0"));
        assert_eq!(routes[0].proto.as_deref(), Some("dhcp"));
        assert_eq!(routes[0].metric.as_deref(), Some("100"));
        assert_eq!(routes[1].destination, "10.240.0.0/16");
        assert_eq!(routes[1].dev.as_deref(), Some("wg0"));
        assert_eq!(routes[1].via, None);
        assert_eq!(routes[3].destination, "blackhole 10.99.0.0/8");
        assert_eq!(routes[3].dev, None);
    }

    #[test]
    fn ip_route_table_skips_empty_lines() {
        assert!(parse_ip_route_table("").is_empty());
        assert!(parse_ip_route_table("\n\n").is_empty());
    }

    #[test]
    fn ip_o_link_parses_state_and_mtu() {
        let out = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n\
                   2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000";
        let rows = parse_ip_o_link(out);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "lo");
        assert_eq!(rows[0].mtu, Some(65536));
        assert_eq!(rows[0].state.as_deref(), Some("UNKNOWN"));
        assert_eq!(rows[1].name, "eth0");
        assert_eq!(rows[1].mtu, Some(1500));
        assert_eq!(rows[1].state.as_deref(), Some("UP"));
    }

    #[test]
    fn ip_o_addr_keeps_prefix() {
        let out = "2: eth0    inet 192.168.1.50/24 brd 192.168.1.255 scope global dynamic eth0\n\
                   3: wg0    inet 10.240.0.2/16 scope global wg0";
        let addrs = parse_ip_o_addr(out);
        assert_eq!(addrs.len(), 2);
        assert_eq!(
            addrs[0],
            ("eth0".to_string(), "192.168.1.50/24".to_string())
        );
        assert_eq!(addrs[1], ("wg0".to_string(), "10.240.0.2/16".to_string()));
    }

    #[test]
    fn assemble_interfaces_merges_and_marks_managed() {
        let links = vec![
            LinkRow {
                name: "eth0".into(),
                state: Some("UP".into()),
                mtu: Some(1500),
            },
            LinkRow {
                name: "wg0".into(),
                state: Some("UP".into()),
                mtu: Some(1420),
            },
        ];
        let addrs = vec![
            ("eth0".to_string(), "192.168.1.50/24".to_string()),
            ("wg0".to_string(), "10.240.0.2/16".to_string()),
        ];
        let ifaces = assemble_interfaces(&links, &addrs, "wg0");
        assert_eq!(ifaces.len(), 2);
        let wg = ifaces.iter().find(|i| i.name == "wg0").unwrap();
        assert!(wg.managed);
        assert_eq!(wg.mtu, Some(1420));
        assert_eq!(wg.addrs, vec!["10.240.0.2/16".to_string()]);
        let eth = ifaces.iter().find(|i| i.name == "eth0").unwrap();
        assert!(!eth.managed);
    }

    #[test]
    fn assemble_interfaces_falls_back_when_link_missing() {
        let addrs = vec![("veth1".to_string(), "10.0.0.9/24".to_string())];
        let ifaces = assemble_interfaces(&[], &addrs, "wg0");
        assert_eq!(ifaces.len(), 1);
        assert_eq!(ifaces[0].name, "veth1");
        assert_eq!(ifaces[0].mtu, None);
    }

    #[test]
    fn wg_dump_full_parse() {
        let dump = format!(
            "priv==\tpub==\t51820\toff\n{}\t(none)\t10.240.0.3:16190\t10.240.0.3/32,10.241.1.0/24\t1700000000\t1234\t5678\toff",
            key()
        );
        let (port, peers) = parse_wg_dump(&dump, 1700000100);
        assert_eq!(port, Some(51820));
        assert_eq!(peers.len(), 1);
        let p = &peers[0];
        assert_eq!(p.public_key, key());
        assert_eq!(p.endpoint.as_deref(), Some("10.240.0.3:16190"));
        assert_eq!(p.latest_handshake_age_secs, Some(100));
        assert_eq!(p.transfer_rx, Some(1234));
        assert_eq!(p.transfer_tx, Some(5678));
        assert_eq!(p.allowed_ips.len(), 2);
    }

    #[test]
    fn wg_dump_treats_unset_and_never_handshake() {
        let dump = format!(
            "priv==\tpub==\toff\toff\n{}\t(none)\t(none)\t10.240.0.3/32\t0\t0\t0\toff",
            key()
        );
        let (port, peers) = parse_wg_dump(&dump, 1700000100);
        assert_eq!(port, None);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].endpoint, None);
        assert_eq!(peers[0].latest_handshake_age_secs, None);
        assert_eq!(peers[0].transfer_rx, Some(0));
    }

    #[test]
    fn wg_dump_skips_malformed_peer_lines() {
        let dump = format!(
            "priv==\tpub==\t51820\toff\n{}\t(none)\t10.0.0.1:1\t10.0.0.1/32\nbogus-short",
            key()
        );
        let (_, peers) = parse_wg_dump(&dump, 1);
        assert_eq!(peers.len(), 1);
    }

    #[test]
    fn route_print_parses_active_section() {
        let out = "===========================================================================\n\
                   IPv4 Route Table\n\
                   ===========================================================================\n\
                   Active Routes:\n\
                   Network Destination        Netmask          Gateway       Interface  Metric\n\
                             0.0.0.0          0.0.0.0     192.168.1.1    192.168.1.50     25\n\
                          10.240.0.0      255.255.0.0       On-link         10.240.0.2    291\n\
                   ===========================================================================\n\
                   Persistent Routes:\n  None\n";
        let routes = parse_route_print(out);
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].destination, "default");
        assert_eq!(routes[0].via.as_deref(), Some("192.168.1.1"));
        assert_eq!(routes[0].dev.as_deref(), Some("192.168.1.50"));
        assert_eq!(routes[0].metric.as_deref(), Some("25"));
        assert_eq!(routes[1].destination, "10.240.0.0/16");
        assert_eq!(routes[1].via, None);
        assert_eq!(routes[1].dev.as_deref(), Some("10.240.0.2"));
    }

    #[test]
    fn netmask_prefix_requires_contiguous() {
        assert_eq!(netmask_prefix("255.255.255.0"), Some(24));
        assert_eq!(netmask_prefix("255.255.0.0"), Some(16));
        assert_eq!(netmask_prefix("0.0.0.0"), Some(0));
        assert_eq!(netmask_prefix("255.0.255.0"), None);
        assert_eq!(netmask_prefix("not-a-mask"), None);
    }

    #[test]
    fn netsh_interfaces_parse() {
        let out = "Idx     Met         MTU          State                  Name\n\
                   ---  ----------  ----------  ------------  ---------------------------\n\
                     1          50       65536  connected     Loopback Pseudo-Interface 1\n\
                    12          25        1420  connected     WireGuard\n";
        let rows = parse_netsh_interfaces(out);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "Loopback Pseudo-Interface 1");
        assert_eq!(rows[0].mtu, Some(65536));
        assert_eq!(rows[0].state.as_deref(), Some("connected"));
        assert_eq!(rows[1].name, "WireGuard");
        assert_eq!(rows[1].mtu, Some(1420));
    }

    #[test]
    fn netsh_config_addrs_parse() {
        let out = "Configuration for interface \"WireGuard\"\n\
                       DHCP enabled:                         No\n\
                       IP Address:                           10.240.0.2\n\
                       Subnet Prefix:                        10.240.0.0/16 (mask 255.255.0.0)\n\
                   Configuration for interface \"Ethernet\"\n\
                       IP Address:                           192.168.1.50\n";
        let addrs = parse_netsh_config_addrs(out);
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0].0, "WireGuard");
        assert_eq!(addrs[0].1, vec!["10.240.0.2".to_string()]);
        assert_eq!(addrs[1].0, "Ethernet");
        assert_eq!(addrs[1].1, vec!["192.168.1.50".to_string()]);
    }

    #[test]
    fn ping_rtt_parses_iputils_and_windows() {
        assert_eq!(
            parse_ping_rtt_ms("64 bytes from 10.240.0.1: icmp_seq=1 ttl=64 time=0.512 ms"),
            Some(1)
        );
        assert_eq!(
            parse_ping_rtt_ms("Reply from 10.240.0.1: bytes=32 time=1ms TTL=64"),
            Some(1)
        );
        assert_eq!(
            parse_ping_rtt_ms("来自 10.240.0.1 的回复: 字节=32 时间=12ms TTL=64"),
            Some(12)
        );
        assert_eq!(parse_ping_rtt_ms("Request timed out."), None);
        assert_eq!(parse_ping_rtt_ms(""), None);
    }
}
