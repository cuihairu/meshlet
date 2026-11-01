//! meshlet-cli：类 ZeroTier 的命令行工具。
//!
//! 常用命令：
//!   meshlet info             设备信息（名称、IP、状态）
//!   meshlet status           agent 运行状态
//!   meshlet peers            直连节点列表（IP/模式/延时/端点/流量）
//!   meshlet agent diag       网络诊断快照（路由表/接口清单/wg 读数）
//!   meshlet agent diag --peers   在快照后追加直连 peers 表
//!   meshlet networks         子网/路由列表
//!   meshlet config           显示配置
//!   meshlet version          版本号

use meshlet_network::SystemBackend;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("");

    // `meshlet agent diag [--peers]`：二层子命令。
    if cmd == "agent" {
        let sub = args.get(1).map(|s| s.as_str()).unwrap_or("");
        match sub {
            "diag" => {
                let show_peers = args.iter().any(|a| a == "--peers");
                cmd_agent_diag(show_peers);
            }
            other => {
                eprintln!("error: unknown agent subcommand '{other}'");
                std::process::exit(1);
            }
        }
        return;
    }

    match cmd {
        "info" => cmd_info(),
        "status" => cmd_status(),
        "peers" => cmd_peers(),
        "networks" => cmd_networks(),
        "config" => cmd_config(),
        "version" | "--version" | "-V" => {
            println!("meshlet-cli {}", env!("CARGO_PKG_VERSION"));
        }
        "help" | "--help" | "-H" | "" => print_usage(),
        other => {
            eprintln!("error: unknown command '{other}'");
            eprintln!();
            print_usage();
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    println!(
        "meshlet-cli {}\n\n\
         Usage: meshlet <command>\n\n\
         Commands:\n\
         \x20 info          Show device info (name, IP, status)\n\
         \x20 status        Show agent status\n\
         \x20 peers         List direct peers (IP/mode/RTT/endpoint/traffic)\n\
         \x20 agent diag    Show network diagnostics snapshot (routes/interfaces/wg)\n\
         \x20 agent diag --peers   Append direct peers table to the snapshot\n\
         \x20 networks      List subnets/routes\n\
         \x20 config        Show configuration\n\
         \x20 version       Show version\n\
         \x20 help          Show this help",
        env!("CARGO_PKG_VERSION")
    );
}

fn state_dir() -> PathBuf {
    // 优先 ProgramData（服务运行），回退用户目录
    let pd = PathBuf::from("C:\\ProgramData\\meshlet\\state");
    if pd.exists() {
        return pd;
    }
    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:/Users/Public".into());
    PathBuf::from(home).join(".meshlet").join("state")
}

fn config_path() -> PathBuf {
    let pd = PathBuf::from("C:\\ProgramData\\meshlet\\config.toml");
    if pd.exists() {
        return pd;
    }
    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:/Users/Public".into());
    PathBuf::from(home).join(".meshlet").join("config.toml")
}

fn cmd_info() {
    let cfg = read_config();
    let device_name = cfg
        .get("device_name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let server_url = cfg
        .get("server_url")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // 从 WireGuard 获取本机 IP
    let wg_ip = wg_local_ip().unwrap_or_else(|| "not connected".to_string());

    // 从 status.json 获取状态
    let status = read_status();
    let state = status
        .get("state")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    println!("device:    {device_name}");
    println!("server:    {server_url}");
    println!("ip:        {wg_ip}");
    println!("status:    {state}");
}

fn cmd_status() {
    let status = read_status();
    let state = status
        .get("state")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let tooltip = status.get("tooltip").and_then(|v| v.as_str()).unwrap_or("");

    // agent 进程是否存活
    let agent_alive = cfg!(windows) && process_exists("meshlet-agent");
    let tray_alive = cfg!(windows) && process_exists("meshlet-tray");

    println!(
        "agent:     {}",
        if agent_alive { "running" } else { "stopped" }
    );
    println!(
        "tray:      {}",
        if tray_alive { "running" } else { "stopped" }
    );
    println!("state:     {state}");
    if !tooltip.is_empty() {
        println!("detail:    {tooltip}");
    }

    // WireGuard 隧道
    if cfg!(windows) {
        let tunnel = service_running("WireGuardTunnel$WireGuard");
        println!("tunnel:    {}", if tunnel { "up" } else { "down" });
    }
}

/// `meshlet peers`（R-DIAG-2）：本机直连对端表——overlay IP / 连接模式 /
/// 直连端点 / 实测 RTT / 最近握手 / 累计流量。
///
/// 数据源为本机 wg 读数（`diagnostics_sync` 的 wg 段）+ 对 overlay 地址实测
/// RTT：wg 里存在即直连候选（agent 已下发 `wg set`），握手新鲜判 P2P 直连、
/// 否则直连 pending。中继对端不出现在 wg（走 hub 整段路由），不在此列。
fn cmd_peers() {
    let backend = diag_backend();
    let ifname = detect_wg_interface().unwrap_or_else(|| "wg0".into());
    print_peers_table(&backend, &ifname);
}

/// 构造诊断后端：默认 `wg0`，若本机存在实际 wg 接口则用其名（配置常改
/// `wg-mlt` 等，默认名不符实；按链路类型自动检测，读不到回落默认）。
fn diag_backend() -> SystemBackend {
    let backend = SystemBackend::new();
    match detect_wg_interface() {
        Some(ifname) => backend.with_interface(ifname),
        None => backend,
    }
}

/// 检测本机 wireguard 类型接口名（Linux `ip -o link show type wireguard`）。
fn detect_wg_interface() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let out = std::process::Command::new("ip")
            .args(["-o", "link", "show", "type", "wireguard"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 2 {
                let name = fields[1].trim_end_matches(':');
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = ();
    }
    None
}

/// `meshlet agent diag [--peers]`（R-DIAG / R-DIAG-2）：本机网络诊断快照。
/// 采集失败如实报错（诊断面绝不臆测默认值）；`--peers` 在快照后追加直连表。
fn cmd_agent_diag(show_peers: bool) {
    let backend = diag_backend();
    let ifname = detect_wg_interface().unwrap_or_else(|| "wg0".into());
    let net = match backend.diagnostics_sync() {
        Ok(net) => net,
        Err(e) => {
            eprintln!("diag failed: {e}");
            std::process::exit(1);
        }
    };

    println!(
        "== routes ({}) ==",
        net.collected_at.as_deref().unwrap_or("?")
    );
    if net.route_table.is_empty() {
        println!("(not collected)");
    } else {
        for line in &net.route_table {
            println!("{line}");
        }
    }

    println!("\n== interfaces ==");
    if net.interfaces.is_empty() {
        println!("(not collected)");
    } else {
        println!("{:<16} {:<6} {:>5}  IPV4", "NAME", "STATE", "MTU");
        for i in &net.interfaces {
            let ipv4 = match (&i.ipv4, i.prefix) {
                (ip, Some(p)) if !ip.is_empty() => format!("{ip}/{p}"),
                _ => "—".to_string(),
            };
            println!(
                "{:<16} {:<6} {:>5}  {}",
                i.name,
                i.state,
                i.mtu.map(|m| m.to_string()).unwrap_or_else(|| "?".into()),
                ipv4
            );
        }
    }

    println!("\n== wg peers ({ifname}) ==");
    print_wg_peers(&net.wg, &ifname);

    if show_peers {
        println!("\n== direct peers ==");
        print_peers_table(&backend, &ifname);
    }
}

/// 打印 wg 段：读数为空时如实区分「无直连对端」与「读数需提权」。
fn print_wg_peers(wg: &[meshlet_network::WgPeerDiagnostic], ifname: &str) {
    if wg.is_empty() {
        if wg_readable(ifname) {
            println!("(no direct peers)");
        } else {
            println!("(wg reading unavailable — requires root/administrator)");
        }
        return;
    }
    for p in wg {
        println!(
            "endpoint={} allowed_ips={} last_handshake={} rx={} tx={}",
            if p.endpoint.is_empty() {
                "—"
            } else {
                &p.endpoint
            },
            if p.allowed_ips.is_empty() {
                "—"
            } else {
                &p.allowed_ips
            },
            if p.last_handshake > 0 {
                p.last_handshake.to_string()
            } else {
                "never".into()
            },
            format_bytes(p.rx_bytes),
            format_bytes(p.tx_bytes),
        );
    }
}

/// wg 配置读数是否可访问（`wg show <if> dump` 需 root/CAP_NET_ADMIN）。
fn wg_readable(ifname: &str) -> bool {
    std::process::Command::new("wg")
        .args(["show", ifname, "dump"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// 打印直连对端表（`meshlet peers` 与 `agent diag --peers` 共用）。
fn print_peers_table(backend: &SystemBackend, ifname: &str) {
    let net = match backend.diagnostics_sync() {
        Ok(net) => net,
        Err(e) => {
            eprintln!("peers: diagnostics unavailable: {e}");
            return;
        }
    };
    if net.wg.is_empty() {
        if wg_readable(ifname) {
            println!("(no direct peers; hub relay covers all)");
        } else {
            println!("(wg reading unavailable — requires root/administrator)");
        }
        return;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!(
        "{:<18} {:<14} {:<12} {:<20} {:>6} {:>9} {:>8} {:>8}",
        "PUBLIC_KEY", "OVERLAY_IP", "MODE", "ENDPOINT", "RTT_MS", "HANDSHAKE", "RX", "TX"
    );
    for p in &net.wg {
        let (mode, overlay, is_direct) = peer_mode(&p.allowed_ips, p.last_handshake, now);
        let addr = overlay.parse::<std::net::Ipv4Addr>().ok();
        let rtt = match (is_direct, addr) {
            (true, Some(ip)) => backend
                .ping_rtt_ms(ip)
                .map(|v| v.to_string())
                .unwrap_or_else(|| "—".into()),
            _ => "—".into(),
        };
        let handshake = if p.last_handshake > 0 {
            format!("{}s ago", now.saturating_sub(p.last_handshake))
        } else {
            "never".into()
        };
        println!(
            "{:<18} {:<14} {:<12} {:<20} {:>6} {:>9} {:>8} {:>8}",
            &p.public_key[..p.public_key.len().min(18)],
            overlay,
            mode,
            if p.endpoint.is_empty() {
                "—"
            } else {
                &p.endpoint
            },
            rtt,
            handshake,
            format_bytes(p.rx_bytes),
            format_bytes(p.tx_bytes),
        );
    }
}

/// 直连对端表一行判定（纯函数，可测）：allowed_ips 首个 CIDR 为 /32 =
/// 直连对端（agent 下发 `wg set` 时只写对端 /32），整段（如 /16）= hub
/// 中继对端。直连对端再按握手新鲜度分 p2p_direct / direct_pending。
/// 返回 (mode, overlay_ip, is_direct)；中继对端 overlay 为 "—"。
fn peer_mode(allowed_ips: &str, last_handshake: u64, now: u64) -> (String, String, bool) {
    let cidr = allowed_ips
        .split(',')
        .next()
        .unwrap_or("")
        .trim()
        .split_once('/');
    let prefix = cidr.and_then(|(_, p)| p.parse::<u8>().ok());
    let addr = cidr.map(|(a, _)| a.trim().to_string());
    let is_direct = prefix == Some(32);
    let mode = if !is_direct {
        "hub_relay".to_string()
    } else if last_handshake > 0 && now.saturating_sub(last_handshake) < 180 {
        "p2p_direct".to_string()
    } else {
        "direct_pending".to_string()
    };
    let overlay = if is_direct {
        addr.unwrap_or_default()
    } else {
        "—".to_string()
    };
    (mode, overlay, is_direct)
}

fn cmd_networks() {
    // 从 WireGuard 配置和路由表获取
    if cfg!(windows) {
        let routes = wg_routes();
        if routes.is_empty() {
            println!("no routes");
            return;
        }
        println!("{:<24} INTERFACE", "DESTINATION");
        for r in routes {
            println!("{:<24} {}", r.0, r.1);
        }
    } else {
        println!("networks: not supported on this platform yet");
    }
}

fn cmd_config() {
    let path = config_path();
    println!("# {}", path.display());
    match std::fs::read_to_string(&path) {
        Ok(text) => print!("{text}"),
        Err(_) => println!("(config not found)"),
    }
}

// ── helpers ──────────────────────────────────────────────────────────

fn read_config() -> serde_json::Value {
    let path = config_path();
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let mut map = serde_json::Map::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim().to_string();
            let v = v.trim().trim_matches('"').to_string();
            map.insert(k, serde_json::Value::String(v));
        }
    }
    serde_json::Value::Object(map)
}

fn read_status() -> serde_json::Value {
    let path = state_dir().join("tray").join("status.json");
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::json!({}))
}

fn wg_local_ip() -> Option<String> {
    #[cfg(windows)]
    {
        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command",
                "(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -match 'WireGuard' } | Select-Object -First 1).IPAddress"])
            .output()
            .ok()?;
        let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if ip.is_empty() {
            None
        } else {
            Some(ip)
        }
    }
    #[cfg(not(windows))]
    {
        None
    }
}

fn wg_routes() -> Vec<(String, String)> {
    #[cfg(windows)]
    {
        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command",
                "(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -match 'WireGuard' } | ForEach-Object { \"$($_.DestinationPrefix)|$($_.InterfaceAlias)\" })"])
            .output()
            .ok();
        if let Some(o) = output {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|l| {
                    l.split_once('|')
                        .map(|(a, b)| (a.to_string(), b.to_string()))
                })
                .collect()
        } else {
            vec![]
        }
    }
    #[cfg(not(windows))]
    {
        vec![]
    }
}

#[cfg(windows)]
fn process_exists(name: &str) -> bool {
    std::process::Command::new("tasklist")
        .args(["/FI", &format!("IMAGENAME eq {name}.exe"), "/NH"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(name))
        .unwrap_or(false)
}

#[cfg(windows)]
fn service_running(name: &str) -> bool {
    std::process::Command::new("sc")
        .args(["query", name])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("RUNNING"))
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn process_exists(_: &str) -> bool {
    false
}

#[cfg(not(windows))]
fn service_running(_: &str) -> bool {
    false
}

fn format_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n}B")
    } else if n < 1024 * 1024 {
        format!("{:.1}K", n as f64 / 1024.0)
    } else if n < 1024 * 1024 * 1024 {
        format!("{:.1}M", n as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2}G", n as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::peer_mode;

    #[test]
    fn usage_works() {
        // 确保 version 命令不 panic
        let _ = super::format_bytes(0);
    }

    /// R-DIAG-2：allowed_ips 判直连（/32）与 hub（整段），握手判 P2P/pending。
    #[test]
    fn peer_mode_distinguishes_direct_from_hub() {
        let now = 1_000_000u64;
        // hub 中继：整段 /16，无论握手多新都是 relay，overlay 不显示。
        let (mode, overlay, is_direct) = peer_mode("10.240.0.0/16", now - 5, now);
        assert_eq!(mode, "hub_relay");
        assert_eq!(overlay, "—");
        assert!(!is_direct);

        // 直连对端 /32 + 新鲜握手 → p2p_direct，overlay 取地址。
        let (mode, overlay, is_direct) = peer_mode("10.240.0.3/32", now - 5, now);
        assert_eq!(mode, "p2p_direct");
        assert_eq!(overlay, "10.240.0.3");
        assert!(is_direct);

        // 直连对端 /32 + 陈旧/从未握手 → pending。
        let (mode, _, _) = peer_mode("10.240.0.3/32", now - 5000, now);
        assert_eq!(mode, "direct_pending");
        let (mode, _, _) = peer_mode("10.240.0.3/32", 0, now);
        assert_eq!(mode, "direct_pending");

        // 多 allowed-ips 取首个；空/无前缀按非直连处理（不误报）。
        let (mode, _, is_direct) = peer_mode("10.240.0.3/32,192.168.1.0/24", now - 5, now);
        assert_eq!(mode, "p2p_direct");
        assert!(is_direct);
        let (mode, _, is_direct) = peer_mode("", 0, now);
        assert_eq!(mode, "hub_relay");
        assert!(!is_direct);
    }
}
