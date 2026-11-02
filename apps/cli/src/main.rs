//! meshlet-cli：类 ZeroTier 的命令行工具。
//!
//! 常用命令：
//!   meshlet info             设备信息（名称、IP、状态）
//!   meshlet status           agent 运行状态
//!   meshlet peers            直连节点列表（IP/模式/延时/端点/流量）
//!   meshlet peer dial <node> 强制对目标节点发起直连拨号（名称/IP）
//!   meshlet agent diag       网络诊断快照（路由表/接口清单/wg 读数）
//!   meshlet agent diag --peers   在快照后追加直连 peers 表
//!   meshlet networks         子网/路由列表
//!   meshlet config           显示配置
//!   meshlet version          版本号

use meshlet_network::dial::{self, DirectDialRequest, DirectPeerView};
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

    // `meshlet peer dial [<node>]`：二层子命令。
    if cmd == "peer" {
        let sub = args.get(1).map(|s| s.as_str()).unwrap_or("");
        match sub {
            "dial" => cmd_peer_dial(args.get(2).map(|s| s.as_str())),
            other => {
                eprintln!("error: unknown peer subcommand '{other}'");
                eprintln!();
                print_usage();
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
    // R-TRAY-1：帮助文本由命令目录生成（单一事实源），与托盘「命令」区
    // 同源——新增命令自动出现在两处，`--help` 与目录不可能漂移。
    print!(
        "{}",
        meshlet_commands::usage_text(env!("CARGO_PKG_VERSION"))
    );
}

fn state_dir() -> PathBuf {
    // 与安装脚本/agent/tray 约定一致：状态写 `%LOCALAPPDATA%\meshlet\state`
    // （install.ps1 的 state_dir；tray `meshlet_state_dir` 同源）。旧的
    // ProgramData/config.toml 读不到真实 agent 状态，故废弃。
    state_dir_from_local(&local_appdata().to_string_lossy())
}

fn config_path() -> PathBuf {
    // 与安装脚本/agent/tray 约定一致：agent 配置 `%LOCALAPPDATA%\meshlet\agent.toml`
    // （install.ps1 写该路径；tray `config_path_from_local` 同源）。
    config_path_from_local(&local_appdata().to_string_lossy())
}

/// `%LOCALAPPDATA%`（回退 `%USERPROFILE%\AppData\Local`，再回退 Public）。
fn local_appdata() -> PathBuf {
    std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|_| {
            std::env::var("USERPROFILE").map(|h| PathBuf::from(h).join("AppData").join("Local"))
        })
        .unwrap_or_else(|_| PathBuf::from("C:/Users/Public/AppData/Local"))
}

/// 纯路径构造（可测）：`<local>/meshlet/state`——与 tray
/// `state_dir_from_local` 同一约定。
fn state_dir_from_local(local: &str) -> PathBuf {
    PathBuf::from(local).join("meshlet").join("state")
}

/// 纯路径构造（可测）：`<local>/meshlet/agent.toml`——与 tray
/// `config_path_from_local` 同一约定。
fn config_path_from_local(local: &str) -> PathBuf {
    PathBuf::from(local).join("meshlet").join("agent.toml")
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

    // WireGuard 隧道（实际隧道名按 install.ps1/README 为 wg-meshlet，后端
    // 默认 meshlet；旧硬编码 "WireGuard" 查不到真实隧道服务）。
    if cfg!(windows) {
        let tunnel = tunnel_service_running();
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

/// 拨号结果等待上限（秒）：agent 探测周期 30s，留足一个周期 + 处理余量。
const DIAL_RESULT_TIMEOUT_SECS: u64 = 45;
/// 结果轮询间隔（毫秒）。
const DIAL_POLL_MILLIS: u64 = 500;

/// `meshlet peer dial [<node>]`（R-AGENT-WIN-1 补充 ③）。
///
/// 无 `<node>`：列出可拨号候选（名称/IP/模式/延时/端点）——托盘「连接节点…」
/// 子菜单的数据源。有 `<node>`：解析目标（名称/IP/公钥前缀）→ 写拨号意图 →
/// 轮询 agent 结果 → 显示成功/失败。
///
/// 数据源 = agent 发布的 `{state_dir}/direct-peers.json`（与 `peers` 命令同一
/// 链路：都来自 agent 直连探测周期对内核的读数）。拨号本身经 agent 执行
/// （CLI 用户会话无权限 `wg set`；agent 持数据面后端），本命令只发意图、
/// 等结果——这就是「executor 接 meshlet-network 发起直连拨号」的进程边界。
fn cmd_peer_dial(node: Option<&str>) {
    let state = state_dir();
    let views = dial::load_direct_peers(&state);
    match node {
        None => print_dial_targets(&views),
        Some(node) => dial_node(&state, views, node),
    }
}

/// 无参模式：打印可拨号候选表。
fn print_dial_targets(views: &Option<Vec<DirectPeerView>>) {
    let views = match views {
        Some(v) => v,
        None => {
            println!("(no direct candidates — agent not reporting yet)");
            return;
        }
    };
    if views.is_empty() {
        println!("(no direct candidates)");
        return;
    }
    print!("{}", format_dial_targets(views));
}

/// 候选表渲染（纯函数，可测）：名称/overlay/模式/延时/端点。
fn format_dial_targets(views: &[DirectPeerView]) -> String {
    let mut out = format!(
        "{:<24} {:<16} {:<14} {:>8}  {}\n",
        "NAME", "OVERLAY_IP", "MODE", "RTT_MS", "ENDPOINT"
    );
    for v in views {
        let rtt = v
            .rtt_ms
            .map(|r| r.to_string())
            .unwrap_or_else(|| "—".into());
        let endpoint = if v.endpoint.is_empty() {
            "—".into()
        } else {
            v.endpoint.clone()
        };
        out.push_str(&format!(
            "{:<24} {:<16} {:<14} {:>8}  {}\n",
            v.name, v.virtual_ipv4, v.mode, rtt, endpoint
        ));
    }
    out
}

/// 解析 `<node>`：名称精确 / overlay IP / 公钥前缀（大小写不敏感）。
/// 纯函数（可测），无匹配返回 `None`。
fn resolve_dial_target<'a>(views: &'a [DirectPeerView], node: &str) -> Option<&'a DirectPeerView> {
    let node = node.trim();
    let lower = node.to_ascii_lowercase();
    views.iter().find(|v| {
        v.name == node
            || v.virtual_ipv4.to_string() == node
            || v.public_key.to_ascii_lowercase().starts_with(&lower)
    })
}

/// 有参模式：解析目标 → 写意图 → 轮询结果 → 打印成功/失败。
fn dial_node(state: &std::path::Path, views: Option<Vec<DirectPeerView>>, node: &str) {
    let views = match views {
        Some(v) => v,
        None => {
            eprintln!("peer dial: no direct candidates (agent not reporting yet)");
            std::process::exit(1);
        }
    };
    let target = match resolve_dial_target(&views, node) {
        Some(t) => t,
        None => {
            eprintln!("peer dial: unknown node '{node}'");
            std::process::exit(1);
        }
    };
    let request = DirectDialRequest {
        node: node.trim().to_string(),
        public_key: target.public_key.clone(),
        virtual_ipv4: target.virtual_ipv4,
        request_id: dial_request_id(),
        requested_at: dial::now_millis(),
    };
    if let Err(e) = dial::write_request(state, &request) {
        eprintln!("peer dial: cannot write request: {e}");
        std::process::exit(1);
    }
    println!(
        "dialing {} ({}) — waiting for agent...",
        target.name, target.virtual_ipv4
    );
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(DIAL_RESULT_TIMEOUT_SECS);
    while std::time::Instant::now() < deadline {
        if let Some(result) = dial::load_result(state) {
            if result.request_id == request.request_id {
                if result.ok {
                    println!("ok: {} ({})", result.message, result.mode);
                } else {
                    eprintln!("failed: {}", result.message);
                    std::process::exit(1);
                }
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(DIAL_POLL_MILLIS));
    }
    eprintln!("peer dial: timeout waiting for agent (is the agent running?)");
    std::process::exit(1);
}

/// 拨号请求 ID：Unix 毫秒 + 本进程号（跨进程唯一性足够）。
fn dial_request_id() -> String {
    format!("{}-{}", dial::now_millis(), std::process::id())
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
                "(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -match '^(wg-meshlet|meshlet)$' } | Select-Object -First 1).IPAddress"])
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
                "(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -match '^(wg-meshlet|meshlet)$' } | ForEach-Object { \"$($_.DestinationPrefix)|$($_.InterfaceAlias)\" })"])
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

/// WireGuard Windows 隧道服务名候选（`WireGuardTunnel$<iface>`）：实际隧道名
/// 按 install.ps1/README 为 wg-meshlet，后端默认 meshlet。纯函数（可测）。
/// 非 Windows 构建下仅测试引用，允许 dead_code 以免 `clippy -D warnings` 挂。
#[cfg_attr(not(windows), allow(dead_code))]
fn tunnel_service_names() -> Vec<String> {
    ["wg-meshlet", "meshlet"]
        .iter()
        .map(|iface| format!("WireGuardTunnel${iface}"))
        .collect()
}

#[cfg(windows)]
fn tunnel_service_running() -> bool {
    tunnel_service_names()
        .iter()
        .any(|svc| service_running(svc))
}

#[cfg(not(windows))]
fn tunnel_service_running() -> bool {
    false
}

#[cfg(not(windows))]
fn process_exists(_: &str) -> bool {
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

    /// R-TRAY-1：命令目录与 `meshlet --help` 实际输出一致（对账测试）。
    /// 帮助文本由目录生成，故二者同源；本测防「有人手改 help 造成漂移」。
    #[test]
    fn catalog_matches_help_and_dispatch() {
        let help = meshlet_commands::usage_text(env!("CARGO_PKG_VERSION"));
        // ① 目录每条命令都出现在 --help 输出里（名称+用途）。
        for c in meshlet_commands::COMMANDS {
            assert!(
                help.contains(c.name),
                "catalog '{}' missing from help",
                c.name
            );
            assert!(help.contains(c.summary), "summary of '{}' missing", c.name);
        }
        // ② 目录顶层命令集合与 main() 实际分发的命令集合一致（不遗漏、
        //    不虚增——新增命令必须进目录，目录命令必须能分发）。
        let catalog_top: std::collections::BTreeSet<&str> = meshlet_commands::COMMANDS
            .iter()
            .map(|c| c.name.split(' ').next().unwrap())
            .collect();
        let dispatched = std::collections::BTreeSet::from([
            "info", "status", "peers", "peer", "agent", "networks", "config", "version", "help",
        ]);
        assert_eq!(catalog_top, dispatched, "catalog and dispatch disagree");
        // ③ agent/peer 子命令同样覆盖（diag/dial 在目录，分发只认它们）。
        let sub_catalog: Vec<&str> = meshlet_commands::COMMANDS
            .iter()
            .filter(|c| c.name.starts_with("agent ") || c.name.starts_with("peer "))
            .map(|c| c.name)
            .collect();
        assert!(sub_catalog.contains(&"agent diag"));
        assert!(sub_catalog.contains(&"peer dial"));
    }

    /// 审核发现 3a：state_dir/config_path 走 `%LOCALAPPDATA%\meshlet\`
    /// （install.ps1/agent/tray 同一约定），旧 ProgramData/config.toml 废弃。
    /// 用 PathBuf 同构期望，跨平台（Linux `/` 分隔）不失真。
    #[test]
    fn state_dir_uses_localappdata_meshlet() {
        let local = r"C:\Users\bob\AppData\Local";
        let state = super::state_dir_from_local(local);
        assert_eq!(
            state,
            std::path::Path::new(local).join("meshlet").join("state")
        );
        let cfg = super::config_path_from_local(local);
        assert_eq!(
            cfg,
            std::path::Path::new(local)
                .join("meshlet")
                .join("agent.toml")
        );
    }

    /// 审核发现 3b：隧道服务名按实际隧道 wg-meshlet/后端默认 meshlet，
    /// 不再有 `WireGuardTunnel$WireGuard` 硬编码。
    #[test]
    fn tunnel_service_names_match_install_conventions() {
        let names = super::tunnel_service_names();
        assert!(names.contains(&"WireGuardTunnel$wg-meshlet".to_string()));
        assert!(names.contains(&"WireGuardTunnel$meshlet".to_string()));
        assert!(!names.iter().any(|n| n.contains("$WireGuard")));
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

    /// `peer dial <node>`：解析目标（名称/IP/公钥前缀），未知目标不误配。
    #[test]
    fn resolve_dial_target_matches_name_ip_and_key_prefix() {
        use super::DirectPeerView;
        let views = vec![DirectPeerView {
            name: "peer-b".into(),
            virtual_ipv4: "10.240.0.3".parse().unwrap(),
            public_key: "AbCdEfGh1234==".into(),
            mode: "hub_relay".into(),
            rtt_ms: None,
            endpoint: String::new(),
            last_handshake_at: None,
        }];
        // 名称精确。
        assert_eq!(
            super::resolve_dial_target(&views, "peer-b").unwrap().name,
            "peer-b"
        );
        // overlay IP。
        assert_eq!(
            super::resolve_dial_target(&views, "10.240.0.3")
                .unwrap()
                .name,
            "peer-b"
        );
        // 公钥前缀（大小写不敏感）。
        assert_eq!(
            super::resolve_dial_target(&views, "abcdefgh").unwrap().name,
            "peer-b"
        );
        // 未知目标 → None（不误配别的节点）。
        assert!(super::resolve_dial_target(&views, "peer-c").is_none());
        assert!(super::resolve_dial_target(&views, "10.240.0.9").is_none());
    }

    /// 无参 `peer dial`：候选表含表头与每节点一行。
    #[test]
    fn format_dial_targets_lists_every_candidate() {
        use super::DirectPeerView;
        let views = vec![DirectPeerView {
            name: "peer-b".into(),
            virtual_ipv4: "10.240.0.3".parse().unwrap(),
            public_key: "k==".into(),
            mode: "hub_relay".into(),
            rtt_ms: None,
            endpoint: String::new(),
            last_handshake_at: None,
        }];
        let text = super::format_dial_targets(&views);
        assert!(text.contains("NAME"));
        assert!(text.contains("peer-b"));
        assert!(text.contains("10.240.0.3"));
        assert!(text.contains("hub_relay"));
    }
}
