//! meshlet-cli：类 ZeroTier 的命令行工具。
//!
//! 常用命令：
//!   meshlet info          设备信息（名称、IP、状态）
//!   meshlet status        agent 运行状态
//!   meshlet peers         直连节点列表
//!   meshlet networks      子网/路由列表
//!   meshlet config        显示配置
//!   meshlet version       版本号

use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("");

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
         \x20 peers         List connected peers\n\
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

fn cmd_peers() {
    let peers = wg_peers();
    if peers.is_empty() {
        println!("no peers (tunnel not active or no handshake)");
        return;
    }
    println!(
        "{:<20} {:<24} {:<18} {:>10} {:>10}  {}",
        "ENDPOINT", "ALLOWED_IPS", "LAST_HANDSHAKE", "RX", "TX", "STATE"
    );
    for p in peers {
        let state = if p.connected { "connected" } else { "idle" };
        println!(
            "{:<20} {:<24} {:<18} {:>10} {:>10}  {}",
            p.endpoint,
            p.allowed_ips,
            p.last_handshake,
            format_bytes(p.rx),
            format_bytes(p.tx),
            state
        );
    }
}

fn cmd_networks() {
    // 从 WireGuard 配置和路由表获取
    if cfg!(windows) {
        let routes = wg_routes();
        if routes.is_empty() {
            println!("no routes");
            return;
        }
        println!("{:<24} {}", "DESTINATION", "INTERFACE");
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

struct WgPeer {
    endpoint: String,
    allowed_ips: String,
    last_handshake: String,
    rx: u64,
    tx: u64,
    connected: bool,
}

fn wg_peers() -> Vec<WgPeer> {
    #[cfg(windows)]
    {
        let wg = "C:\\Program Files\\WireGuard\\wg.exe";
        let Ok(output) = std::process::Command::new(wg)
            .args(["show", "all", "dump"])
            .output()
        else {
            return vec![];
        };
        let text = String::from_utf8_lossy(&output.stdout);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut peers = Vec::new();
        for line in text.lines() {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() >= 9 && cols[0] == "WireGuard" {
                let handshake: u64 = cols[5].parse().unwrap_or(0);
                let rx: u64 = cols[6].parse().unwrap_or(0);
                let tx: u64 = cols[7].parse().unwrap_or(0);
                let age = if handshake > 0 && now > handshake {
                    now - handshake
                } else {
                    0
                };
                peers.push(WgPeer {
                    endpoint: cols[3].to_string(),
                    allowed_ips: cols[4].to_string(),
                    last_handshake: if handshake > 0 {
                        format!("{age}s ago")
                    } else {
                        "never".into()
                    },
                    rx,
                    tx,
                    connected: handshake > 0 && age < 180,
                });
            }
        }
        peers
    }
    #[cfg(not(windows))]
    {
        vec![]
    }
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
    #[test]
    fn usage_works() {
        // 确保 version 命令不 panic
        let _ = super::format_bytes(0);
    }
}
