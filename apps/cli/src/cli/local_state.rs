use crate::cli::render::print_peers_table;
use crate::cli::windows_diagnostics::{
    detect_wg_interface, diag_backend, process_exists, tunnel_service_running, wg_local_ip,
    wg_routes,
};
pub(crate) fn cmd_info() {
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

pub(crate) fn cmd_status() {
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
pub(crate) fn cmd_peers() {
    let backend = diag_backend();
    let ifname = detect_wg_interface().unwrap_or_else(|| "wg0".into());
    print_peers_table(&backend, &ifname);
}

pub(crate) fn cmd_networks() {
    // 从 WireGuard 配置和路由表获取
    if cfg!(windows) {
        let routes = wg_routes();
        if routes.is_empty() {
            println!("no routes");
            return;
        }
        println!("{:<24} INTERFACE", "DESTINATION");
        for (destination, interface) in routes {
            println!("{:<24} {}", destination, interface);
        }
    } else {
        println!("networks: not supported on this platform yet");
    }
}

pub(crate) fn cmd_config() {
    let path = config_path();
    println!("# {}", path.display());
    match std::fs::read_to_string(&path) {
        Ok(text) => print!("{text}"),
        Err(_) => println!("(config not found)"),
    }
}

pub(crate) fn state_dir() -> std::path::PathBuf {
    // 与安装脚本/agent/tray 约定一致：状态写 `%LOCALAPPDATA%\meshlet\state`
    // （install.ps1 的 state_dir；tray `meshlet_state_dir` 同源）。旧的
    // ProgramData/config.toml 读不到真实 agent 状态，故废弃。
    state_dir_from_local(&local_appdata().to_string_lossy())
}

pub(crate) fn config_path() -> std::path::PathBuf {
    // 与安装脚本/agent/tray 约定一致：agent 配置 `%LOCALAPPDATA%\meshlet\agent.toml`
    // （install.ps1 写该路径；tray `config_path_from_local` 同源）。
    config_path_from_local(&local_appdata().to_string_lossy())
}

/// `%LOCALAPPDATA%`（回退 `%USERPROFILE%\AppData\Local`，再回退 Public）。
fn local_appdata() -> std::path::PathBuf {
    std::env::var("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .or_else(|_| {
            std::env::var("USERPROFILE")
                .map(|home| std::path::PathBuf::from(home).join("AppData").join("Local"))
        })
        .unwrap_or_else(|_| std::path::PathBuf::from("C:/Users/Public/AppData/Local"))
}

/// 纯路径构造（可测）：`<local>/meshlet/state`——与 tray
/// `state_dir_from_local` 同一约定。
fn state_dir_from_local(local: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(local)
        .join("meshlet")
        .join("state")
}

/// 纯路径构造（可测）：`<local>/meshlet/agent.toml`——与 tray
/// `config_path_from_local` 同一约定。
fn config_path_from_local(local: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(local)
        .join("meshlet")
        .join("agent.toml")
}

pub(crate) fn read_config() -> serde_json::Value {
    let path = config_path();
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let mut map = serde_json::Map::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_string();
            let value = value.trim().trim_matches('"').to_string();
            map.insert(key, serde_json::Value::String(value));
        }
    }
    serde_json::Value::Object(map)
}

pub(crate) fn read_status() -> serde_json::Value {
    let path = state_dir().join("tray").join("status.json");
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|status| serde_json::from_str(&status).ok())
        .unwrap_or(serde_json::json!({}))
}

#[cfg(test)]
mod tests {
    #[test]
    fn state_dir_uses_localappdata_meshlet() {
        let local = r"C:\Users\bob\AppData\Local";
        let state = super::state_dir_from_local(local);
        assert_eq!(
            state,
            std::path::Path::new(local).join("meshlet").join("state")
        );
        let config = super::config_path_from_local(local);
        assert_eq!(
            config,
            std::path::Path::new(local)
                .join("meshlet")
                .join("agent.toml")
        );
    }
}
