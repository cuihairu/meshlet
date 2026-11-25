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

    // Get this machine's IP from WireGuard
    let wg_ip = wg_local_ip().unwrap_or_else(|| "not connected".to_string());

    // Read the status out of status.json
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

    // Whether the agent process is alive
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

    // WireGuard tunnel (the real tunnel name is wg-meshlet per install.ps1/README,
    // backend defaulting to meshlet; the old hardcoded "WireGuard" finds no real tunnel service).
    if cfg!(windows) {
        let tunnel = tunnel_service_running();
        println!("tunnel:    {}", if tunnel { "up" } else { "down" });
    }
}

/// `meshlet peers` (R-DIAG-2): the local direct peer table — overlay IP /
/// connection mode / direct endpoint / measured RTT / last handshake / traffic.
///
/// Data: local wg readings (the wg section of `diagnostics_sync`) plus RTT
/// measured against the overlay address. Present in wg marks a direct candidate
/// (the agent already issued `wg set`); a fresh handshake means P2P direct, else pending; relayed peers are hub-routed and never appear in wg, so they are not listed.
pub(crate) fn cmd_peers() {
    let backend = diag_backend();
    let ifname = detect_wg_interface().unwrap_or_else(|| "wg0".into());
    print_peers_table(&backend, &ifname);
}

pub(crate) fn cmd_networks() {
    // Taken from the WireGuard config and the route table
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
    // Same convention as the installer/agent/tray: status lives in `%LOCALAPPDATA%\meshlet\state`
    // (install.ps1's state_dir; the tray's `meshlet_state_dir` is the same source). The old
    // ProgramData/config.toml cannot see real agent state, so it is retired.
    state_dir_from_local(&local_appdata().to_string_lossy())
}

pub(crate) fn config_path() -> std::path::PathBuf {
    // Same convention as the installer/agent/tray: agent config is `%LOCALAPPDATA%\meshlet\agent.toml`
    // (install.ps1 writes that path; the tray's `config_path_from_local` is the same source).
    config_path_from_local(&local_appdata().to_string_lossy())
}

/// `%LOCALAPPDATA%` (falling back to `%USERPROFILE%\AppData\Local`, then to Public).
fn local_appdata() -> std::path::PathBuf {
    std::env::var("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .or_else(|_| {
            std::env::var("USERPROFILE")
                .map(|home| std::path::PathBuf::from(home).join("AppData").join("Local"))
        })
        .unwrap_or_else(|_| std::path::PathBuf::from("C:/Users/Public/AppData/Local"))
}

/// Pure path construction (testable): `<local>/meshlet/state` — the same
/// convention as the tray's `state_dir_from_local`.
fn state_dir_from_local(local: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(local)
        .join("meshlet")
        .join("state")
}

/// Pure path construction (testable): `<local>/meshlet/agent.toml` — the same
/// convention as the tray's `config_path_from_local`.
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
