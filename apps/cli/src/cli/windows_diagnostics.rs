use crate::cli::render::{print_peers_table, print_wg_peers};
use meshlet_network::SystemBackend;

/// 构造诊断后端：默认 `wg0`，若本机存在实际 wg 接口则用其名（配置常改
/// `wg-mlt` 等，默认名不符实；按链路类型自动检测，读不到回落默认）。
pub(crate) fn diag_backend() -> SystemBackend {
    let backend = SystemBackend::new();
    match detect_wg_interface() {
        Some(interface) => backend.with_interface(interface),
        None => backend,
    }
}

/// 检测本机 wireguard 类型接口名（Linux `ip -o link show type wireguard`）。
pub(crate) fn detect_wg_interface() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("ip")
            .args(["-o", "link", "show", "type", "wireguard"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
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
pub(crate) fn cmd_agent_diag(show_peers: bool) {
    let backend = diag_backend();
    let interface = detect_wg_interface().unwrap_or_else(|| "wg0".into());
    let network = match backend.diagnostics_sync() {
        Ok(network) => network,
        Err(error) => {
            eprintln!("diag failed: {error}");
            std::process::exit(1);
        }
    };

    println!(
        "== routes ({}) ==",
        network.collected_at.as_deref().unwrap_or("?")
    );
    if network.route_table.is_empty() {
        println!("(not collected)");
    } else {
        for line in &network.route_table {
            println!("{line}");
        }
    }

    println!("\n== interfaces ==");
    if network.interfaces.is_empty() {
        println!("(not collected)");
    } else {
        println!("{:<16} {:<6} {:>5}  IPV4", "NAME", "STATE", "MTU");
        for interface_info in &network.interfaces {
            let ipv4 = match (&interface_info.ipv4, interface_info.prefix) {
                (ip, Some(prefix)) if !ip.is_empty() => format!("{ip}/{prefix}"),
                _ => "—".to_string(),
            };
            println!(
                "{:<16} {:<6} {:>5}  {}",
                interface_info.name,
                interface_info.state,
                interface_info
                    .mtu
                    .map(|mtu| mtu.to_string())
                    .unwrap_or_else(|| "?".into()),
                ipv4
            );
        }
    }

    println!("\n== wg peers ({interface}) ==");
    print_wg_peers(&network.wg, &interface);

    if show_peers {
        println!("\n== direct peers ==");
        print_peers_table(&backend, &interface);
    }
}

pub(crate) fn wg_local_ip() -> Option<String> {
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

pub(crate) fn wg_routes() -> Vec<(String, String)> {
    #[cfg(windows)]
    {
        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command",
                "(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -match '^(wg-meshlet|meshlet)$' } | ForEach-Object { \"$($_.DestinationPrefix)|$($_.InterfaceAlias)\" })"])
            .output()
            .ok();
        if let Some(output) = output {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|line| !line.trim().is_empty())
                .filter_map(|line| {
                    line.split_once('|').map(|(destination, interface)| {
                        (destination.to_string(), interface.to_string())
                    })
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
pub(crate) fn process_exists(name: &str) -> bool {
    std::process::Command::new("tasklist")
        .args(["/FI", &format!("IMAGENAME eq {name}.exe"), "/NH"])
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).contains(name))
        .unwrap_or(false)
}

#[cfg(windows)]
fn service_running(name: &str) -> bool {
    std::process::Command::new("sc")
        .args(["query", name])
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).contains("RUNNING"))
        .unwrap_or(false)
}

/// WireGuard Windows 隧道服务名候选（`WireGuardTunnel$<iface>`）：实际隧道名
/// 按 install.ps1/README 为 wg-meshlet，后端默认 meshlet。纯函数（可测）。
/// 非 Windows 构建下仅测试引用，允许 dead_code 以免 `clippy -D warnings` 挂。
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn tunnel_service_names() -> Vec<String> {
    ["wg-meshlet", "meshlet"]
        .iter()
        .map(|interface| format!("WireGuardTunnel${interface}"))
        .collect()
}

#[cfg(windows)]
pub(crate) fn tunnel_service_running() -> bool {
    tunnel_service_names()
        .iter()
        .any(|service| service_running(service))
}

#[cfg(not(windows))]
pub(crate) fn tunnel_service_running() -> bool {
    false
}

#[cfg(not(windows))]
pub(crate) fn process_exists(_: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    /// 审核发现 3b：隧道服务名按实际隧道 wg-meshlet/后端默认 meshlet，
    /// 不再有 `WireGuardTunnel$WireGuard` 硬编码。
    #[test]
    fn tunnel_service_names_match_install_conventions() {
        let names = super::tunnel_service_names();
        assert!(names.contains(&"WireGuardTunnel$wg-meshlet".to_string()));
        assert!(names.contains(&"WireGuardTunnel$meshlet".to_string()));
        assert!(!names.iter().any(|name| name.contains("$WireGuard")));
    }
}
