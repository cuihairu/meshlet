use crate::cli::render::{print_peers_table, print_wg_peers};
use meshlet_network::{NetworkBackend, SystemBackend};

/// Build the diagnostics backend: defaults to `wg0` but uses the real wg interface name when one
/// exists locally (configs often rename it to `wg-mlt` etc.; auto-detected, falls back to default).
pub(crate) fn diag_backend() -> SystemBackend {
    let backend = SystemBackend::new();
    match detect_wg_interface() {
        Some(interface) => backend.with_interface(interface),
        None => backend,
    }
}

/// Detect the local wireguard-style interface name (reuses [meshlet_network::detect_wireguard_interface],
/// the same source of truth as the MCP `doctor`, so the two probe logics cannot drift).
pub(crate) fn detect_wg_interface() -> Option<String> {
    meshlet_network::detect_wireguard_interface()
}

/// `meshlet agent diag [--peers]` (R-DIAG / R-DIAG-2): a local network diagnostics snapshot.
/// Collection failure is reported as-is (the diagnostics surface never invents defaults); `--peers` appends the direct peer table.
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

/// `meshlet agent doctor` (AGENT-DOC-1): coexistence health check for foreign overlays.
///
/// Read-only check, touches no kernel state. **Exit code 1 when any FAIL exists** (a gate for
/// monitoring/scripts); data-starved items are marked `SKIP`, not PASS — missing data is not a pass (§7.5).
pub(crate) fn cmd_agent_doctor() {
    use meshlet_network::doctor::CheckStatus;

    // `wg` / `iptables` / `zerotier-cli` all need privileges to read. The agent runs as root,
    // but the CLI is usually typed by a plain user — without elevation, 3 of the 5 checks can
    // only SKIP, making the health check useless. `/proc/self`'s owner uid equals this process's
    // euid (Linux semantics, no libc); non-root goes via `sudo -n`; if passwordless fails, the command errors -> the verdict honestly reports not_assessed.
    let backend = diag_backend();
    // sudo elevation is Unix-only: root runs directly, non-root uses `sudo -n` (if passwordless
    // access is unavailable the command fails -> the verdict honestly reports not_assessed).
    // Windows commands degrade on their own, no extra elevation — `with_sudo` only exists on
    // the unix backend and must be cfg-gated, else windows targets hit E0599 (run 45321046165).
    #[cfg(unix)]
    let backend = {
        use std::os::unix::fs::MetadataExt;
        let is_root = std::fs::metadata("/proc/self")
            .map(|meta| meta.uid() == 0)
            .unwrap_or(false);
        if is_root {
            backend
        } else {
            backend.with_sudo()
        }
    };

    let report = backend.doctor();
    println!("== meshlet agent doctor ({}) ==", report.collected_at);
    for check in &report.checks {
        let badge = match check.status {
            CheckStatus::Pass => "PASS",
            CheckStatus::Warn => "WARN",
            CheckStatus::Fail => "FAIL",
            CheckStatus::NotAssessed => "SKIP",
        };
        println!("{badge}  {:<24} {}", check.id, check.title);
        println!("      {}", check.evidence);
    }
    let [pass, warn, fail, skip] = report.counts();
    println!();
    println!("{pass} pass, {warn} warn, {fail} fail, {skip} not assessed");
    if report.has_failure() {
        std::process::exit(1);
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

/// Candidate service names for the WireGuard Windows tunnel (`WireGuardTunnel$<iface>`): the real
/// tunnel name is wg-meshlet per install.ps1/README, backend default meshlet. Pure (testable).
/// On non-Windows builds only tests reference it; allow dead_code so `clippy -D warnings` stays green.
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
    /// Audit finding 3b: tunnel service names follow the real tunnel wg-meshlet / backend
    /// default meshlet; no more `WireGuardTunnel$WireGuard` hardcoding.
    #[test]
    fn tunnel_service_names_match_install_conventions() {
        let names = super::tunnel_service_names();
        assert!(names.contains(&"WireGuardTunnel$wg-meshlet".to_string()));
        assert!(names.contains(&"WireGuardTunnel$meshlet".to_string()));
        assert!(!names.iter().any(|name| name.contains("$WireGuard")));
    }
}
