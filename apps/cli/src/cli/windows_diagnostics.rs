use crate::cli::render::{print_peers_table, print_wg_peers};
use meshlet_network::{NetworkBackend, SystemBackend};

/// 构造诊断后端：默认 `wg0`，若本机存在实际 wg 接口则用其名（配置常改
/// `wg-mlt` 等，默认名不符实；按链路类型自动检测，读不到回落默认）。
pub(crate) fn diag_backend() -> SystemBackend {
    let backend = SystemBackend::new();
    match detect_wg_interface() {
        Some(interface) => backend.with_interface(interface),
        None => backend,
    }
}

/// 检测本机 wireguard 类型接口名（复用 [meshlet_network::detect_wireguard_interface]，
/// 与 MCP `doctor` 同一事实源，避免两处探测逻辑漂移）。
pub(crate) fn detect_wg_interface() -> Option<String> {
    meshlet_network::detect_wireguard_interface()
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

/// `meshlet agent doctor`（AGENT-DOC-1）：外来 overlay 共存体检。
///
/// 只读体检，不改任何内核状态。**存在 FAIL 时退出码 1**（供监控 / 脚本判据）；
/// 数据不足的项标 `SKIP` 而非 PASS——缺数据不等于没问题（§7.5）。
pub(crate) fn cmd_agent_doctor() {
    use meshlet_network::doctor::CheckStatus;

    // `wg` / `iptables` / `zerotier-cli` 都要特权才能读。agent 本身以 root 跑，
    // CLI 却常由普通用户敲——不提权则 5 项里 3 项只能 SKIP，体检等于没做。
    // `/proc/self` 的属主 uid 即本进程 euid（Linux 语义，无需 libc）；非 root
    // 时走 `sudo -n`，免密不可用则命令失败 → 判定层如实报 not_assessed。
    let backend = diag_backend();
    // sudo 提权仅 Unix 语义：root 直跑、非 root 走 `sudo -n`（免密不可用
    // 则命令失败 → 判定层如实报 not_assessed）。Windows 命令自身按权限
    // 降级，不额外提权——with_sudo 只在 unix 后端存在，必须 cfg 门控，
    // 否则 windows 目标因另一分支类型检查报 E0599（run 45321046165 实证）。
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
