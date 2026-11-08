use meshlet_network::SystemBackend;

/// 候选表渲染（纯函数，可测）：名称/overlay/模式/延时/端点。
pub(crate) fn format_dial_targets(views: &[meshlet_network::dial::DirectPeerView]) -> String {
    let mut output = format!(
        "{:<24} {:<16} {:<14} {:>8}  {}\n",
        "NAME", "OVERLAY_IP", "MODE", "RTT_MS", "ENDPOINT"
    );
    for view in views {
        let rtt = view
            .rtt_ms
            .map(|value| value.to_string())
            .unwrap_or_else(|| "—".into());
        let endpoint = if view.endpoint.is_empty() {
            "—".into()
        } else {
            view.endpoint.clone()
        };
        output.push_str(&format!(
            "{:<24} {:<16} {:<14} {:>8}  {}\n",
            view.name, view.virtual_ipv4, view.mode, rtt, endpoint
        ));
    }
    output
}

/// 打印 wg 段：读数为空时如实区分「无直连对端」与「读数需提权」。
pub(crate) fn print_wg_peers(peers: &[meshlet_network::WgPeerDiagnostic], interface: &str) {
    if peers.is_empty() {
        if wg_readable(interface) {
            println!("(no direct peers)");
        } else {
            println!("(wg reading unavailable — requires root/administrator)");
        }
        return;
    }
    for peer in peers {
        println!(
            "endpoint={} allowed_ips={} last_handshake={} rx={} tx={}",
            if peer.endpoint.is_empty() {
                "—"
            } else {
                &peer.endpoint
            },
            if peer.allowed_ips.is_empty() {
                "—"
            } else {
                &peer.allowed_ips
            },
            if peer.last_handshake > 0 {
                peer.last_handshake.to_string()
            } else {
                "never".into()
            },
            format_bytes(peer.rx_bytes),
            format_bytes(peer.tx_bytes),
        );
    }
}

/// wg 配置读数是否可访问（`wg show <if> dump` 需 root/CAP_NET_ADMIN）。
fn wg_readable(interface: &str) -> bool {
    std::process::Command::new("wg")
        .args(["show", interface, "dump"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// 打印直连对端表（`meshlet peers` 与 `agent diag --peers` 共用）。
pub(crate) fn print_peers_table(backend: &SystemBackend, interface: &str) {
    let network = match backend.diagnostics_sync() {
        Ok(network) => network,
        Err(error) => {
            eprintln!("peers: diagnostics unavailable: {error}");
            return;
        }
    };
    if network.wg.is_empty() {
        if wg_readable(interface) {
            println!("(no direct peers; hub relay covers all)");
        } else {
            println!("(wg reading unavailable — requires root/administrator)");
        }
        return;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    println!(
        "{:<18} {:<14} {:<12} {:<20} {:>6} {:>9} {:>8} {:>8}",
        "PUBLIC_KEY", "OVERLAY_IP", "MODE", "ENDPOINT", "RTT_MS", "HANDSHAKE", "RX", "TX"
    );
    for peer in &network.wg {
        let (mode, overlay, is_direct) = peer_mode(&peer.allowed_ips, peer.last_handshake, now);
        let address = overlay.parse::<std::net::Ipv4Addr>().ok();
        let rtt = match (is_direct, address) {
            (true, Some(ip)) => backend
                .ping_rtt_ms(ip)
                .map(|value| value.to_string())
                .unwrap_or_else(|| "—".into()),
            _ => "—".into(),
        };
        let handshake = if peer.last_handshake > 0 {
            format!("{}s ago", now.saturating_sub(peer.last_handshake))
        } else {
            "never".into()
        };
        println!(
            "{:<18} {:<14} {:<12} {:<20} {:>6} {:>9} {:>8} {:>8}",
            &peer.public_key[..peer.public_key.len().min(18)],
            overlay,
            mode,
            if peer.endpoint.is_empty() {
                "—"
            } else {
                &peer.endpoint
            },
            rtt,
            handshake,
            format_bytes(peer.rx_bytes),
            format_bytes(peer.tx_bytes),
        );
    }
}

/// 直连对端表一行判定（纯函数，可测）：allowed_ips 首个 CIDR 为 /32 =
/// 直连对端（agent 下发 `wg set` 时只写对端 /32），整段（如 /16）= hub
/// 中继对端。直连对端再按握手新鲜度分 p2p_direct / direct_pending。
pub(crate) fn peer_mode(
    allowed_ips: &str,
    last_handshake: u64,
    now: u64,
) -> (String, String, bool) {
    let cidr = allowed_ips
        .split(',')
        .next()
        .unwrap_or("")
        .trim()
        .split_once('/');
    let prefix = cidr.and_then(|(_, prefix)| prefix.parse::<u8>().ok());
    let address = cidr.map(|(address, _)| address.trim().to_string());
    let is_direct = prefix == Some(32);
    let mode = if !is_direct {
        "hub_relay".to_string()
    } else if last_handshake > 0 && now.saturating_sub(last_handshake) < 180 {
        "p2p_direct".to_string()
    } else {
        "direct_pending".to_string()
    };
    let overlay = if is_direct {
        address.unwrap_or_default()
    } else {
        "—".to_string()
    };
    (mode, overlay, is_direct)
}

pub(crate) fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1}K", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1}M", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2}G", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::{format_bytes, peer_mode};

    #[test]
    fn usage_works() {
        let _ = format_bytes(0);
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
