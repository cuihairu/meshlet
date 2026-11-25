use crate::{InterfaceDiagnostic, NetworkError, WgPeerDiagnostic};
use std::net::Ipv4Addr;

/// Parse `reg query IPEnableRouter` output into a boolean (`0x1` → true,
/// `0x0` → false, value missing / anything else → None). Pure string verdict:
/// the Windows language pack does not affect the `0x` prefix.
pub(super) fn parse_ip_enable_router(text: &str) -> Option<bool> {
    if text.contains("0x1") {
        Some(true)
    } else if text.contains("0x0") {
        Some(false)
    } else {
        None
    }
}

/// Parse the interface's first IPv4 address out of
/// `netsh interface ipv4 show addresses name=<if>` output (the adapter address
/// reading for the BUG② drift verdict; pure function, cross-platform unit
/// tests).
///
/// Lines look like en `   IP Address:                           10.240.0.7` or
/// the zh-CN "IP address" label followed by the same value — the label is
/// matched broadly (`IP Address` plus the Chinese label) and the last token in
/// the line that parses as IPv4 is taken. The subnet prefix line's
/// `(masked …)` holds no standalone IPv4 token and does not match the address
/// label, so it cannot false-hit. Nothing readable → None.
pub(super) fn parse_netsh_interface_ipv4_address(text: &str) -> Option<std::net::Ipv4Addr> {
    for line in text.lines() {
        let is_address_label =
            line.to_ascii_lowercase().contains("ip address") || line.contains("IP 地址");
        if !is_address_label {
            continue;
        }
        if let Some(addr) = line
            .split_whitespace()
            .filter_map(|token| {
                token
                    .trim_end_matches(':')
                    .parse::<std::net::Ipv4Addr>()
                    .ok()
            })
            .next_back()
        {
            return Some(addr);
        }
    }
    None
}

pub(super) fn mask_to_prefix(mask: &str) -> u8 {
    let octets: Vec<u8> = mask.split('.').filter_map(|s| s.parse().ok()).collect();
    if octets.len() != 4 {
        return 0;
    }
    octets.iter().map(|b| b.count_ones() as u8).sum()
}

/// Parse the first RTT (milliseconds) from Windows `ping` output, supporting
/// both the English `time=1ms` and the Chinese `time=<ms>` (localized label)
/// forms; returns `None` when there is no reading.
pub(super) fn parse_ping_rtt_ms_windows(text: &str) -> Option<u128> {
    let marker = if text.contains("time") {
        "time"
    } else if text.contains("时间") {
        "时间"
    } else {
        return None;
    };
    let start = text.find(marker)?;
    let rest = &text[start + marker.len()..];
    let start = rest.find(|c: char| c.is_ascii_digit())?;
    let rest = &rest[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(rest.len());
    rest[..end].parse::<f64>().ok().map(|v| v.round() as u128)
}

/// Parse a peer line of `wg.exe show <name> dump` into diagnostic readings
/// (pure function, unit-tested on any platform). The official format is
/// tab-separated: the first line is the interface, then one line per peer as
/// `pubkey preshared endpoint allowed-ips latest-handshake transfer-rx
/// transfer-tx keepalive`. Missing columns are padded with 0/empty.
pub(super) fn parse_wg_dump_diag_line_windows(line: &str) -> Option<WgPeerDiagnostic> {
    let fields: Vec<&str> = line.split('\t').collect();
    let public_key = fields.first()?.trim();
    if public_key.is_empty() {
        return None;
    }
    let endpoint = fields.get(2).unwrap_or(&"").trim().to_string();
    let allowed_ips = fields.get(3).unwrap_or(&"").trim().to_string();
    let last_handshake: u64 = fields
        .get(4)
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let rx_bytes: u64 = fields
        .get(6)
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let tx_bytes: u64 = fields
        .get(7)
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    Some(WgPeerDiagnostic {
        public_key: public_key.to_string(),
        endpoint,
        allowed_ips,
        last_handshake,
        rx_bytes,
        tx_bytes,
    })
}

/// Parse the interface list out of `Get-NetIPConfiguration | ConvertTo-Json`
/// (pure function, unit-tested on any platform). The output is either an object
/// array or a single object; missing fields default to empty/None.
pub(super) fn parse_windows_interfaces_json(text: &str) -> Vec<InterfaceDiagnostic> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let value: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let items: Vec<&serde_json::Value> = match &value {
        serde_json::Value::Array(arr) => arr.iter().collect(),
        serde_json::Value::Object(_) => vec![&value],
        _ => return Vec::new(),
    };
    items
        .into_iter()
        .filter_map(|item| {
            let name = item.get("Name").and_then(|v| v.as_str()).unwrap_or("");
            if name.is_empty() {
                return None;
            }
            let ipv4 = item
                .get("IP")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let prefix = item.get("Prefix").and_then(|v| {
                v.as_str()
                    .and_then(|s| s.parse().ok())
                    .or_else(|| v.as_u64().and_then(|n| u8::try_from(n).ok()))
            });
            let state = item
                .get("State")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let mtu = item
                .get("Mtu")
                .and_then(|v| v.as_u64().and_then(|n| u32::try_from(n).ok()));
            Some(InterfaceDiagnostic {
                name: name.to_string(),
                ipv4,
                prefix,
                state,
                mtu,
            })
        })
        .collect()
}

/// Windows LAN interface verdict (§12 P2P candidate criterion, mirroring Linux
/// `is_lan_interface`): excludes this managed wg interface, loopback, Hyper-V
/// vEthernet, Tailscale, other wg interfaces, and wireguard-nt tunnels (the nt
/// model's OS alias is exactly `WireGuard`, and the tunnel name appears only in
/// InterfaceDescription — not excluding it would treat the tunnel as a LAN
/// candidate, lan over-capture);
/// **foreign overlays are excluded too** (`zerotier*` = `ZeroTier One [nwid]`
/// aliases, the counterpart of Linux's `zt*`): treating their subnet as the
/// local LAN would classify the peer's ZeroTier address as same-subnet direct,
/// and pointing the WG endpoint into another tunnel makes the two sides wrap
/// each other into a loop (2026-11-23 real-machine incident). Alias comparison
/// is case-insensitive (Windows interface aliases such as `Tailscale`,
/// `vEthernet (WSL …)`).
pub(super) fn is_windows_lan_interface(alias: &str, wg_interface: &str) -> bool {
    let lower = alias.to_ascii_lowercase();
    if alias == wg_interface || lower.starts_with("loopback") {
        return false;
    }
    for prefix in [
        "vethernet",
        "tailscale",
        "wg",
        "wireguard",
        "docker",
        "veth",
        "zerotier",
    ] {
        if lower.starts_with(prefix) {
            return false;
        }
    }
    true
}

/// Parse `Get-NetIPAddress … | ConvertTo-Json -Compress` into a list of
/// `(alias, address, prefix)`. PowerShell emits an object for a **single
/// result** and an array for multiple — both are normalized over `Value`
/// (same convention as [parse_windows_interfaces_json]). Malformed entries
/// (missing fields / parse failures) are skipped one by one instead of
/// discarding the whole batch of readings.
pub(super) fn parse_lan_ip_json(text: &str) -> Result<Vec<(String, Ipv4Addr, u8)>, NetworkError> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let value: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|error| NetworkError::ApplyRejected(format!("Get-NetIPAddress json: {error}")))?;
    let items: Vec<&serde_json::Value> = match &value {
        serde_json::Value::Array(arr) => arr.iter().collect(),
        serde_json::Value::Object(_) => vec![&value],
        _ => return Ok(Vec::new()),
    };
    Ok(items
        .into_iter()
        .filter_map(|item| {
            let alias = item.get("InterfaceAlias").and_then(|v| v.as_str())?;
            let addr: Ipv4Addr = item
                .get("IPAddress")
                .and_then(|v| v.as_str())?
                .parse()
                .ok()?;
            let prefix = item
                .get("PrefixLength")
                .and_then(|v| v.as_u64())
                .and_then(|n| u8::try_from(n).ok())?;
            Some((alias.to_string(), addr, prefix))
        })
        .collect())
}
