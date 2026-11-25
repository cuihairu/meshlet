use super::backend::WindowsNetworkBackend;
use super::parsing::{
    is_windows_lan_interface, mask_to_prefix, parse_ip_enable_router, parse_lan_ip_json,
    parse_netsh_interface_ipv4_address, parse_ping_rtt_ms_windows, parse_wg_dump_diag_line_windows,
    parse_windows_interfaces_json,
};
use std::net::Ipv4Addr;

#[test]
fn lan_ip_json_parses_single_object_and_array() {
    // Multiple results: PowerShell emits an array.
    let arr = r#"[{"IPAddress":"192.168.88.51","InterfaceAlias":"WLAN 7","PrefixLength":24},{"IPAddress":"10.147.19.97","InterfaceAlias":"ZeroTier One [db64858fedb29f06]","PrefixLength":24},{"IPAddress":"169.254.209.18","InterfaceAlias":"WLAN 9","PrefixLength":16}]"#;
    let entries = parse_lan_ip_json(arr).expect("array");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].1, "192.168.88.51".parse::<Ipv4Addr>().unwrap());
    assert_eq!(entries[0].2, 24);
    // Single result: PowerShell emits a bare object.
    let obj = r#"{"IPAddress":"10.0.0.5","InterfaceAlias":"以太网","PrefixLength":24}"#;
    let one = parse_lan_ip_json(obj).expect("object");
    assert_eq!(one.len(), 1);
    // Empty and malformed.
    assert!(parse_lan_ip_json("").unwrap().is_empty());
    assert!(parse_lan_ip_json("not json").is_err());
}

#[test]
fn windows_lan_interface_filter_keeps_lan_drops_virtual_and_foreign_overlay() {
    // Managed interface / loopback / Hyper-V / Tailscale / other wg → excluded.
    assert!(!is_windows_lan_interface("wg-meshlet", "wg-meshlet"));
    assert!(!is_windows_lan_interface(
        "Loopback Pseudo-Interface 1",
        "wg-meshlet"
    ));
    assert!(!is_windows_lan_interface(
        "vEthernet (WSL (Hyper-V firewall))",
        "wg-meshlet"
    ));
    assert!(!is_windows_lan_interface("Tailscale", "wg-meshlet"));
    assert!(!is_windows_lan_interface("wg-newapi", "wg-meshlet"));
    // The wireguard-nt tunnel's OS alias is exactly `WireGuard` (the tunnel name
    // appears only in InterfaceDescription) → it must be excluded, otherwise it
    // gets treated as a LAN candidate (lan over-capture).
    assert!(!is_windows_lan_interface("WireGuard", "wg-meshlet"));
    assert!(!is_windows_lan_interface("wireguard", "wg-meshlet"));
    // Foreign overlays (ZeroTier) are excluded too: keeping them would classify
    // the peer's ZT address as same-subnet direct, and pointing the WG endpoint
    // into another tunnel → the two sides wrap each other into a loop
    // (2026-11-23 real-machine incident). Case-insensitive (alias
    // `ZeroTier One [nwid]`).
    assert!(!is_windows_lan_interface(
        "ZeroTier One [db64858fedb29f06]",
        "wg-meshlet"
    ));
    assert!(!is_windows_lan_interface("zerotier", "wg-meshlet"));
    // Physical LAN → kept (candidate criterion matches Linux).
    assert!(is_windows_lan_interface("WLAN 7", "wg-meshlet"));
    assert!(is_windows_lan_interface("以太网 2", "wg-meshlet"));
}

#[test]
fn parse_ping_rtt_windows_supports_english_and_chinese() {
    assert_eq!(
        parse_ping_rtt_ms_windows("Reply from 10.0.0.2: bytes=32 time=12ms TTL=64"),
        Some(12)
    );
    assert_eq!(
        parse_ping_rtt_ms_windows("来自 10.0.0.2 的回复: 字节=32 时间=1ms TTL=64"),
        Some(1)
    );
    assert_eq!(parse_ping_rtt_ms_windows("Request timed out."), None);
}

#[test]
fn wg_dump_diag_line_windows_reads_all_columns() {
    let line = "PUB-KEY\t(preshared)\t198.51.100.10:51820\t10.240.0.1/32\t1234567\t1024\t2048\t25";
    let diag = parse_wg_dump_diag_line_windows(line).expect("valid");
    assert_eq!(diag.public_key, "PUB-KEY");
    assert_eq!(diag.endpoint, "198.51.100.10:51820");
    assert_eq!(diag.allowed_ips, "10.240.0.1/32");
    assert_eq!(diag.last_handshake, 1234567);
    assert_eq!(diag.rx_bytes, 2048);
    assert_eq!(diag.tx_bytes, 25);
    // Empty line / empty public key → None.
    assert!(parse_wg_dump_diag_line_windows("").is_none());
    assert!(parse_wg_dump_diag_line_windows("\t\t\t").is_none());
}

/// netsh interface address parsing (BUG② reading side): both en/zh labels hit
/// and the IPv4 token in the line is taken; no label line / no address → None.
#[test]
fn netsh_interface_address_parses_en_and_zh_labels() {
    let en = "Configuration for interface \"meshlet\"\r\n\
              DHCP enabled:                         No\r\n\
              IP Address:                           10.240.0.7\r\n\
              Subnet Prefix:                        10.240.0.7/32 (masked 255.255.255.255)\r\n";
    assert_eq!(
        parse_netsh_interface_ipv4_address(en),
        Some("10.240.0.7".parse().unwrap())
    );
    let zh = "接口 \"meshlet\" 的 IP 配置\r\n\
              DHCP 已启用:                          否\r\n\
              IP 地址:                           10.240.0.9\r\n\
              子网前缀:                          10.240.0.9/32 (掩码 255.255.255.255)\r\n";
    assert_eq!(
        parse_netsh_interface_ipv4_address(zh),
        Some("10.240.0.9".parse().unwrap())
    );
    // Lines without an address label / entirely unrelated text → None.
    assert_eq!(
        parse_netsh_interface_ipv4_address("   子网前缀: 10.240.0.7/32\r\n"),
        None
    );
    assert_eq!(parse_netsh_interface_ipv4_address(""), None);
    assert_eq!(parse_netsh_interface_ipv4_address("not a netsh dump"), None);
}

#[test]
fn windows_interfaces_json_parses_object_and_array() {
    let single = r#"{"Name":"meshlet","IP":"10.240.0.2","Prefix":16,"State":"Up","Mtu":1420}"#;
    let v = parse_windows_interfaces_json(single);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].name, "meshlet");
    assert_eq!(v[0].ipv4, "10.240.0.2");
    assert_eq!(v[0].prefix, Some(16));
    assert_eq!(v[0].state, "Up");
    assert_eq!(v[0].mtu, Some(1420));

    let arr = r#"[{"Name":"eth0","IP":"192.168.1.5","Prefix":24,"State":"Up","Mtu":1500},
                   {"Name":"meshlet","IP":"10.240.0.2","Prefix":16,"State":"Up","Mtu":1420}]"#;
    let v = parse_windows_interfaces_json(arr);
    assert_eq!(v.len(), 2);
    assert_eq!(v[1].name, "meshlet");
    assert_eq!(v[1].ipv4, "10.240.0.2");
    assert_eq!(v[1].prefix, Some(16));
    assert_eq!(v[1].state, "Up");
    assert_eq!(v[1].mtu, Some(1420));

    // Empty / invalid JSON → empty (no interfaces are invented).
    assert!(parse_windows_interfaces_json("").is_empty());
    assert!(parse_windows_interfaces_json("not-json").is_empty());
}

#[test]
fn mask_to_prefix_conversion() {
    assert_eq!(mask_to_prefix("255.255.255.0"), 24);
    assert_eq!(mask_to_prefix("255.255.0.0"), 16);
    assert_eq!(mask_to_prefix("255.0.0.0"), 8);
    assert_eq!(mask_to_prefix("255.255.255.255"), 32);
    assert_eq!(mask_to_prefix("0.0.0.0"), 0);
}

#[test]
fn backend_default_interface_is_meshlet() {
    let backend = WindowsNetworkBackend::new();
    assert_eq!(backend.interface, "meshlet");
}

#[test]
fn with_interface_overrides_default() {
    let backend = WindowsNetworkBackend::new().with_interface("wg0");
    assert_eq!(backend.interface, "wg0");
}

/// IPEnableRouter registry output → forwarding flag (the precondition for
/// drifted() convergence).
#[test]
fn ip_enable_router_registry_text_maps_to_forwarding_flag() {
    assert_eq!(
        parse_ip_enable_router(
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
IPEnableRouter    REG_DWORD    0x1"
        ),
        Some(true)
    );
    assert_eq!(
        parse_ip_enable_router(r"    IPEnableRouter    REG_DWORD    0x0"),
        Some(false)
    );
    // Value missing (reg query failure text) → None: the drift verdict treats
    // it as not enabled.
    assert_eq!(
        parse_ip_enable_router(
            "ERROR: The system was unable to find the specified registry key or value."
        ),
        None
    );
    assert_eq!(parse_ip_enable_router(""), None);
}
