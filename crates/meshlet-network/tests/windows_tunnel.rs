//! Integration tests for the runnable surface of the Windows tunnel planning layer + execution layer
//! ([ADR-008]).
//!
//! The same file-level `#![cfg]` discipline as [windows_netsh](windows_netsh) and
//! [windows_cleanup_e2e](windows_cleanup_e2e): compiled and executed on Windows only; the CI
//! windows-latest job's `cargo test --workspace` really runs this file, and the Linux job is
//! unaffected.
//!
//! **No real tunnel installation is triggered** (the CI hosted runner has no WireGuardNT driver, and
//! there is no intention to create kernel tunnels here): this file covers only the execution surface
//! that needs neither a driver nor elevation -- writing the conf and reading it back (byte-identical,
//! an overwrite rewrite = an idempotent re-apply) and pinning the exec entry-point signature.
//!
//! **Still uncovered (an honestly kept gap; R-05 stays unchecked)**: the tunnel's full lifecycle after
//! the WireGuardNT driver is installed (install -> start -> stop -> uninstall), the elevated execution
//! layer's real-machine messages, the boot-recovery reboot verification, and the
//! [crate::SystemBackend] wiring decision made on that basis; see ADR-008's review conditions. The
//! wireguard.exe command shape is pinned by the planning layer's unit tests (the Windows canonical
//! argv); the real binary's pass-through semantics await the above real-machine acceptance.

#![cfg(target_os = "windows")]

use meshlet_domain::Ipv4Cidr;
use meshlet_network::windows_tunnel::{
    conf_file_name,
    exec::{run_wireguard_command, write_tunnel_conf},
    render_wireguard_conf, WireGuardCommand,
};
use meshlet_network::{ApplyResult, NetworkError, PeerConfig, TunnelConfig};
use std::path::{Path, PathBuf};

/// The probe tunnel name: a dedicated prefix, never touching machine-global service/tunnel objects.
const PROBE_TUNNEL: &str = "__meshlet_probe_tunnel";

fn probe_tunnel_config() -> TunnelConfig {
    TunnelConfig {
        name: PROBE_TUNNEL.into(),
        address: "10.240.0.7".parse().unwrap(),
        address_prefix: 32,
        listen_port: Some(51820),
        peers: vec![PeerConfig {
            public_key: "PROBE-PUBLIC-KEY-BASE64==".into(),
            allowed_ips: vec!["10.240.0.1/32".parse::<Ipv4Cidr>().unwrap()],
            endpoint: Some("198.51.100.10:51820".into()),
            persistent_keepalive_secs: Some(25),
        }],
        mtu: None,
        private_key: Some("PROBE-PRIVATE-KEY-BASE64==".into()),
    }
}

fn probe_conf_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "meshlet-tunnel-int-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// Pinning the exec entry-point signature: it takes only a planned command and an executable
/// override and returns the planning layer's result; the test starts no wireguard.exe and touches
/// no real tunnel.
#[test]
fn exec_entrypoint_takes_planned_command_and_returns_planned_result() {
    fn assert_signature(
        _run: fn(&WireGuardCommand, Option<&Path>) -> Result<ApplyResult, NetworkError>,
    ) {
    }
    assert_signature(run_wireguard_command);
}

/// Writing the conf and reading it back: byte-identical (the private key's base64 is not mangled by
/// re-encoding), and an overwrite rewrite = an idempotent re-apply.
#[test]
fn conf_write_round_trips_and_overwrite_is_idempotent() {
    let path = probe_conf_path();
    let conf = render_wireguard_conf(&probe_tunnel_config());
    write_tunnel_conf(&path, &conf).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), conf);

    let mut rotated = probe_tunnel_config();
    rotated.private_key = Some("ROTATED-PROBE-KEY-BASE64==".into());
    let rotated_conf = render_wireguard_conf(&rotated);
    write_tunnel_conf(&path, &rotated_conf).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), rotated_conf);
    assert!(rotated_conf.contains("ROTATED-PROBE-KEY-BASE64=="));

    let _ = std::fs::remove_file(&path);
}

/// The planning layer's rendering closing the loop through the exec write path: the file is exactly
/// the rendered text; the tunnel name is derived from the .conf file name (asserted via
/// conf_file_name), no Name key remains inside the conf (removed by ADR-008), and the key lines
/// are preserved verbatim.
#[test]
fn plan_renders_through_write_path_unchanged() {
    let path = probe_conf_path();
    let config = probe_tunnel_config();
    let conf = render_wireguard_conf(&config);
    write_tunnel_conf(&path, &conf).unwrap();
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(!on_disk.contains("Name = "));
    assert!(on_disk.contains("PrivateKey = PROBE-PRIVATE-KEY-BASE64==\n"));
    assert!(on_disk.contains("AllowedIPs = 10.240.0.1/32\n"));
    assert_eq!(on_disk, conf);
    assert_eq!(conf_file_name(PROBE_TUNNEL), "__meshlet_probe_tunnel.conf");

    let _ = std::fs::remove_file(&path);
}
