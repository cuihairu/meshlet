//! Pure parsing and reconciliation (split out from lib.rs): parsing wg output, the handshake age
//! table, and item-by-item reconciliation between the plan and the kernel snapshot (no IO, shared by
//! both platforms, testable on a local Linux box).

use crate::{DevicePlan, NetworkSnapshot};

/// Parse the output of `wg show <if> latest-handshakes` (each line is `public key  handshake unix time  seconds ago`):
/// returns public key → seconds ago. The third column wins (the age WireGuard already computed); when
/// it is missing, fall back to `now - handshake time`. Peers with handshake time 0 (never shook
/// hands) are absent from the output — callers treat them as "no reading" (the Unknown vs Unhealthy
/// distinction of §12 `classify_probe`).
///
/// Re-exported from the crate root (the implementation lives in this module, not the [crate::linux]
/// module): this is **pure parsing logic** shared by both platforms, and the Windows execution layer
/// (the `windows` module, `#[cfg(windows)]`) and the Linux execution layer each take what they need —
/// parsing itself is platform-independent and the wire format matches on both sides.
pub(crate) fn parse_handshake_ages(
    text: &str,
    now_secs: u64,
) -> std::collections::BTreeMap<String, u64> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let key = fields.next()?;
            // A public key is 44 characters of base64 ending in `=` (the same criterion as dump-line parsing).
            if key.len() != 44 || !key.ends_with('=') {
                return None;
            }
            let ts: u64 = fields.next()?.parse().ok()?;
            if ts == 0 {
                return None;
            }
            let age = fields
                .next()
                .and_then(|ago| ago.parse::<u64>().ok())
                .unwrap_or_else(|| now_secs.saturating_sub(ts));
            Some((key.to_string(), age))
        })
        .collect()
}

/// Parse the local public-key fingerprint from the interface line of `wg show <if> dump` (field 1;
/// field 0 is the private key and is never handed out). Linux `wg` and Windows `wg.exe` share one
/// dump format, so this parse is shared. The public key is validated as an identity (44 characters of
/// base64, ending in `=`) — partial lines / placeholder text must not fabricate a fingerprint.
pub fn parse_wg_dump_local_public_key(dump: &str) -> Option<String> {
    let header = dump.lines().next()?;
    let public_key = header.split_whitespace().nth(1)?;
    if public_key.len() != 44 || !public_key.ends_with('=') {
        return None;
    }
    Some(public_key.to_string())
}

/// Parse the actual listening port from the interface line of `wg show <if> dump` (field 2). Linux
/// `wg` and Windows `wg.exe` share one dump format, so this parse is shared; if it cannot be parsed
/// (empty / partial line) → `None` (the caller treats it as missing evidence and does not call it drift).
pub fn parse_wg_dump_listen_port(dump: &str) -> Option<u16> {
    dump.lines().next()?.split_whitespace().nth(2)?.parse().ok()
}

/// Item-by-item reconciliation between the plan and the kernel snapshot (a pure function, no IO,
/// testable on a local Linux box).
///
/// Used by the Windows backend's `device_plan_matches_sync` (Linux has an inline stronger
/// implementation); it separates "the tunnel is up but the configuration has drifted" from "wrongly
/// judged matching":
/// ① every planned peer public key must exist in the snapshot peers (the subset direction);
/// ①a. each planned peer's `allowed_ips` must match exactly the allowed-ips read back from the
///    snapshot (order-insensitive; aligned with the identity-level verdict of the Linux counterpart);
/// ② every peer in the snapshot must be a planned peer or in `extra_peer_keys` (no unmanaged drift;
///    `extra_peer_keys` holds extra peers that a direct link retains and so are allowed);
/// ③ each planned route `destination` must be in `installed_routes` (exact CIDR match);
/// ④ if the plan specifies an MTU explicitly, it must match the snapshot `tunnel_mtu`;
/// ⑤ the tunnel not existing (`tunnel_exists=false`) → not matching;
/// ⑥ the adapter's actual address reading exists and differs from the planned address → not matching
///    (a tunnel whose address was moved by hand).
///
/// The caller is the `#[cfg(windows)]` `WindowsNetworkBackend`, so on non-Windows targets this
/// function stays compilable (including its unit tests) but has no callers — following the repo
/// convention it is exempted from dead_code via cfg_attr so a Linux box can run these reconciliation
/// tests.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn device_plan_matches(
    plan: &DevicePlan,
    extra_peer_keys: &std::collections::BTreeSet<String>,
    snapshot: &NetworkSnapshot,
) -> bool {
    if !snapshot.tunnel_exists {
        return false;
    }
    for peer in &plan.tunnel.peers {
        if !snapshot.peers.iter().any(|p| {
            p.public_key == peer.public_key
                // Set semantics: the CIDR order read back by `wg dump` is unstable, compare as sets.
                && p.allowed_ips.len() == peer.allowed_ips.len()
                && peer
                    .allowed_ips
                    .iter()
                    .all(|cidr| p.allowed_ips.contains(cidr))
        }) {
            return false;
        }
    }
    for p in &snapshot.peers {
        if plan
            .tunnel
            .peers
            .iter()
            .any(|pp| pp.public_key == p.public_key)
        {
            continue;
        }
        if extra_peer_keys.contains(&p.public_key) {
            continue;
        }
        return false;
    }
    // Route comparison only holds for backends whose routes are installed independently of peers
    // (the service model). Backends that assemble routes from peer allowed-ips (the nt model's
    // adapter set_default_route) do not take this path — routes are already fully determined by the
    // peer identity-level comparison above (the same drifted convention).
    if !snapshot.routes_from_peers {
        for route in &plan.routes {
            if !snapshot.installed_routes.contains(&route.destination) {
                return false;
            }
        }
    }
    if let Some(mtu) = plan.tunnel.mtu {
        if snapshot.tunnel_mtu != Some(mtu) {
            return false;
        }
    }
    // ⑥ The adapter's actual address: a reading that exists but disagrees with the plan -> the address
    //    was moved by hand, and it must read as not matching. A missing reading (None) is not judged
    //    — missing evidence neither pretends to match nor enters a replay loop.
    if let Some(actual) = snapshot.tunnel_address {
        if actual != plan.tunnel.address {
            return false;
        }
    }
    // ⑦ The actual listening port: the direct-connect-pinned port disagrees with the kernel reading
    //    (a manual `wg set listen-port` / a half-applied state) -> judge not matching and let a
    //    replay correct it. A missing reading is not judged.
    if let Some(port) = plan.tunnel.listen_port {
        if let Some(actual) = snapshot.tunnel_listen_port {
            if actual != port {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod device_plan_matches_tests {
    use super::*;
    use crate::{PeerConfig, PeerObserved, RouteConfig, TunnelConfig};
    use std::collections::BTreeSet;

    fn peer(key: &str) -> PeerConfig {
        PeerConfig {
            public_key: key.into(),
            allowed_ips: vec!["10.240.0.5/32".parse().unwrap()],
            endpoint: None,
            persistent_keepalive_secs: None,
        }
    }

    fn plan(peers: &[&str], routes: &[&str], mtu: Option<u32>) -> DevicePlan {
        DevicePlan {
            desired_revision: 1,
            hub_port: None,
            tunnel: TunnelConfig {
                name: "Meshlet".into(),
                address: "10.240.0.1".parse().unwrap(),
                address_prefix: 16,
                listen_port: None,
                peers: peers.iter().map(|p| peer(p)).collect(),
                mtu,
                private_key: None,
            },
            routes: routes
                .iter()
                .map(|r| RouteConfig {
                    destination: r.parse().unwrap(),
                    interface: "Meshlet".into(),
                    gateway: None,
                })
                .collect(),
            nat_rules: Vec::new(),
            hub_address: None,
            publish: None,
            ssh_config: None,
            desired_config_hash: "h".into(),
        }
    }

    fn snapshot(
        tunnel_exists: bool,
        peers: &[&str],
        routes: &[&str],
        mtu: Option<u32>,
    ) -> NetworkSnapshot {
        NetworkSnapshot {
            tunnel_exists,
            forwarding_enabled: None,
            peers: peers
                .iter()
                .map(|k| PeerObserved {
                    public_key: (*k).into(),
                    allowed_ips: vec!["10.240.0.5/32".parse().unwrap()],
                })
                .collect(),
            installed_routes: routes.iter().map(|r| r.parse().unwrap()).collect(),
            nat_rules: Vec::new(),
            tunnel_mtu: mtu,
            local_public_key: None,
            tunnel_address: None,
            tunnel_listen_port: None,
            routes_from_peers: false,
        }
    }

    fn empty_extra() -> BTreeSet<String> {
        BTreeSet::new()
    }

    #[test]
    fn adapter_address_mismatch_reads_as_not_matching() {
        // The tunnel address was moved by hand (peer/routes/MTU all match) -> must read as not matching;
        // a missing reading (None) is not judged.
        let p = plan(&["pk-a"], &["10.240.0.0/24"], None);
        let mut moved = snapshot(true, &["pk-a"], &["10.240.0.0/24"], None);
        moved.tunnel_address = Some("10.240.0.99".parse().unwrap());
        assert!(!device_plan_matches(&p, &empty_extra(), &moved));
        let mut matching = snapshot(true, &["pk-a"], &["10.240.0.0/24"], None);
        matching.tunnel_address = Some(p.tunnel.address);
        assert!(device_plan_matches(&p, &empty_extra(), &matching));
    }

    #[test]
    fn all_match_true() {
        let p = plan(&["pk-a", "pk-b"], &["10.240.0.0/24"], Some(1420));
        let s = snapshot(true, &["pk-a", "pk-b"], &["10.240.0.0/24"], Some(1420));
        assert!(device_plan_matches(&p, &empty_extra(), &s));
    }

    #[test]
    fn pinned_listen_port_mismatch_reads_as_not_matching() {
        // The direct-connect-pinned port disagrees with the kernel reading (a manual wg set listen-port /
        // a half-applied state) -> must read as not matching and be corrected by a replay; a
        // missing reading (None) is not judged.
        let mut p = plan(&["pk-a"], &["10.240.0.0/24"], None);
        p.tunnel.listen_port = Some(51820);
        let mut drifted = snapshot(true, &["pk-a"], &["10.240.0.0/24"], None);
        drifted.tunnel_listen_port = Some(60736);
        assert!(!device_plan_matches(&p, &empty_extra(), &drifted));
        let mut matching = snapshot(true, &["pk-a"], &["10.240.0.0/24"], None);
        matching.tunnel_listen_port = Some(51820);
        assert!(device_plan_matches(&p, &empty_extra(), &matching));
        // Missing evidence is not judged (so we do not enter a replay loop).
        let mut unreadable = snapshot(true, &["pk-a"], &["10.240.0.0/24"], None);
        unreadable.tunnel_listen_port = None;
        assert!(device_plan_matches(&p, &empty_extra(), &unreadable));
    }

    #[test]
    fn wg_dump_listen_port_parses_interface_line() {
        // Interface-line shape: private key, local public key, listen port, ...
        let dump = format!("{} {} 51820\n", "x".repeat(32), "A".repeat(43) + "=");
        assert_eq!(crate::parse_wg_dump_listen_port(&dump), Some(51820));
        let no_port = format!("{} {}\n", "x".repeat(32), "A".repeat(43) + "=");
        assert_eq!(crate::parse_wg_dump_listen_port(&no_port), None);
        assert_eq!(crate::parse_wg_dump_listen_port(""), None);
        let junk = format!("{} {} not-a-port\n", "x".repeat(32), "A".repeat(43) + "=");
        assert_eq!(crate::parse_wg_dump_listen_port(&junk), None);
    }

    #[test]
    fn missing_plan_peer_false() {
        // The plan has pk-c but the snapshot does not -> drift.
        let p = plan(&["pk-a", "pk-c"], &[], None);
        let s = snapshot(true, &["pk-a"], &[], None);
        assert!(!device_plan_matches(&p, &empty_extra(), &s));
    }

    #[test]
    fn drifted_peer_false_but_extra_allowed_true() {
        // The snapshot carries an extra pk-x: neither planned nor in extra -> unmanaged drift.
        let p = plan(&["pk-a"], &[], None);
        let s = snapshot(true, &["pk-a", "pk-x"], &[], None);
        assert!(!device_plan_matches(&p, &empty_extra(), &s));
        // extra_peer_keys admits pk-x -> matching.
        let mut extra = empty_extra();
        extra.insert("pk-x".into());
        assert!(device_plan_matches(&p, &extra, &s));
    }

    #[test]
    fn drifted_peer_allowed_ips_false() {
        // The planned peer exists but the kernel allowed-ips has drifted (e.g. rewritten by an outside
        // `wg set`) -> must judge not matching so a replay corrects it.
        let p = plan(&["pk-a"], &[], None);
        let mut s = snapshot(true, &["pk-a"], &[], None);
        s.peers[0].allowed_ips = vec!["10.240.0.6/32".parse().unwrap()];
        assert!(!device_plan_matches(&p, &empty_extra(), &s));
    }

    #[test]
    fn missing_route_false() {
        // The planned route 10.240.0.0/24 is not installed -> drift.
        let p = plan(&[], &["10.240.0.0/24"], None);
        let s = snapshot(true, &[], &["192.168.1.0/24"], None);
        assert!(!device_plan_matches(&p, &empty_extra(), &s));
    }

    #[test]
    fn peer_implied_routes_skip_plan_route_check() {
        // In the nt model (wireguard-nt adapter set_default_route) routes are assembled entirely from peer
        // allowed-ips; plan.routes is never pushed through an independent path (netsh route apply is
        // explicitly rejected). device_plan_matches' "missing route" verdict on plan.routes is
        // therefore always false for nt — skip it when routes_from_peers (the same drifted convention).
        let p = plan(&[], &["10.240.0.0/24"], None);
        let mut s = snapshot(true, &[], &[], None);
        s.routes_from_peers = true;
        assert!(device_plan_matches(&p, &empty_extra(), &s));

        // Contrast: the same snapshot under the service-model convention (routes independent of peers,
        // "missing route" judged against plan.routes) -> the planned route is not installed -> must
        // read as not matching.
        s.routes_from_peers = false;
        assert!(!device_plan_matches(&p, &empty_extra(), &s));
    }

    #[test]
    fn mtu_drift_false() {
        // The plan states 1420 explicitly while the kernel reads 1300 -> drift.
        let p = plan(&[], &[], Some(1420));
        let s = snapshot(true, &[], &[], Some(1300));
        assert!(!device_plan_matches(&p, &empty_extra(), &s));
    }

    #[test]
    fn tunnel_not_exists_false() {
        let p = plan(&["pk-a"], &["10.240.0.0/24"], Some(1420));
        let s = snapshot(false, &[], &[], None);
        assert!(!device_plan_matches(&p, &empty_extra(), &s));
    }

    #[test]
    fn no_planned_mtu_skips_mtu_check() {
        // The plan specifies no MTU -> skip the comparison, judging only the rest.
        let p = plan(&["pk-a"], &["10.240.0.0/24"], None);
        let s = snapshot(true, &["pk-a"], &["10.240.0.0/24"], Some(1300));
        assert!(device_plan_matches(&p, &empty_extra(), &s));
    }
    /// Local public-key fingerprint parsing (the reading side fixed by BUG②): field 1 of the interface
    /// line; the private key (field 0) is never returned; partial line / placeholder text / empty
    /// table -> None.
    #[test]
    fn wg_dump_local_public_key_reads_field_one_and_validates_shape() {
        let key = format!("{}=", "K".repeat(43));
        let dump = format!("some-private-key\t{key}\t51820\t0\n");
        assert_eq!(parse_wg_dump_local_public_key(&dump), Some(key.clone()));
        // The interface line comes first and the peer lines after: only the first line is read.
        let with_peer =
            format!("{dump}PEER-KEY-PLACEHOLDER\t\tendpoint\t10.240.0.2/32\t0\t0\t0\t0\n");
        assert_eq!(parse_wg_dump_local_public_key(&with_peer), Some(key));
        // Empty table / partial line / invalid shape.
        assert_eq!(parse_wg_dump_local_public_key(""), None);
        assert_eq!(parse_wg_dump_local_public_key("only-private-key\n"), None);
        assert_eq!(
            parse_wg_dump_local_public_key("priv\tPLACEHOLDER\t51820\t0\n"),
            None
        );
    }
}
