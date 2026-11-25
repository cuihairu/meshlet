//! DirectManager cases: the link_statuses report contract, ledger save/load round trips and
//! self-healing, and the record_*/clear_endpoint enrichment boundary (R-DIAG-2).

use super::*;

#[test]
fn link_statuses_report_active_direct_links_only() {
    let mut manager = DirectManager::new();
    // No peers under management -> an empty report (the UI renders it as relay by default).
    assert!(manager.link_statuses().is_empty());

    // Pending (cycle 1): state direct_pending, with no handshake reading.
    let wanted = vec![peer("peer-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    manager.apply_plan(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert_eq!(
        manager.link_statuses(),
        vec![DirectLinkStatus {
            public_key: "peer-b".into(),
            virtual_ipv4: "10.240.0.3".parse().unwrap(),
            link_state: "direct_pending".into(),
            last_handshake_age_secs: None,
            peer_name: "peer-b-name".into(),
            connection_mode: "direct_pending".into(),
            endpoint: String::new(),
            rtt_ms: None,
            rtt_source: None,
            last_handshake_at: None,
            rx_bytes: 0,
            tx_bytes: 0,
            candidates: vec![],
        }]
    );

    // A healthy handshake -> Direct, carrying the handshake-age snapshot taken at probe time.
    let mut ages = BTreeMap::new();
    ages.insert("peer-b".into(), 7u64);
    manager.apply_plan(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &ages,
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert_eq!(
        manager.link_statuses(),
        vec![DirectLinkStatus {
            public_key: "peer-b".into(),
            virtual_ipv4: "10.240.0.3".parse().unwrap(),
            link_state: "direct".into(),
            last_handshake_age_secs: Some(7),
            peer_name: "peer-b-name".into(),
            connection_mode: "p2p_direct".into(),
            endpoint: String::new(),
            rtt_ms: None,
            rtt_source: None,
            last_handshake_at: None,
            rx_bytes: 0,
            tx_bytes: 0,
            candidates: vec![],
        }]
    );

    // Fallback (candidate revoked) -> the peer is no longer reported.
    manager.apply_plan(
        &[],
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(manager.link_statuses().is_empty());
}

#[test]
fn ledger_round_trips_the_keep_set_and_restores_as_direct() {
    let root = std::env::temp_dir().join(format!("meshlet-direct-ledger-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("direct.json");

    let mut manager = DirectManager::new();
    let _updates = manager.apply_plan(
        &[peer("peer-a", "10.240.0.3", &[lan("192.168.1.50", 51821)])],
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    manager.save(&path).expect("ledger write");

    // Restored from the ledger: the keep set is intact and the peer is held as "established".
    let restored = DirectManager::load(&path);
    assert_eq!(restored.keep_keys(), manager.keep_keys());
    assert!(restored.is_direct("peer-a"));

    // A corrupt/missing file -> an empty manager (self-healing: the probe cycle rebuilds it, without guessing).
    assert_eq!(
        DirectManager::load(&root.join("missing.json"))
            .keep_keys()
            .len(),
        0
    );
    std::fs::write(&path, "not json").unwrap();
    assert_eq!(DirectManager::load(&path).keep_keys().len(), 0);

    let _ = std::fs::remove_dir_all(root);
}

/// R-DIAG-2: record_*/clear_endpoint only touch the matched peer, and a missing peer is a no-op;
/// direct_candidates lists only non-Relay peers.
#[test]
fn direct_peer_status_records_only_managed_non_relay() {
    let mut manager = DirectManager::new();
    manager.peers.insert(
        "peer-a".into(),
        direct_peer("peer-a", "10.240.0.3", PeerLinkState::Direct),
    );
    manager.peers.insert(
        "peer-b".into(),
        direct_peer("peer-b", "10.240.0.4", PeerLinkState::Relay),
    );

    // Enrichment: written for a matched direct peer; a Relay/missing peer is a no-op.
    manager.record_endpoint("peer-a", "192.168.1.50:51821".into());
    manager.record_peer_status(
        "peer-a",
        Some(42),
        Some("overlay"),
        Some(1_700_000_000),
        111,
        222,
    );
    manager.record_endpoint("peer-b", "192.168.1.60:51821".into());
    manager.record_peer_status("ghost", Some(1), Some("overlay"), Some(1), 1, 1);

    let a = &manager.peers["peer-a"];
    assert_eq!(a.endpoint, "192.168.1.50:51821");
    assert_eq!(a.rtt_ms, Some(42));
    assert_eq!(a.last_handshake_at, Some(1_700_000_000));
    assert_eq!((a.rx_bytes, a.tx_bytes), (111, 222));
    // A Relay peer does not take part in direct state recording (it has no direct link).
    assert_eq!(manager.peers["peer-b"].endpoint, "");

    // direct_candidates lists only non-Relay.
    let candidates = manager.direct_candidates();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].0, "peer-a");
    assert_eq!(candidates[0].1, "10.240.0.3".parse::<Ipv4Addr>().unwrap());

    // Clearing: the endpoint and the RTT reset together, while the other readings are retained.
    manager.clear_endpoint("peer-a");
    assert_eq!(manager.peers["peer-a"].endpoint, "");
    assert_eq!(manager.peers["peer-a"].rtt_ms, None);
    assert_eq!(
        manager.peers["peer-a"].last_handshake_at,
        Some(1_700_000_000)
    );
}

/// The memory surface (last_direct) read/write boundary: record_endpoint refreshes it with the kernel's actual
/// situation (including out-of-table faces from wg roaming), and clear_endpoint clears the current value without
/// clearing the memory (a later re-promotion after falling back to relay depends on it to pick the same face back);
/// a Relay peer has no direct link, so both paths are a no-op.
#[test]
fn record_endpoint_refreshes_memory_and_clear_keeps_it() {
    let mut manager = DirectManager::new();
    manager.peers.insert(
        "peer-a".into(),
        direct_peer("peer-a", "10.240.0.3", PeerLinkState::Direct),
    );
    manager.record_endpoint("peer-a", "192.168.5.11:51820".into());
    assert_eq!(
        manager.peers["peer-a"].last_direct,
        Some(lan("192.168.5.11", 51820))
    );
    // The kernel roams to a new face (outside the table) -> the memory follows the actual situation.
    manager.record_endpoint("peer-a", "192.168.5.117:51821".into());
    assert_eq!(
        manager.peers["peer-a"].last_direct,
        Some(lan("192.168.5.117", 51821))
    );
    // The fallback clears the current value, keeping the memory.
    manager.clear_endpoint("peer-a");
    assert_eq!(manager.peers["peer-a"].endpoint, "");
    assert_eq!(
        manager.peers["peer-a"].last_direct,
        Some(lan("192.168.5.117", 51821)),
        "demote clears the endpoint but keeps the remembered face"
    );
    // A Relay peer is a no-op (the memory is maintained by plan_updates's degradation branch).
    manager.peers.insert(
        "peer-b".into(),
        direct_peer("peer-b", "10.240.0.4", PeerLinkState::Relay),
    );
    manager.record_endpoint("peer-b", "192.168.5.11:51820".into());
    assert_eq!(manager.peers["peer-b"].last_direct, None);
}
