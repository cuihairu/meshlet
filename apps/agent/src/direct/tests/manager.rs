//! DirectManager 用例：link_statuses 上报契约、ledger save/load 往返与
//! 自愈、record_*/clear_endpoint 富化边界（R-DIAG-2）。

use super::*;

#[test]
fn link_statuses_report_active_direct_links_only() {
    let mut manager = DirectManager::new();
    // 无在管对端 → 空上报（UI 默认按中继呈现）。
    assert!(manager.link_statuses().is_empty());

    // Pending（第 1 周期）：状态 direct_pending，无握手读数。
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

    // 握手健康 → Direct，并携带探测时的握手年龄快照。
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

    // 回退（候选撤销）→ 不再上报该对端。
    manager.apply_plan(
        &[],
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
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
    );
    manager.save(&path).expect("ledger write");

    // 从 ledger 恢复：keep set 原样、对端按「已建立」持有。
    let restored = DirectManager::load(&path);
    assert_eq!(restored.keep_keys(), manager.keep_keys());
    assert!(restored.is_direct("peer-a"));

    // 损坏/缺失文件 → 空管理器（自愈：探测周期重建，不猜）。
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

/// R-DIAG-2：record_*/clear_endpoint 只改命中对端，缺失对端 no-op；
/// direct_candidates 只列非 Relay 对端。
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

    // 富化：命中直连对端写入，Relay/缺失对端 no-op。
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
    // Relay 对端不参与直连状态记录（无直连链路）。
    assert_eq!(manager.peers["peer-b"].endpoint, "");

    // direct_candidates 只列非 Relay。
    let candidates = manager.direct_candidates();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].0, "peer-a");
    assert_eq!(candidates[0].1, "10.240.0.3".parse::<Ipv4Addr>().unwrap());

    // 清空：endpoint 与 RTT 一并复位，其余读数保留。
    manager.clear_endpoint("peer-a");
    assert_eq!(manager.peers["peer-a"].endpoint, "");
    assert_eq!(manager.peers["peer-a"].rtt_ms, None);
    assert_eq!(
        manager.peers["peer-a"].last_handshake_at,
        Some(1_700_000_000)
    );
}

/// 记忆面（last_direct）读写边界：record_endpoint 随内核实况刷新（含 wg
/// roaming 出来的表外面），clear_endpoint 只清现值不清记忆（回中继后的
/// 再晋升要靠它选回）；Relay 对端无直连链路，两路都 no-op。
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
    // 内核漫游到新面（表外）→ 记忆跟随实况。
    manager.record_endpoint("peer-a", "192.168.5.117:51821".into());
    assert_eq!(
        manager.peers["peer-a"].last_direct,
        Some(lan("192.168.5.117", 51821))
    );
    // 回退清现值，记忆保留。
    manager.clear_endpoint("peer-a");
    assert_eq!(manager.peers["peer-a"].endpoint, "");
    assert_eq!(
        manager.peers["peer-a"].last_direct,
        Some(lan("192.168.5.117", 51821)),
        "demote clears the endpoint but keeps the remembered face"
    );
    // Relay 对端 no-op（记忆随 plan_updates 的劣化分支维护）。
    manager.peers.insert(
        "peer-b".into(),
        direct_peer("peer-b", "10.240.0.4", PeerLinkState::Relay),
    );
    manager.record_endpoint("peer-b", "192.168.5.11:51820".into());
    assert_eq!(manager.peers["peer-b"].last_direct, None);
}
