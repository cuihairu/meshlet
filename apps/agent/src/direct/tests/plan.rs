//! Pure-function cases for plan_updates / merge_handshake_ages: candidate
//! decisions and `/32` boundaries, SEL-003 degradation fallback and recovery
//! gate, the pending promotion threshold, and handshake-age fallback merge.

use super::*;

#[test]
fn relay_promotes_a_lan_reachable_peer_with_a_32() {
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    let updates = plan_updates(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert_eq!(updates.len(), 1);
    assert!(
        matches!(&updates[0], DirectUpdate::Promote { allowed_ips, .. }
        if allowed_ips == &vec![cidr("10.240.0.3/32")])
    );
    assert_eq!(
        current.get("dev-b").map(|p| p.state),
        Some(PeerLinkState::DirectPending { attempts: 1 })
    );
}

#[test]
fn peer_without_any_path_stays_relay_and_emits_nothing() {
    let wanted = vec![peer("dev-b", "10.240.0.3", &[])];
    let mut current = BTreeMap::new();
    let updates = plan_updates(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(updates.is_empty());
    assert_eq!(
        current.get("dev-b").map(|p| p.state),
        Some(PeerLinkState::Relay)
    );
}

#[test]
fn endpoint_inside_overlay_scope_is_rejected_as_hairpin() {
    // AGENT-ISO-2: a candidate inside the overlay scope = using an in-tunnel
    // address as the tunnel endpoint — packets must enter the tunnel first to
    // reach it (measured on imac 2026-11-23: this shape took 1750ms vs 19ms
    // for same-segment direct).
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("10.240.0.7", 51820)])];
    let mut current = BTreeMap::new();
    let updates = plan_updates(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(
        updates.is_empty(),
        "overlay 内 endpoint 不得晋升: {updates:?}"
    );
    assert_eq!(
        current.get("dev-b").map(|p| p.state),
        Some(PeerLinkState::Relay)
    );
}

#[test]
fn overlay_endpoint_does_not_shadow_a_physical_candidate() {
    // After the overlay face is filtered out, the same peer's physical face
    // still promotes — filtering **removes bad faces**, it does not mark the
    // whole peer as undirectable.
    let wanted = vec![peer(
        "dev-b",
        "10.240.0.3",
        &[lan("10.240.0.7", 51820), lan("192.168.1.50", 51821)],
    )];
    let mut current = BTreeMap::new();
    let updates = plan_updates(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert_eq!(updates.len(), 1, "{updates:?}");
    match &updates[0] {
        DirectUpdate::Promote { endpoint, .. } => {
            assert_eq!(
                endpoint.to_string(),
                "192.168.1.50:51821",
                "必须选物理面，不得落到 overlay 面"
            );
        }
        other => panic!("expected Promote, got {other:?}"),
    }
}

#[test]
fn memory_face_inside_overlay_scope_is_not_reused() {
    // The memory face bypasses decide_direct_path and wins directly — a legacy
    // / kernel-roamed overlay address written into it would be re-selected
    // forever unless filtered (filtering candidates alone cannot stop it).
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    let mut seeded = direct_peer("dev-b", "10.240.0.3", PeerLinkState::Relay);
    seeded.last_direct = Some(lan("10.240.0.7", 51820));
    current.insert("dev-b".into(), seeded);

    let updates = plan_updates(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert_eq!(updates.len(), 1, "{updates:?}");
    match &updates[0] {
        DirectUpdate::Promote { endpoint, .. } => {
            assert_eq!(
                endpoint.to_string(),
                "192.168.1.50:51821",
                "记忆面是 overlay 地址时应回落候选表，不得选回它"
            );
        }
        other => panic!("expected Promote, got {other:?}"),
    }
}

#[test]
fn memory_face_on_a_foreign_network_is_not_reused() {
    // The peer's ZeroTier address: our LAN scope no longer counts it as
    // same-segment (zt* interfaces are out of scope) — an un-rechecked memory
    // face would be selected forever, never switching to the physical face
    // (recorded 2026-11-23).
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    let mut seeded = direct_peer("dev-b", "10.240.0.3", PeerLinkState::Relay);
    seeded.last_direct = Some(lan("10.147.19.97", 52931));
    current.insert("dev-b".into(), seeded);

    let updates = plan_updates(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert_eq!(updates.len(), 1, "{updates:?}");
    match &updates[0] {
        DirectUpdate::Promote { endpoint, .. } => assert_eq!(
            endpoint.to_string(),
            "192.168.1.50:51821",
            "外来网段的记忆面必须回落候选表"
        ),
        other => panic!("expected Promote, got {other:?}"),
    }
}

#[test]
fn healthy_direct_peer_is_kept_without_repromoting() {
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    current.insert(
        "dev-b".into(),
        direct_peer("dev-b", "10.240.0.3", PeerLinkState::Direct),
    );
    let mut ages = BTreeMap::new();
    ages.insert("dev-b".into(), 5u64);
    let updates = plan_updates(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &ages,
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(updates.is_empty(), "healthy direct peer: keep, no churn");
    assert_eq!(
        current.get("dev-b").map(|p| p.state),
        Some(PeerLinkState::Direct)
    );
}

#[test]
fn stale_handshake_demotes_but_stale_peer_removed_from_wanted_demotes_too() {
    // Direct link expired (handshake age beyond the health window) → fallback.
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    current.insert(
        "dev-b".into(),
        direct_peer("dev-b", "10.240.0.3", PeerLinkState::Direct),
    );
    let mut ages = BTreeMap::new();
    ages.insert("dev-b".into(), DIRECT_HEALTH_WINDOW_SECS.saturating_add(1));
    let updates = plan_updates(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &ages,
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(matches!(&updates[0], DirectUpdate::Demote { public_key } if public_key == "dev-b"));
    assert_eq!(
        current.get("dev-b").map(|p| p.state),
        Some(PeerLinkState::Relay)
    );

    // Peer disappears from the candidate set (revoke/offline) → fall back and
    // remove even when healthy.
    let mut current2 = BTreeMap::new();
    current2.insert(
        "dev-b".into(),
        direct_peer("dev-b", "10.240.0.3", PeerLinkState::Direct),
    );
    let updates = plan_updates(
        &[],
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current2,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(matches!(&updates[0], DirectUpdate::Demote { public_key } if public_key == "dev-b"));
    assert!(current2.is_empty());
}

#[test]
fn degraded_direct_peer_immediately_falls_back_to_relay() {
    // SEL-003: the direct path degrades (packet-loss spike / timeout) →
    // immediate Demote back to relay.
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    current.insert(
        "dev-b".into(),
        direct_peer("dev-b", "10.240.0.3", PeerLinkState::Direct),
    );
    let mut degraded = BTreeMap::new();
    degraded.insert("dev-b".into(), true);
    let updates = plan_updates(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &degraded,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(matches!(&updates[0], DirectUpdate::Demote { public_key } if public_key == "dev-b"));
    assert_eq!(
        current.get("dev-b").map(|p| p.state),
        Some(PeerLinkState::Relay),
        "degraded direct peer must fall back to relay immediately"
    );
}

#[test]
fn healthy_direct_peer_is_not_degraded() {
    // Not marked degraded → no fallback triggered.
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    current.insert(
        "dev-b".into(),
        direct_peer("dev-b", "10.240.0.3", PeerLinkState::Direct),
    );
    let mut ages = BTreeMap::new();
    ages.insert("dev-b".into(), 5u64);
    let updates = plan_updates(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &ages,
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(updates.is_empty(), "healthy direct peer: no demote");
    assert_eq!(
        current.get("dev-b").map(|p| p.state),
        Some(PeerLinkState::Direct)
    );
}

#[test]
fn recovery_after_degradation_repromotes_via_state_machine() {
    // SEL-003 recovery: back on relay, the next cycle healthy → the state
    // machine re-Promotes (switching back through the hysteresis gate). This
    // verifies the Relay→Promote recovery path (RecoveryGate gates on the
    // agent side, only allowing entry back into candidate decisions after N
    // consecutive healthy rounds).
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    current.insert(
        "dev-b".into(),
        direct_peer("dev-b", "10.240.0.3", PeerLinkState::Relay),
    );
    let updates = plan_updates(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(
        matches!(&updates[0], DirectUpdate::Promote { .. }),
        "recovered peer is re-promoted: {updates:?}"
    );
    assert!(matches!(
        current.get("dev-b").map(|p| p.state),
        Some(PeerLinkState::DirectPending { .. })
    ));
}

#[test]
fn recovery_hold_keeps_relay_until_gate_is_ready() {
    // SEL-003 recovery gate: fewer than N consecutive healthy rounds after
    // returning to relay (hold_relay contains this peer) → stay on relay even
    // when a direct path exists; do not switch back immediately (debounce).
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    current.insert(
        "dev-b".into(),
        direct_peer("dev-b", "10.240.0.3", PeerLinkState::Relay),
    );
    let mut hold = BTreeSet::new();
    hold.insert("dev-b".into());
    let updates = plan_updates(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &hold,
        &BTreeMap::new(),
    );
    assert!(
        updates.is_empty(),
        "held peer must not be re-promoted yet: {updates:?}"
    );
    assert_eq!(
        current.get("dev-b").map(|p| p.state),
        Some(PeerLinkState::Relay),
        "held peer stays in relay"
    );
}

/// Regression fix (observed by the user: direct always stuck at "dialing"):
/// pending has completed the handshake (handshake fresh) but ICMP probing never
/// succeeds (degraded empty, probe readings unavailable) → must promote to
/// Direct in this round, instead of waiting out the attempts timeout to fall
/// back.
#[test]
fn pending_with_fresh_handshake_promotes_via_plan_updates() {
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    current.insert(
        "dev-b".into(),
        direct_peer(
            "dev-b",
            "10.240.0.3",
            PeerLinkState::DirectPending {
                attempts: MAX_PROMOTE_ATTEMPTS,
            },
        ),
    );
    let mut ages = BTreeMap::new();
    ages.insert("dev-b".into(), 30u64);
    let updates = plan_updates(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &ages,
        &BTreeMap::new(), // all probes failed → no window → degraded empty
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(
        updates.is_empty(),
        "promotion is a keep, no churn: {updates:?}"
    );
    assert_eq!(
        current.get("dev-b").map(|p| p.state),
        Some(PeerLinkState::Direct),
        "handshake evidence alone promotes pending → direct"
    );
}

/// Handshake expired (beyond the health window) → pending is judged invalid
/// and falls back (the degradation criterion is not relaxed).
#[test]
fn pending_with_stale_handshake_times_out_to_relay() {
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    current.insert(
        "dev-b".into(),
        direct_peer(
            "dev-b",
            "10.240.0.3",
            PeerLinkState::DirectPending {
                attempts: MAX_PROMOTE_ATTEMPTS,
            },
        ),
    );
    let mut ages = BTreeMap::new();
    ages.insert("dev-b".into(), DIRECT_HEALTH_WINDOW_SECS.saturating_add(1));
    let updates = plan_updates(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &ages,
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(
        matches!(&updates[0], DirectUpdate::Demote { public_key } if public_key == "dev-b"),
        "stale handshake in pending must fall back: {updates:?}"
    );
    assert_eq!(
        current.get("dev-b").map(|p| p.state),
        Some(PeerLinkState::Relay)
    );
}

/// Handshake-reading fallback merge: dedicated readings win, the dump only
/// fills missing keys; if dedicated is entirely empty (latest-handshakes
/// unreadable during Windows tunnel churn) → the dump carries it alone, so
/// the promotion threshold still has input.
#[test]
fn merge_handshake_ages_fills_missing_keys_from_dump() {
    let mut dedicated = BTreeMap::new();
    dedicated.insert("hub".into(), 3u64);
    let mut dump = BTreeMap::new();
    dump.insert("hub".into(), 99u64); // dedicated has it → not overwritten
    dump.insert("peer-b".into(), 12u64); // dedicated lacks it → filled in
    let merged = merge_handshake_ages(dedicated, dump.clone());
    assert_eq!(merged.get("hub"), Some(&3));
    assert_eq!(merged.get("peer-b"), Some(&12));

    // Dedicated readings failed wholesale (empty) → the dump carries it alone.
    let merged = merge_handshake_ages(BTreeMap::new(), dump);
    assert_eq!(merged.get("hub"), Some(&99));
    assert_eq!(merged.get("peer-b"), Some(&12));
}

/// SEL-003 acceptance: a full fallback/recovery timeline unit test with an
/// injectable clock (allowed by the task brief as a substitute when netns is
/// unavailable). Simulates round after round of "probe cycles" (degraded /
/// healthy are the injected clock signals):
/// ① healthy direct → keep; ② direct degraded (loss spike/timeout) → immediately
/// back to relay (Demote); ③ fewer than N(=3) consecutive healthy rounds after
/// returning to relay → stay on relay (no switch back); ④ 3 consecutive
/// healthy rounds → the recovery gate releases → the state machine re-Promotes
/// (switch back).
#[test]
fn sel003_fallback_and_recovery_timeline() {
    use meshlet_network::probe::RecoveryGate;
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    let mut recovery = RecoveryGate::new(3);

    // Each round runs: inject degraded → record in the recovery gate →
    // hold set → state machine.
    fn run_round(
        wanted: &[PeerEndpoints],
        current: &mut BTreeMap<String, DirectPeer>,
        recovery: &mut RecoveryGate,
        degraded: bool,
    ) -> Vec<DirectUpdate> {
        let mut degraded_map = BTreeMap::new();
        if degraded {
            degraded_map.insert("dev-b".to_string(), true);
        }
        let healthy = !degraded;
        let ready = recovery.record("dev-b", healthy);
        let mut hold = BTreeSet::new();
        let is_relay = current
            .get("dev-b")
            .map(|p| p.state == PeerLinkState::Relay)
            .unwrap_or(false);
        if !ready && is_relay {
            hold.insert("dev-b".to_string());
        }
        plan_updates(
            wanted,
            &[cidr(HOME)],
            cidr(OVERLAY),
            "10.240.0.2".parse().unwrap(),
            current,
            &BTreeMap::new(),
            &degraded_map,
            &BTreeSet::new(),
            &hold,
            &BTreeMap::new(),
        )
    }

    // ① healthy → first Promote (DirectPending).
    let updates = run_round(&wanted, &mut current, &mut recovery, false);
    assert!(
        matches!(&updates[0], DirectUpdate::Promote { .. }),
        "initial promote"
    );
    // ② degraded → immediate Demote back to relay.
    let updates = run_round(&wanted, &mut current, &mut recovery, true);
    assert!(
        matches!(&updates[0], DirectUpdate::Demote { public_key } if public_key == "dev-b"),
        "degraded immediately falls back: {updates:?}"
    );
    assert_eq!(current.get("dev-b").unwrap().state, PeerLinkState::Relay);
    // ③ rounds 1 and 2 healthy after returning to relay: the recovery gate has
    // fewer than 3 rounds → stay on relay (no switch back).
    let u1 = run_round(&wanted, &mut current, &mut recovery, false);
    assert!(u1.is_empty(), "round 1 healthy after fallback: hold {u1:?}");
    let u2 = run_round(&wanted, &mut current, &mut recovery, false);
    assert!(u2.is_empty(), "round 2 healthy after fallback: hold {u2:?}");
    assert_eq!(current.get("dev-b").unwrap().state, PeerLinkState::Relay);
    // ④ round 3 healthy: the recovery gate releases → re-Promote (switch back).
    let u3 = run_round(&wanted, &mut current, &mut recovery, false);
    assert!(
        matches!(&u3[0], DirectUpdate::Promote { .. }),
        "round 3 healthy after fallback: switch back {u3:?}"
    );
}

/// Closing the "fresh-handshake short-circuit" hole (proven by the 2026-11-13
/// SEL-002 two-machine acceptance): the direct peer's handshake evidence is
/// fresh (classify_probe judges Healthy under the 240s health window) yet the
/// probe window stays deeply degraded (real-machine records: 1715ms probe_ok /
/// handshake frozen 133–203s pinning the direct link) — in that case the
/// degradation gate must take priority over freshness: Demote back to relay
/// immediately, with probing taking part in the verdict.
#[test]
fn degraded_latency_demotes_even_with_fresh_handshake() {
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    current.insert(
        "dev-b".into(),
        direct_peer("dev-b", "10.240.0.3", PeerLinkState::Direct),
    );
    // Handshake age 5s (far inside the 240s health window — full freshness evidence).
    let mut ages = BTreeMap::new();
    ages.insert("dev-b".to_string(), 5u64);
    // Probe window stays deeply degraded (latency dimension; is_degraded's
    // median rule hits).
    let mut degraded = BTreeMap::new();
    degraded.insert("dev-b".to_string(), true);
    let updates = plan_updates(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &ages,
        &degraded,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(
        matches!(&updates[0], DirectUpdate::Demote { public_key } if public_key == "dev-b"),
        "fresh handshake must not outrank sustained degradation: {updates:?}"
    );
    assert_eq!(current.get("dev-b").unwrap().state, PeerLinkState::Relay);
}

/// Root fix for stranded (2026-11-14 inspection item; the equivalent of the
/// candidate table taking over roaming faces): re-promotion after falling back
/// to relay prefers the memory face — the endpoint actually in use by the last
/// direct link (including a roaming face written by the kernel that is absent
/// from the server candidate table). Taking SameLan by lowest IP in the
/// candidate table would let a 10.x ZT face outrank a 192.168.x face
/// (stranded confirmed: re-promote could only pick the in-table ZT face, never
/// getting back to the healthy face, ~1-5min of direct↔hub churn).
#[test]
fn repromote_returns_to_remembered_face_over_lower_ip_table_face() {
    // In-table candidates: the ZT face 10.x (SameLan-qualifying, lowest IP) +
    // a public face; the memory face 192.168.5.x (an out-of-table roaming
    // face, healthy with no probe window).
    let wanted = vec![peer(
        "dev-b",
        "10.240.0.3",
        &[
            lan("10.147.19.49", 51820),
            EndpointCandidate::public("203.0.113.5".parse().unwrap(), 51820),
        ],
    )];
    let subnets = [cidr("10.147.19.0/24"), cidr("192.168.5.0/24")];
    let remembered = lan("192.168.5.11", 51820);
    let mut current = BTreeMap::new();
    let mut entry = direct_peer("dev-b", "10.240.0.3", PeerLinkState::Direct);
    entry.last_direct = Some(remembered);
    current.insert("dev-b".into(), entry);

    // SEL-003 degradation → immediate fallback; the established Direct keeps
    // the memory face.
    let mut degraded = BTreeMap::new();
    degraded.insert("dev-b".into(), true);
    let updates = plan_updates(
        &wanted,
        &subnets,
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &degraded,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(matches!(&updates[0], DirectUpdate::Demote { .. }));
    assert_eq!(current.get("dev-b").unwrap().state, PeerLinkState::Relay);
    assert_eq!(
        current.get("dev-b").unwrap().last_direct,
        Some(remembered),
        "degrade fallback from Direct keeps the remembered face"
    );

    // Next cycle re-promotion: picks the memory face, not the in-table ZT face
    // with the lowest IP.
    let updates = plan_updates(
        &wanted,
        &subnets,
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(
        matches!(&updates[0], DirectUpdate::Promote { endpoint, .. }
        if endpoint.to_string() == "192.168.5.11:51820"),
        "re-promote must return to the remembered roaming face: {updates:?}"
    );
}

/// Dead-face escape for the memory face: the fallback after pending
/// verification fails (3 ticks without a handshake) drops the memory — when the
/// peer has roamed away (the old face is really dead), re-promotion falls
/// back to candidate-table decisions instead of deadlocking on the old face.
#[test]
fn pending_verify_failure_clears_memory_and_table_decision_wins() {
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.5.99", 51820)])];
    let mut current = BTreeMap::new();
    let mut entry = direct_peer(
        "dev-b",
        "10.240.0.3",
        PeerLinkState::DirectPending {
            attempts: MAX_PROMOTE_ATTEMPTS,
        },
    );
    entry.last_direct = Some(lan("192.168.5.11", 51820));
    current.insert("dev-b".into(), entry);
    let mut ages = BTreeMap::new();
    ages.insert("dev-b".into(), DIRECT_HEALTH_WINDOW_SECS.saturating_add(1));
    let updates = plan_updates(
        &wanted,
        &[cidr("192.168.5.0/24")],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &ages,
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(matches!(&updates[0], DirectUpdate::Demote { .. }));
    assert_eq!(
        current.get("dev-b").unwrap().last_direct,
        None,
        "pending verify failure must drop the remembered face"
    );

    // Next cycle: no memory → the in-table SameLan face wins (the old memory
    // face is no longer picked).
    let updates = plan_updates(
        &wanted,
        &[cidr("192.168.5.0/24")],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(
        matches!(&updates[0], DirectUpdate::Promote { endpoint, .. }
        if endpoint.to_string() == "192.168.5.99:51820"),
        "table decision takes over once memory is dropped: {updates:?}"
    );
}

/// The memory face survives the recovery gate's relay hold: re-promotion
/// after the gate releases still prefers returning to it.
#[test]
fn hold_relay_preserves_remembered_face() {
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("10.147.19.49", 51820)])];
    let mut current = BTreeMap::new();
    let mut entry = direct_peer("dev-b", "10.240.0.3", PeerLinkState::Relay);
    entry.last_direct = Some(lan("192.168.5.11", 51820));
    current.insert("dev-b".into(), entry);
    let mut hold = BTreeSet::new();
    hold.insert("dev-b".into());
    let updates = plan_updates(
        &wanted,
        &[cidr("192.168.5.0/24"), cidr("10.147.19.0/24")],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &hold,
        &BTreeMap::new(),
    );
    assert!(updates.is_empty(), "held peer stays relay: {updates:?}");
    assert_eq!(
        current.get("dev-b").unwrap().last_direct,
        Some(lan("192.168.5.11", 51820)),
        "hold must not wipe the remembered face"
    );
}

/// First promotion (no memory) and established-direct cycles are unaffected:
/// table decisions stay as-is (existing regressions do not loosen); the
/// promote action records the dialed face into memory so the next fallback
/// can pick it back.
#[test]
fn first_promote_records_the_dialed_face_as_memory() {
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.5.99", 51820)])];
    let mut current = BTreeMap::new();
    let updates = plan_updates(
        &wanted,
        &[cidr("192.168.5.0/24")],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(matches!(&updates[0], DirectUpdate::Promote { endpoint, .. }
    if endpoint.to_string() == "192.168.5.99:51820"));
    assert_eq!(
        current.get("dev-b").unwrap().last_direct,
        Some(lan("192.168.5.99", 51820)),
        "promote records the dialed face for future re-promotes"
    );
}

// ---------------------------------------------------------------------------
// Decision records (plan_updates_logged; the 2026-11-14 observability debt:
// after-the-fact replay without console context — every transition/action
// carries mode, reason, and judgement inputs)
// ---------------------------------------------------------------------------

/// Degraded demotion: the decision record carries the mode transition
/// direction, the degraded flag, the judgement input (handshake age), and the
/// endpoint involved (the active face before the demotion).
#[test]
fn degraded_demote_records_decision_with_judgement_inputs() {
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    let mut entry = direct_peer("dev-b", "10.240.0.3", PeerLinkState::Direct);
    entry.endpoint = "192.168.1.50:51821".into();
    current.insert("dev-b".into(), entry);
    let mut degraded = BTreeMap::new();
    degraded.insert("dev-b".into(), true);
    let mut ages = BTreeMap::new();
    ages.insert("dev-b".into(), 5u64);
    let (updates, records) = plan_updates_logged(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &ages,
        &degraded,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(matches!(&updates[0], DirectUpdate::Demote { public_key } if public_key == "dev-b"));
    assert_eq!(records.len(), 1);
    let r = &records[0];
    assert_eq!(r.public_key, "dev-b");
    assert_eq!(r.peer_name, "dev-b-name");
    assert_eq!(r.action, "demote");
    assert_eq!(r.from_mode, "p2p_direct");
    assert_eq!(r.to_mode, "hub_relay");
    assert!(r.degraded);
    assert_eq!(r.handshake_age_secs, Some(5));
    assert_eq!(r.endpoint, "192.168.1.50:51821", "endpoint = demoted face");
    assert!(r.reason.contains("sel003 degraded"));
}

/// Memory-face re-promotion (880b49a semantics): the candidate table is empty
/// and only last_direct is viable → the decision record states the source is
/// the memory face (replay can distinguish "candidate-table routing" from
/// "returning to the last face").
#[test]
fn memory_face_promote_records_its_source() {
    let wanted = vec![peer("dev-b", "10.240.0.3", &[])];
    let mut current = BTreeMap::new();
    let mut entry = direct_peer("dev-b", "10.240.0.3", PeerLinkState::Relay);
    entry.last_direct = Some(lan("192.168.1.77", 51821));
    current.insert("dev-b".into(), entry);
    let (updates, records) = plan_updates_logged(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(matches!(&updates[0], DirectUpdate::Promote { endpoint, .. }
    if endpoint.to_string() == "192.168.1.77:51821"));
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].action, "promote");
    assert_eq!(records[0].from_mode, "hub_relay");
    assert_eq!(records[0].to_mode, "direct_pending");
    assert!(records[0].reason.contains("memory face"));
    assert_eq!(records[0].endpoint, "192.168.1.77:51821");
}

/// First promotion from the candidate table (no memory): the source is
/// marked candidate table.
#[test]
fn candidate_table_promote_records_its_source() {
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    let (_, records) = plan_updates_logged(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].action, "promote");
    assert_eq!(records[0].from_mode, "hub_relay");
    assert_eq!(records[0].to_mode, "direct_pending");
    assert!(records[0].reason.contains("candidate table"));
    assert_eq!(records[0].endpoint, "192.168.1.50:51821");
}

/// pending verified (a Keep action but the state transitions direct_pending →
/// p2p_direct): also records promote — the mode_flip event fires on
/// from_mode ≠ to_mode, so this flip must not be missed.
#[test]
fn pending_verified_promotion_records_the_flip_transition() {
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    current.insert(
        "dev-b".into(),
        direct_peer(
            "dev-b",
            "10.240.0.3",
            PeerLinkState::DirectPending {
                attempts: MAX_PROMOTE_ATTEMPTS,
            },
        ),
    );
    let mut ages = BTreeMap::new();
    ages.insert("dev-b".into(), 30u64);
    let (updates, records) = plan_updates_logged(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &ages,
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(updates.is_empty(), "promotion is a keep, no churn");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].action, "promote");
    assert_eq!(records[0].from_mode, "direct_pending");
    assert_eq!(records[0].to_mode, "p2p_direct");
    assert!(records[0].reason.contains("pending verified"));
    assert_eq!(records[0].handshake_age_secs, Some(30));
}

/// pending waiting round (attempts+1, mode unchanged): decision records are
/// written each round (replaying the waiting process), but from_mode =
/// to_mode produces no mode_flip event.
#[test]
fn waiting_round_records_probe_without_mode_change() {
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    current.insert(
        "dev-b".into(),
        direct_peer(
            "dev-b",
            "10.240.0.3",
            PeerLinkState::DirectPending { attempts: 1 },
        ),
    );
    let (updates, records) = plan_updates_logged(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(updates.is_empty());
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].action, "probe");
    assert_eq!(records[0].from_mode, "direct_pending");
    assert_eq!(records[0].to_mode, "direct_pending");
    assert!(records[0].reason.contains("attempt 2"));
}

/// Recovery-gate hold_relay: recorded each round (replaying "why it has not
/// switched back yet"), mode unchanged.
#[test]
fn hold_relay_records_the_recovery_gate_verdict() {
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    current.insert(
        "dev-b".into(),
        direct_peer("dev-b", "10.240.0.3", PeerLinkState::Relay),
    );
    let mut hold = BTreeSet::new();
    hold.insert("dev-b".into());
    let (updates, records) = plan_updates_logged(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &hold,
        &BTreeMap::new(),
    );
    assert!(updates.is_empty());
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].action, "hold_relay");
    assert_eq!(records[0].from_mode, "hub_relay");
    assert_eq!(records[0].to_mode, "hub_relay");
    assert!(records[0].reason.contains("recovery gate"));
    assert_eq!(
        current.get("dev-b").map(|p| p.state),
        Some(PeerLinkState::Relay)
    );
}

/// The peer leaves the candidate set (revoked/offline/segment change): the
/// decision record leaves a trace (from_mode takes the pre-transition state)
/// and the management state is removed.
#[test]
fn peer_leaving_candidates_records_a_demote_decision() {
    let wanted = vec![];
    let mut current = BTreeMap::new();
    current.insert(
        "dev-b".into(),
        direct_peer("dev-b", "10.240.0.3", PeerLinkState::Direct),
    );
    let (updates, records) = plan_updates_logged(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(matches!(&updates[0], DirectUpdate::Demote { public_key } if public_key == "dev-b"));
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].action, "demote");
    assert_eq!(records[0].from_mode, "p2p_direct");
    assert_eq!(records[0].to_mode, "hub_relay");
    assert_eq!(records[0].reason, "peer left the candidate set");
    assert!(current.is_empty());
}

/// Steady state does not spam: a healthy-direct keep and a no-path relay
/// keep are both Keeps with an unchanged state → zero decision records (the
/// decision log only collects transitions and actions, not one noise line
/// per peer per cycle).
#[test]
fn steady_state_keeps_emit_no_decision_records() {
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    current.insert(
        "dev-b".into(),
        direct_peer("dev-b", "10.240.0.3", PeerLinkState::Direct),
    );
    let mut ages = BTreeMap::new();
    ages.insert("dev-b".into(), 5u64);
    let (_, records) = plan_updates_logged(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &ages,
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(records.is_empty(), "healthy keep: no records");

    // A relay keep without a viable path: also zero records.
    let mut current = BTreeMap::new();
    let (updates, records) = plan_updates_logged(
        &[peer("dev-c", "10.240.0.4", &[])],
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(updates.is_empty());
    assert!(records.is_empty(), "relay keep without a path: no records");
}

// ---------------------------------------------------------------------------
// promote prefers healthy faces (unhealthy_faces pre-filter; inspection item
// nov14-1410, option 2 of 3: re-promoting onto a degraded face would only be
// demoted again immediately — the client-side circuit breaker for the flip
// loop)
// ---------------------------------------------------------------------------

/// The candidate table's only face is inside the degraded window → defer this
/// round: zero actions (do not go onto the degraded face), the decision
/// record leaves a trace (the degraded face's endpoint is replayable), the
/// state stays relay, the memory face is kept.
#[test]
fn degraded_only_candidate_defers_promotion() {
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    let mut unhealthy = BTreeSet::new();
    unhealthy.insert(("dev-b".to_string(), lan("192.168.1.50", 51821)));
    let (updates, records) = plan_updates_logged(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &unhealthy,
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(updates.is_empty(), "degraded face must not be promoted");
    assert_eq!(
        current.get("dev-b").map(|p| p.state),
        Some(PeerLinkState::Relay)
    );
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].action, "defer");
    assert_eq!(records[0].from_mode, "hub_relay");
    assert_eq!(records[0].to_mode, "hub_relay");
    assert!(records[0].degraded);
    assert!(records[0].reason.contains("degraded"));
    assert_eq!(
        records[0].endpoint, "192.168.1.50:51821",
        "deferred face is named for replay"
    );
}

/// Two public candidates, the low-address face degraded → pick the
/// high-address healthy face (healthy-face preference, not a blanket defer:
/// promotion proceeds as usual when a healthy alternative exists).
#[test]
fn healthy_alternative_is_preferred_over_degraded_low_ip_face() {
    let wanted = vec![peer(
        "dev-b",
        "10.240.0.3",
        &[public("203.0.113.5", 51820), public("203.0.113.9", 51820)],
    )];
    let mut current = BTreeMap::new();
    let mut unhealthy = BTreeSet::new();
    unhealthy.insert(("dev-b".to_string(), public("203.0.113.5", 51820)));
    let (updates, records) = plan_updates_logged(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &unhealthy,
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(
        matches!(&updates[0], DirectUpdate::Promote { endpoint, .. }
    if endpoint.to_string() == "203.0.113.9:51820"),
        "healthy high-ip face wins over degraded low-ip face"
    );
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].action, "promote");
    assert!(records[0].reason.contains("candidate table"));
    assert_eq!(records[0].endpoint, "203.0.113.9:51820");
}

/// The memory face is inside the degraded window → do not return to the
/// degraded memory face: a healthy candidate face promotes as usual (reason
/// marked candidate table), and promote records the new face into memory.
#[test]
fn degraded_memory_face_is_skipped_for_healthy_candidate() {
    let wanted = vec![peer(
        "dev-b",
        "10.240.0.3",
        &[lan("192.168.1.50", 51821), lan("192.168.1.60", 51821)],
    )];
    let mut current = BTreeMap::new();
    let mut entry = direct_peer("dev-b", "10.240.0.3", PeerLinkState::Relay);
    entry.last_direct = Some(lan("192.168.1.50", 51821));
    current.insert("dev-b".into(), entry);
    let mut unhealthy = BTreeSet::new();
    unhealthy.insert(("dev-b".to_string(), lan("192.168.1.50", 51821)));
    let (updates, records) = plan_updates_logged(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &unhealthy,
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(
        matches!(&updates[0], DirectUpdate::Promote { endpoint, .. }
    if endpoint.to_string() == "192.168.1.60:51821"),
        "healthy candidate beats degraded memory face"
    );
    assert_eq!(records.len(), 1);
    assert!(
        records[0].reason.contains("candidate table"),
        "memory face was skipped: {}",
        records[0].reason
    );
    // promote records the newly dialed face into memory (the old face steps
    // aside).
    assert_eq!(
        current.get("dev-b").unwrap().last_direct,
        Some(lan("192.168.1.60", 51821))
    );
}

/// The memory face is degraded and the candidate table has no path → defer
/// names the memory face (the only bad point is replayable), and the memory
/// face is not cleared (once the face recovers it is preferred again as
/// usual).
#[test]
fn degraded_memory_face_without_table_path_defers_naming_it() {
    let wanted = vec![peer("dev-b", "10.240.0.3", &[])];
    let mut current = BTreeMap::new();
    let mut entry = direct_peer("dev-b", "10.240.0.3", PeerLinkState::Relay);
    entry.last_direct = Some(lan("192.168.1.77", 51821));
    current.insert("dev-b".into(), entry);
    let mut unhealthy = BTreeSet::new();
    unhealthy.insert(("dev-b".to_string(), lan("192.168.1.77", 51821)));
    let (updates, records) = plan_updates_logged(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &unhealthy,
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(updates.is_empty());
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].action, "defer");
    assert_eq!(records[0].endpoint, "192.168.1.77:51821");
    assert_eq!(
        current.get("dev-b").unwrap().last_direct,
        Some(lan("192.168.1.77", 51821)),
        "memory face kept for recovery"
    );
}

/// No baseline / probes off (the unhealthy set is empty) → the filter does not
/// apply, fully identical to the old behavior (the 9-parameter version called
/// directly; equivalent to the 8-parameter wrapper with an empty set).
#[test]
fn empty_unhealthy_set_keeps_legacy_promotion_behavior() {
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    let (updates, records) = plan_updates_logged(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(matches!(&updates[0], DirectUpdate::Promote { endpoint, .. }
    if endpoint.to_string() == "192.168.1.50:51821"));
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].action, "promote");
}

/// FLIP-001 integration simulation (the flip sequence, domain-layer view):
/// the old configured face degrades → SEL-003 demote → the effective
/// candidate set contains the kernel's new roaming face (produced by
/// merge_into on the candidate table, probe-healthy) → the next round's
/// promote lands on the healthy new face (memory/degraded faces filtered out
/// by unhealthy) → round 3 is a Keep with no action — asserting no
/// promote→demote ring is produced.
#[test]
fn flip_sequence_promotes_healthy_roaming_face_without_ring() {
    let scope = cidr(OVERLAY);
    let self_vip = "10.240.0.2".parse().unwrap();
    let face_a = lan("192.168.5.11", 51820); // the server's candidate face (the degraded ZT face)
    let face_b = lan("192.168.5.23", 51820); // the kernel's new roaming face (healthy)
    let my_lan = [cidr("192.168.5.0/24")];
    // The server's candidates carry only face_a; the effective set after the
    // candidate-table merge contains face_b.
    let effective = [peer("dev-b", "10.240.0.3", &[face_a, face_b])];
    let mut current = BTreeMap::new();
    current.insert(
        "dev-b".into(),
        direct_peer("dev-b", "10.240.0.3", PeerLinkState::Direct),
    );
    // The face_a direct link was established by the original promote (the
    // promote action writes the memory face); the fixture mirrors that.
    current.get_mut("dev-b").unwrap().last_direct = Some(face_a);

    // Round 1: face_a's probe window degrades → immediate return to relay;
    // the Direct memory face is kept.
    let degraded: BTreeMap<String, bool> = [("dev-b".to_string(), true)].into();
    let (updates, _) = plan_updates_logged(
        &effective,
        &my_lan,
        scope,
        self_vip,
        &mut current,
        &BTreeMap::new(),
        &degraded,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert_eq!(
        updates,
        vec![DirectUpdate::Demote {
            public_key: "dev-b".into()
        }]
    );
    assert_eq!(current["dev-b"].state, PeerLinkState::Relay);
    assert_eq!(
        current["dev-b"].last_direct,
        Some(face_a),
        "Direct demote keeps memory face"
    );

    // Round 2: Relay, the recovery gate released (FLIP-001 bypass semantics =
    // empty hold_relay); face_a still degraded (unhealthy_faces) → the memory
    // face is filtered → only face_b remains among the post-filter healthy
    // candidates → promote lands on the new face (without the old "demote
    // first, then wait for the recovery gate" path).
    let unhealthy: BTreeSet<(String, EndpointCandidate)> = [("dev-b".to_string(), face_a)].into();
    let (updates, records) = plan_updates_logged(
        &effective,
        &my_lan,
        scope,
        self_vip,
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &unhealthy,
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert_eq!(
        updates,
        vec![DirectUpdate::Promote {
            public_key: "dev-b".into(),
            allowed_ips: vec![cidr("10.240.0.3/32")],
            endpoint: face_b.socket(),
        }],
        "promote lands on the healthy roaming face, not the degraded config face"
    );
    assert!(
        records
            .iter()
            .any(|r| r.action == "promote" && r.reason.contains("candidate table")),
        "reason={:?}",
        records.iter().map(|r| &r.reason).collect::<Vec<_>>()
    );
    assert_eq!(
        current["dev-b"].last_direct,
        Some(face_b),
        "memory face moves to the new healthy face"
    );

    // Round 3: face_b direct, fresh handshake (30s, inside the health
    // window), probe-healthy → Keep with no action; the ring converges.
    current.get_mut("dev-b").unwrap().state = PeerLinkState::Direct;
    let fresh_hs: BTreeMap<String, u64> = [("dev-b".to_string(), 30)].into();
    let (updates, _) = plan_updates_logged(
        &effective,
        &my_lan,
        scope,
        self_vip,
        &mut current,
        &fresh_hs,
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(updates.is_empty(), "healthy direct link holds; no ring");
    assert_eq!(current["dev-b"].state, PeerLinkState::Direct);
}

#[test]
fn demote_backoff_suppresses_promote_but_keeps_memory_face() {
    // FLIP-002: a Relay peer under suppression does not promote this round —
    // the state stays relay, the memory face is kept as-is, and the decision
    // record has action="defer" with a reason from the suppress map.
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    current.insert(
        "dev-b".into(),
        direct_peer("dev-b", "10.240.0.3", PeerLinkState::Relay),
    );
    current.get_mut("dev-b").unwrap().last_direct = Some(lan("192.168.1.50", 51821));
    let suppress = [(
        "dev-b".to_string(),
        "promote deferred: demote backoff (2 consecutive demote(s), cooling 55s more; FLIP-002)"
            .to_string(),
    )]
    .into();
    let (updates, records) = plan_updates_logged(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &suppress,
    );
    assert!(updates.is_empty(), "suppressed peer must not promote");
    assert_eq!(
        current.get("dev-b").map(|p| p.state),
        Some(PeerLinkState::Relay),
        "suppression holds the peer at relay"
    );
    assert_eq!(
        current["dev-b"].last_direct,
        Some(lan("192.168.1.50", 51821)),
        "memory face survives the defer (retry lands on it)"
    );
    let defer = records
        .iter()
        .find(|r| r.action == "defer")
        .expect("defer decision record");
    assert_eq!(defer.public_key, "dev-b");
    assert!(
        defer.reason.contains("demote backoff"),
        "reason comes from the suppress map: {}",
        defer.reason
    );
}

#[test]
fn demote_backoff_does_not_touch_demote_sensitivity() {
    // FLIP-002: backoff only blocks the promote side — when the direct link
    // degrades (handshake expired), the demote fires as usual even if the
    // peer is in the suppress map (verdict sensitivity is not lowered).
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    current.insert(
        "dev-b".into(),
        direct_peer("dev-b", "10.240.0.3", PeerLinkState::Direct),
    );
    let mut ages = BTreeMap::new();
    ages.insert("dev-b".into(), DIRECT_HEALTH_WINDOW_SECS.saturating_add(1));
    let suppress = [("dev-b".to_string(), "cooling".to_string())].into();
    let (updates, _) = plan_updates_logged(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &ages,
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &suppress,
    );
    assert!(
        matches!(&updates[0], DirectUpdate::Demote { public_key } if public_key == "dev-b"),
        "stale handshake demotes even while suppressed"
    );
    assert_eq!(current["dev-b"].state, PeerLinkState::Relay);
}

#[test]
fn demote_backoff_expiry_restores_normal_promotion() {
    // FLIP-002: suppression expired (the map no longer contains the peer) →
    // promote is restored, memory face first. Same fixture: defer while
    // suppressed, then with an empty map (cleared/expired) promote fires
    // normally.
    let face = lan("192.168.1.50", 51821);
    let wanted = vec![peer("dev-b", "10.240.0.3", &[face])];
    let mut current = BTreeMap::new();
    current.insert(
        "dev-b".into(),
        direct_peer("dev-b", "10.240.0.3", PeerLinkState::Relay),
    );
    current.get_mut("dev-b").unwrap().last_direct = Some(face);
    let suppress = [("dev-b".to_string(), "cooling".to_string())].into();
    let (updates, _) = plan_updates_logged(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &suppress,
    );
    assert!(updates.is_empty(), "cooling: defer");

    let (updates, _) = plan_updates_logged(
        &wanted,
        &[cidr(HOME)],
        cidr(OVERLAY),
        "10.240.0.2".parse().unwrap(),
        &mut current,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(
        matches!(&updates[0], DirectUpdate::Promote { endpoint, .. } if *endpoint == face.socket()),
        "expiry restores promotion, memory face first"
    );
}
