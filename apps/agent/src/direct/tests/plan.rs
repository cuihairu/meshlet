//! plan_updates / merge_handshake_ages 纯函数用例：候选决策与 `/32` 边界、
//! SEL-003 劣化回退与恢复门、pending 晋升门槛、握手年龄兜底合并。

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
    );
    assert!(updates.is_empty());
    assert_eq!(
        current.get("dev-b").map(|p| p.state),
        Some(PeerLinkState::Relay)
    );
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
    );
    assert!(updates.is_empty(), "healthy direct peer: keep, no churn");
    assert_eq!(
        current.get("dev-b").map(|p| p.state),
        Some(PeerLinkState::Direct)
    );
}

#[test]
fn stale_handshake_demotes_but_stale_peer_removed_from_wanted_demotes_too() {
    // 直连过期（握手年龄超过健康窗口）→ 回退。
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
    );
    assert!(matches!(&updates[0], DirectUpdate::Demote { public_key } if public_key == "dev-b"));
    assert_eq!(
        current.get("dev-b").map(|p| p.state),
        Some(PeerLinkState::Relay)
    );

    // 对端从候选集消失（撤销/下线）→ 即使健康也回退并移除。
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
    );
    assert!(matches!(&updates[0], DirectUpdate::Demote { public_key } if public_key == "dev-b"));
    assert!(current2.is_empty());
}

#[test]
fn degraded_direct_peer_immediately_falls_back_to_relay() {
    // SEL-003：直连路径劣化（丢包尖峰/超时）→ 立即 Demote 回中继。
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
    // 未标劣化 → 不触发回退。
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
    );
    assert!(updates.is_empty(), "healthy direct peer: no demote");
    assert_eq!(
        current.get("dev-b").map(|p| p.state),
        Some(PeerLinkState::Direct)
    );
}

#[test]
fn recovery_after_degradation_repromotes_via_state_machine() {
    // SEL-003 恢复：回中继后，下一周期健康 → 状态机重新 Promote（按迟滞
    // 闸切回）。这里验证 Relay→Promote 恢复路径（RecoveryGate 在 agent 侧
    // 门控「连续 N 轮健康」后才允许再次进入候选决策）。
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
    // SEL-003 恢复门：回中继后未连续健康 N 轮（hold_relay 含该对端）→
    // 即使有直连路径也保持中继，不立即切回（防抖）。
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
        &hold,
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

/// 修复回归（用户实测：直连每次都是「拨号中」）：pending 已握上手（握手
/// 新鲜）但 ICMP 探测永不成功（degraded 为空、探测读数不可用）→ 必须
/// 当轮晋升 Direct，不再等满 attempts 超时回退。
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
        &BTreeMap::new(), // 探测全失败 → 无窗口 → degraded 为空
        &BTreeSet::new(),
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

/// 握手过期（超过健康窗口）→ pending 判失效回退（降级口径不放松）。
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

/// 握手读数兜底合并：专项读数优先，dump 只补缺失键；专项全空（Windows
/// 隧道抖动期 latest-handshakes 不可读）→ dump 独挑，晋升门槛仍有输入。
#[test]
fn merge_handshake_ages_fills_missing_keys_from_dump() {
    let mut dedicated = BTreeMap::new();
    dedicated.insert("hub".into(), 3u64);
    let mut dump = BTreeMap::new();
    dump.insert("hub".into(), 99u64); // 专项已有 → 不覆盖
    dump.insert("peer-b".into(), 12u64); // 专项缺失 → 补齐
    let merged = merge_handshake_ages(dedicated, dump.clone());
    assert_eq!(merged.get("hub"), Some(&3));
    assert_eq!(merged.get("peer-b"), Some(&12));

    // 专项读数整体失败（空）→ dump 独挑。
    let merged = merge_handshake_ages(BTreeMap::new(), dump);
    assert_eq!(merged.get("hub"), Some(&99));
    assert_eq!(merged.get("peer-b"), Some(&12));
}

/// SEL-003 验收：可注入时钟的完整回退/恢复时序单测（任务书允许 netns 不可
/// 用时的替代）。模拟一轮轮「探测周期」（degraded / 健康 是注入的时钟信号）：
/// ① 健康直连 → 保持；② 直连劣化（丢包尖峰/超时）→ 立即回中继（Demote）；
/// ③ 回中继后未连续健康 N(=3) 轮 → 保持中继（不切回）；④ 连续 3 轮健康 →
/// 恢复门放行 → 状态机重新 Promote（切回）。
#[test]
fn sel003_fallback_and_recovery_timeline() {
    use meshlet_network::probe::RecoveryGate;
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    let mut recovery = RecoveryGate::new(3);

    // 每轮跑：degraded 注入 → 恢复门记录 → hold 集合 → 状态机。
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
            &hold,
        )
    }

    // ① 健康 → 首次 Promote（DirectPending）。
    let updates = run_round(&wanted, &mut current, &mut recovery, false);
    assert!(
        matches!(&updates[0], DirectUpdate::Promote { .. }),
        "initial promote"
    );
    // ② 劣化 → 立即 Demote 回中继。
    let updates = run_round(&wanted, &mut current, &mut recovery, true);
    assert!(
        matches!(&updates[0], DirectUpdate::Demote { public_key } if public_key == "dev-b"),
        "degraded immediately falls back: {updates:?}"
    );
    assert_eq!(current.get("dev-b").unwrap().state, PeerLinkState::Relay);
    // ③ 回中继后第 1、2 轮健康：恢复门未满 3 轮 → 保持中继（不切回）。
    let u1 = run_round(&wanted, &mut current, &mut recovery, false);
    assert!(u1.is_empty(), "round 1 healthy after fallback: hold {u1:?}");
    let u2 = run_round(&wanted, &mut current, &mut recovery, false);
    assert!(u2.is_empty(), "round 2 healthy after fallback: hold {u2:?}");
    assert_eq!(current.get("dev-b").unwrap().state, PeerLinkState::Relay);
    // ④ 第 3 轮健康：恢复门放行 → 重新 Promote（切回）。
    let u3 = run_round(&wanted, &mut current, &mut recovery, false);
    assert!(
        matches!(&u3[0], DirectUpdate::Promote { .. }),
        "round 3 healthy after fallback: switch back {u3:?}"
    );
}

/// 「握手新鲜短路」补口子（2026-11-13 SEL-002 双机验收实锤）：直连对端
/// 握手证据新鲜（classify_probe 按 240s 健康窗口必判 Healthy）但探测窗口
/// 持续深劣化（真机实录 1715ms probe_ok / hs 冻结 133–203s 钉直连）时，
/// 劣化闸必须优先于 freshness——立即 Demote 回中继，探测参与判定。
#[test]
fn degraded_latency_demotes_even_with_fresh_handshake() {
    let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
    let mut current = BTreeMap::new();
    current.insert(
        "dev-b".into(),
        direct_peer("dev-b", "10.240.0.3", PeerLinkState::Direct),
    );
    // 握手年龄 5s（远在 240s 健康窗口内——freshness 证据满分）。
    let mut ages = BTreeMap::new();
    ages.insert("dev-b".to_string(), 5u64);
    // 探测窗口持续深劣化（时延维度，is_degraded 的中位数规则命中）。
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
    );
    assert!(
        matches!(&updates[0], DirectUpdate::Demote { public_key } if public_key == "dev-b"),
        "fresh handshake must not outrank sustained degradation: {updates:?}"
    );
    assert_eq!(current.get("dev-b").unwrap().state, PeerLinkState::Relay);
}
