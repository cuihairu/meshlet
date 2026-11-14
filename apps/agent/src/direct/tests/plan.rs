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
        &BTreeSet::new(),
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
            &BTreeSet::new(),
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
        &BTreeSet::new(),
    );
    assert!(
        matches!(&updates[0], DirectUpdate::Demote { public_key } if public_key == "dev-b"),
        "fresh handshake must not outrank sustained degradation: {updates:?}"
    );
    assert_eq!(current.get("dev-b").unwrap().state, PeerLinkState::Relay);
}

/// stranded 根修（2026-11-14 巡检单，候选表纳管 roaming 面的等价机制）：
/// 回中继后的再晋升优先选回记忆面——上次直连实际在用的 endpoint（含内核
/// 漫游出来的、不在服务端候选表的 roaming 面）。候选表按最低 IP 取 SameLan
/// 会拿 10.x ZT 面压过 192.168.x 面（stranded 实锤：re-promote 只能挑表内
/// ZT 面，回不到健康面，~1-5min direct↔hub 回收）。
#[test]
fn repromote_returns_to_remembered_face_over_lower_ip_table_face() {
    // 表内候选：ZT 面 10.x（SameLan 合格、IP 最低）+ 公网；记忆面 192.168.5.x
    // （表外 roaming 面，健康且无探测窗口）。
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

    // SEL-003 劣化 → 立即回退；已建立的 Direct 保留记忆面。
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
    );
    assert!(matches!(&updates[0], DirectUpdate::Demote { .. }));
    assert_eq!(current.get("dev-b").unwrap().state, PeerLinkState::Relay);
    assert_eq!(
        current.get("dev-b").unwrap().last_direct,
        Some(remembered),
        "degrade fallback from Direct keeps the remembered face"
    );

    // 下一周期再晋升：选回记忆面，而不是表内 IP 最低的 ZT 面。
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
    );
    assert!(
        matches!(&updates[0], DirectUpdate::Promote { endpoint, .. }
        if endpoint.to_string() == "192.168.5.11:51820"),
        "re-promote must return to the remembered roaming face: {updates:?}"
    );
}

/// 记忆面的死面逃生：pending 验证失败（3 拍无握手）的回退弃用记忆——
/// 对端已漫游走（旧面真死了）时，再晋升退回候选表决策，不死锁旧面。
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
    );
    assert!(matches!(&updates[0], DirectUpdate::Demote { .. }));
    assert_eq!(
        current.get("dev-b").unwrap().last_direct,
        None,
        "pending verify failure must drop the remembered face"
    );

    // 下一周期：无记忆 → 表内 SameLan 面胜出（旧记忆面不再被选）。
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
    );
    assert!(
        matches!(&updates[0], DirectUpdate::Promote { endpoint, .. }
        if endpoint.to_string() == "192.168.5.99:51820"),
        "table decision takes over once memory is dropped: {updates:?}"
    );
}

/// 恢复门保持中继期间记忆面穿透：门放行后的再晋升仍优先选回它。
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
    );
    assert!(updates.is_empty(), "held peer stays relay: {updates:?}");
    assert_eq!(
        current.get("dev-b").unwrap().last_direct,
        Some(lan("192.168.5.11", 51820)),
        "hold must not wipe the remembered face"
    );
}

/// 首次晋升（无记忆）与已建立直连的周期不受影响：表决策原样（既有回归
/// 不松动）；promote 动作把要拨的面记入记忆，供下次回退后选回。
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
// 决策记录（plan_updates_logged；2026-11-14 观测性欠账：无控制台上下文的
// 事后回放——每条迁移/动作带 mode、reason、判据输入）
// ---------------------------------------------------------------------------

/// 劣化降级：决策记录带 mode 迁移方向、劣化标记、判据（握手年龄）与
/// 涉事 endpoint（降级前的现役面）。
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

/// 记忆面再晋升（880b49a 语义）：候选表为空、仅 last_direct 可行 → 决策
/// 记录写明来源是记忆面（回放时能区分「候选表选路」与「选回上次的面」）。
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

/// 候选表首次晋升（无记忆）：来源标 candidate table。
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
    );
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].action, "promote");
    assert_eq!(records[0].from_mode, "hub_relay");
    assert_eq!(records[0].to_mode, "direct_pending");
    assert!(records[0].reason.contains("candidate table"));
    assert_eq!(records[0].endpoint, "192.168.1.50:51821");
}

/// pending 验成（Keep 动作但状态迁移 direct_pending → p2p_direct）：
/// 也记 promote——mode_flip 事件靠 from_mode ≠ to_mode 触发，不漏这次翻转。
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
    );
    assert!(updates.is_empty(), "promotion is a keep, no churn");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].action, "promote");
    assert_eq!(records[0].from_mode, "direct_pending");
    assert_eq!(records[0].to_mode, "p2p_direct");
    assert!(records[0].reason.contains("pending verified"));
    assert_eq!(records[0].handshake_age_secs, Some(30));
}

/// pending 等待轮（attempts+1，模式不变）：决策记录逐轮入账（回放等待
/// 过程），但 from_mode = to_mode 不产生 mode_flip 事件。
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
    );
    assert!(updates.is_empty());
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].action, "probe");
    assert_eq!(records[0].from_mode, "direct_pending");
    assert_eq!(records[0].to_mode, "direct_pending");
    assert!(records[0].reason.contains("attempt 2"));
}

/// 恢复门 hold_relay：逐轮入账（回放「为什么还不切回」），模式不变。
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

/// 对端离开候选集（撤销/下线/换段）：决策记录留痕（from_mode 取迁移前
/// 状态），管理状态移除。
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
    );
    assert!(matches!(&updates[0], DirectUpdate::Demote { public_key } if public_key == "dev-b"));
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].action, "demote");
    assert_eq!(records[0].from_mode, "p2p_direct");
    assert_eq!(records[0].to_mode, "hub_relay");
    assert_eq!(records[0].reason, "peer left the candidate set");
    assert!(current.is_empty());
}

/// 稳态不刷屏：健康直连保持、无路径中继保持都是 Keep 且状态不变 →
/// 零决策记录（决策日志只收迁移与动作，不给每对端每周期一条噪声）。
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
    );
    assert!(records.is_empty(), "healthy keep: no records");

    // 无可行路径的中继保持：同样零记录。
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
    );
    assert!(updates.is_empty());
    assert!(records.is_empty(), "relay keep without a path: no records");
}

// ---------------------------------------------------------------------------
// promote 偏好健康面（unhealthy_faces 前置过滤；巡检单 nov14-1410 三选一
// 之二：劣化面上 re-promote 只会立刻再降级——翻转循环的客户端侧断路器）
// ---------------------------------------------------------------------------

/// 候选表唯一面正处劣化窗口 → 本轮 defer：零动作（不上劣化面）、决策记录
/// 留痕（劣化面 endpoint 可回放）、状态保持中继、记忆面保留。
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

/// 两个公网候选、低地址面劣化 → 选高地址健康面（健康面偏好，不是一刀切
/// defer：有健康替代就照常晋升）。
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

/// 记忆面正处劣化窗口 → 不选回劣化记忆面：健康候选面照常晋升（reason 标
/// candidate table），promote 把新面记入记忆。
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
    // promote 把要拨的新面记入记忆（旧面让位）。
    assert_eq!(
        current.get("dev-b").unwrap().last_direct,
        Some(lan("192.168.1.60", 51821))
    );
}

/// 记忆面劣化且候选表无路 → defer 点名记忆面（唯一坏点可回放），记忆面
/// 不清（面恢复后照常优先选回）。
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

/// 无基线/探测关（unhealthy 集为空）→ 过滤不生效，与旧口径完全一致
/// （9 参数版直呼；等价于 8 参数 wrapper 传空集）。
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
    );
    assert!(matches!(&updates[0], DirectUpdate::Promote { endpoint, .. }
    if endpoint.to_string() == "192.168.1.50:51821"));
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].action, "promote");
}
