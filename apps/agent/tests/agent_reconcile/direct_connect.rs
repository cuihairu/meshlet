use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use meshlet_network::linux::LinuxNetworkBackend;

use crate::common::{
    agent_in_direct, endpoints_body, hub_plan, leaf_plan, netns_exec, require_ok,
    spawn_endpoint_server, temp_state_dir, Topology, HANDSHAKE_TIMEOUT,
};

/// §12 直连建立/回退的真机验收：走**完整真实流程**——mock agent API 下发候选
/// → `reconcile_direct`（拉候选 → 域层状态机 → `wg set`）建立同网段直连 →
/// hub 入口关闭仍通（证明走的是直连，/32 长前缀优先）→ 服务端撤候选 →
/// 状态机回退并移除直连 → 经 hub 恢复。对账全程不得把直连对端当漂移清掉；
/// 外来 peer 注入仍必须按漂移清除。
#[test]
fn agent_direct_connect_establishes_and_falls_back_to_hub() {
    let topo = match Topology::setup("d") {
        Some(t) => t,
        None => return, // 已打印 SKIP:
    };
    let port: u16 = 51820;

    // ---- mock agent API：A 看到候选 B，B 看到候选 A（各自 LAN endpoint）----
    let (server_url, responses) = spawn_endpoint_server(vec![
        (
            "tok-a".into(),
            endpoints_body(&topo.b.public_key, &topo.b.overlay, &topo.b.underlay, port),
        ),
        (
            "tok-b".into(),
            endpoints_body(&topo.a.public_key, &topo.a.overlay, &topo.a.underlay, port),
        ),
    ]);

    // ---- hub 侧先行（server 数据面） --------------------------------------
    let mut hub_backend = LinuxNetworkBackend::new()
        .with_netns(&topo.hub.netns)
        .with_sudo()
        .with_interface("wg0");
    hub_backend
        .apply_device_plan_sync(
            &hub_plan(&topo),
            Some(topo.hub.private_key.clone()),
            None,
            &BTreeSet::new(),
        )
        .expect("hub applies its own plan");

    // ---- A、B 各起一个带直连配置的 agent：reconcile 把 wg0 绑到直连端口 ----
    let a_dir = temp_state_dir("direct-a");
    let b_dir = temp_state_dir("direct-b");
    let mut a_agent = agent_in_direct(&topo.a, &a_dir, port, &server_url, "tok-a");
    let mut b_agent = agent_in_direct(&topo.b, &b_dir, port, &server_url, "tok-b");
    let a_plan = leaf_plan(
        &topo.a,
        &topo.hub,
        &["10.240.0.0/16"],
        &[],
        Vec::new(),
        "hash-a-d",
    );
    let b_plan = leaf_plan(
        &topo.b,
        &topo.hub,
        &["10.240.0.0/16"],
        &[],
        Vec::new(),
        "hash-b-d",
    );
    a_agent.reconcile(&a_plan).expect("A applies hub plan");
    b_agent.reconcile(&b_plan).expect("B applies hub plan");
    assert!(topo.wait_handshake(&topo.a.netns), "A hub handshake");
    assert!(topo.wait_handshake(&topo.b.netns), "B hub handshake");
    assert!(
        topo.ping_within(&topo.a.netns, &topo.b.overlay, HANDSHAKE_TIMEOUT),
        "A -> B via hub"
    );
    // ---- 真实直连探测一轮（拉候选 → SameLan 决策 → wg set 下发）----------
    a_agent.reconcile_direct(&a_plan);
    b_agent.reconcile_direct(&b_plan);

    // 直连握手建立（keepalive 15s 触发；域层健康窗口 35s 判健康）。
    let a_backend = LinuxNetworkBackend::new()
        .with_netns(&topo.a.netns)
        .with_sudo()
        .with_interface("wg0");
    let established = {
        let start = Instant::now();
        loop {
            let ages = a_backend.handshake_ages_sync().expect("A handshake ages");
            if ages.get(&topo.b.public_key).is_some_and(|age| *age <= 35) {
                break true;
            }
            if start.elapsed() >= HANDSHAKE_TIMEOUT {
                break false;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    };
    assert!(established, "direct handshake A <-> B did not establish");

    // ---- §12.3 状态上报：等一个「到期」探测周期（30s 节流真实生效，keepalive
    // 15s 持续刷新握手 → 到期周期读到健康 → 状态机转 Direct）。届时链路状态
    // 导出「direct」并携带探测时的握手年龄快照（供 hub/控制台展示）。------
    let reported_direct = {
        let start = Instant::now();
        loop {
            a_agent.reconcile_direct(&a_plan);
            let statuses = a_agent.direct_link_statuses();
            if statuses.first().is_some_and(|s| s.link_state == "direct") {
                break Some(statuses);
            }
            if start.elapsed() >= Duration::from_secs(50) {
                break None;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    };
    let statuses = reported_direct.expect("state machine promotes to Direct within a due probe");
    assert_eq!(statuses.len(), 1, "one direct link reported: {statuses:?}");
    assert_eq!(statuses[0].public_key, topo.b.public_key, "{statuses:?}");
    assert!(
        statuses[0]
            .last_handshake_age_secs
            .is_some_and(|age| age <= 35),
        "healthy handshake age snapshotted: {statuses:?}"
    );

    // ---- 关 hub 入口：A/B 的 hub peer endpoint 指到死地址。此后 A→B 仍通
    // 必然是直连 peer（/32 长前缀优先）承载，而非 hub。-------------------
    for node in [&topo.a, &topo.b] {
        require_ok(
            &netns_exec(
                &node.netns,
                &[
                    "wg",
                    "set",
                    "wg0",
                    "peer",
                    &topo.hub.public_key,
                    "endpoint",
                    "10.98.0.99:16180",
                ],
            ),
            "kill hub endpoint",
        );
    }
    assert!(
        topo.ping_within(&topo.a.netns, &topo.b.overlay, HANDSHAKE_TIMEOUT),
        "A -> B via direct with hub down"
    );
    assert!(
        topo.ping_within(&topo.b.netns, &topo.a.overlay, HANDSHAKE_TIMEOUT),
        "B -> A via direct with hub down"
    );

    // ---- 直连对端不得被对账当漂移清掉：reconcile 后仍在、且不重放 -------
    let decision = a_agent
        .reconcile(&a_plan)
        .expect("A reconcile with a direct peer");
    assert!(
        !decision.needs_apply,
        "a direct peer must not force a replay: {:?}",
        decision.reason
    );
    assert!(
        a_backend
            .handshake_ages_sync()
            .unwrap()
            .contains_key(&topo.b.public_key),
        "direct peer survived reconcile"
    );

    // ---- 服务端撤候选（B 下线）→ 下一探测周期状态机回退并移除直连 -------
    responses
        .lock()
        .unwrap()
        .iter_mut()
        .for_each(|(_, body)| *body = "[]".into());
    let demoted = {
        let start = Instant::now();
        loop {
            // 30s 节流内新周期不触发，直接再驱动一轮（测试不受节流约束语义）。
            a_agent.reconcile_direct(&a_plan);
            b_agent.reconcile_direct(&b_plan);
            if !a_backend
                .handshake_ages_sync()
                .unwrap()
                .contains_key(&topo.b.public_key)
            {
                break true;
            }
            if start.elapsed() >= Duration::from_secs(60) {
                break false;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    };
    assert!(demoted, "direct peer must be demoted after the revoke");

    // ---- §12.3 状态上报随回退清空：不再上报该对端（UI 默认按中继呈现）----
    assert!(
        a_agent.direct_link_statuses().is_empty(),
        "no direct link reported after fallback"
    );

    // ---- 恢复 hub 入口 → 经 hub 恢复 -------------------------------------
    for node in [&topo.a, &topo.b] {
        require_ok(
            &netns_exec(
                &node.netns,
                &[
                    "wg",
                    "set",
                    "wg0",
                    "peer",
                    &topo.hub.public_key,
                    "endpoint",
                    &format!("{}:16180", topo.hub.underlay),
                ],
            ),
            "restore hub endpoint",
        );
    }
    assert!(
        topo.ping_within(&topo.a.netns, &topo.b.overlay, HANDSHAKE_TIMEOUT),
        "A -> B via hub after fallback"
    );
    assert!(
        topo.ping_within(&topo.b.netns, &topo.a.overlay, HANDSHAKE_TIMEOUT),
        "B -> A via hub after fallback"
    );

    // ---- 回退后对账不再持有直连保留集，也不重放（缺失的直连对端不算漂移）
    let decision = a_agent
        .reconcile(&a_plan)
        .expect("A reconcile after fallback");
    assert!(
        !decision.needs_apply,
        "no replay after fallback: {:?}",
        decision.reason
    );

    drop(topo);
    for dir in [a_dir, b_dir] {
        std::fs::remove_dir_all(dir).ok();
    }
}
