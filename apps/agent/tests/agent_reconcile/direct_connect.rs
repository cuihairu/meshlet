use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use meshlet_network::linux::LinuxNetworkBackend;

use crate::common::{
    agent_in_direct, endpoints_body, hub_plan, leaf_plan, netns_exec, require_ok,
    spawn_endpoint_server, temp_state_dir, Topology, HANDSHAKE_TIMEOUT,
};

/// On-box acceptance for §12 direct-connect setup/fallback: drives the **full real flow** — the mock
/// agent API serves candidates -> `reconcile_direct` (fetch candidates -> domain-layer state machine ->
/// `wg set`) establishes a same-LAN direct link -> with the hub ingress closed traffic still flows (proving
/// it rides the direct peer, the longer /32 prefix winning) -> the server withdraws the candidate -> the
/// state machine falls back and removes the direct peer -> traffic resumes via hub. Reconcile must never clear direct peers as drift; injected foreign peers still must be cleared as drift.
#[test]
fn agent_direct_connect_establishes_and_falls_back_to_hub() {
    let topo = match Topology::setup("d") {
        Some(t) => t,
        None => return, // printed SKIP already:
    };
    let port: u16 = 51820;

    // ---- mock agent API: A sees candidate B and B sees candidate A (each on its own LAN endpoint) ----
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

    // ---- hub side first (server data plane) -------------------------------
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

    // ---- start one direct-configured agent for each of A and B: reconcile binds wg0 to the direct port ----
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
    // ---- one real direct probe round (fetch candidates -> SameLan decision -> wg set) ----
    a_agent.reconcile_direct(&a_plan);
    b_agent.reconcile_direct(&b_plan);

    // The direct handshake comes up (keepalive triggers every 15s; the domain health window is 35s).
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

    // ---- §12.3 status reporting: wait for a probe cycle that becomes "due" (the 30s throttle really
    // applies; keepalive refreshes the handshake every 15s -> the due cycle reads healthy -> the state
    // machine switches to Direct). The link state then exports "direct" carrying the handshake-age snapshot from that probe (for hub/console display). ----
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

    // ---- close the hub ingress: point A's/B's hub peer endpoint at a dead address. A->B still
    // working afterwards must be carried by the direct peer (/32 longest prefix), not the hub. ----
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

    // ---- reconcile must not clear direct peers as drift: still present after reconcile, no replay ----
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

    // ---- server withdraws the candidate (B goes offline) -> next probe cycle the state machine falls back and removes the direct peer ----
    responses
        .lock()
        .unwrap()
        .iter_mut()
        .for_each(|(_, body)| *body = "[]".into());
    let demoted = {
        let start = Instant::now();
        loop {
            // Within the 30s throttle a new cycle would not fire, so just drive another round (the test is not bound by throttling semantics).
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

    // ---- §12.3 status reporting clears on fallback: the peer is no longer reported (the UI defaults to relay presentation) ----
    assert!(
        a_agent.direct_link_statuses().is_empty(),
        "no direct link reported after fallback"
    );

    // ---- restore the hub ingress -> traffic resumes via hub ----
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

    // ---- after fallback reconcile holds no direct-connect retention set and replays nothing (a missing direct peer is not drift)
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
