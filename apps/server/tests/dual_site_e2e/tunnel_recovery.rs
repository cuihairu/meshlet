//! 断线自愈全链路（P2，2026-11-12 任务清单；R-07 soak 前置门禁）。
//!
//! 场景：隧道接口被杀（`ip link del wg0`，即 Windows WireGuardNT 崩溃/
//! 驱动重置的 netns 等价物）→ agent 一轮 tick 感知并重建 → 与 hub 重新
//! 握手 → server 侧设备时间线前进、在线判定收敛回 `online`——全链路
//! ≤60s（任务口径）。数据面真跑：需要 sudo -n + wireguard-tools，缺席
//! 则 SKIP（与其它 dual_site 用例同一守卫）。

#![cfg(target_os = "linux")]

use super::context::*;
use super::support::*;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// 从设备列表里摘一台设备（按 enroll 时的 device_name 匹配）。
fn device_of<'a>(devices: &'a Value, name: &str) -> &'a Value {
    devices
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == json!(name))
        .unwrap_or_else(|| panic!("device {name} not in list: {devices}"))
}

#[test]
fn killed_tunnel_is_rebuilt_within_sixty_seconds_and_the_server_sees_it() {
    let _guard = lock();
    let Some(ctx) = Context::setup() else {
        return;
    };
    // 铺底同 recovery.rs：一条真实业务路由 + 别名，站点2（lan2 在 g2 后面）
    // 经隧道可达——「10.241.2.x = 站点2 的 192.168.1.x」。
    let routes_uri = format!("/api/v1/networks/{}/routes", ctx.network_id);
    let aliases_uri = format!("/api/v1/networks/{}/aliases", ctx.network_id);
    let (code, route) = http_json(
        "POST",
        &format!("{}{routes_uri}", ctx.base),
        Some(&ctx.cookie),
        None,
        Some(json!({
            "gateway_device_id": ctx.g2_id,
            "destination_cidr": "192.168.1.0/24",
            "return_path_mode": "controlled_snat",
            "route_mode": "alias",
        })),
    );
    assert_eq!(code, 201, "route: {route}");
    let route_id = route["id"].as_str().unwrap().to_string();
    let (code, alias) = http_json(
        "POST",
        &format!("{}{aliases_uri}", ctx.base),
        Some(&ctx.cookie),
        None,
        Some(json!({
            "lan_route_id": route_id,
            "alias_cidr": "10.241.2.0/24",
            "translation_mode": "dnat_snat",
        })),
    );
    assert_eq!(code, 201, "alias: {alias}");
    ctx.apply_latest(&ctx.base_b, &ctx.network_b_id);
    ctx.apply_latest(&ctx.base, &ctx.network_id);
    for (node, token, name) in [
        (&ctx.topo.g1, ctx.g1_token.as_str(), "g1"),
        (&ctx.topo.g2, ctx.g2_token.as_str(), "g2"),
        (&ctx.topo.a, ctx.a_token.as_str(), "a"),
    ] {
        tick_agent(
            &ctx.dir,
            &ctx.base,
            name,
            node,
            token,
            Some(&ctx.hub_endpoint),
        );
    }
    tick_agent(
        &ctx.dir,
        &ctx.base_b,
        "laptop-b",
        &ctx.topo.b,
        ctx.b_token.as_str(),
        Some(&ctx.hub_b_endpoint),
    );
    for ns in [
        &ctx.topo.g1.netns,
        &ctx.topo.g2.netns,
        &ctx.topo.a.netns,
        &ctx.topo.hub2.netns,
        &ctx.topo.b.netns,
    ] {
        assert!(ctx.topo.wait_handshake(ns), "baseline handshake in {ns}");
    }

    // 基线：站点2 别名跨隧道可达，server 已把 laptop-a 判在线。
    let devices_before = ctx.devices();
    let baseline = device_of(&devices_before, "laptop-a");
    assert_eq!(
        baseline["online_state"], "online",
        "laptop-a must be online before the tunnel is killed: {baseline}"
    );
    let seen_before = baseline["last_seen_at"]
        .as_str()
        .expect("baseline last_seen_at")
        .to_string();
    let before = tcp_echo(
        &ctx.topo,
        &ctx.dir,
        &ctx.topo.lan2,
        "10.241.2.5",
        "site2",
        7812,
    );
    assert!(
        before.contains("site2"),
        "baseline cross-tunnel echo: {before}"
    );

    // 杀隧道：接口直接删掉（数据面事故的 netns 等价物）。控制面（HTTPS
    // 走 underlay）不受影响——与真机断线场景一致。
    require_ok(
        &netns_exec(&ctx.topo.a.netns, &["ip", "link", "del", "wg0"]),
        "kill the tunnel interface",
    );
    // now() 是秒级精度：留一秒保证重建后心跳时间戳严格前进。
    std::thread::sleep(Duration::from_secs(1));

    // 全链路计时（任务口径 ≤60s）：从「开始自愈」到「server 看到收敛」。
    let started = Instant::now();
    let deadline = started + Duration::from_secs(60);

    // agent 感知并重建：一轮 tick 对账（账本仍在，内核漂移被收敛）。
    tick_agent(
        &ctx.dir,
        &ctx.base,
        "a",
        &ctx.topo.a,
        ctx.a_token.as_str(),
        Some(&ctx.hub_endpoint),
    );
    assert!(
        ctx.topo.wait_handshake(&ctx.topo.a.netns),
        "handshake must re-establish after rebuild"
    );

    // server 状态收敛：laptop-a 的时间线前进（新心跳到达）、在线判定回
    // `online` 且来源是 agent 上报（presence 收敛的完整口径）。
    let mut view = device_of(&ctx.devices(), "laptop-a").clone();
    while view["last_seen_at"] == json!(seen_before) {
        assert!(
            Instant::now() < deadline,
            "server view did not converge within 60s: last_seen_at stuck at {seen_before}"
        );
        std::thread::sleep(Duration::from_millis(200));
        view = device_of(&ctx.devices(), "laptop-a").clone();
    }
    assert!(
        view["last_seen_at"].as_str().unwrap() > seen_before.as_str(),
        "device timeline must advance after the rebuild: {} -> {}",
        seen_before,
        view["last_seen_at"]
    );
    assert_eq!(
        view["online_state"], "online",
        "presence must converge back to online: {view}"
    );
    assert_eq!(
        view["presence_source"], "agent_report",
        "converged state must come from a fresh agent report: {view}"
    );
    // 修订面不残留卡死：没有任何修订停在 applying（§10.3——被中断的 applying
    // 只有收敛为 failed 才合法；pending/applied 是正常历史，superseded 的
    // 旧修订保持 pending 属预期）。
    let revisions = admin(
        &ctx.base,
        &ctx.cookie,
        "GET",
        &format!("/api/v1/networks/{}/config-revisions", ctx.network_id),
        None,
    );
    for revision in revisions.as_array().unwrap() {
        assert_ne!(
            revision["apply_status"], "applying",
            "no revision may be stuck mid-apply after self-healing: {revision}"
        );
    }
    // 数据面恢复：跨隧道 echo 重新可达。
    let after = tcp_echo(
        &ctx.topo,
        &ctx.dir,
        &ctx.topo.lan2,
        "10.241.2.5",
        "site2",
        7813,
    );
    assert!(
        after.contains("site2"),
        "recovered cross-tunnel echo: {after}"
    );

    assert!(
        started.elapsed() <= Duration::from_secs(60),
        "full self-healing chain took {:?} (budget 60s)",
        started.elapsed()
    );
    println!(
        "self-healing chain (kill -> rebuild -> handshake -> server view -> echo): {:?}",
        started.elapsed()
    );
    let _ = std::fs::remove_dir_all(&ctx.dir);
}
