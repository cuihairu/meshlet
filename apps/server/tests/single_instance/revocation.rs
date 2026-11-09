//! Device revocation and failed-revoke rollback must remove live access safely.
#![cfg(target_os = "linux")]
use super::boot::*;
use super::single_instance_support::*;
use axum::http::StatusCode;
use serde_json::{json, Value};

/// 场景 7：撤销一台在线设备后，它手里的旧计划重试不能重新获授权。三层都验：
/// 凭证边界（token 立即失效）、修订/哈希边界（旧回执满足不了新修订）、
/// 「再改一轮配置也不重授」；存活设备不受牵连。
#[tokio::test(flavor = "multi_thread")]
async fn revoked_device_cannot_reauthorize_its_stale_plan() {
    let Some(sandbox) = setup() else {
        return;
    };
    let boot = boot_network(&sandbox, "revoke-key.key").await;

    // hub 上记住的 peer 身份（peer 列表是 CSV，按字符串比对公钥）。
    let peers_of = |sandbox: &Sandbox| -> String {
        String::from_utf8_lossy(&ns(&sandbox.names[0], &["wg", "show", "wg0", "peers"]).stdout)
            .to_string()
    };
    let revoked_key = wg_own_public_key(&sandbox, 1);
    let live_key = wg_own_public_key(&sandbox, 2);
    assert!(
        peers_of(&sandbox).contains(&revoked_key),
        "hub must remember the device to be revoked"
    );
    assert!(peers_of(&sandbox).contains(&live_key));

    // 撤销前拿到的旧计划（peer 只有 hub：设备之间不互连，所以「重授」只能
    // 从 hub 侧的 peer 列表验证——上面的内核证据就是那条基准）。
    let stale = desired_plan(&boot.app, &boot.tokens[0]).await;
    assert_eq!(stale.tunnel.peers.len(), 1);
    assert_eq!(
        stale.tunnel.peers[0].public_key,
        wg_own_public_key(&sandbox, 0),
        "the only peer is the hub"
    );

    admin(
        &boot.app,
        &boot.cookie,
        &format!(
            "/api/v1/networks/{}/devices/{}/revoke",
            boot.network, boot.device_ids[0]
        ),
        json!({}),
    )
    .await;
    assert_eq!(
        apply(&boot.app, &boot.cookie, &boot.network).await["apply_status"],
        "applied"
    );
    let (_, revisions) = request(
        &boot.app,
        "GET",
        &format!("/api/v1/networks/{}/config-revisions", boot.network),
        Value::Null,
        Some(&boot.cookie),
        None,
    )
    .await;
    let latest_revision = revisions.as_array().unwrap().last().unwrap()["revision"]
        .as_u64()
        .unwrap();
    assert!(latest_revision > stale.desired_revision, "{revisions}");

    // 1) 凭证边界：同一个 token 立即失效——取不到计划，也交不进回执，
    // 无论回执里写的是旧修订号还是当前修订号。
    assert_eq!(
        request(
            &boot.app,
            "GET",
            "/api/v1/agent/device/desired",
            Value::Null,
            None,
            Some(&boot.tokens[0])
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    for revision in [stale.desired_revision, latest_revision] {
        let (status, body) = request(
            &boot.app,
            "POST",
            "/api/v1/agent/device/applied",
            json!({"desired_revision":revision,"plan_hash":stale.desired_config_hash,"error":null}),
            None,
            Some(&boot.tokens[0]),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }

    // 2) 修订 / 哈希边界：换成存活设备的合法凭证，旧计划同样满足不了新修订
    // ——旧修订号是「过期回执」，当前修订号配旧哈希是「哈希不符」。
    for revision in [stale.desired_revision, latest_revision] {
        let (status, body) = request(
            &boot.app,
            "POST",
            "/api/v1/agent/device/applied",
            json!({"desired_revision":revision,"plan_hash":stale.desired_config_hash,"error":null}),
            None,
            Some(&boot.tokens[1]),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }

    // 3) 存活设备的计划已不含被撤销 peer，期望哈希也变了。
    let live = desired_plan(&boot.app, &boot.tokens[1]).await;
    assert_ne!(
        live.desired_config_hash, stale.desired_config_hash,
        "the desired plan must change when a peer is revoked"
    );
    assert!(
        live.tunnel
            .peers
            .iter()
            .all(|p| p.public_key != revoked_key),
        "the revoked peer must not be in the live device's plan"
    );

    // 4) 内核侧已移除，且「再改一轮配置」也不会把它带回来。
    assert!(
        !peers_of(&sandbox).contains(&revoked_key),
        "hub must drop the revoked peer"
    );
    admin(
        &boot.app,
        &boot.cookie,
        &format!("/api/v1/networks/{}/routes", boot.network),
        json!({"gateway_device_id":boot.device_ids[1],"destination_cidr":"192.168.61.0/24","route_mode":"direct","return_path_mode":"dual_route"}),
    )
    .await;
    assert_eq!(
        apply(&boot.app, &boot.cookie, &boot.network).await["apply_status"],
        "applied"
    );
    assert!(
        !peers_of(&sandbox).contains(&revoked_key),
        "a fresh revision must not re-admit the revoked peer"
    );
    assert!(peers_of(&sandbox).contains(&live_key));
    assert!(
        !ping(&sandbox.names[2], "10.240.0.2"),
        "the revoked device must stay unreachable"
    );

    // 存活设备必须毫发无损：hub 侧仍有它的握手与流量计数（peer 行的尾部
    // 四列是 handshake / received / sent / keepalive）。
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let (live_handshaking, dump) = loop {
        let dump =
            String::from_utf8_lossy(&ns(&sandbox.names[0], &["wg", "show", "wg0", "dump"]).stdout)
                .to_string();
        let live_line = dump
            .lines()
            .find(|line| line.starts_with(live_key.as_str()));
        let fields: Vec<&str> = live_line.unwrap_or_default().split_whitespace().collect();
        let ok = fields.len() >= 4
            && fields[fields.len() - 4]
                .trim()
                .parse::<u64>()
                .is_ok_and(|handshake| handshake > 0)
            && fields[fields.len() - 3]
                .trim()
                .parse::<u64>()
                .is_ok_and(|received| received > 0);
        if ok || std::time::Instant::now() > deadline {
            break (ok, dump);
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    };
    assert!(
        live_handshaking,
        "the surviving device must keep handshaking: {dump}"
    );
}

/// M4：回滚/重试不得重授已撤销权限。安全语义优先于机械恢复——撤销后诱导
/// 一次失败应用再回滚，恢复出的 last_good_plan 必须先过当前授权快照，
/// 被撤销设备的访问不得重新打开，恢复日志也不得再记它。
#[tokio::test]
async fn rolling_back_a_failed_revoke_does_not_reopen_access() {
    let Some(sandbox) = setup() else {
        return;
    };
    let boot = boot_network(&sandbox, "revoke-rollback.key").await;

    // hub 上记住的 peer 身份（peer 列表是 CSV，按字符串比对公钥）。
    let peers_of = |sandbox: &Sandbox| -> String {
        String::from_utf8_lossy(&ns(&sandbox.names[0], &["wg", "show", "wg0", "peers"]).stdout)
            .to_string()
    };
    let revoked_key = wg_own_public_key(&sandbox, 1);
    let live_key = wg_own_public_key(&sandbox, 2);
    assert!(
        peers_of(&sandbox).contains(&revoked_key),
        "both devices must be authorized before the revoke"
    );
    assert!(peers_of(&sandbox).contains(&live_key));

    // 外来路由占住目的段，后续 apply 的路由步必失败——失败应用可控。
    net(
        &sandbox.names[0],
        &["ip", "route", "add", "192.168.99.0/24", "dev", "lo"],
    );
    admin(
        &boot.app,
        &boot.cookie,
        &format!("/api/v1/networks/{}/routes", boot.network),
        json!({
            "gateway_device_id": boot.device_ids[1],
            "destination_cidr": "192.168.99.0/24",
            "route_mode": "direct",
            "return_path_mode": "dual_route"
        }),
    )
    .await;
    let failed_route = apply(&boot.app, &boot.cookie, &boot.network).await;
    assert_eq!(failed_route["apply_status"], "failed", "{failed_route}");
    // 失败修订不更新恢复日志：日志里还是最初那份已确认计划，含被撤销设备的
    // peer——这正是回滚必须过滤的原因。
    assert!(
        journal_plan(&boot.pool, &boot.network)
            .await
            .to_string()
            .contains(&revoked_key),
        "the journal still holds the last confirmed plan after a failed apply"
    );

    // 撤销优先于机械恢复：同一坏路由仍在，撤销修订的 apply 依然失败，但
    // 隧道步已经把被撤销设备移出 hub。
    let revoked = admin(
        &boot.app,
        &boot.cookie,
        &format!(
            "/api/v1/networks/{}/devices/{}/revoke",
            boot.network, boot.device_ids[0]
        ),
        json!({}),
    )
    .await;
    let revoke_revision = revoked["revision_id"].as_u64().unwrap();
    let failed_revoke = apply(&boot.app, &boot.cookie, &boot.network).await;
    assert_eq!(failed_revoke["apply_status"], "failed", "{failed_revoke}");
    assert!(
        !peers_of(&sandbox).contains(&revoked_key),
        "revocation must take effect even though the apply failed"
    );
    assert!(peers_of(&sandbox).contains(&live_key));
    assert!(
        !ping(&sandbox.names[2], "10.240.0.2"),
        "the revoked device must be unreachable"
    );

    // 回滚失败修订 → 机械上该恢复上一份已确认计划（含被撤销设备）；授权快照
    // 必须先行，被撤销设备不得随 last_good_plan 复活。
    let rolled = admin(
        &boot.app,
        &boot.cookie,
        &format!(
            "/api/v1/networks/{}/config-revisions/{}/rollback",
            boot.network, revoke_revision
        ),
        json!({}),
    )
    .await;
    assert_eq!(rolled["apply_status"], "rolled_back", "{rolled}");
    assert!(
        !peers_of(&sandbox).contains(&revoked_key),
        "rollback must not re-admit the revoked peer"
    );
    assert!(peers_of(&sandbox).contains(&live_key));
    assert!(
        !ping(&sandbox.names[2], "10.240.0.2"),
        "rollback must not reopen access for the revoked device"
    );
    // 网关侧 LAN 路由随回滚回落到上一份计划（那份计划里没有它），alias 无孤儿。
    let (_, routes) = request(
        &boot.app,
        "GET",
        &format!("/api/v1/networks/{}/routes", boot.network),
        Value::Null,
        Some(&boot.cookie),
        None,
    )
    .await;
    assert!(routes.as_array().unwrap().is_empty(), "{routes}");

    // 恢复日志（持久化的 hub 部署）已按授权快照过滤：不含被撤销设备的 peer，
    // 也没有指向已撤销网关的路由。
    let journal = journal_plan(&boot.pool, &boot.network).await;
    let peers: Vec<&Value> = journal["hub"]["tunnel"]["peers"]
        .as_array()
        .unwrap()
        .iter()
        .collect();
    assert!(
        peers
            .iter()
            .all(|p| p["public_key"].as_str().unwrap() != revoked_key.as_str()),
        "the journal must not re-record the revoked peer: {journal}"
    );
    assert!(
        peers
            .iter()
            .any(|p| p["public_key"].as_str().unwrap() == live_key.as_str()),
        "the surviving device must stay in the journal: {journal}"
    );
    assert!(
        journal["routes"].as_array().unwrap().is_empty(),
        "{journal}"
    );
    assert!(
        journal["hub"]["routes"].as_array().unwrap().is_empty(),
        "{journal}"
    );

    // 存活设备不受牵连：hub 侧握手与流量计数持续累加（peer 行尾部四列是
    // handshake / received / sent / keepalive）。
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let (live_handshaking, dump) = loop {
        let dump =
            String::from_utf8_lossy(&ns(&sandbox.names[0], &["wg", "show", "wg0", "dump"]).stdout)
                .to_string();
        let live_line = dump
            .lines()
            .find(|line| line.starts_with(live_key.as_str()));
        let fields: Vec<&str> = live_line.unwrap_or_default().split_whitespace().collect();
        let ok = fields.len() >= 4
            && fields[fields.len() - 4]
                .trim()
                .parse::<u64>()
                .is_ok_and(|handshake| handshake > 0)
            && fields[fields.len() - 3]
                .trim()
                .parse::<u64>()
                .is_ok_and(|received| received > 0);
        if ok || std::time::Instant::now() > deadline {
            break (ok, dump);
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    };
    assert!(
        live_handshaking,
        "the surviving device must keep handshaking: {dump}"
    );

    // 重启恢复：日志里没有被撤销设备，恢复路径因此不会把它带回来。
    let loaded = meshlet_server::persist::load(&boot.pool, Default::default())
        .await
        .unwrap();
    *boot.shared.lock().unwrap() = loaded.mesh;
    meshlet_server::convergence::recover_once(boot.state.clone())
        .await
        .unwrap();
    assert!(
        !peers_of(&sandbox).contains(&revoked_key),
        "restart must not resurrect the revoked peer from the journal"
    );
    assert!(peers_of(&sandbox).contains(&live_key));
    assert!(
        !ping(&sandbox.names[2], "10.240.0.2"),
        "the revoked device must stay unreachable after restart"
    );
}
