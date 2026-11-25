//! Device revocation and failed-revoke rollback must remove live access safely.
#![cfg(target_os = "linux")]
use super::boot::*;
use super::single_instance_support::*;
use axum::http::StatusCode;
use serde_json::{json, Value};

/// Scenario 7: after revoking an online device, its old plan on retry must not regain authorization. Three layers are
/// verified: the credential boundary (the token is invalidated immediately), the revision/hash boundary (an old receipt
/// cannot satisfy a new revision), and "yet another config change does not re-admit either"; a surviving device is untouched.
#[tokio::test(flavor = "multi_thread")]
async fn revoked_device_cannot_reauthorize_its_stale_plan() {
    let Some(sandbox) = setup() else {
        return;
    };
    let boot = boot_network(&sandbox, "revoke-key.key").await;

    // The peer identity remembered on the hub (the peer list is CSV; compare public keys as strings).
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

    // The old plan fetched before the revoke (its only peer is the hub: devices are not interconnected with each other,
    // so "re-admission" can only be verified from the hub's peer list — the kernel evidence above is that baseline).
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

    // 1) Credential boundary: the same token is invalidated immediately — no plan can be fetched and no receipt can be
    // submitted, whether the receipt carries the old revision number or the current one.
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

    // 2) Revision/hash boundary: with a valid credential from the surviving device, the old plan still cannot satisfy the new
    // revision — the old revision number is a "stale receipt", and the current revision number with the old hash is a "hash mismatch".
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

    // 3) The surviving device's plan no longer contains the revoked peer, and the desired hash changed too.
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

    // 4) Gone from the kernel side, and yet another config change does not bring it back either.
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

    // The surviving device must be unharmed: the hub side still has its handshake and traffic counters (the trailing
    // four peer-row columns are handshake / received / sent / keepalive).
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

/// M4: rollback/retry must not re-grant revoked rights. Security semantics outrank mechanical recovery — after revoking,
/// induce a failed apply and then roll back: the restored last_good_plan must first pass through the current authorization
/// snapshot, the revoked device's access must not reopen, and the recovery journal must not record it again.
#[tokio::test]
async fn rolling_back_a_failed_revoke_does_not_reopen_access() {
    let Some(sandbox) = setup() else {
        return;
    };
    let boot = boot_network(&sandbox, "revoke-rollback.key").await;

    // The peer identity remembered on the hub (the peer list is CSV; compare public keys as strings).
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

    // A foreign route occupies the destination segment, so the route step of the next apply must fail — a controllable failed apply.
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
    // A failed revision does not update the recovery journal: it still holds the original confirmed plan, including the
    // revoked device's peer — which is exactly why the rollback must filter it out.
    assert!(
        journal_plan(&boot.pool, &boot.network)
            .await
            .to_string()
            .contains(&revoked_key),
        "the journal still holds the last confirmed plan after a failed apply"
    );

    // Revocation outranks mechanical recovery: the same bad route is still there, so the revoke revision's apply still fails,
    // but the tunnel step has already removed the revoked device from the hub.
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

    // Rolling back a failed revision -> mechanically, the previous confirmed plan (including the revoked device) should be
    // restored; the authorization snapshot must be checked first, so the revoked device must not come back with the last_good_plan.
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
    // The gateway-side LAN route falls back to the previous plan with the rollback (the plan did not have it), and the alias has no orphans.
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

    // The recovery journal (persisted hub deployment) has been filtered by the authorization snapshot: no peer of the
    // revoked device, and no route pointing at the revoked gateway.
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

    // The surviving device is unaffected: hub-side handshake and traffic counters keep increasing (the trailing four
    // peer-row columns are handshake / received / sent / keepalive).
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

    // Restart recovery: the journal has no record of the revoked device, so the recovery path cannot bring it back.
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
