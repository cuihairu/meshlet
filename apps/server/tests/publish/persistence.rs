//! Persistence and audit: every publish write leaves an audit row (no audit, no
//! commit); a restart restores objects from the DB without reusing the id sequence; DevicePlan carries the publish segment (under the desired-config gate the apply stub runs first).

use axum::http::StatusCode;
use serde_json::json;

use super::*;

#[tokio::test]
async fn every_publish_write_leaves_an_audit_row() {
    let ctx = memory_ctx().await;
    let (network_id, device_id, _) = provision(&ctx, "edge-1").await;
    let p = |kind: &str| format!("/api/v1/networks/{network_id}/publish/{kind}");

    let (status, _, raw) = post(
        &ctx,
        &p("forwards"),
        json!({"device_id": device_id, "protocol": "tcp",
               "listener_address": "127.0.0.1:9300", "backend_address": "127.0.0.1:3300",
               "allowed_source_cidrs": ["10.240.0.0/16"]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{raw}");
    let (status, _, raw) = post(
        &ctx,
        &p("http-routes"),
        json!({"device_id": device_id, "hostname": "app.mesh", "path_prefix": "/",
               "backend_address": "127.0.0.1:8080", "listener_address": "127.0.0.1:80",
               "allowed_source_cidrs": ["10.240.0.0/16"]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{raw}");
    let (status, _, raw) = post(
        &ctx,
        &p("probes"),
        json!({"device_id": device_id, "target_kind": "tcp",
               "address": "127.0.0.1:9300", "timeout_secs": 2.0, "interval_secs": 30}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{raw}");
    let (status, _, raw) = post(
        &ctx,
        &p("dns-records"),
        json!({"device_id": device_id, "name": "app", "address": "10.240.0.10", "ttl": 60,
               "bind_address": "0.0.0.0:53", "internal_suffix": "mesh"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{raw}");

    let actions = audit_actions(&ctx, "publish.").await;
    assert_eq!(
        actions.len(),
        4,
        "one audit row per publish write: {actions:?}"
    );

    // Deletions leave a trail too, and the object disappears along with it.
    let (status, body) = delete(&ctx, &format!("{}/pf-1", p("forwards"))).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let actions = audit_actions(&ctx, "publish.").await;
    assert_eq!(actions.len(), 5, "{actions:?}");

    // An audit row's detail must not carry a bearer token (secret material never lands in the audit log).
    let detail = sqlx::query_scalar::<_, String>(
        "SELECT detail FROM audit_events WHERE action = 'publish.http_route_created'",
    )
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
    assert!(
        !detail.contains("s3cret"),
        "audit must not carry tokens: {detail}"
    );

    // Every publish change records a revision (publish objects belong to the desired config).
    let (status, revisions, _) = call(
        &ctx,
        "GET",
        &format!("/api/v1/networks/{network_id}/config-revisions"),
        Some(&ctx.cookie),
        None,
        false,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let count = revisions.as_array().unwrap().len();
    assert!(
        count >= 6,
        "network approve + 4 publish creates + 1 delete must each record a revision, got {count}"
    );
}

#[tokio::test]
async fn publish_objects_restore_after_restart_and_ids_are_not_reused() {
    let (mut ctx, db) = file_ctx().await;
    let (network_id, device_id, _) = provision(&ctx, "edge-1").await;
    let p = |kind: &str| format!("/api/v1/networks/{network_id}/publish/{kind}");

    let (status, body, raw) = post(
        &ctx,
        &p("forwards"),
        json!({"device_id": device_id, "protocol": "tcp",
               "listener_address": "127.0.0.1:9400", "backend_address": "127.0.0.1:3400",
               "allowed_bearer_tokens": ["s3cret"]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{raw}");
    assert_eq!(body["allowed_bearer_token_count"], 1);
    let (status, _, raw) = post(
        &ctx,
        &p("dns-records"),
        json!({"device_id": device_id, "name": "app", "address": "10.240.0.10", "ttl": 60,
               "bind_address": "0.0.0.0:53", "internal_suffix": "mesh"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{raw}");
    let (status, _, raw) = post(
        &ctx,
        &p("probes"),
        json!({"device_id": device_id, "target_kind": "tcp",
               "address": "127.0.0.1:9400", "timeout_secs": 2.0, "interval_secs": 30}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{raw}");

    // Keep the db file around by dropping the connection handle (Drop would delete the file by default).
    ctx.db = None;
    drop(ctx);

    // Restart: rebuild in-memory state from the DB.
    let ctx = reopen(&db).await;
    let (status, forwards) = get(&ctx, &p("forwards")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(forwards.as_array().unwrap().len(), 1);
    let restored = &forwards.as_array().unwrap()[0];
    assert_eq!(restored["id"], "pf-1");
    assert_eq!(restored["allowed_bearer_token_count"], 1);
    assert!(
        !serde_json::to_string(&forwards).unwrap().contains("s3cret"),
        "restored listing must not echo tokens"
    );
    let (status, dns) = get(&ctx, &p("dns-records")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(dns.as_array().unwrap().len(), 1);
    let (status, probes) = get(&ctx, &p("probes")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(probes.as_array().unwrap().len(), 1);
    assert!(
        probes[0]["last_state"].is_null(),
        "health evidence is not restored as configuration"
    );

    // The global publish sequence is monotonic across restarts and never reuses ids:
    // pf-1 / dn-2 / pb-3 already consumed seq 1-3, so the new object after a restart must be seq 4 (not pf-2).
    let (status, next, raw) = post(
        &ctx,
        &p("forwards"),
        json!({"device_id": device_id, "protocol": "udp",
               "listener_address": "127.0.0.1:9400", "backend_address": "127.0.0.1:3401",
               "allowed_source_cidrs": ["10.240.0.0/16"]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{raw}");
    assert_eq!(next["id"], "pf-4");

    remove_db(&db);
}

#[tokio::test]
async fn device_plan_carries_the_publish_segment() {
    if !wg_available() {
        return;
    }
    let dir = std::env::temp_dir().join("meshlet-publish-plan-test");
    std::fs::create_dir_all(&dir).unwrap();
    let key_file = write_hub_key(&dir);
    let pool = meshlet_server::store::connect("sqlite::memory:")
        .await
        .unwrap();
    let dataplane = meshlet_config::DataPlaneConfig {
        enabled: true,
        private_key_file: Some(key_file.to_string_lossy().to_string()),
        ..meshlet_config::DataPlaneConfig::default()
    };
    let app = app_with_pool(pool.clone(), dataplane);
    let cookie = bootstrap(&app).await;
    let ctx = ctx_from(app, cookie, pool, None);

    let (network_id, device_a, token_a) = provision(&ctx, "edge-a").await;
    let (_, token_b) = add_device(&ctx, &network_id, "edge-b", "test-public-key-2").await;

    // A device with publish objects: the plan carries a publish segment, and the plan hash changes because of them.
    let (status, _, raw) = post(
        &ctx,
        &format!("/api/v1/networks/{network_id}/publish/forwards"),
        json!({"device_id": device_a, "protocol": "tcp",
               "listener_address": "127.0.0.1:9500", "backend_address": "127.0.0.1:3500",
               "allowed_source_cidrs": ["10.240.0.0/16"]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{raw}");

    // Desired-config gate: the current revision must already be applied (apply stub succeeded) before the plan is served.
    apply_current(&ctx, &network_id).await;
    let (status, with_publish) = agent_desired(&ctx, &token_a).await;
    assert_eq!(status, StatusCode::OK);
    let publish = &with_publish["publish"];
    assert!(
        publish.is_object(),
        "publish segment must be present: {with_publish}"
    );
    assert_eq!(publish["forwards"][0]["id"], "pf-1");
    assert_eq!(publish["forwards"][0]["listener_address"], "127.0.0.1:9500");

    // A device without publish objects: the publish segment is null (backward compatible with older agents), and the hash differs.
    let (status, without_publish) = agent_desired(&ctx, &token_b).await;
    assert_eq!(status, StatusCode::OK);
    assert!(without_publish["publish"].is_null(), "{without_publish}");
    let hash_a = with_publish["desired_config_hash"].as_str().unwrap();
    let hash_b = without_publish["desired_config_hash"].as_str().unwrap();
    assert_ne!(hash_a, hash_b, "publish objects must change the plan hash");
}
