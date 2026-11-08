//! 持久化与审计：每条发布写都留审计行（无审计不落库）、重启后从 DB 恢复且
//! id 序列不复用、DevicePlan 携带发布段（期望计划门禁下 apply 桩先行）。

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

    // 删除也要留痕，且对象随之消失。
    let (status, body) = delete(&ctx, &format!("{}/pf-1", p("forwards"))).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let actions = audit_actions(&ctx, "publish.").await;
    assert_eq!(actions.len(), 5, "{actions:?}");

    // 审计行的 detail 不得携带 bearer token（密钥材料不落审计）。
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

    // 每条发布变更都记一个修订（对象属于期望配置）。
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

    // 保留库文件再关掉连接句柄（Drop 默认会清理库文件）。
    ctx.db = None;
    drop(ctx);

    // 重启：从 DB 重建内存状态。
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

    // 全局 publish 序列跨重启单调不复用：此前 pf-1 / dn-2 / pb-3 已消耗
    // seq 1-3，重启后的新对象必须是 seq 4（不是 pf-2）。
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

    // 有发布对象的设备：计划带发布段，且计划哈希因发布对象而变。
    let (status, _, raw) = post(
        &ctx,
        &format!("/api/v1/networks/{network_id}/publish/forwards"),
        json!({"device_id": device_a, "protocol": "tcp",
               "listener_address": "127.0.0.1:9500", "backend_address": "127.0.0.1:3500",
               "allowed_source_cidrs": ["10.240.0.0/16"]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{raw}");

    // 期望计划门禁：当前修订必须已应用（apply 桩成功）才下发。
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

    // 无发布对象的设备：publish 段为 null（向后兼容旧 agent），哈希也不同。
    let (status, without_publish) = agent_desired(&ctx, &token_b).await;
    assert_eq!(status, StatusCode::OK);
    assert!(without_publish["publish"].is_null(), "{without_publish}");
    let hash_a = with_publish["desired_config_hash"].as_str().unwrap();
    let hash_b = without_publish["desired_config_hash"].as_str().unwrap();
    assert_ne!(hash_a, hash_b, "publish objects must change the plan hash");
}
