//! 探针与 DNS 记录：agent 健康回报的 `device_id` 守卫（不能替别的设备写
//! 健康）、探针目标校验（http 必带 path/expected、interval 不可为 0）、
//! 每设备一个 DNS 套接字（同套接字多记录合法，跨后缀 409）。

use axum::http::StatusCode;
use serde_json::{json, Value};

use super::*;

#[tokio::test]
async fn probe_health_report_is_guarded_by_device_id() {
    let ctx = memory_ctx().await;
    let (network_id, device_a, token_a) = provision(&ctx, "edge-a").await;
    // 同网络第二个设备（不同 agent 凭证）。
    let (_device_b, token_b) = add_device(&ctx, &network_id, "edge-b", "test-public-key-2").await;

    let uri = format!("/api/v1/networks/{network_id}/publish/probes");
    let (status, probe, raw) = post(
        &ctx,
        &uri,
        json!({
            "device_id": device_a,
            "target_kind": "tcp",
            "address": "127.0.0.1:9200",
            "timeout_secs": 2.0,
            "interval_secs": 30
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create probe: {raw}");
    assert_eq!(probe["id"], "pb-1");
    assert_eq!(probe["target_kind"], "tcp");
    assert_eq!(probe["address"], "127.0.0.1:9200");
    assert!(probe["last_state"].is_null());

    let report = json!({
        "reports": [{
            "probe_id": "pb-1",
            "state": "healthy",
            "checked_at": "2026-10-24T00:00:00Z",
            "detail": null
        }]
    });

    // 别的设备的 agent 不能替它写健康（越权写被拒）。
    let (status, body, _) = call(
        &ctx,
        "POST",
        "/api/v1/agent/publish-health",
        None,
        Some(&token_b),
        false,
        Some(report.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "foreign report: {body}");

    // 无凭证：401。
    let (status, body, _) = call(
        &ctx,
        "POST",
        "/api/v1/agent/publish-health",
        None,
        None,
        false,
        Some(report.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // 本设备回报：落内存视图（不落配置，健康是证据）。
    let (status, body, _) = call(
        &ctx,
        "POST",
        "/api/v1/agent/publish-health",
        None,
        Some(&token_a),
        false,
        Some(report),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, detail, _) = call(
        &ctx,
        "GET",
        &format!("{uri}/pb-1"),
        Some(&ctx.cookie),
        None,
        false,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["last_state"], "healthy");
    assert_eq!(detail["last_checked_at"], "2026-10-24T00:00:00Z");

    // 未知探针：404。
    let (status, body, _) = call(
        &ctx,
        "POST",
        "/api/v1/agent/publish-health",
        None,
        Some(&token_a),
        false,
        Some(json!({"reports": [{"probe_id": "pb-999", "state": "healthy", "checked_at": "2026-10-24T00:00:00Z"}]})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn probe_validation_rejects_bad_targets() {
    let ctx = memory_ctx().await;
    let (network_id, device_id, _) = provision(&ctx, "edge-1").await;
    let uri = format!("/api/v1/networks/{network_id}/publish/probes");

    let bad = |extra: Value| -> Value {
        let mut body = json!({
            "device_id": device_id,
            "target_kind": "tcp",
            "address": "127.0.0.1:1",
            "timeout_secs": 1.0,
            "interval_secs": 30,
        });
        for (key, entry) in extra.as_object().unwrap() {
            body[key] = entry.clone();
        }
        body
    };
    // http 探针必带 path + expected_status。
    let (status, body, _) = post(&ctx, &uri, bad(json!({"target_kind": "http"}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    // interval 不可为 0（钉死 CPU）。
    let (status, body, _) = post(&ctx, &uri, bad(json!({"interval_secs": 0}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    // 未知 target_kind。
    let (status, body, _) = post(&ctx, &uri, bad(json!({"target_kind": "grpc"}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    // 空列表（无请求体）。
    let (status, list) = get(&ctx, &uri).await;
    assert_eq!(status, StatusCode::OK);
    assert!(list.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn dns_records_share_one_socket_per_device() {
    let ctx = memory_ctx().await;
    let (network_id, device_id, _) = provision(&ctx, "edge-1").await;
    let uri = format!("/api/v1/networks/{network_id}/publish/dns-records");
    let record = json!({
        "device_id": device_id,
        "name": "app",
        "address": "10.240.0.10",
        "ttl": 60,
        "priority": 100,
        "bind_address": "0.0.0.0:53",
        "internal_suffix": "mesh"
    });

    let (status, created, raw) = post(&ctx, &uri, record.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "create: {raw}");
    assert_eq!(created["id"], "dn-1");
    assert_eq!(created["name"], "app");
    assert_eq!(created["bind_address"], "0.0.0.0:53");
    assert_eq!(created["internal_suffix"], "mesh");
    assert_eq!(created["ttl"], 60);

    // 同一套接字的第二条记录：合法（同一 DNS 套接字下多记录）。
    let mut second = record.clone();
    second["name"] = json!("db");
    second["address"] = json!("10.240.0.11");
    let (status, second_created, raw) = post(&ctx, &uri, second).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "same socket, second record: {raw}"
    );
    assert_eq!(second_created["id"], "dn-2");

    // 同一设备不同后缀：409（一台设备只能有一个 DNS 套接字）。
    let mut other_suffix = record.clone();
    other_suffix["name"] = json!("api");
    other_suffix["internal_suffix"] = json!("lan");
    let (status, body, _) = post(&ctx, &uri, other_suffix).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "two sockets per device: {body}"
    );

    // 端口 0 无效。
    let mut port_zero = record.clone();
    port_zero["name"] = json!("zero");
    port_zero["bind_address"] = json!("0.0.0.0:0");
    let (status, body, _) = post(&ctx, &uri, port_zero).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let (status, list) = get(&ctx, &uri).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 2);
    let (status, body) = delete(&ctx, &format!("{uri}/dn-2")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (_, list) = get(&ctx, &uri).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
}
