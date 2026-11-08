//! 端口与 HTTP 路由：端口冲突按**设备**判定（同设备同端口 409，别的设备
//! 同端口合法）；HTTP 路由 建-列-查-删 往返与去重；每设备一个 HTTP 监听口、
//! 一种终止模式；TLS passthrough 拒绝其无法执行的能力（token / 路径前缀）。

use axum::http::StatusCode;
use serde_json::json;

use super::*;

#[tokio::test]
async fn port_conflict_is_judged_per_device() {
    let ctx = memory_ctx().await;
    let (network_id, device_a, _) = provision(&ctx, "edge-a").await;
    let (device_b, _) = add_device(&ctx, &network_id, "edge-b", "test-public-key-2").await;

    let uri = format!("/api/v1/networks/{network_id}/publish/forwards");
    let forward = |protocol: &str, device_id: &str| {
        json!({
            "device_id": device_id,
            "protocol": protocol,
            "listener_address": "127.0.0.1:9100",
            "backend_address": "127.0.0.1:3100",
            "allowed_source_cidrs": ["10.240.0.0/16"]
        })
    };

    let (status, _, raw) = post(&ctx, &uri, forward("tcp", &device_a)).await;
    assert_eq!(status, StatusCode::CREATED, "first: {raw}");
    // 同设备同协议同监听：409。
    let (status, body, _) = post(&ctx, &uri, forward("tcp", &device_a)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    // 同设备同监听不同协议：合法（套接字不同）。
    let (status, _, raw) = post(&ctx, &uri, forward("udp", &device_a)).await;
    assert_eq!(status, StatusCode::CREATED, "udp on the same port: {raw}");
    // 同网络别的设备同端口：合法（端口冲突按设备判定）。
    let (status, _, raw) = post(&ctx, &uri, forward("tcp", &device_b)).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "another device may bind it: {raw}"
    );
}

#[tokio::test]
async fn http_route_lifecycle_and_duplicate_rejected() {
    let ctx = memory_ctx().await;
    let (network_id, device_id, _) = provision(&ctx, "edge-1").await;
    let uri = format!("/api/v1/networks/{network_id}/publish/http-routes");

    let (status, created, raw) = post(
        &ctx,
        &uri,
        json!({
            "device_id": device_id,
            "hostname": "app.mesh",
            "path_prefix": "/api",
            "backend_address": "127.0.0.1:8080",
            "listener_address": "127.0.0.1:80",
            "allowed_source_cidrs": ["10.240.0.0/16"],
            "allowed_bearer_tokens": ["s3cret"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create: {raw}");
    assert_eq!(created["id"].as_str().unwrap(), "hr-1");
    assert_eq!(created["hostname"], "app.mesh");
    assert_eq!(created["path_prefix"], "/api");
    assert_eq!(created["tls_passthrough"], false);
    assert_eq!(created["allowed_bearer_token_count"], 1);
    assert!(!raw.contains("s3cret"), "tokens must not be echoed: {raw}");

    // 既无源 CIDR 又无 bearer token 的发布对象一律拒绝（等于对外全开）。
    let (status, body, _) = post(
        &ctx,
        &uri,
        json!({
            "device_id": device_id,
            "hostname": "open.mesh",
            "path_prefix": "/",
            "backend_address": "127.0.0.1:8082",
            "listener_address": "127.0.0.1:80"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // hostname 大小写不敏感 + path_prefix 相同：409。
    let (status, body, _) = post(
        &ctx,
        &uri,
        json!({
            "device_id": device_id,
            "hostname": "App.Mesh",
            "path_prefix": "/api",
            "backend_address": "127.0.0.1:8081",
            "listener_address": "127.0.0.1:80",
            "allowed_source_cidrs": ["10.240.0.0/16"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "duplicate route: {body}");

    let (status, detail) = get(&ctx, &format!("{uri}/hr-1")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["backend_address"], "127.0.0.1:8080");
    let (status, body) = delete(&ctx, &format!("{uri}/hr-1")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = get(&ctx, &format!("{uri}/hr-1")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

/// 一台设备只能有一个 HTTP 监听口、一种终止模式：计划里只有一个
/// `http_listener`，第二个监听口不绑定；混入 TLS 路由会把整台设备切成
/// SNI 嗅探。静默丢弃不可接受，一律 409（与 DNS 套接字口径一致）。
#[tokio::test]
async fn http_route_shares_one_listener_and_mode_per_device() {
    let ctx = memory_ctx().await;
    let (network_id, device_id, _) = provision(&ctx, "edge-1").await;
    let uri = format!("/api/v1/networks/{network_id}/publish/http-routes");
    let route = json!({
        "device_id": device_id,
        "hostname": "one.mesh",
        "path_prefix": "/",
        "backend_address": "127.0.0.1:8080",
        "listener_address": "127.0.0.1:80",
        "allowed_source_cidrs": ["10.240.0.0/16"],
        "tls_passthrough": false
    });

    let (status, created, raw) = post(&ctx, &uri, route.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "baseline: {raw}");
    assert_eq!(created["id"], "hr-1");

    // 同设备、不同监听口：计划只会绑定第一条路由的地址 → 409。
    let mut other_listener = route.clone();
    other_listener["hostname"] = json!("port.mesh");
    other_listener["listener_address"] = json!("127.0.0.1:81");
    let (status, body, _) = post(&ctx, &uri, other_listener).await;
    assert_eq!(status, StatusCode::CONFLICT, "two listeners: {body}");
    assert!(
        body.to_string().contains("one http listener per device"),
        "{body}"
    );

    // 同设备、混入 TLS 路由：会让整台设备切成 SNI 嗅探 → 409。
    let mut tls = route.clone();
    tls["hostname"] = json!("tls.mesh");
    tls["tls_passthrough"] = json!(true);
    let (status, body, _) = post(&ctx, &uri, tls).await;
    assert_eq!(status, StatusCode::CONFLICT, "mixed tls: {body}");
    assert!(
        body.to_string().contains("one termination mode per device"),
        "{body}"
    );

    // 同监听口、同模式：合法（多个 hostname 共用一个监听口）。
    let mut second = route.clone();
    second["hostname"] = json!("two.mesh");
    let (status, second_created, raw) = post(&ctx, &uri, second).await;
    assert_eq!(status, StatusCode::CREATED, "same listener+mode: {raw}");
    assert_eq!(second_created["id"], "hr-2");

    // 换一台设备互不影响（监听口/模式都按设备判定）。
    let (device_b, _) = add_device(&ctx, &network_id, "edge-2", "test-public-key-2").await;
    let mut on_other = route.clone();
    on_other["device_id"] = json!(device_b);
    on_other["hostname"] = json!("other.mesh");
    on_other["listener_address"] = json!("127.0.0.1:8081");
    on_other["tls_passthrough"] = json!(true);
    let (status, other_created, raw) = post(&ctx, &uri, on_other).await;
    assert_eq!(status, StatusCode::CREATED, "other device: {raw}");
    assert_eq!(other_created["tls_passthrough"], true);

    let (status, list) = get(&ctx, &uri).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 3);
}

/// M1 更名与能力拒绝。passthrough 是 SNI 嗅探 + TLS 字节直通，meshlet
/// 没有证书、不解密：无法执行的能力（bearer token、非 `/` 路径前缀）
/// 创建期 409 直接拒绝，不静默忽略；旧字段名 `tls_termination` 仍被映射。
#[tokio::test]
async fn tls_passthrough_rejects_capabilities_it_cannot_enforce() {
    let ctx = memory_ctx().await;
    let (network_id, device_id, _) = provision(&ctx, "edge-1").await;
    let uri = format!("/api/v1/networks/{network_id}/publish/http-routes");

    // 旧字段名映射：请求带 `tls_termination`（M1 前的调用方），响应只出新名。
    let (status, created, raw) = post(
        &ctx,
        &uri,
        json!({
            "device_id": device_id,
            "hostname": "legacy.mesh",
            "path_prefix": "/",
            "backend_address": "127.0.0.1:8443",
            "listener_address": "127.0.0.1:443",
            "allowed_source_cidrs": ["10.240.0.0/16"],
            "tls_termination": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "legacy field alias: {raw}");
    assert_eq!(created["tls_passthrough"], true);
    assert!(created.get("tls_termination").is_none());

    // 新旧名都写一次等于自相矛盾（alias 映射同一字段）：请求解析层按重复
    // 字段拒绝（422，非应用错误，正文非 JSON 信封）。
    let (status, body, _) = post(
        &ctx,
        &uri,
        json!({
            "device_id": device_id,
            "hostname": "both.mesh",
            "path_prefix": "/",
            "backend_address": "127.0.0.1:8446",
            "listener_address": "127.0.0.1:443",
            "allowed_source_cidrs": ["10.240.0.0/16"],
            "tls_passthrough": true,
            "tls_termination": true
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "both old and new name: {body}"
    );

    // token 在不透明 TLS 字节上永远无法校验 → 409。
    let (status, body, _) = post(
        &ctx,
        &uri,
        json!({
            "device_id": device_id,
            "hostname": "token.mesh",
            "path_prefix": "/",
            "backend_address": "127.0.0.1:8444",
            "listener_address": "127.0.0.1:443",
            "allowed_source_cidrs": ["10.240.0.0/16"],
            "allowed_bearer_tokens": ["s3cret"],
            "tls_passthrough": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("never terminates TLS"), "{body}");

    // 路径前缀在 SNI 选路下永不参与匹配 → 409。
    let (status, body, _) = post(
        &ctx,
        &uri,
        json!({
            "device_id": device_id,
            "hostname": "path.mesh",
            "path_prefix": "/api",
            "backend_address": "127.0.0.1:8445",
            "listener_address": "127.0.0.1:443",
            "allowed_source_cidrs": ["10.240.0.0/16"],
            "tls_passthrough": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("never matches a path"), "{body}");

    // plain HTTP 路由不受影响：token 与路径前缀照常可用（换台设备避开模式 409）。
    let (device_b, _) = add_device(&ctx, &network_id, "edge-2", "test-public-key-2").await;
    let (status, created, raw) = post(
        &ctx,
        &uri,
        json!({
            "device_id": device_b,
            "hostname": "plain.mesh",
            "path_prefix": "/api",
            "backend_address": "127.0.0.1:8080",
            "listener_address": "127.0.0.1:80",
            "allowed_source_cidrs": ["10.240.0.0/16"],
            "allowed_bearer_tokens": ["s3cret"],
            "tls_passthrough": false
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "plain keeps features: {raw}");
    assert_eq!(created["tls_passthrough"], false);
    assert_eq!(created["allowed_bearer_token_count"], 1);
}
