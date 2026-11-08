//! 鉴权与回显边界：发布写路径的 WriteUser + CSRF 门槛；
//! `allowed_bearer_tokens` **永不回显**（视图只给计数）。

use axum::http::StatusCode;
use serde_json::json;

use super::*;

#[tokio::test]
async fn forward_lifecycle_and_bearer_tokens_are_never_echoed() {
    let ctx = memory_ctx().await;
    let (network_id, device_id, _) = provision(&ctx, "edge-1").await;
    let uri = format!("/api/v1/networks/{network_id}/publish/forwards");

    let (status, created, raw) = post(
        &ctx,
        &uri,
        json!({
            "device_id": device_id,
            "protocol": "tcp",
            "listener_address": "127.0.0.1:9000",
            "backend_address": "127.0.0.1:3000",
            "allowed_source_cidrs": ["10.240.0.0/16"],
            "allowed_bearer_tokens": ["s3cret-one", "s3cret-two"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create: {raw}");
    assert_eq!(created["id"].as_str().unwrap(), "pf-1");
    assert_eq!(created["protocol"], "tcp");
    assert_eq!(created["listener_address"], "127.0.0.1:9000");
    assert_eq!(created["backend_address"], "127.0.0.1:3000");
    assert_eq!(created["allowed_source_cidrs"][0], "10.240.0.0/16");
    assert_eq!(created["allowed_bearer_token_count"], 2);
    assert_eq!(created["enabled"], true);
    assert!(created["revision_id"].is_u64());
    // 入口授权用的 token 是密钥材料：任何读路径都不许回显原文。
    assert!(
        !raw.contains("s3cret-one") && !raw.contains("s3cret-two"),
        "bearer tokens must never be echoed: {raw}"
    );
    assert!(!raw.contains("allowed_bearer_tokens"), "{raw}");

    // 列表与详情同一形态。
    let (status, list, raw_list) = get_raw(&ctx, &uri).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert!(
        !raw_list.contains("s3cret-one") && !raw_list.contains("s3cret-two"),
        "listing must not echo tokens: {raw_list}"
    );

    let detail_uri = format!("{uri}/pf-1");
    let (status, detail) = get(&ctx, &detail_uri).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["device_id"], device_id);

    // 删除后详情 404，重复删除同样 404。
    let (status, body) = delete(&ctx, &detail_uri).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = get(&ctx, &detail_uri).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = delete(&ctx, &detail_uri).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn writes_require_write_user_and_csrf() {
    let ctx = memory_ctx().await;
    let (network_id, device_id, _) = provision(&ctx, "edge-1").await;
    let uri = format!("/api/v1/networks/{network_id}/publish/forwards");
    let body = json!({
        "device_id": device_id,
        "protocol": "tcp",
        "listener_address": "127.0.0.1:9001",
        "backend_address": "127.0.0.1:3001"
    });

    // 无会话：401（凭证边界）。
    let (status, body, _) = call(&ctx, "POST", &uri, None, None, true, Some(body.clone())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    // 有会话但缺 CSRF：403。
    let (status, body, _) = call(
        &ctx,
        "POST",
        &uri,
        Some(&ctx.cookie),
        None,
        false,
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    // 读路径只要会话，不要 CSRF。
    let (status, list, _) = call(&ctx, "GET", &uri, Some(&ctx.cookie), None, false, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(list.as_array().unwrap().is_empty());
    // 读路径无会话同样被拒。
    let (status, body, _) = call(&ctx, "GET", &uri, None, None, false, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}
