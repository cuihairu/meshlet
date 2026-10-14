//! 集成测试：配置状态机（[存档 §10](../docs/review/chatgpt-2026-10-13.md)、
//! [ADR-009](../docs/decisions/adr-009-config-revision-rollback.md)）。
//!
//! 验收口径：**DB 写入 ≠ 显示生效**——期望配置变更只生成 `Pending` 修订；
//! 只有 backend 成功应用后才 `Applied`；**失败可见**（`failed` +
//! `error_summary`）；**状态可区分**（pending / failed / rollback_pending …）。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt; // oneshot

const OVERLAY: &str = "10.240.0.0/16";

/// 测试上下文：router + 管理会话 Cookie（空库 bootstrap 首个管理员）。
#[derive(Clone)]
struct Ctx {
    app: Router,
    cookie: String,
}

async fn ctx() -> Ctx {
    let pool = meshlet_server::store::connect("sqlite::memory:")
        .await
        .unwrap();
    let mesh = std::sync::Arc::new(std::sync::Mutex::new(
        meshlet_server::service::MeshState::default(),
    ));
    let state = std::sync::Arc::new(meshlet_server::auth::AppState::new(
        mesh,
        meshlet_server::auth::AuthStore::new(pool.clone()),
        meshlet_server::agent::AgentTokenStore::new(pool.clone()),
        meshlet_server::api_token::ApiTokenStore::new(pool),
        false,
    ));
    let app = meshlet_server::router(state);

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "email": "admin@test.local",
                        "password": "bootstrap-password-123",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "bootstrap must succeed");
    let cookie = res
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .expect("session cookie")
        .to_string();
    Ctx { app, cookie }
}

/// 统一的请求构造：可选会话 Cookie 与 CSRF 头（管理写请求必须两者齐备）。
async fn call(
    c: &Ctx,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    csrf: bool,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    if csrf {
        builder = builder.header("x-requested-with", "XMLHttpRequest");
    }
    let body = body.map(|v| Body::from(v.to_string())).unwrap_or_default();
    let req = builder
        .header("content-type", "application/json")
        .body(body)
        .unwrap();
    let res = c.app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Object(Default::default()));
    (status, value)
}

async fn create_network(c: &Ctx) -> Value {
    let (status, body) = call(
        c,
        "POST",
        "/api/v1/networks",
        Some(&c.cookie),
        true,
        Some(json!({ "name": "home", "overlay_cidr": OVERLAY })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    body
}

async fn enroll_device(c: &Ctx, network_id: &str, name: &str, public_key: &str) -> Value {
    let (status, invite) = call(
        c,
        "POST",
        &format!("/api/v1/networks/{network_id}/invites"),
        Some(&c.cookie),
        true,
        Some(json!({ "max_uses": 1 })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let token = invite["token"].as_str().unwrap().to_string();

    let (status, body) = call(
        c,
        "POST",
        "/api/v1/enroll",
        None,
        false,
        Some(json!({
            "invite_token": token,
            "device_name": name,
            "public_key": public_key,
            "platform": "linux",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    body
}

async fn revisions(c: &Ctx, network_id: &str) -> Value {
    let (status, body) = call(
        c,
        "GET",
        &format!("/api/v1/networks/{network_id}/config-revisions"),
        Some(&c.cookie),
        false,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    body
}

async fn apply(c: &Ctx, network_id: &str, revision: u64) -> (StatusCode, Value) {
    call(
        c,
        "POST",
        &format!("/api/v1/networks/{network_id}/config-revisions/{revision}/apply"),
        Some(&c.cookie),
        true,
        None,
    )
    .await
}

async fn rollback(c: &Ctx, network_id: &str, revision: u64) -> (StatusCode, Value) {
    call(
        c,
        "POST",
        &format!("/api/v1/networks/{network_id}/config-revisions/{revision}/rollback"),
        Some(&c.cookie),
        true,
        None,
    )
    .await
}

#[tokio::test]
async fn create_network_records_pending_revision_and_never_claims_effective() {
    let c = ctx().await;
    let created = create_network(&c).await;

    // ADR-009：配置修改类响应必须携带 revision_id 与 apply_status。
    assert_eq!(created["revision_id"], 1);
    assert_eq!(created["apply_status"], "pending");

    let list = revisions(&c, created["id"].as_str().unwrap()).await;
    let entries = list.as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["revision"], 1);
    assert_eq!(entries[0]["apply_status"], "pending");
    // DB 写入 ≠ 生效：从未成功应用的修订不得有 applied_at。
    assert!(entries[0]["applied_at"].is_null());
    assert!(entries[0]["error_summary"].is_null());
    let hash = entries[0]["desired_config_hash"].as_str().unwrap();
    assert_eq!(
        hash.len(),
        64,
        "desired_config_hash must be sha256 hex: {hash}"
    );

    // 网络列表同样以应用状态为准，不以 DB 写入为准。
    let (status, body) = call(&c, "GET", "/api/v1/networks", Some(&c.cookie), false, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap()[0]["apply_status"], "pending");
    assert_eq!(body.as_array().unwrap()[0]["revision_id"], 1);
}

#[tokio::test]
async fn enroll_records_next_revision_with_changed_desired_hash() {
    let c = ctx().await;
    let created = create_network(&c).await;
    let network_id = created["id"].as_str().unwrap().to_string();

    let first_hash = revisions(&c, &network_id).await.as_array().unwrap()[0]["desired_config_hash"]
        .as_str()
        .unwrap()
        .to_string();

    let enroll = enroll_device(&c, &network_id, "laptop", "pub-laptop-0001").await;
    // 加入改变期望配置：新版本号 + 新哈希，仍是 pending。
    assert_eq!(enroll["revision_id"], 2);
    assert_eq!(enroll["apply_status"], "pending");

    let list = revisions(&c, &network_id).await;
    let entries = list.as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["revision"], 1);
    assert_eq!(entries[1]["revision"], 2);
    let second_hash = entries[1]["desired_config_hash"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(
        first_hash, second_hash,
        "new device must change the desired config hash"
    );
    assert_eq!(entries[1]["apply_status"], "pending");
}

#[tokio::test]
async fn apply_without_backend_fails_visibly_everywhere() {
    let c = ctx().await;
    let created = create_network(&c).await;
    let network_id = created["id"].as_str().unwrap().to_string();

    // 本进程无数据面 backend（WireGuard 应用需要 CAP_NET_ADMIN）→ 显式失败。
    let (status, body) = apply(&c, &network_id, 1).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revision"], 1);
    assert_eq!(body["apply_status"], "failed");
    assert!(body["error_summary"]
        .as_str()
        .unwrap()
        .contains("no network backend configured"));
    assert!(
        body["applied_at"].is_null(),
        "failed apply must not claim applied_at"
    );

    // 失败在详情与列表里都可见（不是只在调用返回值里）。
    let (status, detail) = call(
        &c,
        "GET",
        &format!("/api/v1/networks/{network_id}/config-revisions/1"),
        Some(&c.cookie),
        false,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["apply_status"], "failed");
    assert!(detail["error_summary"].is_string());
    assert_eq!(
        revisions(&c, &network_id).await.as_array().unwrap()[0]["apply_status"],
        "failed"
    );
}

#[tokio::test]
async fn reapplying_a_failed_revision_is_a_conflict() {
    let c = ctx().await;
    let created = create_network(&c).await;
    let network_id = created["id"].as_str().unwrap().to_string();

    let (status, first) = apply(&c, &network_id, 1).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["apply_status"], "failed");

    // 原地重试被状态机拒绝（§10.4）：重试路径是记录新修订。
    let (status, body) = apply(&c, &network_id, 1).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "conflict");
}

#[tokio::test]
async fn rollback_without_backend_stays_unconfirmed_with_diagnostics() {
    let c = ctx().await;
    let created = create_network(&c).await;
    let network_id = created["id"].as_str().unwrap().to_string();

    apply(&c, &network_id, 1).await; // -> failed
    let (status, body) = rollback(&c, &network_id, 1).await;
    assert_eq!(status, StatusCode::OK);
    // 回滚未能确认：明确留在 rollback_pending，且诊断合并（应用失败 + 回滚失败）。
    assert_eq!(body["apply_status"], "rollback_pending");
    let summary = body["error_summary"].as_str().unwrap();
    assert!(summary.contains("apply failed") || summary.contains("no network backend configured"));
    assert!(summary.contains("rollback failed"));
}

#[tokio::test]
async fn apply_and_rollback_require_session_and_csrf() {
    let c = ctx().await;
    let created = create_network(&c).await;
    let network_id = created["id"].as_str().unwrap().to_string();

    // 无会话 → 401。
    let (status, _) = call(
        &c,
        "POST",
        &format!("/api/v1/networks/{network_id}/config-revisions/1/apply"),
        None,
        true,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 有会话但缺 CSRF 头 → 403（与既有写端点同一防线）。
    let (status, body) = call(
        &c,
        "POST",
        &format!("/api/v1/networks/{network_id}/config-revisions/1/rollback"),
        Some(&c.cookie),
        false,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "forbidden");

    // 认证失败不得污染修订状态。
    assert_eq!(
        revisions(&c, &network_id).await.as_array().unwrap()[0]["apply_status"],
        "pending"
    );
}

#[tokio::test]
async fn unknown_network_and_unknown_revision_are_404() {
    let c = ctx().await;
    let created = create_network(&c).await;
    let network_id = created["id"].as_str().unwrap().to_string();

    let (status, body) = call(
        &c,
        "GET",
        "/api/v1/networks/net-does-not-exist/config-revisions",
        Some(&c.cookie),
        false,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");

    let (status, body) = apply(&c, &network_id, 99).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");
}
