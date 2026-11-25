//! Integration tests: API Tokens for external machine credentials (2026-10-14 user request).
//!
//! Acceptance: external systems can call long-term (Bearer `mlt_…`); tokens are revocable, least-privilege
//! (`read` / `write`), with clear audit attribution; they coexist with existing Cookie sessions and **do not
//! weaken CSRF protection**.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt; // oneshot

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

async fn call(
    c: &Ctx,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    bearer: Option<&str>,
    csrf: bool,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    if let Some(bearer) = bearer {
        builder = builder.header("authorization", format!("Bearer {bearer}"));
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

async fn create_token(c: &Ctx, name: &str, scopes: &str) -> (StatusCode, Value) {
    call(
        c,
        "POST",
        "/api/v1/auth/tokens",
        Some(&c.cookie),
        None,
        true,
        Some(json!({ "name": name, "scopes": scopes })),
    )
    .await
}

async fn revoke_token(c: &Ctx, id: &str) -> (StatusCode, Value) {
    call(
        c,
        "DELETE",
        &format!("/api/v1/auth/tokens/{id}"),
        Some(&c.cookie),
        None,
        true,
        None,
    )
    .await
}

async fn list_tokens(c: &Ctx) -> Value {
    let (status, body) = call(
        c,
        "GET",
        "/api/v1/auth/tokens",
        Some(&c.cookie),
        None,
        false,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    body
}

#[tokio::test]
async fn write_token_can_read_and_write_the_management_api() {
    let c = ctx().await;
    let (status, created) = create_token(&c, "cockpit", "write").await;
    assert_eq!(status, StatusCode::CREATED);
    let token = created["token"].as_str().unwrap();
    // A recognizable prefix (distinguishes agent tokens from invite tokens) + 32 bytes of random material.
    assert!(token.starts_with("mlt_"), "token must be prefixed: {token}");
    assert_eq!(token.len(), 68, "mlt_ + 64 hex");

    let (status, body) = call(
        &c,
        "GET",
        "/api/v1/networks",
        None,
        Some(token),
        false,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_array());

    let (status, body) = call(
        &c,
        "POST",
        "/api/v1/networks",
        None,
        Some(token),
        true,
        Some(json!({ "name": "remote", "overlay_cidr": "10.240.0.0/16" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    // ADR-009: config-mutating responses carry revision_id and apply_status (the same holds for token callers).
    assert_eq!(body["revision_id"], 1);
    assert_eq!(body["apply_status"], "pending");
}

#[tokio::test]
async fn read_token_cannot_write() {
    let c = ctx().await;
    let (_, created) = create_token(&c, "reader", "read").await;
    let token = created["token"].as_str().unwrap().to_string();

    let (status, _) = call(
        &c,
        "GET",
        "/api/v1/networks",
        None,
        Some(&token),
        false,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = call(
        &c,
        "POST",
        "/api/v1/networks",
        None,
        Some(&token),
        true,
        Some(json!({ "name": "x", "overlay_cidr": "10.240.0.0/16" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "forbidden");

    // Least privilege must not affect a session admin.
    let (status, _) = call(
        &c,
        "POST",
        "/api/v1/networks",
        Some(&c.cookie),
        None,
        true,
        Some(json!({ "name": "x", "overlay_cidr": "10.240.0.0/16" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn csrf_guard_still_applies_to_token_writes() {
    let c = ctx().await;
    let (_, created) = create_token(&c, "cockpit", "write").await;
    let token = created["token"].as_str().unwrap().to_string();

    // Missing X-Requested-With -> 403 (exactly the same defense line as Cookie sessions, not weakened).
    let (status, body) = call(
        &c,
        "POST",
        "/api/v1/networks",
        None,
        Some(&token),
        false,
        Some(json!({ "name": "x", "overlay_cidr": "10.240.0.0/16" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "forbidden");
}

#[tokio::test]
async fn invalid_and_revoked_tokens_are_unauthorized() {
    let c = ctx().await;

    for raw in [
        "",
        "abc",
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    ] {
        let (status, body) =
            call(&c, "GET", "/api/v1/networks", None, Some(raw), false, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "raw={raw:?}");
        assert_eq!(body["error"]["code"], "unauthorized");
    }

    let (_, created) = create_token(&c, "cockpit", "write").await;
    let token = created["token"].as_str().unwrap().to_string();
    let id = created["id"].as_str().unwrap().to_string();
    let (status, _) = revoke_token(&c, &id).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call(
        &c,
        "GET",
        "/api/v1/networks",
        None,
        Some(&token),
        false,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "revoked token must not authenticate"
    );
}

#[tokio::test]
async fn raw_token_is_returned_once_and_never_listed() {
    let c = ctx().await;
    let (status, created) = create_token(&c, "cockpit", "write").await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(created["token"].is_string());
    assert!(created["token"].as_str().unwrap().starts_with("mlt_"));

    let list = list_tokens(&c).await;
    let entries = list.as_array().unwrap();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert!(entry["id"].is_string());
    assert_eq!(entry["name"], "cockpit");
    assert_eq!(entry["scopes"], "write");
    assert!(entry["created_at"].is_string());
    // The listing never returns the raw token or its digest (only the digest is stored, so lists are safe to log).
    assert!(entry.get("token").is_none());
    assert!(entry.get("token_hash").is_none());

    let (status, _) = revoke_token(&c, entry["id"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let list = list_tokens(&c).await;
    let revoked = list.as_array().unwrap()[0]["revoked_at"].clone();
    assert!(
        revoked.is_string(),
        "revoked tokens stay listed with revoked_at"
    );
}

#[tokio::test]
async fn token_management_requires_authentication_and_validation() {
    let c = ctx().await;

    // Create a token without credentials -> 401.
    let (status, body) = call(
        &c,
        "POST",
        "/api/v1/auth/tokens",
        None,
        None,
        true,
        Some(json!({ "name": "x", "scopes": "read" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "unauthorized");

    // Unknown scope -> 400.
    let (status, body) = create_token(&c, "x", "admin").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "validation_failed");

    // Empty name -> 400.
    let (status, _) = create_token(&c, "   ", "read").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Revoking a nonexistent token -> 404.
    let (status, _) = revoke_token(&c, "tok-does-not-exist").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn last_used_at_records_token_ownership_and_usage() {
    let c = ctx().await;
    let (_, created) = create_token(&c, "cockpit", "read").await;
    let token = created["token"].as_str().unwrap().to_string();

    let list = list_tokens(&c).await;
    let before = list.as_array().unwrap()[0]["last_used_at"].is_null();
    assert!(before, "a fresh token has never been used");

    let (status, _) = call(
        &c,
        "GET",
        "/api/v1/networks",
        None,
        Some(&token),
        false,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let list = list_tokens(&c).await;
    let after = list.as_array().unwrap()[0]["last_used_at"].clone();
    assert!(
        after.is_string(),
        "usage must be attributed to the token row"
    );
}

#[tokio::test]
async fn api_tokens_and_agent_tokens_are_separate_boundaries() {
    let c = ctx().await;
    let (_, created) = create_token(&c, "cockpit", "write").await;
    let token = created["token"].as_str().unwrap();

    // A management token is not an agent credential: agent endpoints still require an agent_token (§13.7).
    let (status, body) = call(
        &c,
        "POST",
        "/api/v1/agent/heartbeat",
        None,
        Some(token),
        false,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "unauthorized");

    // The Cookie session is still a full admin channel (the token's existence does not change session semantics).
    let (status, body) = call(
        &c,
        "GET",
        "/api/v1/auth/me",
        Some(&c.cookie),
        None,
        false,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["email"]
        .as_str()
        .unwrap()
        .ends_with("admin@test.local"));
}
