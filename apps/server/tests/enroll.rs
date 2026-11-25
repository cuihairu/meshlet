//! Integration tests: the device-join invite flow (archive §11.2, ADR-010).
//!
//! End-to-end path: create network → generate invite (one-time Token, only its digest is stored) →
//! device joins with its public key (the private key never leaves the client) → virtual IP assigned → the device shows up in the device list.
//! Each test owns its own router instance (independent in-memory state + independent SQLite), with state shared across requests within a test.
//! Management endpoints are accessed with a bootstrap session Cookie + CSRF header (§11.4); /enroll stays public.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt; // oneshot

const OVERLAY: &str = "10.240.0.0/16";

/// Test context: router + management session Cookie. Clones share the same underlying state.
#[derive(Clone)]
struct Ctx {
    app: Router,
    cookie: String,
}

async fn app() -> Ctx {
    let pool = meshlet_server::store::connect("sqlite::memory:")
        .await
        .unwrap();
    let state = std::sync::Arc::new(meshlet_server::auth::AppState::new(
        meshlet_server::service::SharedState::default(),
        meshlet_server::auth::AuthStore::new(pool.clone()),
        meshlet_server::agent::AgentTokenStore::new(pool.clone()),
        meshlet_server::api_token::ApiTokenStore::new(pool),
        false,
    ));
    let app = meshlet_server::router(state);

    // Bootstrap the first administrator on an empty DB and take the session Cookie.
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
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

async fn res_body(res: axum::response::Response) -> serde_json::Value {
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn json_post(
    ctx: Ctx,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let res = ctx
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .header("cookie", &ctx.cookie)
                .header("x-requested-with", "XMLHttpRequest")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    (res.status(), res_body(res).await)
}

async fn json_get(ctx: Ctx, uri: &str) -> (StatusCode, serde_json::Value) {
    let res = ctx
        .app
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("cookie", &ctx.cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    (res.status(), res_body(res).await)
}

async fn json_delete(ctx: Ctx, uri: &str) -> StatusCode {
    let res = ctx
        .app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(uri)
                .header("cookie", &ctx.cookie)
                .header("x-requested-with", "XMLHttpRequest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    res.status()
}

async fn create_network(ctx: Ctx, name: &str) -> (StatusCode, serde_json::Value) {
    json_post(
        ctx,
        "/api/v1/networks",
        serde_json::json!({ "name": name, "overlay_cidr": OVERLAY }),
    )
    .await
}

async fn create_invite(
    ctx: Ctx,
    network_id: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    json_post(ctx, &format!("/api/v1/networks/{network_id}/invites"), body).await
}

async fn enroll(
    ctx: Ctx,
    token: &str,
    device_name: &str,
    public_key: &str,
    platform: &str,
) -> (StatusCode, serde_json::Value) {
    json_post(
        ctx,
        "/api/v1/enroll",
        serde_json::json!({
            "invite_token": token,
            "device_name": device_name,
            "public_key": public_key,
            "platform": platform,
        }),
    )
    .await
}

#[tokio::test]
async fn enroll_end_to_end_allocates_virtual_ip() {
    let app = app().await;
    let (st, network) = create_network(app.clone(), "home").await;
    assert_eq!(st, StatusCode::CREATED);
    let network_id = network["id"].as_str().unwrap();
    assert_eq!(network["overlay_cidr"], OVERLAY);

    let (st, invite) = create_invite(app.clone(), network_id, serde_json::json!({})).await;
    assert_eq!(st, StatusCode::CREATED);
    let token = invite["token"].as_str().unwrap().to_string();
    assert_eq!(token.len(), 64, "token must be 64 hex chars");
    // The raw Token appears only in the create response; nothing lands on disk beyond the digest.
    assert!(invite.get("token_hash").is_none());

    let (st, device) = enroll(app.clone(), &token, "laptop", "pub-key-1", "linux").await;
    assert_eq!(st, StatusCode::CREATED);
    assert_eq!(device["network_id"], network_id);
    assert_eq!(
        device["virtual_ipv4"].as_str().unwrap(),
        "10.240.0.2",
        "first client gets second usable address (hub = .1)"
    );
    // The fingerprint is the SHA-256 of the public key.
    assert_eq!(
        device["fingerprint"].as_str().unwrap(),
        "68112dd75f2b1c7c3861359a6a801ebe43de201375b5d14e0ff978a5c0e08a93"
    );

    // The device is visible in the list and carries only public-key-side material.
    let (st, devices) = json_get(app, &format!("/api/v1/networks/{network_id}/devices")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(devices.as_array().unwrap().len(), 1);
    assert_eq!(devices[0]["name"], "laptop");
}

#[tokio::test]
async fn single_use_invite_rejects_second_enroll() {
    let app = app().await;
    let (_, network) = create_network(app.clone(), "office").await;
    let network_id = network["id"].as_str().unwrap();

    let (_, invite) = create_invite(app.clone(), network_id, serde_json::json!({})).await;
    let token = invite["token"].as_str().unwrap().to_string();

    let (_, d1) = enroll(app.clone(), &token, "phone", "pub-a", "windows").await;
    assert_eq!(d1["virtual_ipv4"].as_str().unwrap(), "10.240.0.2");

    // A second use of the same Token: rejected by one-time semantics (usage cap of 1).
    let (st, err) = enroll(app, &token, "phone-2", "pub-b", "windows").await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(err["error"]["message"]
        .as_str()
        .unwrap()
        .contains("use limit"));
}

#[tokio::test]
async fn multi_use_invite_allocates_sequential_ips() {
    let app = app().await;
    let (_, network) = create_network(app.clone(), "lab").await;
    let network_id = network["id"].as_str().unwrap();

    let (_, invite) = create_invite(
        app.clone(),
        network_id,
        serde_json::json!({ "max_uses": 2 }),
    )
    .await;
    let token = invite["token"].as_str().unwrap().to_string();

    let (_, d1) = enroll(app.clone(), &token, "dev-1", "pub-1", "linux").await;
    let (_, d2) = enroll(app, &token, "dev-2", "pub-2", "linux").await;
    assert_eq!(d1["virtual_ipv4"].as_str().unwrap(), "10.240.0.2");
    assert_eq!(d2["virtual_ipv4"].as_str().unwrap(), "10.240.0.3");
}

#[tokio::test]
async fn enroll_with_unknown_token_is_404_without_does_not_leak_it() {
    let app = app().await;
    let (_, _) = create_network(app.clone(), "secure").await;

    let (st, err) = enroll(app, "wrong-token-abc", "ghost", "pub-x", "linux").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(err["error"]["code"], "not_found");
    // A nonexistent Token is indistinguishable from an invalid one (no existence leak).
    let body = serde_json::to_string(&err).unwrap();
    assert!(!body.contains("wrong-token-abc"));
}

#[tokio::test]
async fn enroll_expired_invite_is_rejected() {
    let app = app().await;
    let (_, network) = create_network(app.clone(), "expired").await;
    let network_id = network["id"].as_str().unwrap();

    let (_, invite) = create_invite(
        app.clone(),
        network_id,
        serde_json::json!({ "expires_at": "2020-01-01T00:00:00Z" }),
    )
    .await;
    let token = invite["token"].as_str().unwrap().to_string();

    let (st, err) = enroll(app, &token, "late", "pub-l", "linux").await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(err["error"]["message"]
        .as_str()
        .unwrap()
        .contains("expired"));
}

#[tokio::test]
async fn enroll_revoked_invite_is_rejected() {
    let app = app().await;
    let (_, network) = create_network(app.clone(), "revoked").await;
    let network_id = network["id"].as_str().unwrap();

    let (_, invite) = create_invite(app.clone(), network_id, serde_json::json!({})).await;
    let token = invite["token"].as_str().unwrap().to_string();
    let invite_id = invite["invite_id"].as_str().unwrap();

    let st = json_delete(
        app.clone(),
        &format!("/api/v1/networks/{network_id}/invites/{invite_id}"),
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);

    let (st, err) = enroll(app, &token, "revoked-dev", "pub-r", "linux").await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(err["error"]["message"]
        .as_str()
        .unwrap()
        .contains("revoked"));
}

#[tokio::test]
async fn enroll_rejects_private_key_field() {
    // The private key never leaves the client: the API boundary rejects any extra field via deny_unknown_fields.
    let app = app().await;
    let (_, network) = create_network(app.clone(), "nopriv").await;
    let network_id = network["id"].as_str().unwrap();
    let (_, invite) = create_invite(app.clone(), network_id, serde_json::json!({})).await;
    let token = invite["token"].as_str().unwrap().to_string();

    let res = app
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/enroll")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "invite_token": token,
                        "device_name": "bad",
                        "public_key": "pub-1",
                        "platform": "linux",
                        "private_key": "super-secret",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    // axum answers a uniform 422 for JSON deserialization failures (including deny_unknown_fields).
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn enroll_never_persists_private_key_material() {
    let app = app().await;
    let (_, network) = create_network(app.clone(), "audit").await;
    let network_id = network["id"].as_str().unwrap();
    let (_, invite) = create_invite(app.clone(), network_id, serde_json::json!({})).await;
    let token = invite["token"].as_str().unwrap().to_string();

    enroll(app.clone(), &token, "audited", "pub-only", "linux").await;

    // The device list carries only the public key + fingerprint; no private-key-side field anywhere in the response.
    let (st, devices) = json_get(app, &format!("/api/v1/networks/{network_id}/devices")).await;
    assert_eq!(st, StatusCode::OK);
    let raw = devices.to_string();
    assert!(raw.contains("public_key"));
    assert!(!raw.contains("private"));
}

#[tokio::test]
async fn create_network_validates_cidr_and_duplicates() {
    let app = app().await;
    let (st, _) = create_network(app.clone(), "net-a").await;
    assert_eq!(st, StatusCode::CREATED);

    // An invalid CIDR with nonzero host bits is rejected.
    let (st, _) = json_post(
        app.clone(),
        "/api/v1/networks",
        serde_json::json!({ "name": "bad", "overlay_cidr": "10.240.0.1/16" }),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // A CIDR that cannot be parsed at all is rejected.
    let (st, _) = json_post(
        app.clone(),
        "/api/v1/networks",
        serde_json::json!({ "name": "bad", "overlay_cidr": "not-a-cidr" }),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // The same overlay range cannot be created twice.
    let (st, _) = json_post(
        app,
        "/api/v1/networks",
        serde_json::json!({ "name": "net-b", "overlay_cidr": OVERLAY }),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
}

#[tokio::test]
async fn enroll_rejects_duplicate_device_name() {
    let app = app().await;
    let (_, network) = create_network(app.clone(), "dup").await;
    let network_id = network["id"].as_str().unwrap();

    let (_, i1) = create_invite(app.clone(), network_id, serde_json::json!({})).await;
    let (_, i2) = create_invite(app.clone(), network_id, serde_json::json!({})).await;

    let (st, _) = enroll(
        app.clone(),
        i1["token"].as_str().unwrap(),
        "same-name",
        "pub-1",
        "linux",
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, err) = enroll(
        app,
        i2["token"].as_str().unwrap(),
        "same-name",
        "pub-2",
        "linux",
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert!(err["error"]["message"].as_str().unwrap().contains("name"));
}

#[tokio::test]
async fn enroll_rejects_unsupported_platform() {
    let app = app().await;
    let (_, network) = create_network(app.clone(), "plat").await;
    let network_id = network["id"].as_str().unwrap();
    let (_, invite) = create_invite(app.clone(), network_id, serde_json::json!({})).await;
    let token = invite["token"].as_str().unwrap().to_string();

    let (st, _) = enroll(app, &token, "watch", "pub-w", "freebsd").await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_invite_rejects_zero_max_uses() {
    let app = app().await;
    let (_, network) = create_network(app.clone(), "zero").await;
    let network_id = network["id"].as_str().unwrap();

    let (st, _) = create_invite(app, network_id, serde_json::json!({ "max_uses": 0 })).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn each_router_holds_independent_state() {
    // Each router instance holds independent in-memory state, so networks never bleed across tests.
    let app_a = app().await;
    let app_b = app().await;

    let (st, _) = create_network(app_a.clone(), "iso-a").await;
    assert_eq!(st, StatusCode::CREATED);

    let (_, nets_a) = json_get(app_a, "/api/v1/networks").await;
    assert_eq!(nets_a.as_array().unwrap().len(), 1);
    let (_, nets_b) = json_get(app_b, "/api/v1/networks").await;
    assert_eq!(nets_b.as_array().unwrap().len(), 0);
}
