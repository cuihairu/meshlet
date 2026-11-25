//! Integration tests: device revocation (the external API controls the "peer revoked" entry; the
//! control-plane half of the full §11.5 chain).
//!
//! Revocation = device state flips to `revoked` (offline) + agent credential invalidated immediately +
//! a desired-config revision (the revoked device is excluded from the config hash, ADR-009). The response is 202 carrying `RevisionRef`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt; // oneshot

const OVERLAY: &str = "10.240.0.0/16";

#[derive(Clone)]
struct Ctx {
    app: Router,
    cookie: String,
}

async fn ctx() -> Ctx {
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
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email": "admin@test.local", "password": "bootstrap-password-123"})
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

async fn json_post(c: &Ctx, uri: &str, body: Value) -> (StatusCode, Value) {
    call(c, "POST", uri, Some(&c.cookie), true, Some(body)).await
}

async fn json_get(c: &Ctx, uri: &str) -> (StatusCode, Value) {
    call(c, "GET", uri, Some(&c.cookie), false, None).await
}

/// Create a network + invite + join one device; returns (network_id, device_id, agent_token).
async fn net_with_device(c: &Ctx, name: &str) -> (String, String, String) {
    let (st, network) = json_post(
        c,
        "/api/v1/networks",
        json!({"name": name, "overlay_cidr": OVERLAY}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let network_id = network["id"].as_str().unwrap().to_string();
    let (st, invite) = json_post(
        c,
        &format!("/api/v1/networks/{network_id}/invites"),
        json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, device) = json_post(
        c,
        "/api/v1/enroll",
        json!({
            "invite_token": invite["token"].as_str().unwrap(),
            "device_name": format!("dev-{name}"),
            "public_key": format!("pub-key-{name}"),
            "platform": "linux",
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    (
        network_id,
        device["device_id"].as_str().unwrap().to_string(),
        device["agent_token"].as_str().unwrap().to_string(),
    )
}

fn revoke_uri(network_id: &str, device_id: &str) -> String {
    format!("/api/v1/networks/{network_id}/devices/{device_id}/revoke")
}

#[tokio::test]
async fn revoke_marks_device_offline_and_records_revision() {
    let c = ctx().await;
    let (network_id, device_id, _agent) = net_with_device(&c, "home").await;

    let (st, rev) = json_post(&c, &revoke_uri(&network_id, &device_id), json!({})).await;
    // 202: accepted; config takes effect pending apply (ADR-009).
    assert_eq!(st, StatusCode::ACCEPTED);
    assert_eq!(rev["revision_id"], 3, "net=1 enroll=2 revoke=3");
    assert_eq!(rev["apply_status"], "pending");

    // Device state flips to revoked (offline); fields like the virtual IP are retained for auditing.
    let (_, devices) = json_get(&c, &format!("/api/v1/networks/{network_id}/devices")).await;
    let entry = devices
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["id"] == device_id.as_str())
        .unwrap();
    assert_eq!(entry["status"], "revoked");
}

#[tokio::test]
async fn revoked_device_leaves_the_desired_config() {
    let c = ctx().await;
    let (network_id, device_id, _agent) = net_with_device(&c, "home").await;

    let (_, before) = json_get(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions"),
    )
    .await;
    assert_eq!(before.as_array().unwrap().len(), 2, "net + enroll");

    let (st, _) = json_post(&c, &revoke_uri(&network_id, &device_id), json!({})).await;
    assert_eq!(st, StatusCode::ACCEPTED);

    // The new revision records the desired config without the revoked device: the hash must change (§10.4 monotonic increase).
    let (_, revisions) = json_get(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions"),
    )
    .await;
    let revisions = revisions.as_array().unwrap();
    assert_eq!(revisions.len(), 3);
    let hash = |r: &Value| r["desired_config_hash"].as_str().unwrap().to_string();
    assert_ne!(
        hash(&revisions[1]),
        hash(&revisions[2]),
        "device left the config"
    );
    assert_eq!(revisions[2]["revision"], 3);
}

#[tokio::test]
async fn revoked_device_agent_token_is_rejected_immediately() {
    let c = ctx().await;
    let (network_id, device_id, agent_token) = net_with_device(&c, "home").await;
    let hb = |_c: &Ctx| {
        let mut req = Request::builder()
            .method("POST")
            .uri("/api/v1/agent/heartbeat")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {agent_token}"))
            .body(Body::from(json!({}).to_string()))
            .unwrap();
        // §12: the heartbeat observes the direct-connection source address (ConnectInfo is wired in the serve layer).
        req.extensions_mut().insert(axum::extract::ConnectInfo(
            "10.240.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
        ));
        req
    };
    // Heartbeat is healthy before revocation.
    let res = c.app.clone().oneshot(hb(&c)).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let (st, _) = json_post(&c, &revoke_uri(&network_id, &device_id), json!({})).await;
    assert_eq!(st, StatusCode::ACCEPTED);

    // After revocation the same agent token is invalidated immediately (credential boundary in sync with device state).
    let res = c.app.clone().oneshot(hb(&c)).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn double_revoke_is_a_conflict() {
    let c = ctx().await;
    let (network_id, device_id, _agent) = net_with_device(&c, "home").await;

    let (st, _) = json_post(&c, &revoke_uri(&network_id, &device_id), json!({})).await;
    assert_eq!(st, StatusCode::ACCEPTED);
    let (st, body) = json_post(&c, &revoke_uri(&network_id, &device_id), json!({})).await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "conflict");
}

#[tokio::test]
async fn revoke_of_unknown_device_or_network_is_404() {
    let c = ctx().await;
    let (network_id, _device_id, _agent) = net_with_device(&c, "home").await;

    let (st, body) = json_post(&c, &revoke_uri(&network_id, "dev-999"), json!({})).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");
    let (st, _) = json_post(&c, &revoke_uri("nope", "dev-1"), json!({})).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn revoke_requires_write_credentials_and_csrf() {
    let c = ctx().await;
    let (network_id, device_id, _agent) = net_with_device(&c, "home").await;

    // No credential → 401.
    let (st, _) = call(
        &c,
        "POST",
        &revoke_uri(&network_id, &device_id),
        None,
        true,
        Some(json!({})),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    // Cookie session without the CSRF header → 403.
    let (st, _) = call(
        &c,
        "POST",
        &revoke_uri(&network_id, &device_id),
        Some(&c.cookie),
        false,
        Some(json!({})),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn revoke_removes_the_revoked_device_published_routes() {
    // §11.5: routes published by a revoked device must be removed along with it (AllowedIPs
    // derivation must be left no segment pointing at a revoked peer); other devices' routes are unaffected.
    let c = ctx().await;
    let (network_id, device_a, _agent_a) = net_with_device(&c, "home").await;

    // A second device (same network, separate invite).
    let (_, invite_b) = json_post(
        &c,
        &format!("/api/v1/networks/{network_id}/invites"),
        json!({}),
    )
    .await;
    assert!(
        invite_b["token"].as_str().unwrap().len() > 32,
        "invite token material"
    );
    let (st, device_b_resp) = json_post(
        &c,
        "/api/v1/enroll",
        json!({
            "invite_token": invite_b["token"].as_str().unwrap(),
            "device_name": "dev-away",
            "public_key": "pub-key-away",
            "platform": "linux",
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let device_b = device_b_resp["device_id"].as_str().unwrap().to_string();

    // Each device publishes one route.
    let routes_uri = format!("/api/v1/networks/{network_id}/routes");
    for (gateway, dst) in [(&device_a, "192.168.1.0/24"), (&device_b, "192.168.2.0/24")] {
        let (st, _) = json_post(
            &c,
            &routes_uri,
            json!({
                "gateway_device_id": gateway,
                "destination_cidr": dst,
                "return_path_mode": "dual_route",
            }),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED, "gateway={gateway}");
    }

    // Revoke device A.
    let (st, rev) = json_post(&c, &revoke_uri(&network_id, &device_a), json!({})).await;
    assert_eq!(st, StatusCode::ACCEPTED);
    assert_eq!(rev["revision_id"], 6, "net=1, enroll×2, route×2 → revoke=6");

    // A's route is removed; B's route is left intact.
    let (_, list) = json_get(&c, &routes_uri).await;
    let routes = list.as_array().unwrap();
    assert_eq!(routes.len(), 1, "only the surviving route remains");
    assert_eq!(routes[0]["gateway_device_id"], device_b.as_str());
    assert_eq!(routes[0]["destination_cidr"], "192.168.2.0/24");
}
