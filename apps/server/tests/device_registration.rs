//! Integration test: device bootstrap registration (ZeroTier-style: bootstrap code -> Pending -> console approve/deny).
//!
//! End-to-end path: create a bootstrap code (the raw code is returned exactly once) -> the device registers
//! with it (lands in Pending, **no virtual IP assigned, not added to the desired config**) -> heartbeat
//! evidence during Pending lands on the registration request -> the console approves (only then is an IP
//! allocated and a revision recorded; credentials are not rotated) or denies (pure state cleanup, no revision). Assertion focus:
//! - Pending devices do not appear in `devices` and the desired endpoint returns 404 (migration 008 tradeoff);
//! - name uniqueness spans both devices and registrations;
//! - registering with a revoked/exhausted bootstrap code returns 401; revoking an unknown id admin-side returns 404;
//! - approval keeps the device id and registration-time credential (the desired endpoint goes from 404 to non-401/404).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt; // oneshot

const OVERLAY: &str = "10.240.0.0/16";

/// Test context: router + admin session cookie. Clones share the same underlying state.
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
    // Extractor rejections (e.g. the 422 from deny_unknown_fields) come back as a plain-text
    // body: wrap it verbatim as a string so assertion messages stay readable.
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| serde_json::Value::String(String::from_utf8_lossy(&bytes).to_string()))
}

/// Admin-side write request (cookie + CSRF header).
async fn admin_post(
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

async fn admin_get(ctx: Ctx, uri: &str) -> (StatusCode, serde_json::Value) {
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

async fn admin_delete(ctx: Ctx, uri: &str) -> StatusCode {
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

/// Public endpoint (bootstrap registration): the device comes with a bootstrap code, no session.
async fn register(ctx: Ctx, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let res = ctx
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/device-registrations")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    (res.status(), res_body(res).await)
}

/// Admin-side write request with no body (approve/deny); `cookie = None` uses the public endpoint (enroll).
async fn admin_post_empty(
    ctx: Ctx,
    uri: &str,
    cookie: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method("POST").uri(uri);
    if let Some(c) = cookie {
        builder = builder
            .header("cookie", c)
            .header("x-requested-with", "XMLHttpRequest");
    }
    let res = ctx
        .app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    // 204/3xx has no body: treat it as null instead of parsing an empty body as JSON.
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, body)
}

/// Agent API (Bearer credential, no CSRF).
async fn desired(ctx: Ctx, agent_token: &str) -> (StatusCode, serde_json::Value) {
    let res = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/agent/device/desired")
                .header("authorization", format!("Bearer {agent_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    (res.status(), res_body(res).await)
}

async fn heartbeat(ctx: Ctx, agent_token: &str) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/v1/agent/heartbeat")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {agent_token}"))
        .body(Body::from(
            serde_json::json!({
                "last_handshake_at": null,
                "dataplane": { "tunnel_mtu": 1420 },
            })
            .to_string(),
        ))
        .unwrap();
    // §12: heartbeat observes the direct-connection source address (ConnectInfo is wired up at the serve layer).
    req.extensions_mut().insert(axum::extract::ConnectInfo(
        "10.240.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
    ));
    let res = ctx.app.oneshot(req).await.unwrap();
    (res.status(), res_body(res).await)
}

async fn create_network(ctx: Ctx, name: &str) -> String {
    let (status, body) = admin_post(
        ctx.clone(),
        "/api/v1/networks",
        serde_json::json!({ "name": name, "overlay_cidr": OVERLAY }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["id"].as_str().unwrap().to_string()
}

async fn create_bootstrap_token(
    ctx: Ctx,
    network_id: &str,
    max_uses: Option<u32>,
) -> serde_json::Value {
    let mut body = serde_json::json!({});
    if let Some(m) = max_uses {
        body["max_uses"] = serde_json::json!(m);
    }
    let (status, resp) = admin_post(
        ctx,
        &format!("/api/v1/networks/{network_id}/bootstrap-tokens"),
        body,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{resp}");
    resp
}

fn reg_body(bootstrap_token: &str, name: &str) -> serde_json::Value {
    serde_json::json!({
        "bootstrap_token": bootstrap_token,
        "device_name": name,
        "public_key": "test-public-key",
        "platform": "linux",
    })
}

#[tokio::test]
async fn bootstrap_token_shown_once_then_metadata_only() {
    let ctx = app().await;
    let network_id = create_network(ctx.clone(), "mesh").await;
    let token = create_bootstrap_token(ctx.clone(), &network_id, Some(2)).await;

    // The raw code is returned exactly once; ids start at bt-1.
    assert_eq!(token["token_id"], "bt-1");
    assert!(token["token"].as_str().unwrap().len() >= 32);
    assert_eq!(token["max_uses"], 2);

    // The listing carries metadata only, never credential material.
    let (status, list) = admin_get(
        ctx.clone(),
        &format!("/api/v1/networks/{network_id}/bootstrap-tokens"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list[0]["id"], "bt-1");
    assert_eq!(list[0]["used_count"], 0);
    assert!(list[0].get("token").is_none(), "raw token must not list");
    assert!(list[0].get("token_hash").is_none(), "digest must not list");

    // Revoking again -> 409; an unknown id -> 404 (separate from the 401 a device gets for a bad code).
    assert_eq!(
        admin_delete(
            ctx.clone(),
            &format!("/api/v1/networks/{network_id}/bootstrap-tokens/bt-1"),
        )
        .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        admin_delete(
            ctx.clone(),
            &format!("/api/v1/networks/{network_id}/bootstrap-tokens/bt-1"),
        )
        .await,
        StatusCode::CONFLICT
    );
    assert_eq!(
        admin_delete(
            ctx.clone(),
            &format!("/api/v1/networks/{network_id}/bootstrap-tokens/bt-99"),
        )
        .await,
        StatusCode::NOT_FOUND
    );

    // Registering with a revoked code -> 401.
    let (status, body) = register(
        ctx.clone(),
        reg_body(token["token"].as_str().unwrap(), "dev-a"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

#[tokio::test]
async fn max_uses_exhaustion_rejects_registration() {
    let ctx = app().await;
    let network_id = create_network(ctx.clone(), "mesh").await;
    let token = create_bootstrap_token(ctx.clone(), &network_id, Some(1)).await;
    let raw = token["token"].as_str().unwrap().to_string();

    let (status, first) = register(ctx.clone(), reg_body(&raw, "dev-a")).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    let (status, second) = register(ctx.clone(), reg_body(&raw, "dev-b")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{second}");
}

#[tokio::test]
async fn self_registration_lifecycle_approve() {
    let ctx = app().await;
    let network_id = create_network(ctx.clone(), "mesh").await;
    let token = create_bootstrap_token(ctx.clone(), &network_id, None).await;
    let raw = token["token"].as_str().unwrap().to_string();

    // Baseline: network creation already recorded the initial revision (§10.1); assert only relative deltas from here.
    let (_, revisions) = admin_get(
        ctx.clone(),
        &format!("/api/v1/networks/{network_id}/config-revisions"),
    )
    .await;
    let baseline = revisions.as_array().unwrap().len();

    // Registration -> Pending (no virtual IP field, state always pending).
    let (status, reg) = register(ctx.clone(), reg_body(&raw, "edge-1")).await;
    assert_eq!(status, StatusCode::CREATED, "{reg}");
    assert_eq!(reg["status"], "pending");
    assert_eq!(reg["device_id"], "dev-reg-1");
    let agent_token = reg["agent_token"].as_str().unwrap().to_string();
    assert!(
        !agent_token.is_empty(),
        "agent credential issued at registration"
    );

    // Absent from the devices list; present in the pending-approval list.
    let (_, devices) = admin_get(
        ctx.clone(),
        &format!("/api/v1/networks/{network_id}/devices"),
    )
    .await;
    assert_eq!(
        devices.as_array().unwrap().len(),
        0,
        "pending must not enter devices"
    );
    let (_, regs) = admin_get(
        ctx.clone(),
        &format!("/api/v1/networks/{network_id}/registrations"),
    )
    .await;
    assert_eq!(regs[0]["id"], "dev-reg-1");
    assert_eq!(regs[0]["name"], "edge-1");
    assert!(
        regs[0]["last_report_at"].is_string(),
        "registration is the first report"
    );

    // Desired endpoint: 404 that names pending approval (nothing enters the desired config before approval).
    let (status, body) = desired(ctx.clone(), &agent_token).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("pending approval"),
        "{body}"
    );

    // Heartbeat while Pending: evidence lands on the registration request, and the receipt says pending.
    let (status, hb) = heartbeat(ctx.clone(), &agent_token).await;
    assert_eq!(status, StatusCode::OK, "{hb}");
    assert_eq!(hb["online_state"], "pending");
    let (_, regs) = admin_get(
        ctx.clone(),
        &format!("/api/v1/networks/{network_id}/registrations"),
    )
    .await;
    assert!(regs[0]["last_report_at"].is_string());
    assert_eq!(regs[0]["dataplane_evidence"]["tunnel_mtu"], 1420);

    // Name conflict: same name as a pending request -> 409 (uniqueness spans both sides).
    let (status, body) = register(ctx.clone(), reg_body(&raw, "edge-1")).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // Approval: allocate an IP and record a revision; the response omits agent_token (credentials are not rotated).
    let (status, approved) = admin_post(
        ctx.clone(),
        &format!("/api/v1/networks/{network_id}/devices/dev-reg-1/approve"),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{approved}");
    assert_eq!(approved["device_id"], "dev-reg-1", "device id is kept");
    assert!(approved["virtual_ipv4"].is_string());
    assert!(approved["revision_id"].is_u64());
    assert!(
        approved.get("agent_token").is_none(),
        "credential is not rotated: the device keeps its registration token"
    );
    assert!(approved["approved_at"].is_string());

    // After promotion: visible in the devices list (active, virtual IP present), and the pending-approval list is empty.
    let (_, devices) = admin_get(
        ctx.clone(),
        &format!("/api/v1/networks/{network_id}/devices"),
    )
    .await;
    assert_eq!(devices[0]["id"], "dev-reg-1");
    assert_eq!(devices[0]["status"], "active");
    assert!(devices[0]["approved_at"].is_string());
    let (_, regs) = admin_get(
        ctx.clone(),
        &format!("/api/v1/networks/{network_id}/registrations"),
    )
    .await;
    assert_eq!(regs.as_array().unwrap().len(), 0);

    // The registration-time credential still works: desired goes from 404 to non-401/404 (the dataplane
    // is off by default -> 503 dataplane_not_configured; 401/404 would mean the credential or device identity broke).
    let (status, body) = desired(ctx.clone(), &agent_token).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "token must survive approval, got: {body}"
    );

    // The revision appears with approval: version list +1 relative to the creation baseline, pending apply (§10.1).
    let (_, revisions) = admin_get(
        ctx.clone(),
        &format!("/api/v1/networks/{network_id}/config-revisions"),
    )
    .await;
    assert_eq!(
        revisions.as_array().unwrap().len(),
        baseline + 1,
        "approve records exactly one revision"
    );
}

#[tokio::test]
async fn deny_registration_is_pure_cleanup() {
    let ctx = app().await;
    let network_id = create_network(ctx.clone(), "mesh").await;
    let token = create_bootstrap_token(ctx.clone(), &network_id, None).await;
    let raw = token["token"].as_str().unwrap().to_string();

    let (_, reg) = register(ctx.clone(), reg_body(&raw, "stray")).await;
    let agent_token = reg["agent_token"].as_str().unwrap().to_string();

    // Baseline: the initial revision recorded at network creation.
    let (_, revisions) = admin_get(
        ctx.clone(),
        &format!("/api/v1/networks/{network_id}/config-revisions"),
    )
    .await;
    let baseline = revisions.as_array().unwrap().len();

    // Deny -> the request and its credential are cleaned up together.
    let (status, _) = admin_post_empty(
        ctx.clone(),
        &format!("/api/v1/networks/{network_id}/devices/dev-reg-1/deny"),
        Some(&ctx.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, regs) = admin_get(
        ctx.clone(),
        &format!("/api/v1/networks/{network_id}/registrations"),
    )
    .await;
    assert_eq!(regs.as_array().unwrap().len(), 0);

    // The credential is invalidated by the denial -> 401; the name is immediately reusable.
    let (status, _) = desired(ctx.clone(), &agent_token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = register(ctx.clone(), reg_body(&raw, "stray")).await;
    assert_eq!(status, StatusCode::CREATED);

    // Did the denial record a revision? No - the desired config never contained a Pending request.
    let (_, revisions) = admin_get(
        ctx.clone(),
        &format!("/api/v1/networks/{network_id}/config-revisions"),
    )
    .await;
    assert_eq!(
        revisions.as_array().unwrap().len(),
        baseline,
        "deny records no revision"
    );
}

#[tokio::test]
async fn name_conflict_against_enrolled_device() {
    let ctx = app().await;
    let network_id = create_network(ctx.clone(), "mesh").await;

    // The invite path takes the name first.
    let (_, invite) = admin_post(
        ctx.clone(),
        &format!("/api/v1/networks/{network_id}/invites"),
        serde_json::json!({ "max_uses": 1 }),
    )
    .await;
    let (status, _) = admin_post(
        ctx.clone(),
        "/api/v1/enroll",
        serde_json::json!({
            "invite_token": invite["token"],
            "device_name": "taken",
            "public_key": "k",
            "platform": "linux",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Bootstrap registration with the same name -> 409.
    let token = create_bootstrap_token(ctx.clone(), &network_id, None).await;
    let (status, body) = register(
        ctx.clone(),
        reg_body(token["token"].as_str().unwrap(), "taken"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}

#[tokio::test]
async fn invalid_input_is_rejected_before_token_use() {
    let ctx = app().await;
    let network_id = create_network(ctx.clone(), "mesh").await;
    let token = create_bootstrap_token(ctx.clone(), &network_id, None).await;
    let raw = token["token"].as_str().unwrap().to_string();

    // Unsupported platform / blank name / empty public key -> 400, and **no** use count is consumed.
    for body in [
        serde_json::json!({ "bootstrap_token": raw, "device_name": "x", "public_key": "k", "platform": "macos" }),
        serde_json::json!({ "bootstrap_token": raw, "device_name": "  ", "public_key": "k", "platform": "linux" }),
        serde_json::json!({ "bootstrap_token": raw, "device_name": "x", "public_key": "", "platform": "linux" }),
    ] {
        let (status, resp) = register(ctx.clone(), body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{resp}");
    }

    // A private-key field is rejected right at the API boundary (deny_unknown_fields -> 422, same
    // discipline as enroll: the private key never leaves the device), also without consuming a use.
    let (status, resp) = register(
        ctx.clone(),
        serde_json::json!({ "bootstrap_token": raw, "device_name": "x", "public_key": "k", "platform": "linux", "private_key": "priv" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{resp}");

    // A valid registration still succeeds (max_uses was not spent by the invalid requests - assert used_count in this unlimited-use case).
    let (status, _) = register(ctx.clone(), reg_body(&raw, "ok")).await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, list) = admin_get(
        ctx.clone(),
        &format!("/api/v1/networks/{network_id}/bootstrap-tokens"),
    )
    .await;
    assert_eq!(list[0]["used_count"], 1);
}
