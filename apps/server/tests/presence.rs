//! Integration test: online-state determination (archive §12.2/§12.4, §14.1).
//!
//! End-to-end path: enrollment (issues the agent_token, exactly once) → agent heartbeat
//! (Bearer credential, optionally carrying a `wg show` handshake reading) → the device list carries
//! `online_state` / `presence_source` / `last_seen_at` (evidence source + update time).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use meshlet_domain::PresenceThresholds;
use std::time::Duration;
use tower::ServiceExt; // oneshot

const OVERLAY: &str = "10.240.0.0/16";

/// Test context: router + admin session cookie + agent_token + network_id.
/// Cloning shares the same underlying state.
#[derive(Clone)]
struct Ctx {
    app: Router,
    cookie: String,
    network_id: String,
    device_id: String,
    agent_token: String,
}

/// The decision windows are injectable (defaults 300s/120s; the tunnel_only case tightens the report window to 0,
/// making "report past the window, handshake still fresh" deterministically constructible).
async fn app(thresholds: PresenceThresholds) -> Ctx {
    let pool = meshlet_server::store::connect("sqlite::memory:")
        .await
        .unwrap();
    let mesh = std::sync::Arc::new(std::sync::Mutex::new(
        meshlet_server::service::MeshState::new(thresholds),
    ));
    let state = std::sync::Arc::new(meshlet_server::auth::AppState::new(
        mesh,
        meshlet_server::auth::AuthStore::new(pool.clone()),
        meshlet_server::agent::AgentTokenStore::new(pool.clone()),
        meshlet_server::api_token::ApiTokenStore::new(pool),
        false,
    ));
    let app = meshlet_server::router(state);

    // Bootstrap the first admin on the empty db, taking the session cookie.
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

    // Create the network + invite + device enrollment (public endpoints, outside the admin API boundary).
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/networks")
                .header("content-type", "application/json")
                .header("cookie", &cookie)
                .header("x-requested-with", "XMLHttpRequest")
                .body(Body::from(
                    serde_json::json!({ "name": "home", "overlay_cidr": OVERLAY }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let network_id = res_body(res).await["id"].as_str().unwrap().to_string();

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/networks/{network_id}/invites"))
                .header("content-type", "application/json")
                .header("cookie", &cookie)
                .header("x-requested-with", "XMLHttpRequest")
                .body(Body::from(serde_json::json!({ "max_uses": 1 }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let invite = res_body(res).await;
    let invite_token = invite["token"].as_str().unwrap().to_string();

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/enroll")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "invite_token": invite_token,
                        "device_name": "laptop",
                        "public_key": "pub-laptop-0001",
                        "platform": "linux",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let enroll = res_body(res).await;
    let device_id = enroll["device_id"].as_str().unwrap().to_string();
    let agent_token = enroll["agent_token"].as_str().unwrap().to_string();
    assert!(
        agent_token.len() == 64 && agent_token.chars().all(|c| c.is_ascii_hexdigit()),
        "agent_token must be a 64-char hex token: {agent_token}"
    );

    Ctx {
        app,
        cookie,
        network_id,
        device_id,
        agent_token,
    }
}

async fn res_body(res: axum::response::Response) -> serde_json::Value {
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// Agent heartbeat (Bearer credential; not the admin API, so no CSRF header needed).
async fn heartbeat(
    ctx: Ctx,
    agent_token: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/v1/agent/heartbeat")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {agent_token}"))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    // §12: observe the direct-connect source address on heartbeat (ConnectInfo is assembled at the serve layer).
    req.extensions_mut().insert(axum::extract::ConnectInfo(
        "10.240.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
    ));
    let res = ctx.app.oneshot(req).await.unwrap();
    (res.status(), res_body(res).await)
}

/// Admin device list (cookie session + CSRF).
async fn list_devices(ctx: &Ctx) -> (StatusCode, serde_json::Value) {
    let res = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/networks/{}/devices", ctx.network_id))
                .header("cookie", &ctx.cookie)
                .header("x-requested-with", "XMLHttpRequest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    (res.status(), res_body(res).await)
}

fn device_of(list: &serde_json::Value, device_id: &str) -> serde_json::Value {
    list.as_array()
        .unwrap()
        .iter()
        .find(|d| d["id"].as_str() == Some(device_id))
        .unwrap_or_else(|| panic!("device {device_id} missing from list"))
        .clone()
}

#[tokio::test]
async fn heartbeat_marks_device_online_with_agent_source() {
    let ctx = app(PresenceThresholds::default()).await;

    // Heartbeat: agent report + the handshake time read locally.
    let (status, body) = heartbeat(
        ctx.clone(),
        &ctx.agent_token,
        serde_json::json!({ "last_handshake_at": "2026-10-14T11:59:00Z" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["online_state"], "online");
    assert_eq!(body["presence_source"], "agent_report");
    assert!(body["last_seen_at"].as_str().is_some_and(|s| !s.is_empty()));

    // The device list carries state + evidence source + update time (§12.2: never just a green icon).
    let (status, list) = list_devices(&ctx).await;
    assert_eq!(status, StatusCode::OK);
    let device = device_of(&list, &ctx.device_id);
    assert_eq!(device["online_state"], "online");
    assert_eq!(device["presence_source"], "agent_report");
    assert!(device["last_seen_at"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
}

#[tokio::test]
async fn device_before_any_heartbeat_is_offline_with_enrollment_source() {
    // Freshly enrolled with no heartbeat/handshake yet: offline, source = enrollment, last time = enrollment moment.
    let ctx = app(PresenceThresholds::default()).await;
    let (status, list) = list_devices(&ctx).await;
    assert_eq!(status, StatusCode::OK);
    let device = device_of(&list, &ctx.device_id);
    assert_eq!(device["online_state"], "offline");
    assert_eq!(device["presence_source"], "enrollment");
    assert!(device["last_seen_at"].as_str().is_some());
}

#[tokio::test]
async fn handshake_only_evidence_is_tunnel_only_not_online() {
    // §12.4: a recent WireGuard handshake ≠ all of the device's networking working.
    // The report window is tightened to 0: at the moment the heartbeat arrives the report is still fresh (delta=0); one second later the report is stale,
    // while the handshake reading is still inside the window → tunnel_only (deterministic: second-granularity timestamps give delta>=1 > 0).
    // The handshake reading comes from the current instant (relative time, unaffected by the wall-clock date).
    let ctx = app(PresenceThresholds {
        agent_window: Duration::ZERO,
        handshake_window: Duration::from_secs(300),
    })
    .await;

    let (status, body) = heartbeat(
        ctx.clone(),
        &ctx.agent_token,
        serde_json::json!({ "last_handshake_at": meshlet_server::service::now() }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["online_state"], "online"); // the report is still fresh the instant it arrives

    tokio::time::sleep(std::time::Duration::from_millis(1050)).await;

    let (_, list) = list_devices(&ctx).await;
    let device = device_of(&list, &ctx.device_id);
    assert_eq!(device["online_state"], "tunnel_only");
    assert_eq!(device["presence_source"], "handshake");
    assert_ne!(device["online_state"], "online");
}

#[tokio::test]
async fn heartbeat_requires_valid_agent_token() {
    let ctx = app(PresenceThresholds::default()).await;
    let body = serde_json::json!({});

    // No Authorization header → 401.
    let res = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/heartbeat")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // A forged token → 401.
    let (status, _) = heartbeat(ctx.clone(), &"deadbeef".repeat(8), body.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A wrong scheme → 401.
    let res = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/heartbeat")
                .header("content-type", "application/json")
                .header("authorization", format!("Basic {}", ctx.agent_token))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // A forged or invalid token must not pollute the device state.
    let (_, list) = list_devices(&ctx).await;
    let device = device_of(&list, &ctx.device_id);
    assert_eq!(device["online_state"], "offline");
}

#[tokio::test]
async fn heartbeat_rejects_malformed_handshake_timestamp() {
    let ctx = app(PresenceThresholds::default()).await;
    let (status, body) = heartbeat(
        ctx.clone(),
        &ctx.agent_token,
        serde_json::json!({ "last_handshake_at": "yesterday" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "validation_failed");
}

#[tokio::test]
async fn heartbeat_without_handshake_field_still_reports() {
    // No handshake reading carried: the report time alone is enough to decide (an agent report is the strongest evidence).
    let ctx = app(PresenceThresholds::default()).await;
    let (status, body) = heartbeat(ctx.clone(), &ctx.agent_token, serde_json::json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["online_state"], "online");
    assert_eq!(body["presence_source"], "agent_report");
}

#[tokio::test]
async fn repeated_heartbeat_keeps_token_valid_and_state_accumulates() {
    // Repeated heartbeats with the same token are all accepted (the digest verification path), and the state keeps accumulating.
    let ctx = app(PresenceThresholds::default()).await;
    for _ in 0..2 {
        let (status, body) = heartbeat(ctx.clone(), &ctx.agent_token, serde_json::json!({})).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["online_state"], "online");
        assert!(body["last_seen_at"].as_str().is_some_and(|s| !s.is_empty()));
    }
}

#[tokio::test]
async fn unknown_path_stays_404_not_401_with_agent_token() {
    // The extractor only runs on a matched route; an unknown path stays 404 (even with an agent token).
    let ctx = app(PresenceThresholds::default()).await;
    let res = ctx
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/definitely-not-here")
                .header("authorization", format!("Bearer {}", ctx.agent_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
