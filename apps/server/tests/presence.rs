//! 集成测试：在线状态判定（存档 §12.2/§12.4、§14.1）。
//!
//! 端到端路径：加入（签发 agent_token，仅此一次）→ agent 心跳上报
//! （Bearer 凭证，可带 `wg show` 握手读数）→ 设备列表携带
//! `online_state` / `presence_source` / `last_seen_at`（数据来源 + 更新时间）。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use meshlet_domain::PresenceThresholds;
use std::time::Duration;
use tower::ServiceExt; // oneshot

const OVERLAY: &str = "10.240.0.0/16";

/// 测试上下文：router + 管理会话 Cookie + agent_token + network_id。
/// Clone 后共享同一底层状态。
#[derive(Clone)]
struct Ctx {
    app: Router,
    cookie: String,
    network_id: String,
    device_id: String,
    agent_token: String,
}

/// 判定窗口可注入（默认 300s/120s；tunnel_only 场景收紧上报窗口到 0，
/// 使「上报已过窗口、握手仍新鲜」可确定性构造）。
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
        meshlet_server::agent::AgentTokenStore::new(pool),
        false,
    ));
    let app = meshlet_server::router(state);

    // 空库 bootstrap 首个管理员，取会话 Cookie。
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

    // 创建网络 + 邀请 + 设备加入（公开端点，管理 API 边界之外）。
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

/// agent 心跳（Bearer 凭证；非管理 API，不需要 CSRF 头）。
async fn heartbeat(
    ctx: Ctx,
    agent_token: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let res = ctx
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/heartbeat")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {agent_token}"))
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    (res.status(), res_body(res).await)
}

/// 管理端设备列表（Cookie 会话 + CSRF）。
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

    // 心跳：agent 上报 + 本地读到的握手时间。
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

    // 设备列表携带状态 + 数据来源 + 更新时间（§12.2：不得只给绿色图标）。
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
    // 刚加入、无任何心跳/握手：offline，来源 = enrollment，最后时间 = 加入时刻。
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
    // §12.4：最近有 WireGuard 握手 ≠ 设备全部网络功能正常。
    // 上报窗口收紧到 0：心跳到达的当下上报仍新鲜（delta=0）；1 秒后上报过期，
    // 而握手读数仍在窗口内 → tunnel_only（确定性：秒级时间戳截距 delta>=1 > 0）。
    let ctx = app(PresenceThresholds {
        agent_window: Duration::ZERO,
        handshake_window: Duration::from_secs(300),
    })
    .await;

    let (status, body) = heartbeat(
        ctx.clone(),
        &ctx.agent_token,
        serde_json::json!({ "last_handshake_at": "2026-10-14T11:59:59Z" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["online_state"], "online"); // 到达瞬间上报仍新鲜

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

    // 无 Authorization 头 → 401。
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

    // 伪造 Token → 401。
    let (status, _) = heartbeat(ctx.clone(), &"deadbeef".repeat(8), body.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 错误 scheme → 401。
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

    // 伪造/失效 Token 不应污染设备状态。
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
    // 不携带握手读数：仅上报时间也可判定（agent 上报即最强证据）。
    let ctx = app(PresenceThresholds::default()).await;
    let (status, body) = heartbeat(ctx.clone(), &ctx.agent_token, serde_json::json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["online_state"], "online");
    assert_eq!(body["presence_source"], "agent_report");
}

#[tokio::test]
async fn repeated_heartbeat_keeps_token_valid_and_state_accumulates() {
    // 同一 Token 多次心跳均放行（摘要校验路径），状态持续累积。
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
    // 提取器只在命中路由上运行；未知路径保持 404（即便携带 agent Token）。
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
