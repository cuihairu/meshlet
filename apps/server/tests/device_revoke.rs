//! 集成测试：撤销设备（外部 API 控制「peer 撤销」条目；完整链路 §11.5 的
//! 控制面部分）。
//!
//! 撤销 = 设备状态转 `revoked`（离线）+ agent 凭证立即失效 + 期望配置
//! 修订（被撤销设备不入配置哈希，ADR-009）。响应 202 携带 `RevisionRef`。

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

/// 建网络 + 邀请 + 加入一台设备；返回 (network_id, device_id, agent_token)。
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
    // 202：已受理；配置生效待 apply（ADR-009）。
    assert_eq!(st, StatusCode::ACCEPTED);
    assert_eq!(rev["revision_id"], 3, "net=1 enroll=2 revoke=3");
    assert_eq!(rev["apply_status"], "pending");

    // 设备状态转 revoked（下线）；虚拟 IP 等字段保留以便审计。
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

    // 新修订记录了不含被撤销设备的期望配置：哈希必须变化（§10.4 单调递增）。
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
        // §12：heartbeat 观测直连源地址（ConnectInfo 装配于 serve 层）。
        req.extensions_mut().insert(axum::extract::ConnectInfo(
            "10.240.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
        ));
        req
    };
    // 撤销前心跳正常。
    let res = c.app.clone().oneshot(hb(&c)).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let (st, _) = json_post(&c, &revoke_uri(&network_id, &device_id), json!({})).await;
    assert_eq!(st, StatusCode::ACCEPTED);

    // 撤销后同一 agent token 立即失效（凭证边界与设备状态同步）。
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

    // 无凭证 → 401。
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
    // Cookie 会话缺 CSRF 头 → 403。
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
    // §11.5：撤销设备的已发布路由必须一并移除（不能给 AllowedIPs 推导留下
    // 指向已撤销 Peer 的网段）；其他设备的路由不受影响。
    let c = ctx().await;
    let (network_id, device_a, _agent_a) = net_with_device(&c, "home").await;

    // 第二台设备（同一网络，独立邀请）。
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

    // 各发布一条路由。
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

    // 撤销设备 A。
    let (st, rev) = json_post(&c, &revoke_uri(&network_id, &device_a), json!({})).await;
    assert_eq!(st, StatusCode::ACCEPTED);
    assert_eq!(rev["revision_id"], 6, "net=1, enroll×2, route×2 → revoke=6");

    // A 的路由被移除；B 的路由原样保留。
    let (_, list) = json_get(&c, &routes_uri).await;
    let routes = list.as_array().unwrap();
    assert_eq!(routes.len(), 1, "only the surviving route remains");
    assert_eq!(routes[0]["gateway_device_id"], device_b.as_str());
    assert_eq!(routes[0]["destination_cidr"], "192.168.2.0/24");
}
