//! 集成测试：设备自举注册（ZeroTier 式：自举码 → Pending → 控制中心审批/拒绝）。
//!
//! 端到端路径：创建自举码（原始码仅此一次返回）→ 设备持码自举注册
//! （落 Pending，**不分配虚拟 IP、不进期望配置**）→ Pending 期心跳证据落
//! 注册申请 → 控制中心批准（此刻才分配 IP + 记修订，凭证不轮换）/ 拒绝
//! （纯状态清理，无修订）。断言重点：
//! - Pending 设备不进 `devices` 列表、desired 端点 404（migration 008 取舍）；
//! - 名字唯一性跨 devices + registrations 两侧；
//! - 自举码撤销/耗尽后注册 401；管理侧按 id 撤销 404（两条错误面分离）；
//! - 批准沿用设备 id 与注册期凭证（desired 端点从 404 变为非 401/404）。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt; // oneshot

const OVERLAY: &str = "10.240.0.0/16";

/// 测试上下文：router + 管理会话 Cookie。Clone 后共享同一底层状态。
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
    // 提取器拒绝（如 deny_unknown_fields 的 422）是纯文本体：原样包成
    // 字符串，保持断言消息可见。
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| serde_json::Value::String(String::from_utf8_lossy(&bytes).to_string()))
}

/// 管理端写请求（Cookie + CSRF 头）。
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

/// 公开端点（自举注册）：设备凭自举码而来，无会话。
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

/// 管理端无请求体的写请求（approve/deny）；`cookie = None` 走公开端点（enroll）。
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
    // 204/3xx 无响应体：按 null 处理，避免把空体当 JSON 解析。
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, body)
}

/// Agent API（Bearer 凭证，无 CSRF）。
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
    let res = ctx
        .app
        .oneshot(
            Request::builder()
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
                .unwrap(),
        )
        .await
        .unwrap();
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

    // 原始码仅此一次返回；id 序列从 bt-1 起。
    assert_eq!(token["token_id"], "bt-1");
    assert!(token["token"].as_str().unwrap().len() >= 32);
    assert_eq!(token["max_uses"], 2);

    // 列表只有元数据，绝无凭据材料。
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

    // 撤销后再撤销 → 409；未知 id → 404（与设备出示无效码的 401 分离）。
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

    // 撤销后的码注册 → 401。
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

    // 基线：建网时已记初始修订（§10.1），后续只断言相对增量。
    let (_, revisions) = admin_get(
        ctx.clone(),
        &format!("/api/v1/networks/{network_id}/config-revisions"),
    )
    .await;
    let baseline = revisions.as_array().unwrap().len();

    // 注册 → Pending（无虚拟 IP 字段，状态恒 pending）。
    let (status, reg) = register(ctx.clone(), reg_body(&raw, "edge-1")).await;
    assert_eq!(status, StatusCode::CREATED, "{reg}");
    assert_eq!(reg["status"], "pending");
    assert_eq!(reg["device_id"], "dev-reg-1");
    let agent_token = reg["agent_token"].as_str().unwrap().to_string();
    assert!(
        !agent_token.is_empty(),
        "agent credential issued at registration"
    );

    // 不进 devices 列表；进待审批列表。
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

    // desired 端点：404 且点名 pending approval（批准前不进期望配置）。
    let (status, body) = desired(ctx.clone(), &agent_token).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("pending approval"),
        "{body}"
    );

    // Pending 心跳：证据落注册申请，回执明确 pending。
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

    // 名字冲突：与待审批申请重名 → 409（唯一性跨两侧）。
    let (status, body) = register(ctx.clone(), reg_body(&raw, "edge-1")).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // 批准：分配 IP + 记修订；响应不含 agent_token（凭证不轮换）。
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

    // 转正后：devices 列表可见（active、无虚拟 IP 缺失），待审批列表清空。
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

    // 注册期凭证继续有效：desired 从 404 变为非 401/404（默认数据面关闭 →
    // 503 dataplane_not_configured；401/404 都意味着凭证或设备身份被破坏）。
    let (status, body) = desired(ctx.clone(), &agent_token).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "token must survive approval, got: {body}"
    );

    // 修订随批准产生：版本列表 +1（相对建网基线），pending 修订待 apply（§10.1）。
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

    // 基线：建网时的初始修订。
    let (_, revisions) = admin_get(
        ctx.clone(),
        &format!("/api/v1/networks/{network_id}/config-revisions"),
    )
    .await;
    let baseline = revisions.as_array().unwrap().len();

    // 拒绝 → 申请与凭证一并清理。
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

    // 凭证随拒绝作废 → 401；名字立即可复用。
    let (status, _) = desired(ctx.clone(), &agent_token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = register(ctx.clone(), reg_body(&raw, "stray")).await;
    assert_eq!(status, StatusCode::CREATED);

    // 拒绝产生过修订吗？没有——期望配置从未包含过 Pending 申请。
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

    // 邀请路径先占用名字。
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

    // 自举注册同名 → 409。
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

    // 不支持的平台 / 空名字 / 空公钥 → 400，且**不消耗**使用次数。
    for body in [
        serde_json::json!({ "bootstrap_token": raw, "device_name": "x", "public_key": "k", "platform": "macos" }),
        serde_json::json!({ "bootstrap_token": raw, "device_name": "  ", "public_key": "k", "platform": "linux" }),
        serde_json::json!({ "bootstrap_token": raw, "device_name": "x", "public_key": "", "platform": "linux" }),
    ] {
        let (status, resp) = register(ctx.clone(), body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{resp}");
    }

    // 私钥字段在 API 边界即被拒（deny_unknown_fields → 422，与 enroll 同
    // 纪律：私钥不出设备），同样不消耗使用次数。
    let (status, resp) = register(
        ctx.clone(),
        serde_json::json!({ "bootstrap_token": raw, "device_name": "x", "public_key": "k", "platform": "linux", "private_key": "priv" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{resp}");

    // 有效注册仍成功（max_uses 未被无效请求消耗——不限次场景下断言 used_count）。
    let (status, _) = register(ctx.clone(), reg_body(&raw, "ok")).await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, list) = admin_get(
        ctx.clone(),
        &format!("/api/v1/networks/{network_id}/bootstrap-tokens"),
    )
    .await;
    assert_eq!(list[0]["used_count"], 1);
}
