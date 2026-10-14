//! 集成测试：审计日志（[存档 §16.5](../../docs/review/chatgpt-2026-10-13.md)）。
//!
//! 验收：**敏感操作全记录；无密码/私钥/Token 明文**。
//! 口径：不留痕不放行——审计写失败即请求失败（`audit::record_or_fail`），
//! 因此凡请求成功，事件必已落库。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt; // oneshot

const PASSWORD: &str = "bootstrap-password-123";
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
                    json!({ "email": "admin@test.local", "password": PASSWORD }).to_string(),
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

async fn write(c: &Ctx, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    call(c, method, uri, Some(&c.cookie), true, body).await
}

/// 登录并返回（状态, 新会话 Cookie）。
async fn login(c: &Ctx) -> (StatusCode, String) {
    let res = c
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "email": "admin@test.local", "password": PASSWORD }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let cookie = res
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .unwrap_or_default()
        .to_string();
    (status, cookie)
}

async fn audit_events(c: &Ctx) -> Value {
    let (status, body) = call(c, "GET", "/api/v1/audit", Some(&c.cookie), false, None).await;
    assert_eq!(status, StatusCode::OK);
    body
}

fn actions(events: &Value) -> Vec<String> {
    events["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap().to_string())
        .collect()
}

fn events_with<'a>(page: &'a Value, action: &str) -> Vec<&'a Value> {
    page["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == action)
        .collect()
}

/// 全生命周期：管理面敏感操作逐一落审计，actor/target 归属正确。
#[tokio::test]
async fn management_lifecycle_is_fully_recorded() {
    let c = ctx().await;

    let (status, network) = write(
        &c,
        "POST",
        "/api/v1/networks",
        Some(json!({ "name": "home", "overlay_cidr": OVERLAY })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let network_id = network["id"].as_str().unwrap();

    let (status, invite) = write(
        &c,
        "POST",
        &format!("/api/v1/networks/{network_id}/invites"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let invite_id = invite["invite_id"].as_str().unwrap();
    let (status, _) = write(
        &c,
        "DELETE",
        &format!("/api/v1/networks/{network_id}/invites/{invite_id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // 第二张邀请 → 设备加入（actor=None，经邀请 Token 而来）。
    let (status, invite2) = write(
        &c,
        "POST",
        &format!("/api/v1/networks/{network_id}/invites"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, enrolled) = call(
        &c,
        "POST",
        "/api/v1/enroll",
        None,
        false,
        Some(json!({
            "invite_token": invite2["token"],
            "device_name": "gateway",
            "public_key": "pub-audit-1",
            "platform": "linux",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let device_id = enrolled["device_id"].as_str().unwrap();

    let (status, route) = write(
        &c,
        "POST",
        &format!("/api/v1/networks/{network_id}/routes"),
        Some(json!({
            "gateway_device_id": device_id,
            "destination_cidr": "192.168.1.0/24",
            "return_path_mode": "dual_route",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let route_id = route["id"].as_str().unwrap();
    let (status, _) = write(
        &c,
        "DELETE",
        &format!("/api/v1/networks/{network_id}/routes/{route_id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = write(
        &c,
        "POST",
        &format!("/api/v1/networks/{network_id}/devices/{device_id}/revoke"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let (status, token) = write(
        &c,
        "POST",
        "/api/v1/auth/tokens",
        Some(json!({ "name": "cockpit", "scopes": "write" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let token_id = token["id"].as_str().unwrap();
    let (status, _) = write(
        &c,
        "DELETE",
        &format!("/api/v1/auth/tokens/{token_id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // 最新修订（撤建设备那次变更）应用：无数据面 backend → 失败必留痕；
    // 随后回滚它（§10.4：只允许回滚当前修订）。
    let (status, revisions) = call(
        &c,
        "GET",
        &format!("/api/v1/networks/{network_id}/config-revisions"),
        Some(&c.cookie),
        false,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let latest = revisions.as_array().unwrap().last().unwrap()["revision"]
        .as_u64()
        .unwrap();
    let (status, _) = write(
        &c,
        "POST",
        &format!("/api/v1/networks/{network_id}/config-revisions/{latest}/apply"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = write(
        &c,
        "POST",
        &format!("/api/v1/networks/{network_id}/config-revisions/{latest}/rollback"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 登出（bootstrap 会话）→ 重新登录换会话，凑齐 user.logout / user.login。
    let (status, _) = write(&c, "POST", "/api/v1/auth/logout", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, cookie) = login(&c).await;
    assert_eq!(status, StatusCode::OK);
    let mut c = c;
    c.cookie = cookie;

    let page = audit_events(&c).await;
    let a = actions(&page);
    for expected in [
        "user.bootstrap",
        "user.logout",
        "user.login",
        "network.created",
        "invite.created",
        "invite.revoked",
        "device.enrolled",
        "route.created",
        "route.deleted",
        "device.revoked",
        "api_token.created",
        "api_token.revoked",
        "revision.apply_failed",
        "revision.rollback_failed",
    ] {
        assert!(
            a.iter().any(|x| x == expected),
            "missing {expected} in {a:?}"
        );
    }
    assert_eq!(page["total"].as_i64().unwrap() as usize, a.len());

    // 归属：用户操作 actor = 管理员；设备加入 actor = None。
    let me = call(&c, "GET", "/api/v1/auth/me", Some(&c.cookie), false, None)
        .await
        .1;
    let admin = me["user_id"].as_str().unwrap();
    let created = &events_with(&page, "network.created")[0];
    assert_eq!(created["actor_id"], admin);
    assert_eq!(created["target_type"], "network");
    assert_eq!(created["target_id"], network_id);
    let enrolled_ev = &events_with(&page, "device.enrolled")[0];
    assert!(enrolled_ev["actor_id"].is_null());
    assert_eq!(enrolled_ev["target_id"], device_id);
    // 失败留痕带诊断摘要（§16.5：配置应用失败必记录）。
    let failed = &events_with(&page, "revision.apply_failed")[0];
    assert_eq!(failed["target_type"], "revision");
    assert_eq!(failed["target_id"], latest.to_string());
    let detail = failed["detail"].as_str().unwrap();
    assert!(detail.contains(&format!("\"network_id\":\"{network_id}\"")));
    assert!(detail.contains("error_summary"));
}

/// 登录失败留痕：email 可见（暴破诊断），密码永不入库。
#[tokio::test]
async fn login_failures_are_recorded_without_password() {
    let c = ctx().await;

    let (status, _) = call(
        &c,
        "POST",
        "/api/v1/auth/login",
        None,
        false,
        Some(json!({ "email": "admin@test.local", "password": "wrong-guess-1" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(
        &c,
        "POST",
        "/api/v1/auth/login",
        None,
        false,
        Some(json!({ "email": "nobody@test.local", "password": "wrong-guess-2" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let page = audit_events(&c).await;
    let failures = events_with(&page, "user.login_failed");
    assert_eq!(
        failures.len(),
        2,
        "both failures recorded: {:?}",
        actions(&page)
    );

    let known = failures
        .iter()
        .find(|e| e["detail"].as_str().unwrap().contains("admin@test.local"))
        .expect("known-user failure carries email");
    assert!(known["detail"].as_str().unwrap().contains("bad_password"));
    let unknown = failures
        .iter()
        .find(|e| e["detail"].as_str().unwrap().contains("nobody@test.local"))
        .expect("unknown-user failure carries attempted email");
    assert!(unknown["detail"].as_str().unwrap().contains("unknown_user"));

    let dumped = serde_json::to_string(&page).unwrap();
    assert!(!dumped.contains("wrong-guess-1"));
    assert!(!dumped.contains("wrong-guess-2"));
}

/// §16.5 红线：密码 / 邀请 Token / agent Token / API Token 原始材料
/// 一律不出现在审计表中（类型上就进不来，测试再兜一道底）。
#[tokio::test]
async fn no_secret_material_in_audit() {
    let c = ctx().await;

    let (status, network) = write(
        &c,
        "POST",
        "/api/v1/networks",
        Some(json!({ "name": "home", "overlay_cidr": OVERLAY })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let network_id = network["id"].as_str().unwrap();

    let (status, invite) = write(
        &c,
        "POST",
        &format!("/api/v1/networks/{network_id}/invites"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let invite_token = invite["token"].as_str().unwrap().to_string();

    let (status, enrolled) = call(
        &c,
        "POST",
        "/api/v1/enroll",
        None,
        false,
        Some(json!({
            "invite_token": invite_token,
            "device_name": "gateway",
            "public_key": "pub-audit-2",
            "platform": "linux",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let agent_token = enrolled["agent_token"].as_str().unwrap().to_string();

    let (status, token) = write(
        &c,
        "POST",
        "/api/v1/auth/tokens",
        Some(json!({ "name": "cockpit", "scopes": "write" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let api_token = token["token"].as_str().unwrap().to_string();

    let page = audit_events(&c).await;
    let dumped = serde_json::to_string(&page).unwrap();
    for secret in [PASSWORD, &invite_token, &agent_token, &api_token] {
        assert!(
            !dumped.contains(secret),
            "audit must not contain raw secret material"
        );
    }
    // 事件本身仍在：三张凭证的签发痕迹可追溯。
    assert!(!events_with(&page, "invite.created").is_empty());
    assert!(!events_with(&page, "device.enrolled").is_empty());
    assert!(!events_with(&page, "api_token.created").is_empty());
}

/// 审计是管理数据：未认证不得读取。
#[tokio::test]
async fn audit_requires_authentication() {
    let c = ctx().await;
    let (status, body) = call(&c, "GET", "/api/v1/audit", None, false, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "unauthorized");
}
