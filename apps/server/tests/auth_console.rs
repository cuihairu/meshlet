//! 集成测试：控制台认证（存档 §11.4，验收：全部管理 API 需认证；
//! 哈希/限流/Cookie 安全属性/CSRF 就位）。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt; // oneshot

const EMAIL: &str = "admin@test.local";
const PASSWORD: &str = "correct-horse-battery";

#[derive(Clone)]
struct Ctx {
    app: Router,
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
    Ctx {
        app: meshlet_server::router(state),
    }
}

async fn post_json(
    ctx: &Ctx,
    uri: &str,
    body: serde_json::Value,
    cookie: Option<&str>,
    csrf: bool,
) -> (StatusCode, serde_json::Value, Option<String>) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(c) = cookie {
        builder = builder.header("cookie", c);
    }
    if csrf {
        builder = builder.header("x-requested-with", "XMLHttpRequest");
    }
    let res = ctx
        .app
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let set_cookie = res
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json, set_cookie)
}

async fn get_json(ctx: &Ctx, uri: &str, cookie: Option<&str>) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().uri(uri);
    if let Some(c) = cookie {
        builder = builder.header("cookie", c);
    }
    let res = ctx
        .app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

fn cookie_value(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap().to_string()
}

/// bootstrap 建管理员 + 发 Cookie。返回会话 Cookie（含属性的原串）。
async fn bootstrap(ctx: &Ctx) -> (StatusCode, serde_json::Value, String) {
    let (st, body, cookie) = post_json(
        ctx,
        "/api/v1/auth/bootstrap",
        serde_json::json!({ "email": EMAIL, "password": PASSWORD }),
        None,
        false,
    )
    .await;
    (st, body, cookie.expect("bootstrap sets cookie"))
}

#[tokio::test]
async fn bootstrap_creates_first_admin_with_secure_cookie() {
    let ctx = ctx().await;
    let (st, body, cookie) = bootstrap(&ctx).await;
    assert_eq!(st, StatusCode::CREATED);
    assert_eq!(body["email"], EMAIL);
    assert!(body["user_id"].as_str().is_some_and(|v| !v.is_empty()));

    // Cookie 安全属性（§11.4）：HttpOnly + SameSite=Strict + Max-Age + 作用域限 /api/v1。
    assert!(cookie.contains("HttpOnly"), "{cookie}");
    assert!(cookie.contains("SameSite=Strict"), "{cookie}");
    assert!(cookie.contains("Max-Age="), "{cookie}");
    assert!(cookie.contains("Path=/api/v1"), "{cookie}");
    // 开发配置（cookie_secure=false）下不带 Secure；生产置 true 由配置测试覆盖。
    assert!(!cookie.contains("; Secure"));

    // 密码与哈希都不出现在响应里。
    let raw = body.to_string();
    assert!(!raw.contains(PASSWORD));
    assert!(!raw.contains("argon2"));
}

#[tokio::test]
async fn bootstrap_closes_once_users_exist() {
    let ctx = ctx().await;
    let (st, _, _) = bootstrap(&ctx).await;
    assert_eq!(st, StatusCode::CREATED);

    let (st, err, _) = post_json(
        &ctx,
        "/api/v1/auth/bootstrap",
        serde_json::json!({ "email": "evil@test.local", "password": "another-password-123" }),
        None,
        false,
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert_eq!(err["error"]["code"], "conflict");
}

#[tokio::test]
async fn login_succeeds_with_correct_password() {
    let ctx = ctx().await;
    bootstrap(&ctx).await;

    let (st, body, cookie) = post_json(
        &ctx,
        "/api/v1/auth/login",
        serde_json::json!({ "email": EMAIL, "password": PASSWORD }),
        None,
        false,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["email"], EMAIL);
    assert!(cookie
        .as_ref()
        .is_some_and(|c| c.contains("meshlet_session=")));

    // 新会话可用：GET /auth/me 返回当前用户。
    let (st, me) = get_json(
        &ctx,
        "/api/v1/auth/me",
        Some(&cookie_value(cookie.as_deref().unwrap())),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(me["email"], EMAIL);
}

#[tokio::test]
async fn login_failure_is_generic_401() {
    let ctx = ctx().await;
    bootstrap(&ctx).await;

    // 错密码与不存在用户同形（不泄露账号存在性）。
    let (st, err, cookie) = post_json(
        &ctx,
        "/api/v1/auth/login",
        serde_json::json!({ "email": EMAIL, "password": "wrong-password-123" }),
        None,
        false,
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(err["error"]["code"], "unauthorized");
    assert!(cookie.is_none(), "failure must not set a session cookie");

    let (st2, err2, _) = post_json(
        &ctx,
        "/api/v1/auth/login",
        serde_json::json!({ "email": "ghost@test.local", "password": "wrong-password-123" }),
        None,
        false,
    )
    .await;
    assert_eq!(st2, StatusCode::UNAUTHORIZED);
    assert_eq!(err2["error"]["code"], err["error"]["code"]);
}

#[tokio::test]
async fn management_api_requires_authentication() {
    let ctx = ctx().await;

    // 未认证：列表 401。
    let (st, err) = get_json(&ctx, "/api/v1/networks", None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(err["error"]["code"], "unauthorized");

    // 未认证：写操作 401（CSRF 头带了也没用）。
    let (st, _, _) = post_json(
        &ctx,
        "/api/v1/networks",
        serde_json::json!({ "name": "sneak", "overlay_cidr": "10.240.0.0/16" }),
        None,
        true,
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn management_api_accepts_valid_session() {
    let ctx = ctx().await;
    let (_, _, cookie) = bootstrap(&ctx).await;
    let cookie = cookie_value(&cookie);

    let (st, networks) = get_json(&ctx, "/api/v1/networks", Some(&cookie)).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(networks.as_array().map(Vec::len), Some(0));

    // 带 CSRF 头的写操作通过。
    let (st, net, _) = post_json(
        &ctx,
        "/api/v1/networks",
        serde_json::json!({ "name": "home", "overlay_cidr": "10.240.0.0/16" }),
        Some(&cookie),
        true,
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    assert_eq!(net["name"], "home");
}

#[tokio::test]
async fn management_writes_require_csrf_header() {
    let ctx = ctx().await;
    let (_, _, cookie) = bootstrap(&ctx).await;
    let cookie = cookie_value(&cookie);

    // 有效会话但缺 X-Requested-With：写操作 403（CSRF 防线）。
    let (st, err, _) = post_json(
        &ctx,
        "/api/v1/networks",
        serde_json::json!({ "name": "csrf-less", "overlay_cidr": "10.240.0.0/16" }),
        Some(&cookie),
        false,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(err["error"]["code"], "forbidden");

    // GET 不受 CSRF 头约束。
    let (st, _) = get_json(&ctx, "/api/v1/networks", Some(&cookie)).await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn logout_revokes_session() {
    let ctx = ctx().await;
    let (_, _, cookie) = bootstrap(&ctx).await;
    let cookie = cookie_value(&cookie);

    let (st, _, clear) = post_json(
        &ctx,
        "/api/v1/auth/logout",
        serde_json::json!({}),
        Some(&cookie),
        true,
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert!(
        clear.is_some_and(|c| c.contains("Max-Age=0")),
        "cookie cleared"
    );

    // 旧会话失效。
    let (st, _) = get_json(&ctx, "/api/v1/networks", Some(&cookie)).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_rate_limit_kicks_in_then_recovers_on_success() {
    let ctx = ctx().await;
    bootstrap(&ctx).await;

    // 5 次失败（LOGIN_MAX_ATTEMPTS）后第 6 次被拒——即使第 6 次密码正确。
    for _ in 0..5 {
        let (st, _, _) = post_json(
            &ctx,
            "/api/v1/auth/login",
            serde_json::json!({ "email": EMAIL, "password": "wrong-password-123" }),
            None,
            false,
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }
    let (st, err, _) = post_json(
        &ctx,
        "/api/v1/auth/login",
        serde_json::json!({ "email": EMAIL, "password": PASSWORD }),
        None,
        false,
    )
    .await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(err["error"]["code"], "too_many_requests");

    // 其他账号不受牵连（按 email 限流）。
    let (st, _, _) = post_json(
        &ctx,
        "/api/v1/auth/login",
        serde_json::json!({ "email": "other@test.local", "password": "wrong-password-123" }),
        None,
        false,
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bootstrap_validates_input() {
    let ctx = ctx().await;
    let (st, err, cookie) = post_json(
        &ctx,
        "/api/v1/auth/bootstrap",
        serde_json::json!({ "email": "not-an-email", "password": PASSWORD }),
        None,
        false,
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(err["error"]["code"], "validation_failed");
    assert!(cookie.is_none());

    let (st, err, _) = post_json(
        &ctx,
        "/api/v1/auth/bootstrap",
        serde_json::json!({ "email": EMAIL, "password": "short" }),
        None,
        false,
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(err["error"]["code"], "validation_failed");
}

#[tokio::test]
async fn enroll_and_status_stay_public() {
    let ctx = ctx().await;

    // enroll 是设备侧端点（邀请 Token 即凭证），无需控制台会话。
    let (st, err, _) = post_json(
        &ctx,
        "/api/v1/enroll",
        serde_json::json!({
            "invite_token": "whatever",
            "device_name": "d",
            "public_key": "k",
            "platform": "linux",
        }),
        None,
        false,
    )
    .await;
    assert_eq!(
        st,
        StatusCode::NOT_FOUND,
        "auth layer must not shadow enroll"
    );
    assert_eq!(err["error"]["code"], "not_found");

    let (st, _) = get_json(&ctx, "/api/v1/system/status", None).await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn cookie_secure_flag_flips_with_config() {
    // cookie_secure=true 时 Cookie 带 Secure（生产：HTTPS 反代后）。
    let pool = meshlet_server::store::connect("sqlite::memory:")
        .await
        .unwrap();
    let state = std::sync::Arc::new(meshlet_server::auth::AppState::new(
        meshlet_server::service::SharedState::default(),
        meshlet_server::auth::AuthStore::new(pool.clone()),
        meshlet_server::agent::AgentTokenStore::new(pool.clone()),
        meshlet_server::api_token::ApiTokenStore::new(pool),
        true,
    ));
    let ctx = Ctx {
        app: meshlet_server::router(state),
    };
    let (_, _, cookie) = bootstrap(&ctx).await;
    assert!(cookie.contains("; Secure"), "{cookie}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_bootstrap_has_exactly_one_admin_session() {
    let ctx = ctx().await;
    let mut requests = Vec::new();
    for i in 0..8 {
        let ctx = ctx.clone();
        requests.push(tokio::spawn(async move {
            post_json(
                &ctx,
                "/api/v1/auth/bootstrap",
                serde_json::json!({"email":format!("admin-{i}@test.local"),"password":PASSWORD}),
                None,
                false,
            )
            .await
        }));
    }
    let mut created = 0;
    for request in requests {
        let (status, _, cookie) = request.await.unwrap();
        if status == StatusCode::CREATED {
            created += 1;
            assert!(cookie.is_some());
        } else {
            assert_eq!(status, StatusCode::CONFLICT);
            assert!(cookie.is_none());
        }
    }
    assert_eq!(
        created, 1,
        "bootstrap must issue only one administrator session"
    );
}
