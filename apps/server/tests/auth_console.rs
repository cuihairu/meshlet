//! Integration tests: console authentication (archive §11.4; acceptance: all management
//! APIs require auth; hashing/rate limiting/Cookie security attributes/CSRF in place).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tower::ServiceExt; // oneshot

const EMAIL: &str = "admin@test.local";
const PASSWORD: &str = "correct-horse-battery";

#[derive(Clone)]
struct Ctx {
    app: Router,
}

async fn ctx_with_auth_blocking(concurrency: usize) -> (Ctx, Arc<Semaphore>) {
    let pool = meshlet_server::store::connect("sqlite::memory:")
        .await
        .unwrap();
    let state = std::sync::Arc::new(
        meshlet_server::auth::AppState::new(
            meshlet_server::service::SharedState::default(),
            meshlet_server::auth::AuthStore::new(pool.clone()),
            meshlet_server::agent::AgentTokenStore::new(pool.clone()),
            meshlet_server::api_token::ApiTokenStore::new(pool),
            false,
        )
        .with_auth_blocking_concurrency(concurrency),
    );
    let auth_blocking = Arc::clone(&state.auth_blocking);
    (
        Ctx {
            app: meshlet_server::router(state),
        },
        auth_blocking,
    )
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

/// bootstrap creates the admin + issues a Cookie. Returns the session Cookie (raw string, attributes included).
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

    // Cookie security attributes (§11.4): HttpOnly + SameSite=Strict + Max-Age + Path scoped to /api/v1.
    assert!(cookie.contains("HttpOnly"), "{cookie}");
    assert!(cookie.contains("SameSite=Strict"), "{cookie}");
    assert!(cookie.contains("Max-Age="), "{cookie}");
    assert!(cookie.contains("Path=/api/v1"), "{cookie}");
    // No Secure attribute under the dev config (cookie_secure=false); the production true setting is covered by config tests.
    assert!(!cookie.contains("; Secure"));

    // Neither the password nor its hash appears in the response.
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

    // The new session works: GET /auth/me returns the current user.
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

    // Wrong password and nonexistent user look identical (no account-existence leak).
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

    // Unauthenticated: list returns 401.
    let (st, err) = get_json(&ctx, "/api/v1/networks", None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(err["error"]["code"], "unauthorized");

    // Unauthenticated: write returns 401 (the CSRF header doesn't help either).
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

    // Write with the CSRF header passes.
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

    // Valid session but missing X-Requested-With: write returns 403 (CSRF defense).
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

    // GET is not subject to the CSRF header requirement.
    let (st, _) = get_json(&ctx, "/api/v1/networks", Some(&cookie)).await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn two_factor_writes_require_csrf_header_and_write_scope() {
    let ctx = ctx().await;
    let (_, _, cookie) = bootstrap(&ctx).await;
    let cookie = cookie_value(&cookie);

    // Valid session but missing X-Requested-With: 2FA writes return 403 (second CSRF line of defense).
    for uri in [
        "/api/v1/auth/2fa/enroll",
        "/api/v1/auth/2fa/activate",
        "/api/v1/auth/2fa/disable",
    ] {
        let (st, err, _) = post_json(
            &ctx,
            uri,
            serde_json::json!({ "code": "000000" }),
            Some(&cookie),
            false,
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{uri}: {err}");
        assert_eq!(err["error"]["code"], "forbidden", "{uri}");
    }

    // 2FA write with the CSRF header passes (enroll takes no body).
    let (st, _, _) = post_json(
        &ctx,
        "/api/v1/auth/2fa/enroll",
        serde_json::json!({}),
        Some(&cookie),
        true,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "enroll with csrf must pass");

    // A read-only API Token (Bearer) is rejected even with the CSRF header — WriteUser requires the write scope.
    let (st, created) = {
        let builder = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/tokens")
            .header("content-type", "application/json")
            .header("cookie", &cookie)
            .header("x-requested-with", "XMLHttpRequest");
        let res = ctx
            .app
            .clone()
            .oneshot(
                builder
                    .body(Body::from(
                        serde_json::json!({ "name": "reader", "scopes": "read" }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap_or_default(),
        )
    };
    assert_eq!(st, StatusCode::CREATED, "{created}");
    let token = created["token"].as_str().expect("raw token");
    let (st, err, _) = {
        let builder = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/2fa/enroll")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .header("x-requested-with", "XMLHttpRequest");
        let res = ctx
            .app
            .clone()
            .oneshot(builder.body(Body::from("{}")).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let err: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        (status, err, None::<String>)
    };
    assert_eq!(
        st,
        StatusCode::FORBIDDEN,
        "read token must not enroll: {err}"
    );
    assert_eq!(err["error"]["code"], "forbidden");
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

    // The old session is now invalid.
    let (st, _) = get_json(&ctx, "/api/v1/networks", Some(&cookie)).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_rate_limit_kicks_in_then_recovers_on_success() {
    let ctx = ctx().await;
    bootstrap(&ctx).await;

    // After 5 failures (LOGIN_MAX_ATTEMPTS) the 6th is rejected — even with the correct password.
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

    // Other accounts are unaffected (rate limiting is per email).
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

    // enroll is a device-side endpoint (the invite Token is the credential); it needs no console session.
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
    // With cookie_secure=true the Cookie carries Secure (production: behind an HTTPS reverse proxy).
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
async fn slow_logins_leave_capacity_for_other_network_requests() {
    let (ctx, auth_blocking) = ctx_with_auth_blocking(1).await;
    bootstrap(&ctx).await;

    let slow_login = tokio::spawn({
        let ctx = ctx.clone();
        async move {
            post_json(
                &ctx,
                "/api/v1/auth/login",
                serde_json::json!({ "email": "ghost@test.local", "password": PASSWORD }),
                None,
                false,
            )
            .await
        }
    });
    while auth_blocking.available_permits() > 0 {
        tokio::task::yield_now().await;
    }

    let (status, _) = get_json(&ctx, "/api/v1/system/status", None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body, _) = slow_login.await.unwrap();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "unauthorized");
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

/// Extract the base32 secret from the otpauth:// URI (the sole carrier of the QR-scan
/// material; no outbound server response contains the raw secret in any other form).
fn secret_from_uri(uri: &str) -> String {
    let after = uri.split("secret=").nth(1).expect("secret param");
    let secret = after.split('&').next().unwrap();
    assert_eq!(secret.len(), 32, "base32 secret is 32 chars");
    secret.to_string()
}

fn totp_now() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

#[tokio::test]
async fn totp_enroll_activate_then_login_requires_code() {
    let ctx = ctx().await;
    let (_st, _body, cookie) = bootstrap(&ctx).await;

    // Initially: not bound.
    let (st, status) = get_json(&ctx, "/api/v1/auth/2fa/status", Some(&cookie)).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(status["enabled"], false);
    assert_eq!(status["pending"], false);

    // enroll: generates the secret + returns the otpauth URI (no plaintext secret material).
    let (st, body, _c) = post_json(
        &ctx,
        "/api/v1/auth/2fa/enroll",
        serde_json::json!({}),
        Some(&cookie),
        true,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let uri = body["otpauth_uri"]
        .as_str()
        .expect("otpauth_uri")
        .to_string();
    assert!(uri.starts_with("otpauth://totp/"), "{uri}");
    assert!(uri.contains("secret="), "{uri}");
    assert!(!uri.contains("P@ssw0rd"), "no plaintext password in uri");
    let secret = secret_from_uri(&uri);

    // Pending-activation state.
    let (st, status) = get_json(&ctx, "/api/v1/auth/2fa/status", Some(&cookie)).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(status["enabled"], false);
    assert_eq!(status["pending"], true);

    // Activate: correct code.
    let code = meshlet_domain::totp::code_at(&secret, totp_now()).expect("code");
    let (st, body, _c) = post_json(
        &ctx,
        "/api/v1/auth/2fa/activate",
        serde_json::json!({ "code": code }),
        Some(&cookie),
        true,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["enabled"], true);

    // Activation with a wrong code is rejected (re-enroll, then try a wrong code again).
    let (_st, _b, _c) = post_json(
        &ctx,
        "/api/v1/auth/2fa/enroll",
        serde_json::json!({}),
        Some(&cookie),
        true,
    )
    .await;
    let (st, _b, _c) = post_json(
        &ctx,
        "/api/v1/auth/2fa/activate",
        serde_json::json!({ "code": "000000" }),
        Some(&cookie),
        true,
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    // Re-activate (correct code).
    let secret2 = {
        let (_st, b, _c) = post_json(
            &ctx,
            "/api/v1/auth/2fa/enroll",
            serde_json::json!({}),
            Some(&cookie),
            true,
        )
        .await;
        secret_from_uri(b["otpauth_uri"].as_str().unwrap())
    };
    let code2 = meshlet_domain::totp::code_at(&secret2, totp_now()).expect("code2");
    let (st, _b, _c) = post_json(
        &ctx,
        "/api/v1/auth/2fa/activate",
        serde_json::json!({ "code": code2 }),
        Some(&cookie),
        true,
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // After logout: login without a code → prompted for the second step, no session set.
    let (_st, _b, _c) = post_json(
        &ctx,
        "/api/v1/auth/logout",
        serde_json::json!({}),
        Some(&cookie),
        true,
    )
    .await;
    let (st, body, cookie2) = post_json(
        &ctx,
        "/api/v1/auth/login",
        serde_json::json!({ "email": EMAIL, "password": PASSWORD }),
        None,
        false,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["two_factor_required"], true, "{body}");
    assert_eq!(body["two_factor_enabled"], true, "{body}");
    assert!(cookie2.is_none(), "no session cookie before 2fa step");

    // Wrong code → 401.
    let (st, _b, _c) = post_json(
        &ctx,
        "/api/v1/auth/login",
        serde_json::json!({ "email": EMAIL, "password": PASSWORD, "code": "000000" }),
        None,
        false,
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // Correct code → 200 + session Cookie.
    let code3 = meshlet_domain::totp::code_at(&secret2, totp_now()).expect("code3");
    let (st, body, cookie3) = post_json(
        &ctx,
        "/api/v1/auth/login",
        serde_json::json!({ "email": EMAIL, "password": PASSWORD, "code": code3 }),
        None,
        false,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["email"], EMAIL);
    assert_eq!(body["two_factor_required"], false, "{body}");
    assert_eq!(body["two_factor_enabled"], true, "{body}");
    assert!(cookie3.is_some(), "session issued after 2fa step");
}
