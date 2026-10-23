//! 集成测试：服务发布（R-06）控制面。
//!
//! 覆盖：PortForward / HTTP 路由 / 探针 / DNS 记录的 建-列-查-删 往返；
//! 写入端点的 WriteUser + CSRF 边界；`allowed_bearer_tokens` **永不回显**
//! （视图只给计数）；端口冲突按**设备**判定（同设备同端口 409，别的设备同
//! 端口合法）；每设备一个 DNS 套接字；agent 探针回报的 `device_id` 守卫
//! （不能替别的设备写健康）；每条写都有审计行（无审计不落库）；重启后从
//! DB 恢复且 id 序列不复用。
//!
//! 真机端到端验收（真实 agent 起监听、真实 DNS 套接字）不在本文件范围。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tower::ServiceExt;

const PASSWORD: &str = "bootstrap-password-123";
const OVERLAY: &str = "10.240.0.0/16";
static DB_SEQ: AtomicU32 = AtomicU32::new(0);

/// `wg` 可用（推导 hub 公钥需要）；不可用时 device-plan 用例 SKIP（与
/// agent_plan.rs 同口径）。
fn wg_available() -> bool {
    match std::process::Command::new("wg").arg("--version").output() {
        Ok(o) if o.status.success() => true,
        _ => {
            eprintln!("SKIP: wireguard-tools (wg) not installed");
            false
        }
    }
}

/// 生成 hub 私钥文件（ADR-010：仅本地，服务端不落库）。
fn write_hub_key(dir: &Path) -> PathBuf {
    let out = std::process::Command::new("wg")
        .arg("genkey")
        .output()
        .expect("run wg genkey");
    assert!(out.status.success(), "wg genkey failed");
    let path = dir.join("hub.key");
    std::fs::write(&path, &out.stdout).unwrap();
    path
}

/// 永远成功的 apply 桩：本文件只验「计划携带发布段」，不碰内核。
struct OkBackend;

impl meshlet_domain::ConfigApplyBackend for OkBackend {
    fn apply(&mut self, _revision: &meshlet_domain::ConfigRevision) -> Result<(), String> {
        Ok(())
    }
    fn rollback(&mut self, _revision: &meshlet_domain::ConfigRevision) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Clone)]
struct Ctx {
    app: Router,
    cookie: String,
    pool: sqlx::SqlitePool,
    db: Option<PathBuf>,
}

impl Drop for Ctx {
    fn drop(&mut self) {
        if let Some(db) = &self.db {
            remove_db(db);
        }
    }
}

fn remove_db(db: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", db.display()));
    }
}

fn file_db() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "meshlet-publish-{pid}-{seq}.db",
        pid = std::process::id(),
        seq = DB_SEQ.fetch_add(1, Ordering::SeqCst),
    ))
}

fn app_with_pool(pool: sqlx::SqlitePool, dataplane: meshlet_config::DataPlaneConfig) -> Router {
    let state = Arc::new(
        meshlet_server::auth::AppState::new(
            meshlet_server::service::SharedState::default(),
            meshlet_server::auth::AuthStore::new(pool.clone()),
            meshlet_server::agent::AgentTokenStore::new(pool.clone()),
            meshlet_server::api_token::ApiTokenStore::new(pool),
            false,
        )
        .with_dataplane(dataplane)
        .with_apply_backend(Arc::new(|_, _| Box::new(OkBackend))),
    );
    meshlet_server::router(state)
}

fn ctx_from(app: Router, cookie: String, pool: sqlx::SqlitePool, db: Option<PathBuf>) -> Ctx {
    Ctx {
        app,
        cookie,
        pool,
        db,
    }
}

async fn memory_ctx() -> Ctx {
    let pool = meshlet_server::store::connect("sqlite::memory:")
        .await
        .unwrap();
    let app = app_with_pool(pool.clone(), meshlet_config::DataPlaneConfig::default());
    let cookie = bootstrap(&app).await;
    ctx_from(app, cookie, pool, None)
}

/// 文件库上下文：用于重启恢复测试。
async fn file_ctx() -> (Ctx, PathBuf) {
    let db = file_db();
    let pool = meshlet_server::store::connect(&format!("sqlite:{}", db.display()))
        .await
        .unwrap();
    let app = app_with_pool(pool.clone(), meshlet_config::DataPlaneConfig::default());
    let cookie = bootstrap(&app).await;
    (ctx_from(app, cookie, pool, Some(db.clone())), db)
}

/// 重启后重开：跑 §17.3 恢复（含发布对象）→ 用 login 拿会话。
async fn reopen(db: &Path) -> Ctx {
    let pool = meshlet_server::store::connect(&format!("sqlite:{}", db.display()))
        .await
        .unwrap();
    let boot = meshlet_server::persist::load(&pool, meshlet_domain::PresenceThresholds::default())
        .await
        .unwrap();
    let state = Arc::new(meshlet_server::auth::AppState::new(
        Arc::new(std::sync::Mutex::new(boot.mesh)),
        meshlet_server::auth::AuthStore::new(pool.clone()),
        meshlet_server::agent::AgentTokenStore::new(pool.clone()),
        meshlet_server::api_token::ApiTokenStore::new(pool.clone()),
        false,
    ));
    let app = meshlet_server::router(state);
    // 空库走 bootstrap，重启后走 login——两种都能拿到会话 Cookie。
    let res = app
        .clone()
        .oneshot(auth_request("/api/v1/auth/bootstrap"))
        .await
        .unwrap();
    let res = if res.status() == StatusCode::CREATED {
        res
    } else {
        let res = app
            .clone()
            .oneshot(auth_request("/api/v1/auth/login"))
            .await
            .unwrap();
        let status = res.status();
        assert_eq!(status, StatusCode::OK, "login after restart");
        res
    };
    let cookie = res
        .headers()
        .get("set-cookie")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .expect("session cookie")
        .to_string();
    ctx_from(app, cookie, pool, None)
}

fn auth_request(path: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"email": "admin@test.local", "password": PASSWORD}).to_string(),
        ))
        .unwrap()
}

async fn bootstrap(app: &Router) -> String {
    let res = app
        .clone()
        .oneshot(auth_request("/api/v1/auth/bootstrap"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "bootstrap must succeed");
    res.headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .expect("session cookie")
        .to_string()
}

async fn call(
    ctx: &Ctx,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    bearer: Option<&str>,
    csrf: bool,
    body: Option<Value>,
) -> (StatusCode, Value, String) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    if let Some(bearer) = bearer {
        builder = builder.header("authorization", format!("Bearer {bearer}"));
    }
    if csrf {
        builder = builder.header("x-requested-with", "XMLHttpRequest");
    }
    let payload = match body {
        Some(value) => {
            builder = builder.header("content-type", "application/json");
            Body::from(value.to_string())
        }
        None => Body::default(),
    };
    let res = ctx
        .app
        .clone()
        .oneshot(builder.body(payload).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&bytes).to_string();
    let value = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, value, text)
}

async fn post(ctx: &Ctx, uri: &str, body: Value) -> (StatusCode, Value, String) {
    call(ctx, "POST", uri, Some(&ctx.cookie), None, true, Some(body)).await
}

async fn get(ctx: &Ctx, uri: &str) -> (StatusCode, Value) {
    let (status, value, _) = call(ctx, "GET", uri, Some(&ctx.cookie), None, false, None).await;
    (status, value)
}

/// 带原始响应体的 GET（用于断言「正文里不出现 token 原文」）。
async fn get_raw(ctx: &Ctx, uri: &str) -> (StatusCode, Value, String) {
    call(ctx, "GET", uri, Some(&ctx.cookie), None, false, None).await
}

async fn delete(ctx: &Ctx, uri: &str) -> (StatusCode, Value) {
    let (status, value, _) = call(ctx, "DELETE", uri, Some(&ctx.cookie), None, true, None).await;
    (status, value)
}

/// 建网络 + 批准一个设备：返回 (network_id, device_id, agent_token)。
async fn provision(ctx: &Ctx, device_name: &str) -> (String, String, String) {
    let (status, net, _) = post(
        ctx,
        "/api/v1/networks",
        json!({"name": device_name, "overlay_cidr": OVERLAY}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{net}");
    let network_id = net["id"].as_str().unwrap().to_string();

    let (status, token, _) = post(
        ctx,
        &format!("/api/v1/networks/{network_id}/bootstrap-tokens"),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let raw = token["token"].as_str().unwrap().to_string();

    let (status, reg, _) = post(
        ctx,
        "/api/v1/device-registrations",
        json!({
            "bootstrap_token": raw,
            "device_name": device_name,
            "public_key": "test-public-key",
            "platform": "linux",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "registration: {reg}");
    let device_id = reg["device_id"].as_str().unwrap().to_string();
    let agent_token = reg["agent_token"].as_str().unwrap().to_string();

    let (status, approved, _) = post(
        ctx,
        &format!("/api/v1/networks/{network_id}/devices/{device_id}/approve"),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "approve: {approved}");
    (network_id, device_id, agent_token)
}

/// 在同一网络里注册并批准第二个设备：返回 (device_id, agent_token)。
async fn add_device(
    ctx: &Ctx,
    network_id: &str,
    device_name: &str,
    public_key: &str,
) -> (String, String) {
    let (status, token, raw) = post(
        ctx,
        &format!("/api/v1/networks/{network_id}/bootstrap-tokens"),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{raw}");
    let (status, reg, raw) = post(
        ctx,
        "/api/v1/device-registrations",
        json!({
            "bootstrap_token": token["token"].as_str().unwrap(),
            "device_name": device_name,
            "public_key": public_key,
            "platform": "linux",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "registration: {raw}");
    let device_id = reg["device_id"].as_str().unwrap().to_string();
    let agent_token = reg["agent_token"].as_str().unwrap().to_string();
    let (status, _approved, raw) = post(
        ctx,
        &format!("/api/v1/networks/{network_id}/devices/{device_id}/approve"),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "approve: {raw}");
    (device_id, agent_token)
}

async fn audit_actions(ctx: &Ctx, prefix: &str) -> Vec<String> {
    sqlx::query_scalar("SELECT action FROM audit_events WHERE action LIKE ?")
        .bind(format!("{prefix}%"))
        .fetch_all(&ctx.pool)
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------
// PortForward
// ---------------------------------------------------------------------------

#[tokio::test]
async fn forward_lifecycle_and_bearer_tokens_are_never_echoed() {
    let ctx = memory_ctx().await;
    let (network_id, device_id, _) = provision(&ctx, "edge-1").await;
    let uri = format!("/api/v1/networks/{network_id}/publish/forwards");

    let (status, created, raw) = post(
        &ctx,
        &uri,
        json!({
            "device_id": device_id,
            "protocol": "tcp",
            "listener_address": "127.0.0.1:9000",
            "backend_address": "127.0.0.1:3000",
            "allowed_source_cidrs": ["10.240.0.0/16"],
            "allowed_bearer_tokens": ["s3cret-one", "s3cret-two"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create: {raw}");
    assert_eq!(created["id"].as_str().unwrap(), "pf-1");
    assert_eq!(created["protocol"], "tcp");
    assert_eq!(created["listener_address"], "127.0.0.1:9000");
    assert_eq!(created["backend_address"], "127.0.0.1:3000");
    assert_eq!(created["allowed_source_cidrs"][0], "10.240.0.0/16");
    assert_eq!(created["allowed_bearer_token_count"], 2);
    assert_eq!(created["enabled"], true);
    assert!(created["revision_id"].is_u64());
    // 入口授权用的 token 是密钥材料：任何读路径都不许回显原文。
    assert!(
        !raw.contains("s3cret-one") && !raw.contains("s3cret-two"),
        "bearer tokens must never be echoed: {raw}"
    );
    assert!(!raw.contains("allowed_bearer_tokens"), "{raw}");

    // 列表与详情同一形态。
    let (status, list, raw_list) = get_raw(&ctx, &uri).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert!(
        !raw_list.contains("s3cret-one") && !raw_list.contains("s3cret-two"),
        "listing must not echo tokens: {raw_list}"
    );

    let detail_uri = format!("{uri}/pf-1");
    let (status, detail) = get(&ctx, &detail_uri).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["device_id"], device_id);

    // 删除后详情 404，重复删除同样 404。
    let (status, body) = delete(&ctx, &detail_uri).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = get(&ctx, &detail_uri).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = delete(&ctx, &detail_uri).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn writes_require_write_user_and_csrf() {
    let ctx = memory_ctx().await;
    let (network_id, device_id, _) = provision(&ctx, "edge-1").await;
    let uri = format!("/api/v1/networks/{network_id}/publish/forwards");
    let body = json!({
        "device_id": device_id,
        "protocol": "tcp",
        "listener_address": "127.0.0.1:9001",
        "backend_address": "127.0.0.1:3001"
    });

    // 无会话：401（凭证边界）。
    let (status, body, _) = call(&ctx, "POST", &uri, None, None, true, Some(body.clone())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    // 有会话但缺 CSRF：403。
    let (status, body, _) = call(
        &ctx,
        "POST",
        &uri,
        Some(&ctx.cookie),
        None,
        false,
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    // 读路径只要会话，不要 CSRF。
    let (status, list, _) = call(&ctx, "GET", &uri, Some(&ctx.cookie), None, false, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(list.as_array().unwrap().is_empty());
    // 读路径无会话同样被拒。
    let (status, body, _) = call(&ctx, "GET", &uri, None, None, false, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

#[tokio::test]
async fn port_conflict_is_judged_per_device() {
    let ctx = memory_ctx().await;
    let (network_id, device_a, _) = provision(&ctx, "edge-a").await;
    let (device_b, _) = add_device(&ctx, &network_id, "edge-b", "test-public-key-2").await;

    let uri = format!("/api/v1/networks/{network_id}/publish/forwards");
    let forward = |protocol: &str, device_id: &str| {
        json!({
            "device_id": device_id,
            "protocol": protocol,
            "listener_address": "127.0.0.1:9100",
            "backend_address": "127.0.0.1:3100",
            "allowed_source_cidrs": ["10.240.0.0/16"]
        })
    };

    let (status, _, raw) = post(&ctx, &uri, forward("tcp", &device_a)).await;
    assert_eq!(status, StatusCode::CREATED, "first: {raw}");
    // 同设备同协议同监听：409。
    let (status, body, _) = post(&ctx, &uri, forward("tcp", &device_a)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    // 同设备同监听不同协议：合法（套接字不同）。
    let (status, _, raw) = post(&ctx, &uri, forward("udp", &device_a)).await;
    assert_eq!(status, StatusCode::CREATED, "udp on the same port: {raw}");
    // 同网络别的设备同端口：合法（端口冲突按设备判定）。
    let (status, _, raw) = post(&ctx, &uri, forward("tcp", &device_b)).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "another device may bind it: {raw}"
    );
}

// ---------------------------------------------------------------------------
// HTTP 路由
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_route_lifecycle_and_duplicate_rejected() {
    let ctx = memory_ctx().await;
    let (network_id, device_id, _) = provision(&ctx, "edge-1").await;
    let uri = format!("/api/v1/networks/{network_id}/publish/http-routes");

    let (status, created, raw) = post(
        &ctx,
        &uri,
        json!({
            "device_id": device_id,
            "hostname": "app.mesh",
            "path_prefix": "/api",
            "backend_address": "127.0.0.1:8080",
            "listener_address": "127.0.0.1:80",
            "allowed_source_cidrs": ["10.240.0.0/16"],
            "allowed_bearer_tokens": ["s3cret"],
            "tls_termination": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create: {raw}");
    assert_eq!(created["id"].as_str().unwrap(), "hr-1");
    assert_eq!(created["hostname"], "app.mesh");
    assert_eq!(created["path_prefix"], "/api");
    assert_eq!(created["tls_termination"], true);
    assert_eq!(created["allowed_bearer_token_count"], 1);
    assert!(!raw.contains("s3cret"), "tokens must not be echoed: {raw}");

    // 既无源 CIDR 又无 bearer token 的发布对象一律拒绝（等于对外全开）。
    let (status, body, _) = post(
        &ctx,
        &uri,
        json!({
            "device_id": device_id,
            "hostname": "open.mesh",
            "path_prefix": "/",
            "backend_address": "127.0.0.1:8082",
            "listener_address": "127.0.0.1:80"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // hostname 大小写不敏感 + path_prefix 相同：409。
    let (status, body, _) = post(
        &ctx,
        &uri,
        json!({
            "device_id": device_id,
            "hostname": "App.Mesh",
            "path_prefix": "/api",
            "backend_address": "127.0.0.1:8081",
            "listener_address": "127.0.0.1:80",
            "allowed_source_cidrs": ["10.240.0.0/16"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "duplicate route: {body}");

    let (status, detail) = get(&ctx, &format!("{uri}/hr-1")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["backend_address"], "127.0.0.1:8080");
    let (status, body) = delete(&ctx, &format!("{uri}/hr-1")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = get(&ctx, &format!("{uri}/hr-1")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

// ---------------------------------------------------------------------------
// 探针 + agent 健康回报
// ---------------------------------------------------------------------------

#[tokio::test]
async fn probe_health_report_is_guarded_by_device_id() {
    let ctx = memory_ctx().await;
    let (network_id, device_a, token_a) = provision(&ctx, "edge-a").await;
    // 同网络第二个设备（不同 agent 凭证）。
    let (_device_b, token_b) = add_device(&ctx, &network_id, "edge-b", "test-public-key-2").await;

    let uri = format!("/api/v1/networks/{network_id}/publish/probes");
    let (status, probe, raw) = post(
        &ctx,
        &uri,
        json!({
            "device_id": device_a,
            "target_kind": "tcp",
            "address": "127.0.0.1:9200",
            "timeout_secs": 2.0,
            "interval_secs": 30
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create probe: {raw}");
    assert_eq!(probe["id"], "pb-1");
    assert_eq!(probe["target_kind"], "tcp");
    assert_eq!(probe["address"], "127.0.0.1:9200");
    assert!(probe["last_state"].is_null());

    let report = json!({
        "reports": [{
            "probe_id": "pb-1",
            "state": "healthy",
            "checked_at": "2026-10-24T00:00:00Z",
            "detail": null
        }]
    });

    // 别的设备的 agent 不能替它写健康（越权写被拒）。
    let (status, body, _) = call(
        &ctx,
        "POST",
        "/api/v1/agent/publish-health",
        None,
        Some(&token_b),
        false,
        Some(report.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "foreign report: {body}");

    // 无凭证：401。
    let (status, body, _) = call(
        &ctx,
        "POST",
        "/api/v1/agent/publish-health",
        None,
        None,
        false,
        Some(report.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // 本设备回报：落内存视图（不落配置，健康是证据）。
    let (status, body, _) = call(
        &ctx,
        "POST",
        "/api/v1/agent/publish-health",
        None,
        Some(&token_a),
        false,
        Some(report),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, detail, _) = call(
        &ctx,
        "GET",
        &format!("{uri}/pb-1"),
        Some(&ctx.cookie),
        None,
        false,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["last_state"], "healthy");
    assert_eq!(detail["last_checked_at"], "2026-10-24T00:00:00Z");

    // 未知探针：404。
    let (status, body, _) = call(
        &ctx,
        "POST",
        "/api/v1/agent/publish-health",
        None,
        Some(&token_a),
        false,
        Some(json!({"reports": [{"probe_id": "pb-999", "state": "healthy", "checked_at": "2026-10-24T00:00:00Z"}]})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn probe_validation_rejects_bad_targets() {
    let ctx = memory_ctx().await;
    let (network_id, device_id, _) = provision(&ctx, "edge-1").await;
    let uri = format!("/api/v1/networks/{network_id}/publish/probes");

    let bad = |extra: Value| -> Value {
        let mut body = json!({
            "device_id": device_id,
            "target_kind": "tcp",
            "address": "127.0.0.1:1",
            "timeout_secs": 1.0,
            "interval_secs": 30,
        });
        for (key, entry) in extra.as_object().unwrap() {
            body[key] = entry.clone();
        }
        body
    };
    // http 探针必带 path + expected_status。
    let (status, body, _) = post(&ctx, &uri, bad(json!({"target_kind": "http"}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    // interval 不可为 0（钉死 CPU）。
    let (status, body, _) = post(&ctx, &uri, bad(json!({"interval_secs": 0}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    // 未知 target_kind。
    let (status, body, _) = post(&ctx, &uri, bad(json!({"target_kind": "grpc"}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    // 空列表（无请求体）。
    let (status, list) = get(&ctx, &uri).await;
    assert_eq!(status, StatusCode::OK);
    assert!(list.as_array().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// DNS 记录
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dns_records_share_one_socket_per_device() {
    let ctx = memory_ctx().await;
    let (network_id, device_id, _) = provision(&ctx, "edge-1").await;
    let uri = format!("/api/v1/networks/{network_id}/publish/dns-records");
    let record = json!({
        "device_id": device_id,
        "name": "app",
        "address": "10.240.0.10",
        "ttl": 60,
        "priority": 100,
        "bind_address": "0.0.0.0:53",
        "internal_suffix": "mesh"
    });

    let (status, created, raw) = post(&ctx, &uri, record.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "create: {raw}");
    assert_eq!(created["id"], "dn-1");
    assert_eq!(created["name"], "app");
    assert_eq!(created["bind_address"], "0.0.0.0:53");
    assert_eq!(created["internal_suffix"], "mesh");
    assert_eq!(created["ttl"], 60);

    // 同一套接字的第二条记录：合法（同一 DNS 套接字下多记录）。
    let mut second = record.clone();
    second["name"] = json!("db");
    second["address"] = json!("10.240.0.11");
    let (status, second_created, raw) = post(&ctx, &uri, second).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "same socket, second record: {raw}"
    );
    assert_eq!(second_created["id"], "dn-2");

    // 同一设备不同后缀：409（一台设备只能有一个 DNS 套接字）。
    let mut other_suffix = record.clone();
    other_suffix["name"] = json!("api");
    other_suffix["internal_suffix"] = json!("lan");
    let (status, body, _) = post(&ctx, &uri, other_suffix).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "two sockets per device: {body}"
    );

    // 端口 0 无效。
    let mut port_zero = record.clone();
    port_zero["name"] = json!("zero");
    port_zero["bind_address"] = json!("0.0.0.0:0");
    let (status, body, _) = post(&ctx, &uri, port_zero).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let (status, list) = get(&ctx, &uri).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 2);
    let (status, body) = delete(&ctx, &format!("{uri}/dn-2")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (_, list) = get(&ctx, &uri).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// 审计 / 修订 / 重启恢复
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_publish_write_leaves_an_audit_row() {
    let ctx = memory_ctx().await;
    let (network_id, device_id, _) = provision(&ctx, "edge-1").await;
    let p = |kind: &str| format!("/api/v1/networks/{network_id}/publish/{kind}");

    let (status, _, raw) = post(
        &ctx,
        &p("forwards"),
        json!({"device_id": device_id, "protocol": "tcp",
               "listener_address": "127.0.0.1:9300", "backend_address": "127.0.0.1:3300",
               "allowed_source_cidrs": ["10.240.0.0/16"]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{raw}");
    let (status, _, raw) = post(
        &ctx,
        &p("http-routes"),
        json!({"device_id": device_id, "hostname": "app.mesh", "path_prefix": "/",
               "backend_address": "127.0.0.1:8080", "listener_address": "127.0.0.1:80",
               "allowed_source_cidrs": ["10.240.0.0/16"]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{raw}");
    let (status, _, raw) = post(
        &ctx,
        &p("probes"),
        json!({"device_id": device_id, "target_kind": "tcp",
               "address": "127.0.0.1:9300", "timeout_secs": 2.0, "interval_secs": 30}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{raw}");
    let (status, _, raw) = post(
        &ctx,
        &p("dns-records"),
        json!({"device_id": device_id, "name": "app", "address": "10.240.0.10", "ttl": 60,
               "bind_address": "0.0.0.0:53", "internal_suffix": "mesh"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{raw}");

    let actions = audit_actions(&ctx, "publish.").await;
    assert_eq!(
        actions.len(),
        4,
        "one audit row per publish write: {actions:?}"
    );

    // 删除也要留痕，且对象随之消失。
    let (status, body) = delete(&ctx, &format!("{}/pf-1", p("forwards"))).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let actions = audit_actions(&ctx, "publish.").await;
    assert_eq!(actions.len(), 5, "{actions:?}");

    // 审计行的 detail 不得携带 bearer token（密钥材料不落审计）。
    let detail = sqlx::query_scalar::<_, String>(
        "SELECT detail FROM audit_events WHERE action = 'publish.http_route_created'",
    )
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
    assert!(
        !detail.contains("s3cret"),
        "audit must not carry tokens: {detail}"
    );

    // 每条发布变更都记一个修订（对象属于期望配置）。
    let (status, revisions, _) = call(
        &ctx,
        "GET",
        &format!("/api/v1/networks/{network_id}/config-revisions"),
        Some(&ctx.cookie),
        None,
        false,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let count = revisions.as_array().unwrap().len();
    assert!(
        count >= 6,
        "network approve + 4 publish creates + 1 delete must each record a revision, got {count}"
    );
}

#[tokio::test]
async fn publish_objects_restore_after_restart_and_ids_are_not_reused() {
    let (mut ctx, db) = file_ctx().await;
    let (network_id, device_id, _) = provision(&ctx, "edge-1").await;
    let p = |kind: &str| format!("/api/v1/networks/{network_id}/publish/{kind}");

    let (status, body, raw) = post(
        &ctx,
        &p("forwards"),
        json!({"device_id": device_id, "protocol": "tcp",
               "listener_address": "127.0.0.1:9400", "backend_address": "127.0.0.1:3400",
               "allowed_bearer_tokens": ["s3cret"]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{raw}");
    assert_eq!(body["allowed_bearer_token_count"], 1);
    let (status, _, raw) = post(
        &ctx,
        &p("dns-records"),
        json!({"device_id": device_id, "name": "app", "address": "10.240.0.10", "ttl": 60,
               "bind_address": "0.0.0.0:53", "internal_suffix": "mesh"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{raw}");
    let (status, _, raw) = post(
        &ctx,
        &p("probes"),
        json!({"device_id": device_id, "target_kind": "tcp",
               "address": "127.0.0.1:9400", "timeout_secs": 2.0, "interval_secs": 30}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{raw}");

    // 保留库文件再关掉连接句柄（Drop 默认会清理库文件）。
    ctx.db = None;
    drop(ctx);

    // 重启：从 DB 重建内存状态。
    let ctx = reopen(&db).await;
    let (status, forwards) = get(&ctx, &p("forwards")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(forwards.as_array().unwrap().len(), 1);
    let restored = &forwards.as_array().unwrap()[0];
    assert_eq!(restored["id"], "pf-1");
    assert_eq!(restored["allowed_bearer_token_count"], 1);
    assert!(
        !serde_json::to_string(&forwards).unwrap().contains("s3cret"),
        "restored listing must not echo tokens"
    );
    let (status, dns) = get(&ctx, &p("dns-records")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(dns.as_array().unwrap().len(), 1);
    let (status, probes) = get(&ctx, &p("probes")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(probes.as_array().unwrap().len(), 1);
    assert!(
        probes[0]["last_state"].is_null(),
        "health evidence is not restored as configuration"
    );

    // 全局 publish 序列跨重启单调不复用：此前 pf-1 / dn-2 / pb-3 已消耗
    // seq 1-3，重启后的新对象必须是 seq 4（不是 pf-2）。
    let (status, next, raw) = post(
        &ctx,
        &p("forwards"),
        json!({"device_id": device_id, "protocol": "udp",
               "listener_address": "127.0.0.1:9400", "backend_address": "127.0.0.1:3401",
               "allowed_source_cidrs": ["10.240.0.0/16"]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{raw}");
    assert_eq!(next["id"], "pf-4");

    remove_db(&db);
}

// ---------------------------------------------------------------------------
// DevicePlan 携带发布段
// ---------------------------------------------------------------------------

#[tokio::test]
async fn device_plan_carries_the_publish_segment() {
    if !wg_available() {
        return;
    }
    let dir = std::env::temp_dir().join("meshlet-publish-plan-test");
    std::fs::create_dir_all(&dir).unwrap();
    let key_file = write_hub_key(&dir);
    let pool = meshlet_server::store::connect("sqlite::memory:")
        .await
        .unwrap();
    let dataplane = meshlet_config::DataPlaneConfig {
        enabled: true,
        private_key_file: Some(key_file.to_string_lossy().to_string()),
        ..meshlet_config::DataPlaneConfig::default()
    };
    let app = app_with_pool(pool.clone(), dataplane);
    let cookie = bootstrap(&app).await;
    let ctx = ctx_from(app, cookie, pool, None);

    let (network_id, device_a, token_a) = provision(&ctx, "edge-a").await;
    let (_, token_b) = add_device(&ctx, &network_id, "edge-b", "test-public-key-2").await;

    // 有发布对象的设备：计划带发布段，且计划哈希因发布对象而变。
    let (status, _, raw) = post(
        &ctx,
        &format!("/api/v1/networks/{network_id}/publish/forwards"),
        json!({"device_id": device_a, "protocol": "tcp",
               "listener_address": "127.0.0.1:9500", "backend_address": "127.0.0.1:3500",
               "allowed_source_cidrs": ["10.240.0.0/16"]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{raw}");

    // 期望计划门禁：当前修订必须已应用（apply 桩成功）才下发。
    apply_current(&ctx, &network_id).await;
    let (status, with_publish) = agent_desired(&ctx, &token_a).await;
    assert_eq!(status, StatusCode::OK);
    let publish = &with_publish["publish"];
    assert!(
        publish.is_object(),
        "publish segment must be present: {with_publish}"
    );
    assert_eq!(publish["forwards"][0]["id"], "pf-1");
    assert_eq!(publish["forwards"][0]["listener_address"], "127.0.0.1:9500");

    // 无发布对象的设备：publish 段为 null（向后兼容旧 agent），哈希也不同。
    let (status, without_publish) = agent_desired(&ctx, &token_b).await;
    assert_eq!(status, StatusCode::OK);
    assert!(without_publish["publish"].is_null(), "{without_publish}");
    let hash_a = with_publish["desired_config_hash"].as_str().unwrap();
    let hash_b = without_publish["desired_config_hash"].as_str().unwrap();
    assert_ne!(hash_a, hash_b, "publish objects must change the plan hash");
}

/// 应用当前最新修订（apply 桩成功）——期望计划下发的门禁（§10.1）。
async fn apply_current(ctx: &Ctx, network_id: &str) {
    let (status, list) = get(
        ctx,
        &format!("/api/v1/networks/{network_id}/config-revisions"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let latest = list
        .as_array()
        .unwrap()
        .last()
        .expect("one revision")
        .clone();
    let revision = latest["revision"].as_u64().unwrap();
    let (status, body, raw) = post(
        ctx,
        &format!("/api/v1/networks/{network_id}/config-revisions/{revision}/apply"),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{raw}");
    assert_eq!(body["apply_status"], "applied", "{body}");
}

/// Agent 拉期望计划（Bearer 凭证，无 CSRF）。
async fn agent_desired(ctx: &Ctx, token: &str) -> (StatusCode, Value) {
    let (status, value, _) = call(
        ctx,
        "GET",
        "/api/v1/agent/device/desired",
        None,
        Some(token),
        false,
        None,
    )
    .await;
    (status, value)
}
