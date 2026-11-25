//! Integration tests: the service publishing (R-06) control plane.
//!
//! Covers create-list-get-delete round trips for PortForward / HTTP routes / probes / DNS records;
//! the WriteUser + CSRF boundary on write endpoints; `allowed_bearer_tokens` is **never echoed**
//! (views expose a count only); port conflicts are judged per **device** (same device + same port
//! is 409, other devices may reuse the port); one DNS socket per device; the `device_id` guard on
//! agent probe reports (a device cannot report health for another device); every write leaves an
//! audit row (no audit, no commit); and state restores from the DB after restart without id reuse.
//!
//! Real-device end-to-end acceptance (a live agent opening listeners, a real DNS socket) is out of scope here.

// Submodules split by object family (shared helpers stay in this file, reused via `use super::*`).
#[path = "publish/auth.rs"]
mod auth; // auth + echo boundary
#[path = "publish/persistence.rs"]
mod persistence; // persistence / audit / the DevicePlan publish section
#[path = "publish/probe_dns.rs"]
mod probe_dns; // probes and DNS records
#[path = "publish/routes.rs"]
mod routes; // port conflicts / HTTP routes / TLS passthrough

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

/// `wg` is available (needed to derive the hub public key); when missing, the device-plan cases
/// SKIP (same rule as agent_plan.rs).
fn wg_available() -> bool {
    match std::process::Command::new("wg").arg("--version").output() {
        Ok(o) if o.status.success() => true,
        _ => {
            eprintln!("SKIP: wireguard-tools (wg) not installed");
            false
        }
    }
}

/// Generate the hub private key file (ADR-010: local only, never persisted by the server).
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

/// An apply stub that always succeeds: this file only checks that "the plan carries the publish section", so it never touches the kernel.
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

/// File-backed DB context: used by the restart-restore tests.
async fn file_ctx() -> (Ctx, PathBuf) {
    let db = file_db();
    let pool = meshlet_server::store::connect(&format!("sqlite:{}", db.display()))
        .await
        .unwrap();
    let app = app_with_pool(pool.clone(), meshlet_config::DataPlaneConfig::default());
    let cookie = bootstrap(&app).await;
    (ctx_from(app, cookie, pool, Some(db.clone())), db)
}

/// Reopen after a restart: run the §17.3 restore (including published objects) → get a session via login.
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
    // An empty DB goes through bootstrap, a restarted one through login — either way a session Cookie is obtained.
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

/// GET returning the raw response body (for asserting "the body never contains the token itself").
async fn get_raw(ctx: &Ctx, uri: &str) -> (StatusCode, Value, String) {
    call(ctx, "GET", uri, Some(&ctx.cookie), None, false, None).await
}

async fn delete(ctx: &Ctx, uri: &str) -> (StatusCode, Value) {
    let (status, value, _) = call(ctx, "DELETE", uri, Some(&ctx.cookie), None, true, None).await;
    (status, value)
}

/// Create a network + approve one device: returns (network_id, device_id, agent_token).
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

/// Register and approve a second device in the same network: returns (device_id, agent_token).
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

/// Apply the current latest revision (stub apply succeeds) — the gate for plan delivery (§10.1).
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

/// Agent fetches the desired plan (Bearer credential, no CSRF).
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
