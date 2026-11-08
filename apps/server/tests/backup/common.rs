//! Shared helpers for the backup and restore integration tests.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::str::FromStr as _;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tower::ServiceExt; // oneshot

pub(crate) static DB_SEQ: AtomicU32 = AtomicU32::new(0);

pub(crate) const EMAIL: &str = "admin@test.local";
pub(crate) const PASSWORD: &str = "bootstrap-password-123";
pub(crate) const OVERLAY: &str = "10.240.0.0/16";

pub(crate) fn tmp_file(tag: &str, ext: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "meshlet-backup-{}-{tag}-{}.{ext}",
        std::process::id(),
        DB_SEQ.fetch_add(1, Ordering::SeqCst)
    ))
}

pub(crate) fn cleanup(path: &Path) {
    for suffix in [
        "",
        "-wal",
        "-shm",
        ".restore-tmp-wal",
        ".restore-tmp-shm",
        ".lock",
    ] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

pub(crate) struct Ctx {
    pub(crate) app: Router,
    pub(crate) cookie: String,
    pub(crate) pool: sqlx::SqlitePool,
}

/// 打开（或恢复后重新打开）文件库并组装应用；`backup_dir` 注入
/// `POST /system/backup` 的目标目录（None = 未配置 → 503）。
pub(crate) async fn open_app(db: &Path, backup_dir: Option<PathBuf>) -> Ctx {
    let pool = meshlet_server::store::connect(&format!("sqlite:{}", db.display()))
        .await
        .unwrap();
    let boot = meshlet_server::persist::load(&pool, meshlet_domain::PresenceThresholds::default())
        .await
        .unwrap();
    let state = Arc::new(
        meshlet_server::auth::AppState::new(
            std::sync::Arc::new(std::sync::Mutex::new(boot.mesh)),
            meshlet_server::auth::AuthStore::new(pool.clone()),
            meshlet_server::agent::AgentTokenStore::new(pool.clone()),
            meshlet_server::api_token::ApiTokenStore::new(pool.clone()),
            false,
        )
        .with_backup_dir(backup_dir),
    );
    let app = meshlet_server::router(state.clone());
    let app_for_ctx = app.clone();

    // bootstrap（空库 201）或 login（重启后 200）——都取会话 Cookie。
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email": EMAIL, "password": PASSWORD}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let res = if res.status() == StatusCode::CREATED {
        res
    } else {
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"email": EMAIL, "password": PASSWORD}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "login after reopen");
        res
    };
    let cookie = res
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .expect("session cookie")
        .to_string();
    Ctx {
        app: app_for_ctx,
        cookie,
        pool,
    }
}

pub(crate) async fn call(
    c: &Ctx,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    builder = builder
        .header("cookie", &c.cookie)
        .header("x-requested-with", "XMLHttpRequest");
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

pub(crate) async fn json_post(c: &Ctx, uri: &str, body: Value) -> (StatusCode, Value) {
    call(c, "POST", uri, Some(body)).await
}

pub(crate) async fn json_get(c: &Ctx, uri: &str) -> (StatusCode, Value) {
    call(c, "GET", uri, None).await
}

/// 不带认证/CSRF 的裸 POST（认证门禁用例；用目标应用自己的 router，
/// Cookie 会话须与其存储同库）。
pub(crate) async fn raw_post(
    app: Router,
    uri: &str,
    cookie: Option<&str>,
    csrf: bool,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method("POST").uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    if csrf {
        builder = builder.header("x-requested-with", "XMLHttpRequest");
    }
    let res = app
        .oneshot(
            builder
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Object(Default::default()));
    (status, value)
}

/// 建网 + 邀请 + 加入一台设备，返回 (network_id, device_id)。
pub(crate) async fn net_with_device(c: &Ctx) -> (String, String) {
    let (st, net) = json_post(
        c,
        "/api/v1/networks",
        json!({"name": "home", "overlay_cidr": OVERLAY}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let network_id = net["id"].as_str().unwrap().to_string();
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
            "device_name": "gw-home",
            "public_key": "pub-key-backup",
            "platform": "linux",
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    (
        network_id,
        device["device_id"].as_str().unwrap().to_string(),
    )
}

/// 触发一次端点备份，断言 200 并返回响应（path/bytes/counts）。
pub(crate) async fn do_backup(c: &Ctx) -> Value {
    let (status, body) = json_post(c, "/api/v1/system/backup", json!({})).await;
    assert_eq!(status, StatusCode::OK, "backup endpoint: {body}");
    body
}

pub(crate) async fn route_post(
    c: &Ctx,
    network_id: &str,
    device_id: &str,
    destination: &str,
) -> (StatusCode, Value) {
    json_post(
        c,
        &format!("/api/v1/networks/{network_id}/routes"),
        json!({
            "gateway_device_id": device_id,
            "destination_cidr": destination,
            "return_path_mode": "dual_route",
        }),
    )
    .await
}

/// 只读打开备份文件，取 (表数, 迁移数, 路由行数, route_seq)。
pub(crate) async fn inspect_backup(path: &Path) -> (usize, i64, i64, Option<String>) {
    let options =
        sqlx::sqlite::SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .read_only(true);
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let tables: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
         AND name NOT LIKE '_sqlx_%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let migrations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    let routes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM lan_routes")
        .fetch_one(&pool)
        .await
        .unwrap();
    let seq: Option<String> =
        sqlx::query_scalar("SELECT value FROM mesh_meta WHERE key = 'route_seq'")
            .fetch_optional(&pool)
            .await
            .unwrap();
    pool.close().await;
    (usize::try_from(tables).unwrap(), migrations, routes, seq)
}

pub(crate) async fn restore_err(backup: &Path, db: &Path) -> String {
    match meshlet_server::persist::restore_from_backup(
        backup,
        db,
        meshlet_domain::PresenceThresholds::default(),
    )
    .await
    {
        Ok(_) => panic!("restore must reject this backup"),
        Err(e) => e.to_string(),
    }
}
