//! Segment and one-way grant management API (ADR-012).
//!
//! Covers validation, Pending/Applied hash behavior, scoped resources,
//! persistence, and the write-auth/CSRF boundary.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use tower::ServiceExt;

const OVERLAY: &str = "10.240.0.0/16";
static DB_SEQ: AtomicU32 = AtomicU32::new(0);

#[derive(Clone)]
struct Ctx {
    app: Router,
    cookie: String,
    pool: sqlx::SqlitePool,
    db: PathBuf,
}

impl Drop for Ctx {
    fn drop(&mut self) {
        cleanup(&self.db);
    }
}

fn tmp_file(tag: &str, ext: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "meshlet-segments-{tag}-{}-{}.{}",
        std::process::id(),
        DB_SEQ.fetch_add(1, Ordering::SeqCst),
        ext
    ))
}

fn cleanup(path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

async fn ctx() -> Ctx {
    let db = tmp_file("live", "db");
    cleanup(&db);
    let pool = meshlet_server::store::connect(&format!("sqlite:{}", db.display()))
        .await
        .unwrap();
    let state = std::sync::Arc::new(meshlet_server::auth::AppState::new(
        meshlet_server::service::SharedState::default(),
        meshlet_server::auth::AuthStore::new(pool.clone()),
        meshlet_server::agent::AgentTokenStore::new(pool.clone()),
        meshlet_server::api_token::ApiTokenStore::new(pool.clone()),
        false,
    ));
    let app = meshlet_server::router(state);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "email": "admin@test.local",
                        "password": "bootstrap-password-123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let cookie = response
        .headers()
        .get("set-cookie")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .expect("session cookie")
        .to_string();
    Ctx {
        app,
        cookie,
        pool,
        db,
    }
}

async fn call(
    ctx: &Ctx,
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
    let body = body.map(|value| Body::from(value.to_string()));
    let request = builder
        .header("content-type", "application/json")
        .body(body.unwrap_or_default())
        .unwrap();
    let response = ctx.app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Object(Default::default()));
    (status, value)
}

async fn json_post(ctx: &Ctx, uri: &str, body: Value) -> (StatusCode, Value) {
    call(ctx, "POST", uri, Some(&ctx.cookie), true, Some(body)).await
}

async fn json_get(ctx: &Ctx, uri: &str) -> (StatusCode, Value) {
    call(ctx, "GET", uri, Some(&ctx.cookie), false, None).await
}

async fn json_delete(ctx: &Ctx, uri: &str) -> (StatusCode, Value) {
    call(ctx, "DELETE", uri, Some(&ctx.cookie), true, None).await
}

async fn create_network(ctx: &Ctx, name: &str, overlay: &str) -> String {
    let (status, body) = json_post(
        ctx,
        "/api/v1/networks",
        json!({"name": name, "overlay_cidr": overlay}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["id"].as_str().unwrap().to_string()
}

async fn create_segment(ctx: &Ctx, network_id: &str, name: &str, cidr: &str) -> Value {
    let (status, body) = json_post(
        ctx,
        &format!("/api/v1/networks/{network_id}/segments"),
        json!({"name": name, "cidr": cidr}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body
}

async fn create_grant(
    ctx: &Ctx,
    network_id: &str,
    source_segment_id: &str,
    destination_segment_id: &str,
) -> (StatusCode, Value) {
    json_post(
        ctx,
        &format!("/api/v1/networks/{network_id}/segment-grants"),
        json!({
            "source_segment_id": source_segment_id,
            "destination_segment_id": destination_segment_id,
        }),
    )
    .await
}

async fn revision(ctx: &Ctx, network_id: &str, number: u64) -> Value {
    let (status, body) = json_get(
        ctx,
        &format!("/api/v1/networks/{network_id}/config-revisions/{number}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

#[tokio::test]
async fn create_and_list_network_scoped_segments() {
    let ctx = ctx().await;
    let network_id = create_network(&ctx, "home", OVERLAY).await;
    let other_id = create_network(&ctx, "away", "10.241.0.0/16").await;
    create_segment(&ctx, &network_id, "lab", "10.240.1.0/24").await;

    let (status, body) = json_get(&ctx, &format!("/api/v1/networks/{network_id}/segments")).await;
    assert_eq!(status, StatusCode::OK);
    let rows = body.as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["name"], "default");
    assert_eq!(rows[0]["cidr"], OVERLAY);
    assert_eq!(rows[1]["name"], "lab");
    assert_eq!(rows[1]["cidr"], "10.240.1.0/24");

    let (status, body) = json_get(&ctx, &format!("/api/v1/networks/{other_id}/segments")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn segment_validation_rejects_unknown_namespaced_or_overlapping_segments() {
    let ctx = ctx().await;
    let network_id = create_network(&ctx, "home", OVERLAY).await;
    let other_id = create_network(&ctx, "away", "10.241.0.0/16").await;
    create_segment(&ctx, &network_id, "lab", "10.240.1.0/24").await;
    let base = format!("/api/v1/networks/{network_id}/segments");

    let (status, body) = json_post(&ctx, &base, json!({"name": "default", "cidr": OVERLAY})).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (status, body) = json_post(
        &ctx,
        &base,
        json!({"name": "duplicate", "cidr": "10.240.1.0/24"}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (status, body) =
        json_post(&ctx, &base, json!({"name": "lab", "cidr": "10.240.2.0/24"})).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (status, body) = json_post(
        &ctx,
        &base,
        json!({"name": "outside", "cidr": "10.241.1.0/24"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = json_post(&ctx, &base, json!({"name": "full", "cidr": OVERLAY})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = json_post(
        &ctx,
        &base,
        json!({"name": "overlap", "cidr": "10.240.1.0/24"}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    let foreign_base = format!("/api/v1/networks/{other_id}/segments");
    let (status, body) = json_post(
        &ctx,
        &foreign_base,
        json!({"name": "lab", "cidr": "10.241.1.0/24"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn grant_lifecycle_only_affects_hash_when_applied() {
    let ctx = ctx().await;
    let network_id = create_network(&ctx, "home", OVERLAY).await;
    let source = create_segment(&ctx, &network_id, "office", "10.240.1.0/24").await;
    let destination = create_segment(&ctx, &network_id, "plant", "10.240.2.0/24").await;
    let source_id = source["id"].as_str().unwrap().to_string();
    let destination_id = destination["id"].as_str().unwrap().to_string();

    let (status, pending) = create_grant(&ctx, &network_id, &source_id, &destination_id).await;
    assert_eq!(status, StatusCode::CREATED, "{pending}");
    assert_eq!(pending["status"], "pending");
    assert_eq!(pending["revision_id"], 4);
    assert_eq!(pending["apply_status"], "pending");

    let (status, grant) = json_get(
        &ctx,
        &format!("/api/v1/networks/{network_id}/segment-grants"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(grant.as_array().unwrap().len(), 1);
    let grant_id = pending["id"].as_str().unwrap().to_string();

    let pending_hash = revision(&ctx, &network_id, 4).await["desired_config_hash"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, applied) = json_post(
        &ctx,
        &format!("/api/v1/networks/{network_id}/segment-grants/{grant_id}/apply"),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    assert_eq!(applied["status"], "applied");
    assert_eq!(applied["revision_id"], 5);
    assert_eq!(applied["apply_status"], "pending");
    let applied_hash = revision(&ctx, &network_id, 5).await["desired_config_hash"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(pending_hash, applied_hash);

    let (status, _) = json_delete(
        &ctx,
        &format!("/api/v1/networks/{network_id}/segment-grants/{grant_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let revoked_hash = revision(&ctx, &network_id, 6).await["desired_config_hash"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(applied_hash, revoked_hash);
    // Revoked grants are excluded, so their hash matches the Pending hash.
    assert_eq!(pending_hash, revoked_hash);

    let (status, _) = json_delete(
        &ctx,
        &format!("/api/v1/networks/{network_id}/segment-grants/{grant_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn segments_and_grants_survive_backup_reload() {
    let ctx = ctx().await;
    let network_id = create_network(&ctx, "home", OVERLAY).await;
    let source = create_segment(&ctx, &network_id, "office", "10.240.1.0/24").await;
    let destination = create_segment(&ctx, &network_id, "plant", "10.240.2.0/24").await;
    let (status, grant) = create_grant(
        &ctx,
        &network_id,
        source["id"].as_str().unwrap(),
        destination["id"].as_str().unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{grant}");
    let grant_id = grant["id"].as_str().unwrap().to_string();
    let (status, _) = json_post(
        &ctx,
        &format!("/api/v1/networks/{network_id}/segment-grants/{grant_id}/apply"),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "meshlet-segment-backup-{}-{}",
        std::process::id(),
        DB_SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let backup = meshlet_server::persist::backup_to(&ctx.pool, &dir)
        .await
        .unwrap_or_else(|error| panic!("backup failed: {error}; dir exists={}", dir.exists()));
    let backup_path = PathBuf::from(backup.path.clone());
    assert!(backup_path.starts_with(&dir));
    assert_eq!(backup.view.segments, 3);
    assert_eq!(backup.view.segment_grants, 1);

    let pool = meshlet_server::store::connect(&format!("sqlite:{}", backup_path.display()))
        .await
        .unwrap();
    let boot = meshlet_server::persist::load(&pool, Default::default())
        .await
        .unwrap();
    assert_eq!(boot.summary.segments, 3);
    assert_eq!(boot.summary.segment_grants, 1);
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT status FROM segment_grants WHERE id = ?",)
            .bind(&grant_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        "applied"
    );
    pool.close().await;
    ctx.pool.close().await;
    std::fs::remove_file(&backup_path).unwrap();
    std::fs::remove_dir(&dir).unwrap();
}

#[tokio::test]
async fn grant_validation_is_scoped_and_rejects_duplicates() {
    let ctx = ctx().await;
    let network_id = create_network(&ctx, "home", OVERLAY).await;
    let source = create_segment(&ctx, &network_id, "office", "10.240.1.0/24").await;
    let destination = create_segment(&ctx, &network_id, "plant", "10.240.2.0/24").await;
    let source_id = source["id"].as_str().unwrap();
    let destination_id = destination["id"].as_str().unwrap();

    let (status, body) = create_grant(&ctx, &network_id, source_id, destination_id).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = create_grant(&ctx, &network_id, source_id, destination_id).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (status, body) = create_grant(&ctx, &network_id, source_id, source_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = create_grant(&ctx, &network_id, source_id, "seg-other").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, _) = json_delete(
        &ctx,
        &format!("/api/v1/networks/{network_id}/segment-grants/sg-other"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = json_get(&ctx, "/api/v1/networks/nope/segment-grants").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");
}

#[tokio::test]
async fn segment_writes_require_write_credentials_and_csrf() {
    let ctx = ctx().await;
    let network_id = create_network(&ctx, "home", OVERLAY).await;
    let segments_uri = format!("/api/v1/networks/{network_id}/segments");
    let grants_uri = format!("/api/v1/networks/{network_id}/segment-grants");

    let (status, body) = call(
        &ctx,
        "POST",
        &segments_uri,
        None,
        true,
        Some(json!({"name": "lab", "cidr": "10.240.1.0/24"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "unauthorized");
    let (status, body) = call(
        &ctx,
        "POST",
        &segments_uri,
        Some(&ctx.cookie),
        false,
        Some(json!({"name": "lab", "cidr": "10.240.1.0/24"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "forbidden");

    let (status, created) = json_post(
        &ctx,
        "/api/v1/auth/tokens",
        json!({"name": "reader", "scopes": "read"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let token = created["token"].as_str().unwrap().to_string();
    let builder = Request::builder()
        .method("POST")
        .uri(&grants_uri)
        .header("authorization", format!("Bearer {token}"))
        .header("x-requested-with", "XMLHttpRequest")
        .header("content-type", "application/json");
    let request = builder
        .body(Body::from(
            json!({"source_segment_id": "seg-a", "destination_segment_id": "seg-b"}).to_string(),
        ))
        .unwrap();
    let response = ctx.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
