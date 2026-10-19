use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use meshlet_domain::PresenceThresholds;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

const OVERLAY: &str = "10.245.0.0/16";
const PUBLIC_KEY: &str = "63WKTVQHfLQMkXWNpBdDQqfWf2vN6VjYtYQjbfYnPEo=";

struct Ctx {
    app: Router,
    cookie: String,
    pool: sqlx::SqlitePool,
}

async fn app() -> Ctx {
    let debug_dir = std::env::temp_dir().join("meshlet-txdebug");
    std::fs::create_dir_all(&debug_dir).unwrap();
    let db = debug_dir.join(format!(
        "meshlet-tx-boundary-{}-{}-debug.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", db.display()));
    }
    let pool = meshlet_server::store::connect(&format!("sqlite:{}", db.display()))
        .await
        .unwrap();
    let mesh = meshlet_server::persist::load(&pool, PresenceThresholds::default())
        .await
        .unwrap()
        .mesh;
    let state = Arc::new(
        meshlet_server::auth::AppState::new(
            Arc::new(Mutex::new(mesh)),
            meshlet_server::auth::AuthStore::new(pool.clone()),
            meshlet_server::agent::AgentTokenStore::new(pool.clone()),
            meshlet_server::api_token::ApiTokenStore::new(pool.clone()),
            false,
        )
        .with_dataplane(meshlet_config::DataPlaneConfig {
            enabled: true,
            ..meshlet_config::DataPlaneConfig::default()
        })
        .with_apply_backend(Arc::new(|_, _| Box::new(AlwaysApply))),
    );
    let app = meshlet_server::router(state);
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email": "admin@test.local", "password": "transaction-pass-123"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let cookie = res
        .headers()
        .get("set-cookie")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .expect("session cookie")
        .to_string();
    Ctx { app, cookie, pool }
}

struct AlwaysApply;

impl meshlet_domain::ConfigApplyBackend for AlwaysApply {
    fn apply(&mut self, _revision: &meshlet_domain::ConfigRevision) -> Result<(), String> {
        Ok(())
    }
    fn rollback(&mut self, _revision: &meshlet_domain::ConfigRevision) -> Result<(), String> {
        Ok(())
    }
}

async fn body(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    }
}

async fn call(
    ctx: &Ctx,
    method: &str,
    uri: &str,
    request_body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    builder = builder
        .header("cookie", &ctx.cookie)
        .header("x-requested-with", "XMLHttpRequest");
    let request_body = request_body
        .map(|value| Body::from(value.to_string()))
        .unwrap_or_default();
    let response = ctx
        .app
        .clone()
        .oneshot(
            builder
                .header("content-type", "application/json")
                .body(request_body)
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    (status, body(response).await)
}

async fn trigger(ctx: &Ctx, name: &str, table: &str) {
    sqlx::query(&format!(
        "CREATE TRIGGER {name} BEFORE INSERT ON {table}
         BEGIN SELECT RAISE(FAIL, '{name}'); END"
    ))
    .execute(&ctx.pool)
    .await
    .unwrap();
}

async fn drop_trigger(ctx: &Ctx, name: &str) {
    sqlx::query(&format!("DROP TRIGGER {name}"))
        .execute(&ctx.pool)
        .await
        .unwrap();
}

async fn counts(ctx: &Ctx, table: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(&ctx.pool)
        .await
        .unwrap()
}

async fn setup_device(ctx: &Ctx) -> (String, String, String, String) {
    let (status, network) = call(
        ctx,
        "POST",
        "/api/v1/networks",
        Some(json!({"name": "boundary", "overlay_cidr": OVERLAY})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{network}");
    let network_id = network["id"].as_str().unwrap();
    let (status, invite) = call(
        ctx,
        "POST",
        &format!("/api/v1/networks/{network_id}/invites"),
        Some(json!({"max_uses": 5})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{invite}");
    let invite_token = invite["token"].as_str().unwrap();
    let response = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/enroll")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "invite_token": invite_token,
                        "device_name": "gateway",
                        "public_key": PUBLIC_KEY,
                        "platform": "linux",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let device = body(response).await;
    (
        network_id.to_string(),
        device["device_id"].as_str().unwrap().to_string(),
        invite_token.to_string(),
        device["agent_token"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
async fn write_failures_preserve_memory_db_and_allow_retry() {
    let ctx = app().await;
    let (network_id, device_id, _invite_token, _) = setup_device(&ctx).await;
    let route_path = format!("/api/v1/networks/{network_id}/routes");
    let route = json!({
        "gateway_device_id": device_id,
        "destination_cidr": "192.168.100.0/24",
        "return_path_mode": "dual_route"
    });

    trigger(&ctx, "fail_resource", "lan_routes").await;
    let (status, error) = call(&ctx, "POST", &route_path, Some(route.clone())).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{error}");
    assert_eq!(counts(&ctx, "lan_routes").await, 0);
    assert_eq!(counts(&ctx, "config_revisions").await, 2);
    assert_eq!(counts(&ctx, "audit_events").await, 4);
    drop_trigger(&ctx, "fail_resource").await;
    let (status, retry) = call(&ctx, "POST", &route_path, Some(route.clone())).await;
    assert_eq!(status, StatusCode::CREATED, "{retry}");
    assert_eq!(counts(&ctx, "lan_routes").await, 1);
    assert_eq!(counts(&ctx, "config_revisions").await, 3);
    assert_eq!(counts(&ctx, "audit_events").await, 5);
    let route_id = retry["id"].as_str().unwrap();

    trigger(&ctx, "fail_revision", "config_revisions").await;
    let (status, error) = call(&ctx, "DELETE", &format!("{route_path}/{route_id}"), None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{error}");
    assert_eq!(counts(&ctx, "lan_routes").await, 1);
    assert_eq!(counts(&ctx, "config_revisions").await, 3);
    assert_eq!(counts(&ctx, "audit_events").await, 5);
    drop_trigger(&ctx, "fail_revision").await;
    let (delete_status, delete_response) =
        call(&ctx, "DELETE", &format!("{route_path}/{route_id}"), None).await;
    assert_eq!(delete_status, StatusCode::NO_CONTENT, "{delete_response}");
    assert_eq!(counts(&ctx, "lan_routes").await, 0);
    assert_eq!(counts(&ctx, "config_revisions").await, 4);
    assert_eq!(counts(&ctx, "audit_events").await, 6);

    let second_invite_path = format!("/api/v1/networks/{network_id}/invites");
    let (status, second_invite) = call(
        &ctx,
        "POST",
        &second_invite_path,
        Some(json!({"max_uses": 1})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{second_invite}");
    let second_token = second_invite["token"].as_str().unwrap().to_string();
    trigger(&ctx, "fail_token", "agent_tokens").await;
    let (status, error) = enroll(&ctx, &second_token, "peer", "peer-public-key-unique").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{error}");
    assert_eq!(counts(&ctx, "devices").await, 1);
    assert_eq!(counts(&ctx, "agent_tokens").await, 1);
    let invite_used_count: i64 = sqlx::query_scalar::<_, i64>("SELECT used_count FROM invitations")
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    assert_eq!(invite_used_count, 1);
    drop_trigger(&ctx, "fail_token").await;
    let (status, retry) = enroll(&ctx, &second_token, "peer", "peer-public-key-unique").await;
    assert_eq!(status, StatusCode::CREATED, "{retry}");
    assert_eq!(counts(&ctx, "devices").await, 2);
    assert_eq!(counts(&ctx, "agent_tokens").await, 2);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT used_count FROM invitations")
            .fetch_one(&ctx.pool)
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn audit_failure_rolls_back_all_business_resources() {
    let ctx = app().await;
    let (network_id, device_id, _, _) = setup_device(&ctx).await;
    trigger(&ctx, "fail_audit", "audit_events").await;
    let (status, error) = call(
        &ctx,
        "POST",
        &format!("/api/v1/networks/{network_id}/routes"),
        Some(json!({
            "gateway_device_id": device_id,
            "destination_cidr": "192.168.101.0/24",
            "return_path_mode": "dual_route"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{error}");
    assert_eq!(counts(&ctx, "lan_routes").await, 0);
    assert_eq!(counts(&ctx, "config_revisions").await, 2);
    assert_eq!(counts(&ctx, "agent_tokens").await, 1);
}

async fn enroll(
    ctx: &Ctx,
    invite_token: &str,
    device_name: &str,
    public_key: &str,
) -> (StatusCode, Value) {
    let response = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/enroll")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "invite_token": invite_token,
                        "device_name": device_name,
                        "public_key": public_key,
                        "platform": "linux",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    (status, body(response).await)
}
