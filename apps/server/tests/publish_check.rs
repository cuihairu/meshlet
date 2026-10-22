use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

const PASSWORD: &str = "bootstrap-password-123";

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

    let response = app
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
    assert_eq!(response.status(), StatusCode::CREATED);
    let cookie = response
        .headers()
        .get("set-cookie")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .expect("session cookie")
        .to_string();
    Ctx { app, cookie }
}

async fn check(body: Value) -> (StatusCode, Value) {
    let context = ctx().await;
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/publish/routes/check")
        .header("content-type", "application/json")
        .header("cookie", &context.cookie)
        .header("x-requested-with", "XMLHttpRequest")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = context.app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn authorized_source_is_allowed() {
    let (status, body) = check(json!({
        "remote": "10.240.4.9:40000",
        "policy": {
            "allowed_source_cidrs": ["10.240.0.0/16"],
            "allowed_bearer_tokens": []
        }
    }))
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["allowed"], true);
    assert_eq!(body["reason"], "authorized");
}

#[tokio::test]
async fn unauthorized_source_is_denied_without_error() {
    let (status, body) = check(json!({
        "remote": "192.168.9.9:40000",
        "auth_header": "Bearer wrong",
        "policy": {
            "allowed_source_cidrs": ["10.240.0.0/16"],
            "allowed_bearer_tokens": ["secret"]
        }
    }))
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["allowed"], false);
    assert_eq!(body["reason"], "source or bearer token not authorized");
}
