use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;
#[tokio::test]
async fn update_manifest_is_public_and_reports_workspace_version() {
    let pool = meshlet_server::store::connect("sqlite::memory:").await.unwrap();
    let state = std::sync::Arc::new(meshlet_server::auth::AppState::new(
        meshlet_server::service::SharedState::default(),
        meshlet_server::auth::AuthStore::new(pool.clone()),
        meshlet_server::agent::AgentTokenStore::new(pool.clone()),
        meshlet_server::api_token::ApiTokenStore::new(pool),
        false,
    ));
    let app: Router = meshlet_server::router(state);
    let response = app
        .oneshot(Request::get("/api/v1/update-manifest").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert!(body["url"].as_str().is_some_and(|url| url.starts_with("https://")));
    assert_eq!(body["sha256"].as_str().map(str::len), Some(64));
}
