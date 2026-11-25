//! Integration test: static hosting of `console_dir` (the console SPA is served directly by the server).
//!
//! Contract: once `console_dir` is set, non-`/api` paths fall back to static file serving;
//! `/api/v1/*` route precedence is unchanged; a missing file returns 404.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt; // oneshot

/// Create a throwaway console directory: index.html + assets/app.js, returning its path.
fn write_console_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("meshlet-console-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(dir.join("assets")).unwrap();
    std::fs::write(dir.join("index.html"), "<html>meshlet console</html>").unwrap();
    std::fs::write(dir.join("assets/app.js"), "console.log('meshlet')").unwrap();
    dir
}

async fn console_router(dir: &std::path::Path) -> axum::Router {
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
    meshlet_server::router_with_console(state, dir.to_str().unwrap())
}

async fn get(app: axum::Router, uri: &str) -> (StatusCode, String) {
    let res = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let body = res.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn console_index_served_at_root() {
    let dir = write_console_dir("index");
    let app = console_router(&dir).await;

    let (status, body) = get(app, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "<html>meshlet console</html>");

    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn console_asset_served_by_path() {
    let dir = write_console_dir("asset");
    let app = console_router(&dir).await;

    let (status, body) = get(app, "/assets/app.js").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "console.log('meshlet')");

    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn api_routes_win_over_console_fallback() {
    let dir = write_console_dir("api");
    let app = console_router(&dir).await;

    // `/api` hits a real route: status is publicly available.
    let (status, _) = get(app, "/api/v1/system/status").await;
    assert_eq!(status, StatusCode::OK);

    let dir2 = write_console_dir("api-auth");
    let app2 = console_router(&dir2).await;
    // `/api` misses every route: neither index.html nor 200 (the SPA fallback only applies outside the /api prefix).
    let (status, body) = get(app2, "/api/v1/definitely-not-here").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_ne!(body, "<html>meshlet console</html>");

    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_dir_all(&dir2).unwrap();
}

#[tokio::test]
async fn missing_console_file_is_404() {
    let dir = write_console_dir("missing");
    let app = console_router(&dir).await;

    let (status, _) = get(app, "/assets/does-not-exist.js").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn management_api_still_requires_auth_with_console_mounted() {
    let dir = write_console_dir("auth");
    let app = console_router(&dir).await;

    let (status, _) = get(app, "/api/v1/networks").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    std::fs::remove_dir_all(&dir).unwrap();
}
