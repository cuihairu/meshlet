//! 集成测试：`GET /api/v1/system/status` 契约（api-contract.md）。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt; // oneshot

#[tokio::test]
async fn status_endpoint_returns_ok_envelope() {
    let app = meshlet_server::router(meshlet_server::service::SharedState::default());
    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/system/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["status"], "ok");
    assert!(json["version"].as_str().is_some_and(|v| !v.is_empty()));
}

#[tokio::test]
async fn unknown_route_is_404_not_500() {
    let app = meshlet_server::router(meshlet_server::service::SharedState::default());
    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/definitely-not-here")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn status_payload_matches_contract_type() {
    let s = meshlet_server::system_status();
    let json = serde_json::to_value(&s).unwrap();
    assert_eq!(
        json,
        serde_json::json!({ "status": "ok", "version": s.version })
    );
}
