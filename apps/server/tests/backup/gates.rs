use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::common::{cleanup, open_app, raw_post, tmp_file};
#[tokio::test]
async fn backup_endpoint_auth_and_configuration_gates() {
    let db = tmp_file("gates", "db");
    let c = open_app(&db, None).await;

    // 无凭证 → 401。
    let (st, body) = raw_post(c.app.clone(), "/api/v1/system/backup", None, true).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "no credentials: {body}");

    // 会话在，CSRF 头缺失 → 403。
    let (st, body) = raw_post(
        c.app.clone(),
        "/api/v1/system/backup",
        Some(&c.cookie),
        false,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "missing CSRF: {body}");

    // 已认证但未配置备份目录 → 503 backup_not_configured（默认部署不产生文件）。
    let (st, body) = raw_post(
        c.app.clone(),
        "/api/v1/system/backup",
        Some(&c.cookie),
        true,
    )
    .await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE, "unconfigured: {body}");
    assert_eq!(body["error"]["code"], "backup_not_configured");
    assert_eq!(
        body["error"]["message"].as_str().unwrap(),
        "backup directory is not configured ([backup] dir in server config)"
    );
    let api_errors = [
        meshlet_server::backup::BackupApiError::TargetExists("/tmp/taken.db".into()),
        meshlet_server::backup::BackupApiError::Internal("disk unavailable".into()),
    ];
    for error in api_errors {
        let response = error.into_response();
        assert!(response.status().is_client_error() || response.status().is_server_error());
    }
    assert!(matches!(
        meshlet_server::backup::BackupApiError::from(
            meshlet_server::persist::BackupError::TargetExists("/tmp/taken.db".into())
        ),
        meshlet_server::backup::BackupApiError::TargetExists(_)
    ));
    assert!(matches!(
        meshlet_server::backup::BackupApiError::from(meshlet_server::persist::BackupError::Locked(
            "server is running".into()
        )),
        meshlet_server::backup::BackupApiError::Internal(_)
    ));
    assert!(matches!(
        meshlet_server::backup::BackupApiError::from(
            meshlet_server::persist::BackupError::Corrupt("bad header".into())
        ),
        meshlet_server::backup::BackupApiError::Internal(_)
    ));
    c.pool.close().await;
    cleanup(&db);
}
