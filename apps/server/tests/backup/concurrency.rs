use std::path::PathBuf;
use std::str::FromStr as _;

use axum::body::Body;
use axum::http::Request;
use axum::http::StatusCode;
use serde_json::json;
use tower::ServiceExt;

use crate::common::{cleanup, net_with_device, open_app, route_post, tmp_file};
#[tokio::test]
async fn concurrent_backup_contains_only_complete_business_commits() {
    let db = tmp_file("concurrent", "db");
    let backup_dir = tmp_file("concurrentdir", "dir");
    std::fs::create_dir_all(&backup_dir).unwrap();
    let (network_id, device_id, backup_path);
    {
        let c = open_app(&db, Some(backup_dir.clone())).await;
        (network_id, device_id) = net_with_device(&c).await;
        sqlx::query(
            "CREATE TRIGGER pause_between_resource_and_revision
             AFTER INSERT ON lan_routes FOR EACH ROW
             BEGIN
               SELECT SUM(n) FROM
                 (WITH RECURSIVE counter(n) AS
                    (SELECT 0 UNION ALL SELECT n + 1 FROM counter WHERE n < 700000)
                  SELECT n FROM counter);
             END",
        )
        .execute(&c.pool)
        .await
        .unwrap();

        let writer = {
            let app = c.app.clone();
            let uri = format!("/api/v1/networks/{network_id}/routes");
            let body = serde_json::to_string(&json!({
                "gateway_device_id": device_id,
                "destination_cidr": "192.168.77.0/24",
                "return_path_mode": "dual_route",
            }))
            .unwrap();
            let cookie = c.cookie.clone();
            tokio::spawn(async move {
                app.oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(uri)
                        .header("content-type", "application/json")
                        .header("cookie", cookie)
                        .header("x-requested-with", "XMLHttpRequest")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap()
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        let pool = c.pool.clone();
        let report = meshlet_server::persist::backup_once(&pool, &backup_dir, None)
            .await
            .unwrap();
        backup_path = PathBuf::from(report.path);
        let response = writer.await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        c.pool.close().await;
    }

    let backup_pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::from_str(&format!(
                "sqlite:{}",
                backup_path.display()
            ))
            .unwrap()
            .read_only(true),
        )
        .await
        .unwrap();
    let routes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM lan_routes")
        .fetch_one(&backup_pool)
        .await
        .unwrap();
    let revisions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM config_revisions")
        .fetch_one(&backup_pool)
        .await
        .unwrap();
    let max_revision: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(revision), 0) FROM config_revisions")
            .fetch_one(&backup_pool)
            .await
            .unwrap();
    backup_pool.close().await;
    assert_eq!(routes, 0);
    assert_eq!(revisions, 2);
    assert_eq!(max_revision, 2);

    // Windows 会短暂延迟释放 SQLite/WAL 句柄（并发写刚刚停掉尤其明显），
    // 有限重试只吸收文件锁；业务结果仍强断言（与 sibling 恢复用例一致）。
    let mut report = None;
    for _ in 0..10 {
        match meshlet_server::persist::restore_from_backup(
            &backup_path,
            &db,
            meshlet_domain::PresenceThresholds::default(),
        )
        .await
        {
            Ok(restored) => {
                report = Some(restored);
                break;
            }
            Err(meshlet_server::persist::BackupError::Io(error))
                if error.raw_os_error() == Some(32) =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            Err(error) => panic!("{error:?}"),
        }
    }
    let report = report.expect("restore eventually acquires Windows file handles");
    assert_eq!(report.summary.networks, 1);
    assert_eq!(report.summary.devices, 1);
    assert_eq!(report.summary.routes, 0);
    assert_eq!(report.summary.revisions, 2);

    let restored = open_app(&db, None).await;
    let (status, route) = route_post(&restored, &network_id, &device_id, "192.168.78.0/24").await;
    assert_eq!(status, StatusCode::CREATED, "{route}");
    assert_eq!(route["id"], "rt-1");
    assert_eq!(route["revision_id"], 3);
    restored.pool.close().await;

    cleanup(&db);
    cleanup(&backup_path);
}
