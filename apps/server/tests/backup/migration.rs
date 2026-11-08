use std::path::PathBuf;

use axum::http::StatusCode;

use crate::common::{cleanup, net_with_device, open_app, route_post, tmp_file};
#[tokio::test]
async fn version_eight_backup_is_upgraded_in_staging_before_restore() {
    let dir = std::env::temp_dir().join(format!("meshlet-v8-restore-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let backup = dir.join("version-eight.db");
    let _ = std::fs::remove_file(&backup);
    let pool =
        meshlet_server::store::connect(&format!("sqlite:{}", dir.join("source.db").display()))
            .await
            .unwrap();
    sqlx::query("DROP TABLE device_apply_receipts")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE hub_deployments")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE devices DROP COLUMN segment_id")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE segment_grants")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE segments")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE publish_probe_reports")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE publish_dns_records")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE publish_probes")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE publish_http_routes")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE publish_forwards")
        .execute(&pool)
        .await
        .unwrap();
    // 014_user_totp：v8 快照没有这两列，恢复到 v8 必须回退到 v8 形状，
    // 否则重跑 014 会撞「duplicate column」。
    sqlx::query("ALTER TABLE users DROP COLUMN totp_enabled")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE users DROP COLUMN totp_secret")
        .execute(&pool)
        .await
        .unwrap();
    // 015_tasks：v8 快照没有 tasks 表，恢复到 v8 必须回退到 v8 形状，
    // 否则重跑 015（建表）会撞「table tasks already exists」；016 的
    // ALTER 依赖 015 建出的表，回退必须先删净。
    sqlx::query("DROP TABLE tasks")
        .execute(&pool)
        .await
        .unwrap();
    // 017_device_labels：v8 快照没有 devices.labels 列（tasks 已删，
    // required_labels 随之消失），回退列否则重跑 017 撞「duplicate column」。
    sqlx::query("ALTER TABLE devices DROP COLUMN labels")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version >= 9")
        .execute(&pool)
        .await
        .unwrap();
    // An actual backup is a standalone VACUUM snapshot, not a live WAL database.
    sqlx::query("VACUUM INTO ?")
        .bind(backup.to_string_lossy().as_ref())
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        backup.exists(),
        "VACUUM must produce a standalone file snapshot"
    );
    pool.close().await;
    meshlet_server::persist::validate_backup(&backup)
        .await
        .unwrap();
    let restored = dir.join("restored.db");
    meshlet_server::persist::restore_from_backup(&backup, &restored, Default::default())
        .await
        .unwrap();
    let pool = meshlet_server::store::connect(&format!("sqlite:{}", restored.display()))
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE name IN ('hub_deployments','device_apply_receipts')").fetch_one(&pool).await.unwrap();
    assert_eq!(count, 2);
    let version: i64 = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(version, 17);
    let default_segments: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM segments")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        default_segments, 0,
        "no network rows need defaults in empty v8 DB"
    );
    pool.close().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn failed_backup_migration_preserves_live_database() {
    let dir = std::env::temp_dir().join(format!("meshlet-bad-migration-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let backup = dir.join("bad.db");
    let live = dir.join("live.db");
    let _ = std::fs::remove_file(&backup);
    let _ = std::fs::remove_file(&live);
    let pool = meshlet_server::store::connect(&format!("sqlite:{}", backup.display()))
        .await
        .unwrap();
    sqlx::query("UPDATE _sqlx_migrations SET checksum=x'00' WHERE version=9")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    let pool = meshlet_server::store::connect(&format!("sqlite:{}", live.display()))
        .await
        .unwrap();
    pool.close().await;
    let before = std::fs::read(&live).unwrap();
    assert!(
        meshlet_server::persist::restore_from_backup(&backup, &live, Default::default())
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&live).unwrap(), before);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn failed_revision_write_never_backs_up_or_restores_orphan_resource() {
    let db = tmp_file("failed-write", "db");
    let backup_dir = tmp_file("failed-writedir", "dir");
    std::fs::create_dir_all(&backup_dir).unwrap();
    let backup_path;
    let (network_id, device_id);
    {
        let c = open_app(&db, Some(backup_dir.clone())).await;
        (network_id, device_id) = net_with_device(&c).await;
        sqlx::query("CREATE TRIGGER fail_revision BEFORE INSERT ON config_revisions BEGIN SELECT RAISE(FAIL, 'revision write failed'); END")
            .execute(&c.pool)
            .await
            .unwrap();
        let (status, error) = route_post(&c, &network_id, &device_id, "192.168.91.0/24").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{error}");
        sqlx::query("DROP TRIGGER fail_revision")
            .execute(&c.pool)
            .await
            .unwrap();
        let report =
            meshlet_server::persist::backup_once(&c.pool, std::path::Path::new(&backup_dir), None)
                .await
                .unwrap();
        backup_path = PathBuf::from(report.path);
        assert_eq!(report.view.routes, 0);
        assert_eq!(report.view.revisions, 2);
        c.pool.close().await;
    }

    meshlet_server::persist::restore_from_backup(
        &backup_path,
        &db,
        meshlet_domain::PresenceThresholds::default(),
    )
    .await
    .unwrap();
    let restored = open_app(&db, None).await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM lan_routes")
            .fetch_one(&restored.pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM config_revisions")
            .fetch_one(&restored.pool)
            .await
            .unwrap(),
        2
    );
    let (status, route) = route_post(&restored, &network_id, &device_id, "192.168.92.0/24").await;
    assert_eq!(status, StatusCode::CREATED, "{route}");
    assert_eq!(route["revision_id"], 3);
    restored.pool.close().await;

    cleanup(&db);
    cleanup(&backup_path);
}
