use std::path::PathBuf;

use serde_json::json;

use axum::http::StatusCode;

use crate::common::{
    cleanup, do_backup, json_get, json_post, net_with_device, open_app, restore_err, tmp_file,
};
#[tokio::test]
async fn corrupt_or_incomplete_backups_rejected_without_half_state() {
    let db = tmp_file("corrupt", "db");
    let backup_dir = tmp_file("corruptdir", "dir");
    std::fs::create_dir_all(&backup_dir).unwrap();
    let (network_id, device_id, backup_path);
    let (mutated_routes, mutated_devices, mutated_revisions);
    {
        let c = open_app(&db, Some(backup_dir)).await;
        (network_id, device_id) = net_with_device(&c).await;
        backup_path = PathBuf::from(do_backup(&c).await["path"].as_str().unwrap().to_string());

        // Keep mutating after the backup (the live DB and the backup diverge).
        let (st, _) = json_post(
            &c,
            &format!("/api/v1/networks/{network_id}/routes"),
            json!({
                "gateway_device_id": device_id,
                "destination_cidr": "192.168.2.0/24",
                "return_path_mode": "dual_route",
            }),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        mutated_routes = json_get(&c, &format!("/api/v1/networks/{network_id}/routes"))
            .await
            .1;
        mutated_devices = json_get(&c, &format!("/api/v1/networks/{network_id}/devices"))
            .await
            .1;
        mutated_revisions = json_get(
            &c,
            &format!("/api/v1/networks/{network_id}/config-revisions"),
        )
        .await
        .1;
        c.pool.close().await;
    }

    // (a) A garbage file: not a database at all.
    let garbage = tmp_file("garbage", "db");
    std::fs::write(&garbage, "this is not a database at all").unwrap();
    let err = restore_err(&garbage, &db).await;
    assert!(
        err.contains("not a usable database"),
        "garbage file rejected: {err}"
    );

    // (b) A truncated but otherwise valid backup.
    let truncated = tmp_file("truncated", "db");
    let bytes = std::fs::read(&backup_path).unwrap();
    std::fs::write(&truncated, &bytes[..bytes.len() / 2]).unwrap();
    let err = restore_err(&truncated, &db).await;
    assert!(
        err.contains("not a usable database") || err.contains("corrupt"),
        "truncated backup rejected: {err}"
    );

    // (c) Valid SQLite but missing tables (an incomplete schema).
    let empty_schema = tmp_file("empty-schema", "db");
    {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&empty_schema)
            .create_if_missing(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        pool.close().await;
    }
    let err = restore_err(&empty_schema, &db).await;
    assert!(
        err.contains("missing required tables"),
        "incomplete schema rejected: {err}"
    );

    // (d) A backup with an unmerged WAL sitting beside it: copying only the main file loses committed transactions -> rejected.
    let with_wal = tmp_file("unsettled-wal", "db");
    std::fs::copy(&backup_path, &with_wal).unwrap();
    std::fs::write(format!("{}-wal", with_wal.display()), b"stale wal bytes").unwrap();
    let err = restore_err(&with_wal, &db).await;
    assert!(
        err.contains("unsettled write-ahead log"),
        "backup with live WAL rejected: {err}"
    );
    cleanup(&with_wal);

    // After the three rejections the live DB is untouched field by field (no half-restored state).
    let c = open_app(&db, None).await;
    assert_eq!(
        json_get(&c, &format!("/api/v1/networks/{network_id}/routes"))
            .await
            .1,
        mutated_routes,
        "live routes untouched by failed restores"
    );
    assert_eq!(
        json_get(&c, &format!("/api/v1/networks/{network_id}/devices"))
            .await
            .1,
        mutated_devices
    );
    assert_eq!(
        json_get(
            &c,
            &format!("/api/v1/networks/{network_id}/config-revisions")
        )
        .await
        .1,
        mutated_revisions
    );
    c.pool.close().await;

    cleanup(&db);
    cleanup(&backup_path);
    cleanup(&garbage);
    cleanup(&truncated);
    cleanup(&empty_schema);
}
