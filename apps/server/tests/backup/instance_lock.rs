use std::path::PathBuf;

use axum::http::StatusCode;

use crate::common::{cleanup, do_backup, net_with_device, open_app, route_post, tmp_file};
/// §17.4 instance lock guard: while meshlet-server is running (holding the live DB lock), a restore must be
/// **rejected as a whole** with the live DB untouched; once the lock is released, restore succeeds as usual.
///
/// Previously "stop the service before restoring" was enforced only by prose - the 2026-10-24 deployment
/// acceptance recorded the failure: a restore during runtime left the service `active`, and one token mint
/// returning HTTP 201 vanished into a detached inode; a pre-restore `BEGIN EXCLUSIVE` cannot stop it under WAL, since an idle service holds no write transaction.
#[tokio::test]
async fn restore_refuses_as_a_whole_while_a_server_holds_the_instance_lock() {
    let db = tmp_file("lock-guard", "db");
    let backup_dir = tmp_file("lock-guaddir", "dir");
    std::fs::create_dir_all(&backup_dir).unwrap();
    let (network_id, device_id, backup_path);
    {
        let c = open_app(&db, Some(backup_dir.clone())).await;
        (network_id, device_id) = net_with_device(&c).await;
        let (st, route) = route_post(&c, &network_id, &device_id, "192.168.1.0/24").await;
        assert_eq!(st, StatusCode::CREATED, "{route}");
        assert_eq!(route["id"], "rt-1");
        let backup = do_backup(&c).await;
        assert_eq!(backup["routes"], 1);
        backup_path = PathBuf::from(backup["path"].as_str().unwrap().to_string());

        // Keep writing to the live DB after the backup: this change is exactly the "overwritten by the rename" victim.
        let (st, second) = route_post(&c, &network_id, &device_id, "192.168.2.0/24").await;
        assert_eq!(st, StatusCode::CREATED, "{second}");
        c.pool.close().await;
    }

    // Simulate a running meshlet-server: hold the live DB's instance lock.
    let held = meshlet_server::instance_lock::try_acquire(&db).unwrap();

    let error = meshlet_server::persist::restore_from_backup(
        &backup_path,
        &db,
        meshlet_domain::PresenceThresholds::default(),
    )
    .await
    .unwrap_err();
    let meshlet_server::persist::BackupError::Locked(why) = error else {
        panic!("a live server must be refused with Locked, got {error:?}")
    };
    assert!(
        why.contains("stop meshlet-server"),
        "the refusal must name the remedy: {why}"
    );

    // The refusal path leaves no half-restore: the live DB still holds the two routes written **after** the backup.
    let live = open_app(&db, None).await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM lan_routes")
            .fetch_one(&live.pool)
            .await
            .unwrap(),
        2
    );
    live.pool.close().await;
    drop(held);

    // With the lock released, restore succeeds as usual: the live DB returns to its single-route state from backup time.
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
        1
    );
    // After the restore, numbering increments as usual - no half-restore residue.
    let (st, route) = route_post(&restored, &network_id, &device_id, "192.168.92.0/24").await;
    assert_eq!(st, StatusCode::CREATED, "{route}");
    assert_eq!(route["revision_id"], 4);
    restored.pool.close().await;

    cleanup(&db);
    cleanup(&backup_path);
    cleanup(meshlet_server::instance_lock::lock_path(&db).as_path());
}
