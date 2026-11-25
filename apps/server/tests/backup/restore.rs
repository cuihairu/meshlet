use std::path::PathBuf;

use serde_json::json;

use axum::http::StatusCode;

use crate::common::{
    call, cleanup, do_backup, json_get, json_post, net_with_device, open_app, tmp_file, OVERLAY,
};
#[tokio::test]
async fn restore_rebuilds_field_by_field_and_continues_numbering() {
    let db = tmp_file("restore", "db");
    let backup_dir = tmp_file("restoredir", "dir");
    std::fs::create_dir_all(&backup_dir).unwrap();
    let (network_id, device_id, backup_path);
    let (snap_networks, snap_devices, snap_routes, snap_revisions);
    {
        let c = open_app(&db, Some(backup_dir.clone())).await;
        (network_id, device_id) = net_with_device(&c).await;
        let (st, _) = json_post(
            &c,
            &format!("/api/v1/networks/{network_id}/routes"),
            json!({
                "gateway_device_id": device_id,
                "destination_cidr": "192.168.1.0/24",
                "return_path_mode": "dual_route",
            }),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);

        snap_networks = json_get(&c, "/api/v1/networks").await.1;
        snap_devices = json_get(&c, &format!("/api/v1/networks/{network_id}/devices"))
            .await
            .1;
        snap_routes = json_get(&c, &format!("/api/v1/networks/{network_id}/routes"))
            .await
            .1;
        snap_revisions = json_get(
            &c,
            &format!("/api/v1/networks/{network_id}/config-revisions"),
        )
        .await
        .1;
        backup_path = PathBuf::from(do_backup(&c).await["path"].as_str().unwrap().to_string());

        // The live DB keeps evolving after the backup: delete rt-1 and add a second device (revision numbers drift far ahead).
        let (st, _) = call(
            &c,
            "DELETE",
            &format!("/api/v1/networks/{network_id}/routes/rt-1"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        let (st, invite) = json_post(
            &c,
            &format!("/api/v1/networks/{network_id}/invites"),
            json!({}),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        let (st, _) = json_post(
            &c,
            "/api/v1/enroll",
            json!({
                "invite_token": invite["token"].as_str().unwrap(),
                "device_name": "laptop",
                "public_key": "pub-key-restore-2",
                "platform": "windows",
            }),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        c.pool.close().await;
    }

    // Offline restore (the same function the meshlet-server restore subcommand uses). Windows briefly delays
    // releasing SQLite/WAL handles, so the bounded retry only absorbs the file lock; business results stay hard-asserted.
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
    assert_eq!(report.summary.routes, 1);
    assert_eq!(report.summary.revisions, 3);
    assert!(report.interrupted.is_empty());

    // Field-by-field agreement after restore (networks / devices / routes / revision sequence and desired_config_hash).
    let c = open_app(&db, None).await;
    let (default_segment_id, default_segment_cidr): (String, String) =
        sqlx::query_as("SELECT id, cidr FROM segments WHERE network_id = ? AND name = 'default'")
            .bind(&network_id)
            .fetch_one(&c.pool)
            .await
            .unwrap();
    assert_eq!(default_segment_id, format!("seg-{network_id}"));
    assert_eq!(default_segment_cidr, OVERLAY);
    let device_segment_id: String =
        sqlx::query_scalar("SELECT segment_id FROM devices WHERE id = ?")
            .bind(&device_id)
            .fetch_one(&c.pool)
            .await
            .unwrap();
    assert_eq!(device_segment_id, default_segment_id);
    assert_eq!(
        json_get(&c, "/api/v1/networks").await.1,
        snap_networks,
        "networks survive restore"
    );
    assert_eq!(
        json_get(&c, &format!("/api/v1/networks/{network_id}/devices"))
            .await
            .1,
        snap_devices,
        "devices survive restore"
    );
    assert_eq!(
        json_get(&c, &format!("/api/v1/networks/{network_id}/routes"))
            .await
            .1,
        snap_routes,
        "routes survive restore"
    );
    assert_eq!(
        json_get(
            &c,
            &format!("/api/v1/networks/{network_id}/config-revisions")
        )
        .await
        .1,
        snap_revisions,
        "revisions (hashes + status) survive restore verbatim"
    );
    let numbers: Vec<u64> = snap_revisions
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["revision"].as_u64().unwrap())
        .collect();
    assert_eq!(numbers, vec![1, 2, 3], "contiguous revision numbers");

    // Audit trail: system.restore (actor=None, an offline command).
    let (_, audit) = json_get(&c, "/api/v1/audit").await;
    assert!(
        audit["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "system.restore"),
        "system.restore audited"
    );

    // route_seq returns to its value at backup time: a new route continues as rt-2 (no id clash with the surviving rt-1).
    let (st, route) = json_post(
        &c,
        &format!("/api/v1/networks/{network_id}/routes"),
        json!({
            "gateway_device_id": device_id,
            "destination_cidr": "192.168.9.0/24",
            "return_path_mode": "dual_route",
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    assert_eq!(route["id"], "rt-2");
    c.pool.close().await;

    cleanup(&db);
    cleanup(&backup_path);
}

/// §17.4 acceptance 3: the convergence semantics of a restore match those of the §17.3 boot path (no weaker than the status quo) -
/// a revision stuck at `applying` in the backup lands at `failed` after restore, `rollback_pending` is preserved as-is and
/// stays rollbackable, and rolling back a superseded revision returns 409.
#[tokio::test]
async fn restore_convergence_matches_boot_semantics() {
    let db = tmp_file("conv", "db");
    let backup_dir = tmp_file("convdir", "dir");
    std::fs::create_dir_all(&backup_dir).unwrap();
    let (network_id, backup_path);
    {
        let c = open_app(&db, Some(backup_dir.clone())).await;
        (network_id, _) = net_with_device(&c).await;
        backup_path = PathBuf::from(do_backup(&c).await["path"].as_str().unwrap().to_string());
        c.pool.close().await;
    }

    // Simulate "a crash scene got backed up": rewrite the revisions inside the backup file to an intermediate state
    // (rev1 rollback_pending / rev2 applying).
    {
        let pool = meshlet_server::store::connect(&format!("sqlite:{}", backup_path.display()))
            .await
            .unwrap();
        sqlx::query(
            "UPDATE config_revisions SET apply_status = 'rollback_pending', \
             error_summary = 'apply boom' WHERE network_id = ? AND revision = 1",
        )
        .bind(&network_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE config_revisions SET apply_status = 'applying' \
             WHERE network_id = ? AND revision = 2",
        )
        .bind(&network_id)
        .execute(&pool)
        .await
        .unwrap();
        // Writes to the backup file must be folded back into the main file (a backup whose WAL was never checkpointed
        // is explicitly rejected by the restore path - this is exactly the "unsettled WAL refuses to restore" line of defense).
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&pool)
            .await
            .unwrap();
        let wal_len = std::fs::metadata(format!("{}-wal", backup_path.display()))
            .map(|m| m.len())
            .unwrap_or(0);
        assert_eq!(
            wal_len, 0,
            "checkpoint must fold the WAL into the backup file"
        );
        pool.close().await;
    }

    let report = meshlet_server::persist::restore_from_backup(
        &backup_path,
        &db,
        meshlet_domain::PresenceThresholds::default(),
    )
    .await
    .unwrap();
    assert_eq!(report.interrupted.len(), 1, "applying converged");
    assert_eq!(report.interrupted[0], (network_id.clone(), 2));

    let c = open_app(&db, None).await;
    // applying -> failed + an interruption diagnosis (§10.3 does not pretend success).
    let (st, rev2) = json_get(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions/2"),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(rev2["apply_status"], "failed");
    assert!(rev2["error_summary"]
        .as_str()
        .unwrap()
        .contains("interrupted"));

    // rollback_pending is preserved as-is (the diagnosis is replayed verbatim and stays distinguishable).
    let (_, rev1) = json_get(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions/1"),
    )
    .await;
    assert_eq!(rev1["apply_status"], "rollback_pending");
    assert_eq!(rev1["error_summary"], "apply boom");

    // The current revision (rev2, failed) can be rolled back (no backend -> it parks at rollback_pending).
    let (st, rolled) = json_post(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions/2/rollback"),
        json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(rolled["apply_status"], "rollback_pending");
    // The superseded rev1 refuses a rollback (the §10.4 cross-corruption guard holds across a restore).
    let (st, _) = json_post(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions/1/rollback"),
        json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);

    // The restore leaves an audit trail.
    let (_, audit) = json_get(&c, "/api/v1/audit").await;
    assert!(audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["action"] == "system.restore"));
    c.pool.close().await;

    cleanup(&db);
    cleanup(&backup_path);
}
