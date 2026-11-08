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

        // 备份后活动库继续演进：删掉 rt-1、再加第二台设备（修订号走远）。
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

    // 离线恢复（与 meshlet-server restore 子命令同一函数）。Windows 会短暂
    // 延迟释放 SQLite/WAL 句柄，有限重试只吸收文件锁；业务结果仍强断言。
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

    // 恢复后逐字段一致（网络/设备/路由/修订序列与 desired_config_hash）。
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

    // 审计留痕：system.restore（actor=None，离线命令）。
    let (_, audit) = json_get(&c, "/api/v1/audit").await;
    assert!(
        audit["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "system.restore"),
        "system.restore audited"
    );

    // route_seq 回到备份时刻：新路由接续 rt-2（与现存 rt-1 不重号）。
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

/// §17.4 验收 3：恢复的收敛语义与 §17.3 启动一致（不比现在更弱）——
/// 备份里停在 `applying` 的修订恢复后落 `failed`，`rollback_pending`
/// 原样保留可回滚，被取代修订回滚 409。
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

    // 模拟「崩溃现场被备份」：直接把备份文件里的修订改成中间态
    // （rev1 rollback_pending / rev2 applying）。
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
        // 备份文件的写入必须合并回主文件（WAL 未 checkpoint 的备份会被
        // 恢复路径明确拒绝——正是「未合并 WAL 拒绝恢复」防线）。
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
    // applying → failed + 中断诊断（§10.3 不假装成功）。
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

    // rollback_pending 原样保留（诊断逐字回放，可区分）。
    let (_, rev1) = json_get(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions/1"),
    )
    .await;
    assert_eq!(rev1["apply_status"], "rollback_pending");
    assert_eq!(rev1["error_summary"], "apply boom");

    // 当前修订（rev2, failed）可回滚（无 backend → 停在 rollback_pending）。
    let (st, rolled) = json_post(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions/2/rollback"),
        json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(rolled["apply_status"], "rollback_pending");
    // 被取代的 rev1 拒绝回滚（§10.4 交叉破坏防线跨恢复成立）。
    let (st, _) = json_post(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions/1/rollback"),
        json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);

    // 恢复留痕。
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
