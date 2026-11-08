use std::path::PathBuf;

use serde_json::json;

use axum::http::StatusCode;

use crate::common::{
    cleanup, do_backup, inspect_backup, json_get, json_post, net_with_device, open_app, tmp_file,
};
#[tokio::test]
async fn backup_file_is_independent_snapshot_not_written_back() {
    let db = tmp_file("snap", "db");
    let backup_dir = tmp_file("snapdir", "dir");
    std::fs::create_dir_all(&backup_dir).unwrap();
    let (network_id, device_id, backup_path);
    {
        let c = open_app(&db, Some(backup_dir.clone())).await;
        (network_id, device_id) = net_with_device(&c).await;
        let (st, route) = json_post(
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
        assert_eq!(route["id"], "rt-1");

        let backup = do_backup(&c).await;
        assert!(backup["path"]
            .as_str()
            .unwrap()
            .starts_with(backup_dir.display().to_string().as_str()));
        assert_eq!(backup["networks"], 1);
        assert_eq!(backup["devices"], 1);
        assert_eq!(backup["routes"], 1);
        assert_eq!(backup["revisions"], 3); // net=1 enroll=2 route=3
        assert!(backup["bytes"].as_u64().unwrap() > 0);
        backup_path = PathBuf::from(backup["path"].as_str().unwrap().to_string());

        // 备份含口令哈希等敏感材料：落盘即收紧权限（unix 0600）。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&backup_path)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "backup file restricted to owner");
        }

        // 审计留痕：system.backup，actor = 操作会话的用户 id。
        let (_, me) = json_get(&c, "/api/v1/auth/me").await;
        let (_, audit) = json_get(&c, "/api/v1/audit").await;
        let events = audit["events"].as_array().unwrap();
        let backup_event = events
            .iter()
            .find(|e| e["action"] == "system.backup")
            .expect("system.backup audited");
        assert_eq!(backup_event["actor_id"], me["user_id"]);

        // 备份之后的变更：第二条路由（rt-2）+ 第二台设备。
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
                "public_key": "pub-key-backup-2",
                "platform": "windows",
            }),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        c.pool.close().await;
    }

    // 备份文件独立可打开：26 表 + 16 个迁移齐全；内容停留在备份时刻
    // （路由 1 条、route_seq=1），不随活动库后续变更回写。
    let (tables, migrations, routes, seq) = inspect_backup(&backup_path).await;
    assert_eq!(tables, 26, "schema complete in backup");
    assert_eq!(migrations, 17, "migrations 001-017 recorded in backup");
    assert_eq!(routes, 1, "backup frozen at snapshot moment");
    assert_eq!(seq.as_deref(), Some("1"));

    cleanup(&db);
    cleanup(&backup_path);
}
