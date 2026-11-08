use std::path::PathBuf;

use axum::http::StatusCode;

use crate::common::{cleanup, do_backup, net_with_device, open_app, route_post, tmp_file};
/// §17.4 实例锁守卫：meshlet-server 在跑（持有活动库锁）时恢复必须**整体
/// 拒绝**，活动库一字不动；锁一释放恢复照常成功。
///
/// 之前的「先停服务再恢复」只靠散文约束——2026-10-24 的部署验收实录：运行中
/// 恢复后服务仍 `active`，一次返回 HTTP 201 的 token 铸造就写进了脱链 inode
/// 而消失。恢复前的 `BEGIN EXCLUSIVE` 在 WAL 下拦不住（空闲服务不持写事务）。
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

        // 备份之后继续写活动库：这条变更正是「被换名覆盖」的靶子。
        let (st, second) = route_post(&c, &network_id, &device_id, "192.168.2.0/24").await;
        assert_eq!(st, StatusCode::CREATED, "{second}");
        c.pool.close().await;
    }

    // 模拟运行中的 meshlet-server：持有活动库实例锁。
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

    // 拒绝路径不留半恢复：活动库仍是备份**之后**的两条路由。
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

    // 锁释放后恢复照常成功：活动库回到备份时的单条路由状态。
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
    // 恢复后编号照常递增，没有半恢复残留。
    let (st, route) = route_post(&restored, &network_id, &device_id, "192.168.92.0/24").await;
    assert_eq!(st, StatusCode::CREATED, "{route}");
    assert_eq!(route["revision_id"], 4);
    restored.pool.close().await;

    cleanup(&db);
    cleanup(&backup_path);
    cleanup(meshlet_server::instance_lock::lock_path(&db).as_path());
}
