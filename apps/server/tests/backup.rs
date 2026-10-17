//! 集成测试：一致性备份与恢复（[存档 §17.4](../../docs/review/chatgpt-2026-10-13.md)）。
//!
//! 1. 备份是**独立快照**：可单独打开、schema 完整、内容自洽；备份之后的
//!    活动库变更不会被回写进备份文件；
//! 2. 恢复后逐字段一致（含 `desired_config_hash`、修订连续编号、路由 id
//!    序列不重号），后续操作照常递增；
//! 3. 恢复的收敛语义与 §17.3 启动一致，不比现在更弱：`applying` → `failed`
//!    （§10.3）、`rollback_pending` 保留可回滚、被取代修订 409；
//! 4. 损坏/不完整备份明确拒绝，活动库**不留半恢复状态**；
//! 5. 端点认证/CSRF/未配置 503；备份与恢复均留审计事件。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::str::FromStr as _;
use std::sync::atomic::{AtomicU32, Ordering};
use tower::ServiceExt; // oneshot

static DB_SEQ: AtomicU32 = AtomicU32::new(0);

const EMAIL: &str = "admin@test.local";
const PASSWORD: &str = "bootstrap-password-123";
const OVERLAY: &str = "10.240.0.0/16";

fn tmp_file(tag: &str, ext: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "meshlet-backup-{}-{tag}-{}.{ext}",
        std::process::id(),
        DB_SEQ.fetch_add(1, Ordering::SeqCst)
    ))
}

fn cleanup(path: &Path) {
    for suffix in ["", "-wal", "-shm", ".restore-tmp-wal", ".restore-tmp-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

struct Ctx {
    app: Router,
    cookie: String,
    pool: sqlx::SqlitePool,
}

/// 打开（或恢复后重新打开）文件库并组装应用；`backup_dir` 注入
/// `POST /system/backup` 的目标目录（None = 未配置 → 503）。
async fn open_app(db: &Path, backup_dir: Option<PathBuf>) -> Ctx {
    let pool = meshlet_server::store::connect(&format!("sqlite:{}", db.display()))
        .await
        .unwrap();
    let boot = meshlet_server::persist::load(&pool, meshlet_domain::PresenceThresholds::default())
        .await
        .unwrap();
    let state = std::sync::Arc::new(
        meshlet_server::auth::AppState::new(
            std::sync::Arc::new(std::sync::Mutex::new(boot.mesh)),
            meshlet_server::auth::AuthStore::new(pool.clone()),
            meshlet_server::agent::AgentTokenStore::new(pool.clone()),
            meshlet_server::api_token::ApiTokenStore::new(pool.clone()),
            false,
        )
        .with_backup_dir(backup_dir),
    );
    let app = meshlet_server::router(state);

    // bootstrap（空库 201）或 login（重启后 200）——都取会话 Cookie。
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email": EMAIL, "password": PASSWORD}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let res = if res.status() == StatusCode::CREATED {
        res
    } else {
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"email": EMAIL, "password": PASSWORD}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "login after reopen");
        res
    };
    let cookie = res
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .expect("session cookie")
        .to_string();
    Ctx { app, cookie, pool }
}

async fn call(c: &Ctx, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    builder = builder
        .header("cookie", &c.cookie)
        .header("x-requested-with", "XMLHttpRequest");
    let body = body.map(|v| Body::from(v.to_string())).unwrap_or_default();
    let req = builder
        .header("content-type", "application/json")
        .body(body)
        .unwrap();
    let res = c.app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Object(Default::default()));
    (status, value)
}

async fn json_post(c: &Ctx, uri: &str, body: Value) -> (StatusCode, Value) {
    call(c, "POST", uri, Some(body)).await
}

async fn json_get(c: &Ctx, uri: &str) -> (StatusCode, Value) {
    call(c, "GET", uri, None).await
}

/// 不带认证/CSRF 的裸 POST（认证门禁用例；用目标应用自己的 router，
/// Cookie 会话须与其存储同库）。
async fn raw_post(app: Router, uri: &str, cookie: Option<&str>, csrf: bool) -> (StatusCode, Value) {
    let mut builder = Request::builder().method("POST").uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    if csrf {
        builder = builder.header("x-requested-with", "XMLHttpRequest");
    }
    let res = app
        .oneshot(
            builder
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Object(Default::default()));
    (status, value)
}

/// 建网 + 邀请 + 加入一台设备，返回 (network_id, device_id)。
async fn net_with_device(c: &Ctx) -> (String, String) {
    let (st, net) = json_post(
        c,
        "/api/v1/networks",
        json!({"name": "home", "overlay_cidr": OVERLAY}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let network_id = net["id"].as_str().unwrap().to_string();
    let (st, invite) = json_post(
        c,
        &format!("/api/v1/networks/{network_id}/invites"),
        json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, device) = json_post(
        c,
        "/api/v1/enroll",
        json!({
            "invite_token": invite["token"].as_str().unwrap(),
            "device_name": "gw-home",
            "public_key": "pub-key-backup",
            "platform": "linux",
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    (
        network_id,
        device["device_id"].as_str().unwrap().to_string(),
    )
}

/// 触发一次端点备份，断言 200 并返回响应（path/bytes/counts）。
async fn do_backup(c: &Ctx) -> Value {
    let (st, body) = json_post(c, "/api/v1/system/backup", json!({})).await;
    assert_eq!(st, StatusCode::OK, "backup endpoint: {body}");
    body
}

/// 只读打开备份文件，取 (表数, 迁移数, 路由行数, route_seq)。
async fn inspect_backup(path: &Path) -> (usize, i64, i64, Option<String>) {
    let options =
        sqlx::sqlite::SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .read_only(true);
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let tables: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
         AND name NOT LIKE '_sqlx_%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let migrations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    let routes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM lan_routes")
        .fetch_one(&pool)
        .await
        .unwrap();
    let seq: Option<String> =
        sqlx::query_scalar("SELECT value FROM mesh_meta WHERE key = 'route_seq'")
            .fetch_optional(&pool)
            .await
            .unwrap();
    pool.close().await;
    (usize::try_from(tables).unwrap(), migrations, routes, seq)
}

/// §17.4 验收 1：备份是独立快照——可单独打开、schema/迁移完整，后续变更
/// 不回写。
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

    // 备份文件独立可打开：20 表 + 11 个迁移齐全；内容停留在备份时刻
    // （路由 1 条、route_seq=1），不随活动库后续变更回写。
    let (tables, migrations, routes, seq) = inspect_backup(&backup_path).await;
    assert_eq!(tables, 20, "schema complete in backup");
    assert_eq!(migrations, 11, "migrations 001-011 recorded in backup");
    assert_eq!(routes, 1, "backup frozen at snapshot moment");
    assert_eq!(seq.as_deref(), Some("1"));

    cleanup(&db);
    cleanup(&backup_path);
}

/// §17.4 验收 2：恢复后逐字段一致 + 后续编号照常递增。
#[tokio::test]
async fn restore_rebuilds_field_by_field_and_continues_numbering() {
    let db = tmp_file("restore", "db");
    let backup_dir = tmp_file("restoredir", "dir");
    std::fs::create_dir_all(&backup_dir).unwrap();
    let (network_id, device_id, backup_path);
    let (snap_networks, snap_devices, snap_routes, snap_revisions);
    {
        let c = open_app(&db, Some(backup_dir)).await;
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
        let c = open_app(&db, Some(backup_dir)).await;
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

/// §17.4 验收 4：损坏/不完整备份明确拒绝，活动库不留半恢复状态。
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

        // 备份后继续变更（活动库与备份分叉）。
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

    // (a) 垃圾文件：根本不是数据库。
    let garbage = tmp_file("garbage", "db");
    std::fs::write(&garbage, "this is not a database at all").unwrap();
    let err = restore_err(&garbage, &db).await;
    assert!(
        err.contains("not a usable database"),
        "garbage file rejected: {err}"
    );

    // (b) 截断的合法备份。
    let truncated = tmp_file("truncated", "db");
    let bytes = std::fs::read(&backup_path).unwrap();
    std::fs::write(&truncated, &bytes[..bytes.len() / 2]).unwrap();
    let err = restore_err(&truncated, &db).await;
    assert!(
        err.contains("not a usable database") || err.contains("corrupt"),
        "truncated backup rejected: {err}"
    );

    // (c) 合法 SQLite 但缺表（不完整 schema）。
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

    // (d) 旁挂未合并 WAL 的备份：只拷主文件会丢已提交事务 → 拒绝。
    let with_wal = tmp_file("unsettled-wal", "db");
    std::fs::copy(&backup_path, &with_wal).unwrap();
    std::fs::write(format!("{}-wal", with_wal.display()), b"stale wal bytes").unwrap();
    let err = restore_err(&with_wal, &db).await;
    assert!(
        err.contains("unsettled write-ahead log"),
        "backup with live WAL rejected: {err}"
    );
    cleanup(&with_wal);

    // 三次拒绝后活动库逐字段未动（没有半恢复状态）。
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

async fn restore_err(backup: &Path, db: &Path) -> String {
    match meshlet_server::persist::restore_from_backup(
        backup,
        db,
        meshlet_domain::PresenceThresholds::default(),
    )
    .await
    {
        Ok(_) => panic!("restore must reject this backup"),
        Err(e) => e.to_string(),
    }
}

/// §17.4 验收 5：端点门禁——未认证 401、缺 CSRF 403、未配置目录 503。
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
    c.pool.close().await;
    cleanup(&db);
}

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
    assert_eq!(version, 11);
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
