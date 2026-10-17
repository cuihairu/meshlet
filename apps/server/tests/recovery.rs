//! 集成测试：故障恢复（[存档 §17.3](../../docs/review/chatgpt-2026-10-13.md)）。
//!
//! 服务端重启后按期望状态恢复：
//! 1. 建网 + 加入设备 + 发路由 + apply → 关库再从同一 DB 重建 →
//!    网络/设备虚拟 IP/路由/修订序列逐字段一致，重启后编号与分配继续递增；
//! 2. 停在 `applying` 的修订重启后按 §10.3 落 `failed`（不假装成功），
//!    `rollback_pending` 保留可重试；
//! 3. 已删路由的 id 重启后不复用；
//! 4. presence 证据重启后保守判定——旧证据不虚构 `online`（§12.4）；
//! 5. 自举码与待审批注册申请（含 Pending 心跳证据）跨重启逐字段重建，
//!    注册期 agent 凭证跨重启继续有效（2026-10-15 自举注册）。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use tower::ServiceExt; // oneshot

static DB_SEQ: AtomicU32 = AtomicU32::new(0);

const EMAIL: &str = "admin@test.local";
const PASSWORD: &str = "bootstrap-password-123";
const OVERLAY: &str = "10.240.0.0/16";

/// 唯一的临时库文件（进程 + 用例双维度隔离； WAL/SHM 伴生文件一并清理）。
/// 目录用 cargo 为集成测试提供的 `CARGO_TARGET_TMPDIR`（构建区内可写）。
fn db_file(tag: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "meshlet-recovery-{}-{tag}-{}.db",
        std::process::id(),
        DB_SEQ.fetch_add(1, Ordering::SeqCst)
    ))
}

fn cleanup_db(path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

struct Ctx {
    app: Router,
    cookie: String,
    pool: sqlx::SqlitePool,
}

/// 打开（或重启后重新打开）一个文件库：跑 migration → §17.3 重建 Mesh 状态 →
/// 组装应用。首开空库走 bootstrap；重启后库里有用户，走 login——两种都拿会话
/// Cookie（顺带证明用户/会话凭证本身跨重启持久）。
async fn open_app(db: &Path) -> Ctx {
    let url = format!("sqlite:{}", db.display());
    let pool = meshlet_server::store::connect(&url).await.unwrap();
    let boot = meshlet_server::persist::load(&pool, meshlet_domain::PresenceThresholds::default())
        .await
        .unwrap();
    let state = std::sync::Arc::new(meshlet_server::auth::AppState::new(
        std::sync::Arc::new(std::sync::Mutex::new(boot.mesh)),
        meshlet_server::auth::AuthStore::new(pool.clone()),
        meshlet_server::agent::AgentTokenStore::new(pool.clone()),
        meshlet_server::api_token::ApiTokenStore::new(pool.clone()),
        false,
    ));
    let app = meshlet_server::router(state);

    // bootstrap（空库 201）或 login（重启后 200）——都从 Set-Cookie 取会话。
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
        assert_eq!(res.status(), StatusCode::OK, "login after restart");
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
            "public_key": "pub-key-recovery",
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

/// §17.3 验收 1：关库 → 同一 DB 重建 → 期望状态逐字段一致，编号继续递增。
#[tokio::test]
async fn restart_rebuilds_state_field_by_field() {
    let db = db_file("rebuild");
    let (network_id, device_id);
    let (before_networks, before_devices, before_routes, before_revisions);
    {
        let c = open_app(&db).await;
        (network_id, device_id) = net_with_device(&c).await;
        let (st, _route) = json_post(
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
        // apply 走无 backend 路径 → failed（失败可见且被持久化，也是恢复语义的一部分）。
        let (st, applied) = json_post(
            &c,
            &format!("/api/v1/networks/{network_id}/config-revisions/3/apply"),
            json!({}),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(applied["apply_status"], "failed");

        before_networks = json_get(&c, "/api/v1/networks").await.1;
        before_devices = json_get(&c, &format!("/api/v1/networks/{network_id}/devices"))
            .await
            .1;
        before_routes = json_get(&c, &format!("/api/v1/networks/{network_id}/routes"))
            .await
            .1;
        before_revisions = json_get(
            &c,
            &format!("/api/v1/networks/{network_id}/config-revisions"),
        )
        .await
        .1;
        c.pool.close().await;
    }

    // 重启：同一 DB 重建（open_app 内部经 persist::load）。
    let c = open_app(&db).await;
    let after_networks = json_get(&c, "/api/v1/networks").await.1;
    let after_devices = json_get(&c, &format!("/api/v1/networks/{network_id}/devices"))
        .await
        .1;
    let after_routes = json_get(&c, &format!("/api/v1/networks/{network_id}/routes"))
        .await
        .1;
    let after_revisions = json_get(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions"),
    )
    .await
    .1;

    // 逐字段一致：网络（含当前修订号）、设备（虚拟 IP/公钥/状态）、路由、
    // 修订序列（版本号连续、desired_config_hash 与 error_summary 逐字回放）。
    assert_eq!(before_networks, after_networks, "networks survive restart");
    assert_eq!(before_devices, after_devices, "devices survive restart");
    assert_eq!(before_routes, after_routes, "routes survive restart");
    assert_eq!(
        before_revisions, after_revisions,
        "revisions (numbers + hashes + apply results) survive restart verbatim"
    );
    let revisions = before_revisions.as_array().unwrap();
    let numbers: Vec<u64> = revisions
        .iter()
        .map(|r| r["revision"].as_u64().unwrap())
        .collect();
    assert_eq!(numbers, vec![1, 2, 3], "net=1 enroll=2 route=3, contiguous");
    assert!(
        revisions
            .iter()
            .all(|r| r["desired_config_hash"].as_str().unwrap().len() == 64),
        "hashes restored"
    );

    // 重启后一切继续递增：新设备拿下一个虚拟 IP（不复用 .2）、修订号接续、
    // 新路由 id 接续（rt-2，不重发 rt-1 的号）。
    let (st, invite) = json_post(
        &c,
        &format!("/api/v1/networks/{network_id}/invites"),
        json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, second) = json_post(
        &c,
        "/api/v1/enroll",
        json!({
            "invite_token": invite["token"].as_str().unwrap(),
            "device_name": "laptop",
            "public_key": "pub-key-recovery-2",
            "platform": "windows",
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    assert_eq!(second["virtual_ipv4"], "10.240.0.3", "ipam continues");
    assert_eq!(second["revision_id"], 4, "revision numbering continues");
    let (st, route) = json_post(
        &c,
        &format!("/api/v1/networks/{network_id}/routes"),
        json!({
            "gateway_device_id": second["device_id"],
            "destination_cidr": "192.168.2.0/24",
            "return_path_mode": "controlled_snat",
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    assert_eq!(route["id"], "rt-2", "route id sequence continues");

    c.pool.close().await;
    cleanup_db(&db);
}

/// §17.3 验收 2（§10.3 不假装成功）：停在 `applying` 的修订重启后落
/// `failed` + 中断诊断；`rollback_pending` 保留可重试。
#[tokio::test]
async fn interrupted_applying_lands_failed_after_restart() {
    let db = db_file("interrupted");
    let network_id;
    {
        let c = open_app(&db).await;
        (network_id, _) = net_with_device(&c).await;
        // 模拟崩溃现场：把修订 2 直接改成 applying / 修订 1 改成 rollback_pending
        //（未来数据面落地后这就是真实的中间态落库）。
        sqlx::query(
            "UPDATE config_revisions SET apply_status = 'rollback_pending', \
             error_summary = 'apply boom' WHERE network_id = ? AND revision = 1",
        )
        .bind(&network_id)
        .execute(&c.pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE config_revisions SET apply_status = 'applying' \
             WHERE network_id = ? AND revision = 2",
        )
        .bind(&network_id)
        .execute(&c.pool)
        .await
        .unwrap();
        c.pool.close().await;
    }

    let c = open_app(&db).await;
    // applying → failed，错误点名进程中断（结果不可知，不假装成功）。
    let (st, rev2) = json_get(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions/2"),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(rev2["apply_status"], "failed");
    let summary = rev2["error_summary"].as_str().unwrap();
    assert!(summary.contains("interrupted"), "summary: {summary}");

    // rollback_pending 原样保留：状态与原失败诊断逐字回放（可区分）。
    let (st, rev1) = json_get(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions/1"),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(rev1["apply_status"], "rollback_pending");
    assert_eq!(rev1["error_summary"], "apply boom");

    // 收敛后的 rev2（failed）是当前修订 → 它是回滚入口（§10.4）：无 backend
    // 时回滚停在 rollback_pending（明确未确认，诊断合并）——200 而非 404/409。
    let (st, rolled) = json_post(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions/2/rollback"),
        json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(rolled["apply_status"], "rollback_pending");
    assert!(
        rolled["error_summary"]
            .as_str()
            .unwrap()
            .contains("interrupted"),
        "diagnosis merged: {}",
        rolled["error_summary"]
    );
    // 被 rev2 取代的 rev1 不再是回滚入口（§10.4 交叉破坏防线跨重启成立）。
    let (st, _) = json_post(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions/1/rollback"),
        json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "superseded revision rejected");

    // 收敛幂等：再重启一次——非 applying 状态不受影响（rev2 停在回滚后的
    // rollback_pending，逐字保留；没有「再次收敛」这回事）。
    c.pool.close().await;
    let c = open_app(&db).await;
    let (st, rev2) = json_get(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions/2"),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(rev2["apply_status"], "rollback_pending");
    assert!(
        rev2["error_summary"]
            .as_str()
            .unwrap()
            .contains("interrupted"),
        "diagnosis preserved across second restart"
    );

    c.pool.close().await;
    cleanup_db(&db);
}

/// §17.3 验收 3：路由 id 序列持久化（mesh_meta）——已删路由的 id 重启不复用。
#[tokio::test]
async fn deleted_route_id_is_never_reused_after_restart() {
    let db = db_file("route-seq");
    let (network_id, device_id);
    {
        let c = open_app(&db).await;
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
        let route_id = route["id"].as_str().unwrap().to_string();
        assert_eq!(route_id, "rt-1");
        let (st, _) = call(
            &c,
            "DELETE",
            &format!("/api/v1/networks/{network_id}/routes/{route_id}"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        c.pool.close().await;
    }

    // 重启后新建路由：id 从序列继续（rt-2），不重发 rt-1。
    let c = open_app(&db).await;
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
    assert_eq!(route["id"], "rt-2", "deleted route id must not be reused");

    c.pool.close().await;
    cleanup_db(&db);
}

/// §17.3 验收 4（§12.4 保守判定）：重启后旧证据不虚构 online。
#[tokio::test]
async fn presence_is_conservative_after_restart() {
    let db = db_file("presence");
    let network_id;
    {
        let c = open_app(&db).await;
        (network_id, _) = net_with_device(&c).await;
        // 心跳前先拿 agent token（enroll 只返回一次）——重新走一遍邀请/加入。
        let (st, invite) = json_post(
            &c,
            &format!("/api/v1/networks/{network_id}/invites"),
            json!({}),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        let (st, agent_dev) = json_post(
            &c,
            "/api/v1/enroll",
            json!({
                "invite_token": invite["token"].as_str().unwrap(),
                "device_name": "laptop",
                "public_key": "pub-key-presence",
                "platform": "linux",
            }),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        let agent_token = agent_dev["agent_token"].as_str().unwrap().to_string();

        // 心跳（带握手证据 + 数据面实测证据，§7.5）→ online。
        let res = c
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agent/heartbeat")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {agent_token}"))
                    .body(Body::from(
                        json!({
                            "last_handshake_at": meshlet_server::service::now(),
                            "dataplane": {
                                "tunnel_mtu": 1380,
                                "nat_rules_present": false,
                                "mtu_probe_payload": 1352,
                            },
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let hb: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(hb["online_state"], "online");

        // 实测证据已落库：重启后同源可见（§17.3 逐字段恢复）。
        let (_, before) = json_get(&c, &format!("/api/v1/networks/{network_id}/devices")).await;
        let laptop = before
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["name"] == "laptop")
            .unwrap();
        assert_eq!(laptop["dataplane_evidence"]["tunnel_mtu"], 1380);
        assert_eq!(laptop["dataplane_evidence"]["mtu_probe_payload"], 1352);

        // 模拟「重启后时间流逝」：把证据时间戳改到远古（直接改 DB 等价于
        // 服务停了很久——判定在读取时刻做，不由启动时刻虚构）。
        sqlx::query(
            "UPDATE devices SET last_seen_at = '2026-01-01T00:00:00Z', \
             last_handshake_at = '2026-01-01T00:00:00Z', \
             last_report_at = '2026-01-01T00:00:00Z'",
        )
        .execute(&c.pool)
        .await
        .unwrap();
        c.pool.close().await;
    }

    let c = open_app(&db).await;
    let (_, devices) = json_get(&c, &format!("/api/v1/networks/{network_id}/devices")).await;
    for d in devices.as_array().unwrap() {
        assert_eq!(
            d["online_state"], "offline",
            "stale evidence must not fabricate online: {d}"
        );
        assert_ne!(
            d["presence_source"], "none",
            "source of last evidence shown"
        );
    }
    // 数据面证据随设备行恢复（重启不清零读数；staleness 由 presence 承载）。
    let laptop = devices
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == "laptop")
        .unwrap();
    assert_eq!(laptop["dataplane_evidence"]["tunnel_mtu"], 1380);
    assert_eq!(laptop["dataplane_evidence"]["nat_rules_present"], false);

    c.pool.close().await;
    cleanup_db(&db);
}

/// Agent API 调用（Bearer 凭证，无会话/CSRF）。
async fn agent_call(
    app: &Router,
    method: &str,
    uri: &str,
    agent_token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    builder = builder.header("authorization", format!("Bearer {agent_token}"));
    let body = body.map(|v| Body::from(v.to_string())).unwrap_or_default();
    let req = builder
        .header("content-type", "application/json")
        .body(body)
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Object(Default::default()));
    (status, value)
}

/// §17.3 延伸（2026-10-15 自举注册）：自举码与待审批申请跨重启逐字段重建，
/// 注册期 agent 凭证跨重启继续有效（心跳仍 pending），重启后批准照常走通。
#[tokio::test]
async fn pending_registrations_and_bootstrap_tokens_survive_restart() {
    let db = db_file("selfreg");
    let network_id;
    let agent_token;
    let before_regs;
    let before_tokens;
    {
        let c = open_app(&db).await;
        let (st, net) = json_post(
            &c,
            "/api/v1/networks",
            json!({"name": "selfreg", "overlay_cidr": OVERLAY}),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        network_id = net["id"].as_str().unwrap().to_string();
        let default_segment: (String, String, String) =
            sqlx::query_as("SELECT id, name, cidr FROM segments WHERE network_id = ?")
                .bind(&network_id)
                .fetch_one(&c.pool)
                .await
                .unwrap();
        assert_eq!(
            default_segment,
            (
                format!("seg-{network_id}"),
                "default".into(),
                OVERLAY.into()
            ),
            "new networks persist the canonical default segment"
        );

        // 自举码 → 设备自注册 → Pending 心跳（带数据面证据）。
        let (st, token) = json_post(
            &c,
            &format!("/api/v1/networks/{network_id}/bootstrap-tokens"),
            json!({}),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED, "{token}");
        let (st, reg) = call(
            &c,
            "POST",
            "/api/v1/device-registrations",
            Some(json!({
                "bootstrap_token": token["token"],
                "device_name": "edge-restart",
                "public_key": "pub-selfreg-recovery",
                "platform": "linux",
            })),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED, "{reg}");
        agent_token = reg["agent_token"].as_str().unwrap().to_string();
        let (st, hb) = agent_call(
            &c.app,
            "POST",
            "/api/v1/agent/heartbeat",
            &agent_token,
            Some(json!({
                "last_handshake_at": null,
                "dataplane": { "tunnel_mtu": 1380 },
            })),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{hb}");
        assert_eq!(hb["online_state"], "pending");

        before_regs = json_get(&c, &format!("/api/v1/networks/{network_id}/registrations"))
            .await
            .1;
        before_tokens = json_get(
            &c,
            &format!("/api/v1/networks/{network_id}/bootstrap-tokens"),
        )
        .await
        .1;
        c.pool.close().await;
    }

    // 重启：同一 DB 重建——自举码元数据与待审批申请（含心跳证据）逐字段恢复。
    let c = open_app(&db).await;
    let after_regs = json_get(&c, &format!("/api/v1/networks/{network_id}/registrations"))
        .await
        .1;
    let after_tokens = json_get(
        &c,
        &format!("/api/v1/networks/{network_id}/bootstrap-tokens"),
    )
    .await
    .1;
    assert_eq!(before_regs, after_regs, "registrations survive restart");
    assert_eq!(after_regs[0]["name"], "edge-restart");
    assert_eq!(
        after_regs[0]["dataplane_evidence"]["tunnel_mtu"], 1380,
        "pending-period heartbeat evidence restored"
    );
    assert_eq!(
        before_tokens, after_tokens,
        "bootstrap tokens survive restart"
    );
    assert_eq!(after_tokens[0]["id"], "bt-1");
    assert_eq!(after_tokens[0]["used_count"], 1);

    // 注册期凭证跨重启仍有效：心跳继续 pending；desired 仍 404 pending approval。
    let (st, hb) = agent_call(
        &c.app,
        "POST",
        "/api/v1/agent/heartbeat",
        &agent_token,
        Some(json!({
            "last_handshake_at": null,
            "dataplane": { "tunnel_mtu": 1380 },
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "credential survives restart: {hb}");
    assert_eq!(hb["online_state"], "pending");
    let (st, desired) = agent_call(
        &c.app,
        "GET",
        "/api/v1/agent/device/desired",
        &agent_token,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{desired}");
    assert!(desired["error"]["message"]
        .as_str()
        .unwrap()
        .contains("pending approval"));

    // 重启后批准照常走通：设备入册 + 恰好一个新修订（基线 = 建网初始修订）。
    let (st, revisions_before) = json_get(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions"),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let baseline = revisions_before.as_array().unwrap().len();
    let (st, approved) = json_post(
        &c,
        &format!("/api/v1/networks/{network_id}/devices/dev-reg-1/approve"),
        json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{approved}");
    assert!(approved["virtual_ipv4"].is_string());
    let assigned_segment: String =
        sqlx::query_scalar("SELECT segment_id FROM devices WHERE id = 'dev-reg-1'")
            .fetch_one(&c.pool)
            .await
            .unwrap();
    assert_eq!(assigned_segment, format!("seg-{network_id}"));
    let (_, revisions_after) = json_get(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions"),
    )
    .await;
    assert_eq!(
        revisions_after.as_array().unwrap().len(),
        baseline + 1,
        "approve after restart records exactly one revision"
    );

    c.pool.close().await;
    // The restarted loader reconstructs the approved device using its stored
    // segment assignment, which remains attached to the canonical row.
    let c = open_app(&db).await;
    let reloaded_segment: String =
        sqlx::query_scalar("SELECT segment_id FROM devices WHERE id = 'dev-reg-1'")
            .fetch_one(&c.pool)
            .await
            .unwrap();
    assert_eq!(reloaded_segment, assigned_segment);
    let (st, devices) = json_get(&c, &format!("/api/v1/networks/{network_id}/devices")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(devices.as_array().unwrap().len(), 1);
    c.pool.close().await;
    cleanup_db(&db);
}
