//! 集成测试：MT-002 任务下发与回执（断线补派幂等）。
//!
//! 端到端路径：控制台派发（`POST /api/v1/networks/{id}/tasks`，Cookie+CSRF）
//! → agent 拉待办（Bearer）→ ack → result 回执。断言重点：
//! - 派发成功 201 / 重复派发同 id 幂等 200（不重置状态、不重建）；
//! - 终态任务不再出现在 pending（agent 不会再次拿到 → 不会重跑）；
//! - ack / result 对已越过该步的状态幂等成功（补派重发不报错）；
//! - 越界目标（他网设备 / 未激活设备 / 不存在设备）拒绝。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use meshlet_domain::PresenceThresholds;
use std::sync::Arc;
use tower::ServiceExt; // oneshot

const OVERLAY: &str = "10.240.0.0/16";
type SharedAppState = std::sync::Arc<meshlet_server::auth::AppState>;

#[derive(Clone)]
struct Ctx {
    app: Router,
    cookie: String,
    network_id: String,
}

struct OkBackend;

impl meshlet_domain::ConfigApplyBackend for OkBackend {
    fn apply(&mut self, _revision: &meshlet_domain::ConfigRevision) -> Result<(), String> {
        Ok(())
    }
    fn rollback(&mut self, _revision: &meshlet_domain::ConfigRevision) -> Result<(), String> {
        Ok(())
    }
}

/// 构建 router（数据面默认关：任务通道不依赖数据面开关）。
async fn app() -> (Router, SharedAppState) {
    let pool = meshlet_server::store::connect("sqlite::memory:")
        .await
        .unwrap();
    let mesh = Arc::new(std::sync::Mutex::new(
        meshlet_server::service::MeshState::new(PresenceThresholds::default()),
    ));
    let state = Arc::new(
        meshlet_server::auth::AppState::new(
            mesh,
            meshlet_server::auth::AuthStore::new(pool.clone()),
            meshlet_server::agent::AgentTokenStore::new(pool.clone()),
            meshlet_server::api_token::ApiTokenStore::new(pool),
            false,
        )
        .with_dataplane(meshlet_config::DataPlaneConfig::default())
        .with_apply_backend(Arc::new(|_, _| Box::new(OkBackend))),
    );
    let router = meshlet_server::router(state.clone());
    (router, state)
}

async fn res_body(res: axum::response::Response) -> serde_json::Value {
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn admin(
    app: &Router,
    cookie: &str,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header("cookie", cookie)
                .header("x-requested-with", "XMLHttpRequest")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    (res.status(), res_body(res).await)
}

/// bootstrap → 建网络 → 邀请首台设备入网。返回 (ctx, device_id, agent_token)。
async fn bootstrap(name: &str, public_key: &str) -> (Ctx, String, String, SharedAppState) {
    let (app, state) = app().await;
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "email": "admin@test.local",
                        "password": "bootstrap-password-123",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let cookie = res
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .expect("session cookie")
        .to_string();

    let (st, net) = admin(
        &app,
        &cookie,
        "/api/v1/networks",
        serde_json::json!({ "name": "home", "overlay_cidr": OVERLAY }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{net}");
    let network_id = net["id"].as_str().unwrap().to_string();
    let ctx = Ctx {
        app,
        cookie,
        network_id,
    };
    let (device_id, token) = enroll(&ctx, name, public_key).await;
    (ctx, device_id, token, state)
}

/// 在同一 server 实例上追加第二个网络（跨网络幂等/隔离测试用）。
async fn add_network(ctx: &Ctx) -> Ctx {
    let (st, net) = admin(
        &ctx.app,
        &ctx.cookie,
        "/api/v1/networks",
        serde_json::json!({ "name": "other", "overlay_cidr": "10.241.0.0/16" }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{net}");
    assert_ne!(
        net["id"].as_str().unwrap(),
        &ctx.network_id,
        "distinct network"
    );
    Ctx {
        app: ctx.app.clone(),
        cookie: ctx.cookie.clone(),
        network_id: net["id"].as_str().unwrap().to_string(),
    }
}

/// 邀请 + 入网一台设备（返回 device_id、agent_token）。
async fn enroll(ctx: &Ctx, name: &str, public_key: &str) -> (String, String) {
    let (st, invite) = admin(
        &ctx.app,
        &ctx.cookie,
        &format!("/api/v1/networks/{}/invites", ctx.network_id),
        serde_json::json!({ "max_uses": 5 }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{invite}");
    let invite_token = invite["token"].as_str().unwrap().to_string();
    let res = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/enroll")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "invite_token": invite_token,
                        "device_name": name,
                        "public_key": public_key,
                        "platform": "linux",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let enroll = res_body(res).await;
    (
        enroll["device_id"].as_str().unwrap().to_string(),
        enroll["agent_token"].as_str().unwrap().to_string(),
    )
}

/// 控制台派发任务。
async fn assign(
    ctx: &Ctx,
    target: &str,
    cmd: &str,
    id: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut body = serde_json::json!({
        "target_device_id": target,
        "cmd": cmd,
    });
    if let Some(id) = id {
        body["id"] = serde_json::json!(id);
    }
    admin(
        &ctx.app,
        &ctx.cookie,
        &format!("/api/v1/networks/{}/tasks", ctx.network_id),
        body,
    )
    .await
}

/// agent 拉待办。
async fn pending(app: &Router, token: &str) -> serde_json::Value {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/agent/tasks/pending")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    res_body(res).await
}

/// agent 确认接收（幂等）。
async fn ack(app: &Router, token: &str, id: &str) -> StatusCode {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/agent/tasks/{id}/ack"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    res.status()
}

/// agent 回传结果。
async fn result(
    app: &Router,
    token: &str,
    id: &str,
    exit_code: i32,
) -> (StatusCode, serde_json::Value) {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/agent/tasks/{id}/result"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "exit_code": exit_code, "log_tail": "hello-task" })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    (res.status(), res_body(res).await)
}

/// 控制台列取网络任务。
async fn task_list(ctx: &Ctx) -> (StatusCode, serde_json::Value) {
    let res = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/networks/{}/tasks", ctx.network_id))
                .header("cookie", &ctx.cookie)
                .header("x-requested-with", "XMLHttpRequest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    (res.status(), res_body(res).await)
}

/// 控制台确认完成（`POST .../tasks/{id}/confirm`）。
async fn confirm(ctx: &Ctx, id: &str) -> (StatusCode, serde_json::Value) {
    admin(
        &ctx.app,
        &ctx.cookie,
        &format!("/api/v1/networks/{}/tasks/{id}/confirm", ctx.network_id),
        serde_json::json!({}),
    )
    .await
}

/// 控制台驳回重跑（`POST .../tasks/{id}/retry`）。
async fn retry(ctx: &Ctx, id: &str) -> (StatusCode, serde_json::Value) {
    admin(
        &ctx.app,
        &ctx.cookie,
        &format!("/api/v1/networks/{}/tasks/{id}/retry", ctx.network_id),
        serde_json::json!({}),
    )
    .await
}

/// 把任务 updated_at 拨老（集成测试复用生产回收扫描）。
fn age_task(state: &SharedAppState, id: &str, age_secs: u64) {
    meshlet_server::task::age_task_for_test(&mut state.mesh.lock().unwrap(), id, age_secs);
}

#[tokio::test]
async fn dispatch_lifecycle_and_redispatch_idempotency() {
    let (ctx, device_id, token, _state) = bootstrap("edge-1", "pub-edge-aaaa-0001").await;

    // 1. 派发：201，初始 assigned，自动生成 task-1。
    let (st, task) = assign(&ctx, &device_id, "echo hi", None).await;
    assert_eq!(st, StatusCode::CREATED, "{task}");
    let id = task["id"].as_str().unwrap().to_string();
    assert_eq!(task["state"], "assigned");
    assert_eq!(task["cmd"], "echo hi");

    // 2. agent 拉到待办（assigned 在列）。
    let pend = pending(&ctx.app, &token).await;
    assert_eq!(pend.as_array().unwrap().len(), 1);
    assert_eq!(pend[0]["id"], id);

    // 3. ack → acked，仍 pending（未终态）。
    assert_eq!(ack(&ctx.app, &token, &id).await, StatusCode::OK);
    let pend = pending(&ctx.app, &token).await;
    assert_eq!(pend.as_array().unwrap().len(), 1);

    // 4. result → done（exit_code 落库），pending 清空（终态不再下发）。
    let (st, done) = result(&ctx.app, &token, &id, 0).await;
    assert_eq!(st, StatusCode::OK, "{done}");
    assert_eq!(done["state"], "done");
    assert_eq!(done["exit_code"], 0);
    assert_eq!(done["log_tail"], "hello-task");
    assert_eq!(pending(&ctx.app, &token).await.as_array().unwrap().len(), 0);

    // 5. 断线补派同 id：200（幂等），状态不重置、结果保留。
    let (st, re) = assign(&ctx, &device_id, "echo hi", Some(&id)).await;
    assert_eq!(st, StatusCode::OK, "{re}");
    assert_eq!(re["id"], id);
    assert_eq!(
        re["state"], "done",
        "redispatch must not reset terminal state"
    );
    assert_eq!(re["exit_code"], 0);

    // 6. 补派后 agent 再拉：仍为空（不会拿到终态任务 → 不会重跑）。
    assert_eq!(pending(&ctx.app, &token).await.as_array().unwrap().len(), 0);

    // 7. 重复 ack / 重复回执：幂等 200，状态仍是 done。
    assert_eq!(ack(&ctx.app, &token, &id).await, StatusCode::OK);
    let (st, again) = result(&ctx.app, &token, &id, 0).await;
    assert_eq!(st, StatusCode::OK, "{again}");
    assert_eq!(again["state"], "done");
    assert_eq!(again["exit_code"], 0);
}

#[tokio::test]
async fn dispatch_rejects_unknown_or_inactive_target() {
    let (ctx, device_id, _token, _state) = bootstrap("edge-1", "pub-edge-aaaa-0001").await;

    // 不存在的设备 → 404。
    let (st, body) = assign(&ctx, "no-such-device", "echo hi", None).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{body}");

    // 第二台在网激活设备（供 agent 端点 404 检查用其未撤销凭证）。
    let (edge2_id, token2) = enroll(&ctx, "edge-2", "pub-edge-aaaa-0002").await;
    assert_ne!(edge2_id, device_id);

    // 已撤销设备：注册表保留但未激活 → 409（与 agent token 失效同步）。
    let (st, _) = admin(
        &ctx.app,
        &ctx.cookie,
        &format!(
            "/api/v1/networks/{}/devices/{device_id}/revoke",
            ctx.network_id
        ),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::ACCEPTED);
    let (st, body) = assign(&ctx, &device_id, "echo hi", None).await;
    assert_eq!(st, StatusCode::CONFLICT, "{body}");

    // 网内待审批设备（bootstrap-token 注册，未激活）→ 409。
    let (st, bt) = admin(
        &ctx.app,
        &ctx.cookie,
        &format!("/api/v1/networks/{}/bootstrap-tokens", ctx.network_id),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{bt}");
    let res = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/device-registrations")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "bootstrap_token": bt["token"].as_str().unwrap(),
                        "device_name": "edge-pending",
                        "public_key": "pub-edge-pending",
                        "platform": "linux",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let pending_device = res_body(res).await;
    let pending_id = pending_device["device_id"].as_str().unwrap().to_string();
    // 待审批设备尚未进入数据面注册表 → 404（批准前不可派发）。
    let (st, body) = assign(&ctx, &pending_id, "echo hi", None).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{body}");

    // 凭证有效但任务不存在 → agent 端点 404。
    let res = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/tasks/task-999/ack")
                .header("authorization", format!("Bearer {token2}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

/// MT-003 用户确认交互：确认是用户侧动作（agent 端点无确认能力），
/// 确认仅 done 可做且幂等；驳回重跑置 rejected_at 并派发新一代
/// `{root}-r{n}`（新 id 才能触发 agent 重跑），运行中不可驳回。
#[tokio::test]
async fn user_confirm_and_retry_lifecycle() {
    let (ctx, device_id, token, _state) = bootstrap("edge-1", "pub-edge-aaaa-0001").await;

    // 1. 派发 → agent 全程 → done。
    let (st, task) = assign(&ctx, &device_id, "echo hi", None).await;
    assert_eq!(st, StatusCode::CREATED, "{task}");
    let id = task["id"].as_str().unwrap().to_string();
    assert_eq!(ack(&ctx.app, &token, &id).await, StatusCode::OK);
    let (st, done) = result(&ctx.app, &token, &id, 0).await;
    assert_eq!(st, StatusCode::OK, "{done}");
    assert_eq!(done["state"], "done");

    // 2. 运行中不可确认：新派任务（assigned）→ confirm 409。
    let (st, running) = assign(&ctx, &device_id, "echo again", None).await;
    assert_eq!(st, StatusCode::CREATED, "{running}");
    let running_id = running["id"].as_str().unwrap().to_string();
    let (st, body) = confirm(&ctx, &running_id).await;
    assert_eq!(st, StatusCode::CONFLICT, "{body}");

    // 3. 确认完成：200，confirmed_at 落，状态仍 done（确认不改执行状态）。
    let (st, confirmed) = confirm(&ctx, &id).await;
    assert_eq!(st, StatusCode::OK, "{confirmed}");
    assert_eq!(confirmed["state"], "done");
    assert!(confirmed["confirmed_at"].as_str().is_some());
    assert!(confirmed["rejected_at"].is_null());

    // 4. 重复确认幂等：200，confirmed_at 不变。
    let (st, again) = confirm(&ctx, &id).await;
    assert_eq!(st, StatusCode::OK, "{again}");
    assert_eq!(again["confirmed_at"], confirmed["confirmed_at"]);

    // 5. 驳回重跑：201 新代 `{root}-r1`，原任务置 rejected_at，
    //    新任务 assigned（agent 会重新拉到 → 重跑）。
    let (st, rerun) = retry(&ctx, &id).await;
    assert_eq!(st, StatusCode::CREATED, "{rerun}");
    let r1 = rerun["id"].as_str().unwrap().to_string();
    assert_eq!(r1, format!("{id}-r1"));
    assert_eq!(rerun["state"], "assigned");
    assert_eq!(rerun["parent_task_id"], id);
    assert_eq!(rerun["cmd"], "echo hi");
    let (st, rejected) = confirm(&ctx, &id).await; // 原任务仍未 done 确认态变化不影响
    assert_eq!(st, StatusCode::OK, "{rejected}");
    assert!(rejected["rejected_at"].as_str().is_some());

    // 5b. 重入防护：r1 在途（assigned）时再驳回原任务 → 409（防双击重复下发）。
    let (st, dup) = retry(&ctx, &id).await;
    assert_eq!(st, StatusCode::CONFLICT, "{dup}");

    // 6. agent 拉到新代（重跑真实下发，与未确认的运行中任务同列）；
    //    完成后可再次驳回 → `-r2`。
    let pend = pending(&ctx.app, &token).await;
    let pend_ids: Vec<&str> = pend
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["id"].as_str().unwrap())
        .collect();
    assert!(pend_ids.contains(&r1.as_str()), "{pend}");
    assert!(pend_ids.contains(&running_id.as_str()), "{pend}");
    assert_eq!(ack(&ctx.app, &token, &r1).await, StatusCode::OK);
    let (st, r1done) = result(&ctx.app, &token, &r1, 0).await;
    assert_eq!(st, StatusCode::OK, "{r1done}");
    let (st, rerun2) = retry(&ctx, &r1).await;
    assert_eq!(st, StatusCode::CREATED, "{rerun2}");
    assert_eq!(rerun2["id"], format!("{id}-r2"));
    assert_eq!(rerun2["parent_task_id"], r1);

    // 7. 列取：4 条（原任务 + 运行中 + r1 + r2），含确认/驳回/父链字段。
    let (st, list) = task_list(&ctx).await;
    assert_eq!(st, StatusCode::OK, "{list}");
    let arr = list.as_array().unwrap();
    assert_eq!(arr.len(), 4);
    let orig = arr.iter().find(|t| t["id"] == id).expect("orig task");
    assert!(orig["confirmed_at"].as_str().is_some());
    assert!(orig["rejected_at"].as_str().is_some());
    let r2 = arr
        .iter()
        .find(|t| t["id"] == format!("{id}-r2"))
        .expect("r2 task");
    assert_eq!(r2["parent_task_id"], r1);
    assert!(r2["confirmed_at"].is_null());
    assert!(r2["rejected_at"].is_null());
}

/// 列取需认证（未登录 401）。
#[tokio::test]
async fn task_list_requires_authentication() {
    let (ctx, device_id, _token, _state) = bootstrap("edge-1", "pub-edge-aaaa-0001").await;
    let (st, task) = assign(&ctx, &device_id, "echo hi", None).await;
    assert_eq!(st, StatusCode::CREATED, "{task}");
    let res = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/networks/{}/tasks", ctx.network_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn agent_endpoints_require_valid_token() {
    let (ctx, _, _, _) = bootstrap("edge-1", "pub-edge-aaaa-0001").await;

    // 无凭证 / 伪造凭证 → 401（agent API 认证边界）。
    let res = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/agent/tasks/pending")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let res = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/agent/tasks/pending")
                .header("authorization", "Bearer forged-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

/// MT-005 标签路由（端到端）：操作员给设备打标 → 按标签自动选点派单 →
/// 显式目标与标签不符拒绝 → 无匹配设备拒绝。
#[tokio::test]
async fn label_routed_dispatch_and_labels_endpoint() {
    let (ctx, worker_id, worker_token, _state) = bootstrap("worker", "pub-edge-aaaa-0001").await;
    let (builder_id, builder_token) = enroll(&ctx, "builder", "pub-edge-aaaa-0002").await;

    // 操作员打标：worker → role=builder；builder → 无标。
    let (st, body) = admin(
        &ctx.app,
        &ctx.cookie,
        &format!(
            "/api/v1/networks/{}/devices/{worker_id}/labels",
            ctx.network_id
        ),
        serde_json::json!({ "labels": { "role": "builder", "cap": "gpu" } }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["labels"]["role"], "builder");
    assert_eq!(body["labels"]["cap"], "gpu");

    // 按标签自动选点（无 target）：命中唯一 role=builder 的 worker。
    let (st, task) = assign_labeled(&ctx, None, "echo build", None, builder_lbl()).await;
    assert_eq!(st, StatusCode::CREATED, "{task}");
    assert_eq!(task["target_device_id"], worker_id);

    // 显式指定 builder（无标）却要求 role=builder → 409。
    let (st, body) = assign_labeled(
        &ctx,
        Some(&builder_id),
        "echo build",
        Some("task-mismatch"),
        builder_lbl(),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "{body}");

    // 无匹配设备（要求 role=worker，没人打）→ 409。
    let (st, body) = assign_labeled(
        &ctx,
        None,
        "echo build",
        Some("task-nomatch"),
        serde_json::json!({ "role": "worker" }),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "{body}");

    // worker 的 agent 能拉到自动选点的任务。
    let pend = pending(&ctx.app, &worker_token).await;
    let ids: Vec<&str> = pend
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["id"].as_str())
        .collect();
    assert!(ids.contains(&"task-1"), "{pend:?}");

    // builder（无标）的 agent 拉不到任何任务。
    let pend_builder = pending(&ctx.app, &builder_token).await;
    assert!(
        pend_builder.as_array().unwrap().is_empty(),
        "{pend_builder:?}"
    );
}

fn builder_lbl() -> serde_json::Value {
    serde_json::json!({ "role": "builder" })
}

/// 带标签要求的派单：`target` None = 省略 target_device_id（自动选点）。
async fn assign_labeled(
    ctx: &Ctx,
    target: Option<&str>,
    cmd: &str,
    id: Option<&str>,
    required_labels: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let mut body = serde_json::json!({
        "cmd": cmd,
        "required_labels": required_labels,
    });
    if let Some(t) = target {
        body["target_device_id"] = serde_json::json!(t);
    }
    if let Some(i) = id {
        body["id"] = serde_json::json!(i);
    }
    admin(
        &ctx.app,
        &ctx.cookie,
        &format!("/api/v1/networks/{}/tasks", ctx.network_id),
        body,
    )
    .await
}

/// 跨网络幂等 assign：网络 B 的 console 用户 POST /networks/B/tasks 传
/// 网络 A 已有 id → 404（不泄漏 A 任务），与 confirm/retry 一致。
#[tokio::test]
async fn assign_foreign_network_id_is_not_found() {
    let (ctx, device_id, _token, _state) = bootstrap("edge-1", "pub-edge-aaaa-0001").await;
    let other = add_network(&ctx).await;

    // 网络 A 建任务。
    let (st, task) = assign(&ctx, &device_id, "echo hi", Some("task-cross")).await;
    assert_eq!(st, StatusCode::CREATED, "{task}");

    // 网络 B 用同 id：404，不返回 A 的任务（防 cmd/log 泄漏）。
    let (st, body) = assign(&other, &device_id, "echo hi", Some("task-cross")).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"]["code"], "not_found");
    assert_eq!(body["error"]["message"], "task task-cross not found");
}

/// 自动 id 与显式 id 碰撞：用户显式传过 `id="task-1"` 后，自动序列
/// 不得静默覆盖——生成时跳过已占用的 `task-{seq}` 并递增。
#[tokio::test]
async fn auto_id_skips_collision_with_explicit_id() {
    let (ctx, device_id, _token, _state) = bootstrap("edge-1", "pub-edge-aaaa-0001").await;

    // 用户显式占掉 task-1。
    let (st, explicit) = assign(&ctx, &device_id, "echo explicit", Some("task-1")).await;
    assert_eq!(st, StatusCode::CREATED, "{explicit}");
    assert_eq!(explicit["cmd"], "echo explicit");

    // 下一次自动派发：不得覆盖 task-1 → 取 task-2，原任务保留。
    let (st, auto) = assign(&ctx, &device_id, "echo auto", None).await;
    assert_eq!(st, StatusCode::CREATED, "{auto}");
    assert_eq!(auto["id"], "task-2");
    assert_eq!(auto["cmd"], "echo auto");

    let (st, list) = task_list(&ctx).await;
    assert_eq!(st, StatusCode::OK, "{list}");
    let arr = list.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    let orig = arr
        .iter()
        .find(|t| t["id"] == "task-1")
        .expect("explicit task preserved");
    assert_eq!(orig["cmd"], "echo explicit");
    assert_eq!(orig["state"], "assigned");
}

/// 深链（第二代 r2）重派预算：reclaim 必须沿 parent 链回到根，否则
/// `task-1-r2` 的 root 误判为 `task-1-r1` 而数不到兄弟 `task-1-r1`，
/// 预算恒 0 → 无限重派。回收 `-r2`（已产生 r1、r2 两代，limit=2）应
/// 不再派发。
#[tokio::test]
async fn deep_chain_redispatch_respects_budget() {
    let (ctx, device_id, _token, state) = bootstrap("edge-1", "pub-edge-aaaa-0001").await;

    // 首代 → r1 → r2（limit=2）。
    let (st, orig) = assign(&ctx, &device_id, "echo hi", Some("task-deep")).await;
    assert_eq!(st, StatusCode::CREATED, "{orig}");
    // 首代须终态才可驳回。
    {
        let mut guard = state.mesh.lock().unwrap();
        meshlet_server::task::complete_task_for_test(&mut guard, "task-deep", true);
    }
    let r1: serde_json::Value;
    {
        let (st, task) = retry(&ctx, "task-deep").await;
        assert_eq!(st, StatusCode::CREATED, "{task}");
        r1 = task;
    }
    // r1 完成后再驳回 r1 → r2。
    let r1_id = r1["id"].as_str().unwrap().to_string();
    {
        let mut guard = state.mesh.lock().unwrap();
        meshlet_server::task::complete_task_for_test(&mut guard, &r1_id, true);
    }
    let (st, task) = retry(&ctx, &r1_id).await;
    assert_eq!(st, StatusCode::CREATED, "{task}");
    let r2 = task;
    assert_eq!(r2["id"], "task-deep-r2");

    // 把 r2 拨老（超窗）→ 回收扫描。r2 已存在且 r1 也在（root=task-deep），
    // next_retry_seq(task-deep) = 3，used = 2 ≥ limit=2 → 不再派发 r3。
    age_task(&state, "task-deep-r2", 400);
    meshlet_server::task::task_recovery_for_test(state.clone()).await;

    let guard = state.mesh.lock().unwrap();
    let rec =
        meshlet_server::task::task_for_test(&guard, "task-deep-r2").expect("r2 still present");
    assert_eq!(rec.task.state, meshlet_domain::TaskState::Failed);
    assert_eq!(
        rec.result.as_ref().unwrap().exit_code,
        124,
        "reclaimed synthetic timeout exit"
    );
    assert!(
        meshlet_server::task::task_for_test(&guard, "task-deep-r3").is_none(),
        "budget exhausted: must not redispatch r3"
    );
}

/// 回收与活 agent 竞争：server 先回收（failed+exit124），agent 随后回执
/// 旧结果——`record_result` 对终态任务不得覆盖 result/state。
#[tokio::test]
async fn stale_result_does_not_overwrite_terminal_state() {
    let (ctx, device_id, token, state) = bootstrap("edge-1", "pub-edge-aaaa-0001").await;

    // 派发任务，agent 拉到并 ack（ack 后 server 才可回收）。
    let (st, task) = assign(&ctx, &device_id, "echo hi", None).await;
    assert_eq!(st, StatusCode::CREATED, "{task}");
    let id = task["id"].as_str().unwrap().to_string();
    assert_eq!(ack(&ctx.app, &token, &id).await, StatusCode::OK);

    // 拨老触发回收：failed + 合成超时结果。
    age_task(&state, &id, 400);
    meshlet_server::task::task_recovery_for_test(state.clone()).await;

    {
        let guard = state.mesh.lock().unwrap();
        let rec = meshlet_server::task::task_for_test(&guard, &id).expect("reclaimed");
        assert_eq!(rec.task.state, meshlet_domain::TaskState::Failed);
        assert_eq!(rec.result.as_ref().unwrap().exit_code, 124);
    }

    // agent 旧回执（真实 exit 0）：200，但终态不被覆盖（仍 failed+124）。
    let (st, body) = result(&ctx.app, &token, &id, 0).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "failed");
    assert_eq!(
        body["exit_code"], 124,
        "terminal result must not be overwritten"
    );
}
