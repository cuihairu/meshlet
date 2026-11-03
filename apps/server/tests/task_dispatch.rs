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
async fn app() -> Router {
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
    meshlet_server::router(state)
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
async fn bootstrap(name: &str, public_key: &str) -> (Ctx, String, String) {
    let app = app().await;
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
    (ctx, device_id, token)
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

#[tokio::test]
async fn dispatch_lifecycle_and_redispatch_idempotency() {
    let (ctx, device_id, token) = bootstrap("edge-1", "pub-edge-aaaa-0001").await;

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
    let (ctx, device_id, _token) = bootstrap("edge-1", "pub-edge-aaaa-0001").await;

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
    let (ctx, device_id, token) = bootstrap("edge-1", "pub-edge-aaaa-0001").await;

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
    let (ctx, device_id, _token) = bootstrap("edge-1", "pub-edge-aaaa-0001").await;
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
    let (ctx, _, _) = bootstrap("edge-1", "pub-edge-aaaa-0001").await;

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
