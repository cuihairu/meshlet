//! Integration test: MT-002 task dispatch and receipts (idempotent redispatch after disconnect).
//!
//! End-to-end path: console dispatch (`POST /api/v1/networks/{id}/tasks`, cookie + CSRF)
//! -> the agent pulls pending work (Bearer) -> ack -> result receipt. Assertion focus:
//! - a successful dispatch returns 201 / redispatching the same id is idempotent with 200 (state is not reset, nothing is rebuilt);
//! - tasks in a terminal state no longer appear in pending (the agent never receives them again -> no rerun);
//! - ack / result succeed idempotently for states that already passed that step (redispatch resends do not error);
//! - out-of-bounds targets (another network's device / an inactive device / a nonexistent device) are rejected.

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

/// Build the router (the dataplane is off by default: the task channel does not depend on the dataplane switch).
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

/// bootstrap -> create network -> enroll the first device. Returns (ctx, device_id, agent_token).
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

/// Add a second network on the same server instance (used by cross-network idempotency/isolation tests).
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

/// Invite and enroll one device (returns device_id and agent_token).
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

/// Dispatch a task from the console.
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

/// The agent pulls pending tasks.
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

/// The agent acknowledges receipt (idempotent).
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

/// The agent reports its result.
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

/// The console lists the network's tasks.
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

/// The console confirms completion (`POST .../tasks/{id}/confirm`).
async fn confirm(ctx: &Ctx, id: &str) -> (StatusCode, serde_json::Value) {
    admin(
        &ctx.app,
        &ctx.cookie,
        &format!("/api/v1/networks/{}/tasks/{id}/confirm", ctx.network_id),
        serde_json::json!({}),
    )
    .await
}

/// The console rejects and reruns (`POST .../tasks/{id}/retry`).
async fn retry(ctx: &Ctx, id: &str) -> (StatusCode, serde_json::Value) {
    admin(
        &ctx.app,
        &ctx.cookie,
        &format!("/api/v1/networks/{}/tasks/{id}/retry", ctx.network_id),
        serde_json::json!({}),
    )
    .await
}

/// Age a task's updated_at (the integration test reuses the production recovery scan).
fn age_task(state: &SharedAppState, id: &str, age_secs: u64) {
    meshlet_server::task::age_task_for_test(&mut state.mesh.lock().unwrap(), id, age_secs);
}

#[tokio::test]
async fn dispatch_lifecycle_and_redispatch_idempotency() {
    let (ctx, device_id, token, _state) = bootstrap("edge-1", "pub-edge-aaaa-0001").await;

    // 1. Dispatch: 201, initially assigned, task-1 is generated automatically.
    let (st, task) = assign(&ctx, &device_id, "echo hi", None).await;
    assert_eq!(st, StatusCode::CREATED, "{task}");
    let id = task["id"].as_str().unwrap().to_string();
    assert_eq!(task["state"], "assigned");
    assert_eq!(task["cmd"], "echo hi");

    // 2. The agent pulls pending tasks (assigned is listed).
    let pend = pending(&ctx.app, &token).await;
    assert_eq!(pend.as_array().unwrap().len(), 1);
    assert_eq!(pend[0]["id"], id);

    // 3. ack -> acked, still pending (not terminal).
    assert_eq!(ack(&ctx.app, &token, &id).await, StatusCode::OK);
    let pend = pending(&ctx.app, &token).await;
    assert_eq!(pend.as_array().unwrap().len(), 1);

    // 4. result -> done (exit_code persisted), pending is cleared (terminal tasks are no longer dispatched).
    let (st, done) = result(&ctx.app, &token, &id, 0).await;
    assert_eq!(st, StatusCode::OK, "{done}");
    assert_eq!(done["state"], "done");
    assert_eq!(done["exit_code"], 0);
    assert_eq!(done["log_tail"], "hello-task");
    assert_eq!(pending(&ctx.app, &token).await.as_array().unwrap().len(), 0);

    // 5. Redispatch after a disconnect with the same id: 200 (idempotent), state not reset, result preserved.
    let (st, re) = assign(&ctx, &device_id, "echo hi", Some(&id)).await;
    assert_eq!(st, StatusCode::OK, "{re}");
    assert_eq!(re["id"], id);
    assert_eq!(
        re["state"], "done",
        "redispatch must not reset terminal state"
    );
    assert_eq!(re["exit_code"], 0);

    // 6. After redispatch the agent pulls again: still empty (it never receives a terminal task -> no rerun).
    assert_eq!(pending(&ctx.app, &token).await.as_array().unwrap().len(), 0);

    // 7. Duplicate ack / duplicate receipt: idempotent 200, state still done.
    assert_eq!(ack(&ctx.app, &token, &id).await, StatusCode::OK);
    let (st, again) = result(&ctx.app, &token, &id, 0).await;
    assert_eq!(st, StatusCode::OK, "{again}");
    assert_eq!(again["state"], "done");
    assert_eq!(again["exit_code"], 0);
}

#[tokio::test]
async fn dispatch_rejects_unknown_or_inactive_target() {
    let (ctx, device_id, _token, _state) = bootstrap("edge-1", "pub-edge-aaaa-0001").await;

    // A nonexistent device -> 404.
    let (st, body) = assign(&ctx, "no-such-device", "echo hi", None).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{body}");

    // A second enrolled, active device (its unrevoked credential feeds the agent endpoint 404 check).
    let (edge2_id, token2) = enroll(&ctx, "edge-2", "pub-edge-aaaa-0002").await;
    assert_ne!(edge2_id, device_id);

    // A revoked device: kept in the registry but inactive -> 409 (in step with agent token invalidation).
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

    // An in-network pending-approval device (registered via bootstrap token, not activated) -> 409.
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
    // The pending device has not entered the dataplane registry yet -> 404 (nothing can be dispatched before approval).
    let (st, body) = assign(&ctx, &pending_id, "echo hi", None).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{body}");

    // A valid credential but no such task -> 404 on the agent endpoint.
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

/// MT-003 user confirmation flow: confirming is a user-side action (agent endpoints have no confirm capability),
/// confirmation is only possible while done and is idempotent; rejecting for a rerun sets rejected_at and dispatches a
/// new generation `{root}-r{n}` (only a new id triggers an agent rerun), and a running task cannot be rejected.
#[tokio::test]
async fn user_confirm_and_retry_lifecycle() {
    let (ctx, device_id, token, _state) = bootstrap("edge-1", "pub-edge-aaaa-0001").await;

    // 1. Dispatch -> the full agent flow -> done.
    let (st, task) = assign(&ctx, &device_id, "echo hi", None).await;
    assert_eq!(st, StatusCode::CREATED, "{task}");
    let id = task["id"].as_str().unwrap().to_string();
    assert_eq!(ack(&ctx.app, &token, &id).await, StatusCode::OK);
    let (st, done) = result(&ctx.app, &token, &id, 0).await;
    assert_eq!(st, StatusCode::OK, "{done}");
    assert_eq!(done["state"], "done");

    // 2. A running task cannot be confirmed: a freshly dispatched task (assigned) -> confirm 409.
    let (st, running) = assign(&ctx, &device_id, "echo again", None).await;
    assert_eq!(st, StatusCode::CREATED, "{running}");
    let running_id = running["id"].as_str().unwrap().to_string();
    let (st, body) = confirm(&ctx, &running_id).await;
    assert_eq!(st, StatusCode::CONFLICT, "{body}");

    // 3. Confirm completion: 200, confirmed_at is set, state stays done (confirmation does not change execution state).
    let (st, confirmed) = confirm(&ctx, &id).await;
    assert_eq!(st, StatusCode::OK, "{confirmed}");
    assert_eq!(confirmed["state"], "done");
    assert!(confirmed["confirmed_at"].as_str().is_some());
    assert!(confirmed["rejected_at"].is_null());

    // 4. Duplicate confirmation is idempotent: 200, confirmed_at unchanged.
    let (st, again) = confirm(&ctx, &id).await;
    assert_eq!(st, StatusCode::OK, "{again}");
    assert_eq!(again["confirmed_at"], confirmed["confirmed_at"]);

    // 5. Reject for a rerun: 201 with a new generation `{root}-r1`, the original task gets rejected_at,
    //    and the new task is assigned (the agent will pull it again -> rerun).
    let (st, rerun) = retry(&ctx, &id).await;
    assert_eq!(st, StatusCode::CREATED, "{rerun}");
    let r1 = rerun["id"].as_str().unwrap().to_string();
    assert_eq!(r1, format!("{id}-r1"));
    assert_eq!(rerun["state"], "assigned");
    assert_eq!(rerun["parent_task_id"], id);
    assert_eq!(rerun["cmd"], "echo hi");
    let (st, rejected) = confirm(&ctx, &id).await; // the original task is still not done; the confirmation-state change does not affect it
    assert_eq!(st, StatusCode::OK, "{rejected}");
    assert!(rejected["rejected_at"].as_str().is_some());

    // 5b. Re-entry guard: rejecting the original task again while r1 is in flight (assigned) -> 409 (prevents double-click duplicate dispatch).
    let (st, dup) = retry(&ctx, &id).await;
    assert_eq!(st, StatusCode::CONFLICT, "{dup}");

    // 6. The agent pulls the new generation (the rerun is genuinely dispatched, listed alongside the unconfirmed running task);
    //    once it completes, reject again -> `-r2`.
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

    // 7. Listing: 4 entries (original + running + r1 + r2), with confirmation/rejection/parent-chain fields.
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

/// Listing requires auth (401 when not logged in).
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

    // No credential / a forged credential -> 401 (agent API auth boundary).
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

/// MT-005 label routing (end to end): the operator tags a device -> label-based automatic target selection dispatches ->
/// an explicit target that conflicts with the labels is rejected -> no matching device is rejected.
#[tokio::test]
async fn label_routed_dispatch_and_labels_endpoint() {
    let (ctx, worker_id, worker_token, _state) = bootstrap("worker", "pub-edge-aaaa-0001").await;
    let (builder_id, builder_token) = enroll(&ctx, "builder", "pub-edge-aaaa-0002").await;

    // Operator tagging: worker -> role=builder; builder -> no labels.
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

    // Automatic target selection by label (no target given): picks the only worker with role=builder.
    let (st, task) = assign_labeled(&ctx, None, "echo build", None, builder_lbl()).await;
    assert_eq!(st, StatusCode::CREATED, "{task}");
    assert_eq!(task["target_device_id"], worker_id);

    // Explicitly naming builder (unlabeled) while requiring role=builder -> 409.
    let (st, body) = assign_labeled(
        &ctx,
        Some(&builder_id),
        "echo build",
        Some("task-mismatch"),
        builder_lbl(),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "{body}");

    // No matching device (requires role=worker, which nobody carries) -> 409.
    let (st, body) = assign_labeled(
        &ctx,
        None,
        "echo build",
        Some("task-nomatch"),
        serde_json::json!({ "role": "worker" }),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "{body}");

    // The worker's agent can pull the label-selected task.
    let pend = pending(&ctx.app, &worker_token).await;
    let ids: Vec<&str> = pend
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["id"].as_str())
        .collect();
    assert!(ids.contains(&"task-1"), "{pend:?}");

    // The builder's agent (unlabeled) pulls no tasks at all.
    let pend_builder = pending(&ctx.app, &builder_token).await;
    assert!(
        pend_builder.as_array().unwrap().is_empty(),
        "{pend_builder:?}"
    );
}

fn builder_lbl() -> serde_json::Value {
    serde_json::json!({ "role": "builder" })
}

/// Dispatch with label requirements: `target` None means target_device_id is omitted (automatic selection).
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

/// Cross-network idempotent assign: a console user of network B posts /networks/B/tasks with
/// an id already existing in network A -> 404 (no leakage of A's task), consistent with confirm/retry.
#[tokio::test]
async fn assign_foreign_network_id_is_not_found() {
    let (ctx, device_id, _token, _state) = bootstrap("edge-1", "pub-edge-aaaa-0001").await;
    let other = add_network(&ctx).await;

    // Create the task in network A.
    let (st, task) = assign(&ctx, &device_id, "echo hi", Some("task-cross")).await;
    assert_eq!(st, StatusCode::CREATED, "{task}");

    // Network B uses the same id: 404, and A's task is not returned (guards against cmd/log leakage).
    let (st, body) = assign(&other, &device_id, "echo hi", Some("task-cross")).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"]["code"], "not_found");
    assert_eq!(body["error"]["message"], "task task-cross not found");
}

/// Collision between auto ids and explicit ids: once the user has supplied `id="task-1"` explicitly, the automatic
/// sequence must not silently overwrite it - generation skips an occupied `task-{seq}` and increments.
#[tokio::test]
async fn auto_id_skips_collision_with_explicit_id() {
    let (ctx, device_id, _token, _state) = bootstrap("edge-1", "pub-edge-aaaa-0001").await;

    // The user takes task-1 explicitly.
    let (st, explicit) = assign(&ctx, &device_id, "echo explicit", Some("task-1")).await;
    assert_eq!(st, StatusCode::CREATED, "{explicit}");
    assert_eq!(explicit["cmd"], "echo explicit");

    // The next automatic dispatch: task-1 must not be overwritten -> task-2 is taken, the original task survives.
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

/// Redispatch budget for a deep chain (second generation r2): reclaim must walk the parent chain back to the root,
/// otherwise the root of `task-1-r2` is misread as `task-1-r1` and its sibling `task-1-r1` is never counted,
/// leaving the budget at 0 forever -> unbounded redispatch. Reclaiming `-r2` (with r1 and r2 already generated, limit=2)
/// must not dispatch anything more.
#[tokio::test]
async fn deep_chain_redispatch_respects_budget() {
    let (ctx, device_id, _token, state) = bootstrap("edge-1", "pub-edge-aaaa-0001").await;

    // First generation -> r1 -> r2 (limit=2).
    let (st, orig) = assign(&ctx, &device_id, "echo hi", Some("task-deep")).await;
    assert_eq!(st, StatusCode::CREATED, "{orig}");
    // The first generation must be terminal before it can be rejected.
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
    // Once r1 completes, reject r1 -> r2.
    let r1_id = r1["id"].as_str().unwrap().to_string();
    {
        let mut guard = state.mesh.lock().unwrap();
        meshlet_server::task::complete_task_for_test(&mut guard, &r1_id, true);
    }
    let (st, task) = retry(&ctx, &r1_id).await;
    assert_eq!(st, StatusCode::CREATED, "{task}");
    let r2 = task;
    assert_eq!(r2["id"], "task-deep-r2");

    // Age r2 past the window -> the recovery scan runs. r2 already exists and so does r1 (root=task-deep),
    // next_retry_seq(task-deep) = 3, used = 2 >= limit=2 -> r3 must not be dispatched.
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

/// Reclamation racing a live agent: the server reclaims first (failed + exit 124), then the agent reports its
/// stale result - `record_result` must not overwrite result/state on a task already in a terminal state.
#[tokio::test]
async fn stale_result_does_not_overwrite_terminal_state() {
    let (ctx, device_id, token, state) = bootstrap("edge-1", "pub-edge-aaaa-0001").await;

    // Dispatch the task; the agent pulls and acks it (the server may only reclaim after the ack).
    let (st, task) = assign(&ctx, &device_id, "echo hi", None).await;
    assert_eq!(st, StatusCode::CREATED, "{task}");
    let id = task["id"].as_str().unwrap().to_string();
    assert_eq!(ack(&ctx.app, &token, &id).await, StatusCode::OK);

    // Age it to trigger reclamation: failed + a synthetic timeout result.
    age_task(&state, &id, 400);
    meshlet_server::task::task_recovery_for_test(state.clone()).await;

    {
        let guard = state.mesh.lock().unwrap();
        let rec = meshlet_server::task::task_for_test(&guard, &id).expect("reclaimed");
        assert_eq!(rec.task.state, meshlet_domain::TaskState::Failed);
        assert_eq!(rec.result.as_ref().unwrap().exit_code, 124);
    }

    // The agent's stale receipt (a real exit 0): 200, but the terminal state is not overwritten (still failed + 124).
    let (st, body) = result(&ctx.app, &token, &id, 0).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "failed");
    assert_eq!(
        body["exit_code"], 124,
        "terminal result must not be overwritten"
    );
}
