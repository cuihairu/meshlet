//! Integration tests: the config state machine ([archive §10](../docs/review/chatgpt-2026-10-13.md),
//! [ADR-009](../docs/decisions/adr-009-config-revision-rollback.md)).
//!
//! Acceptance rule: **DB write ≠ shown as effective** — a desired-config change only creates a `Pending` revision;
//! only a successful backend apply marks it `Applied`; **failures are visible** (`failed` +
//! `error_summary`); **states are distinguishable** (pending / failed / rollback_pending ...).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use tower::ServiceExt; // oneshot

use meshlet_domain::{ConfigApplyBackend, ConfigRevision};
use meshlet_server::revision;
use std::time::Duration;

const OVERLAY: &str = "10.240.0.0/16";

/// Test context: router + management session Cookie (bootstrap the first administrator on an empty DB).
#[derive(Clone)]
struct Ctx {
    app: Router,
    cookie: String,
}

async fn ctx() -> Ctx {
    ctx_with_backend(revision::unconfigured_backend_factory()).await
}

/// Context with an injected custom backend (API-level verification of §10.3 idempotency / §10.4 rollback boundaries).
async fn ctx_with_backend(backend: revision::BackendFactory) -> Ctx {
    let pool = meshlet_server::store::connect("sqlite::memory:")
        .await
        .unwrap();
    let mesh = std::sync::Arc::new(std::sync::Mutex::new(
        meshlet_server::service::MeshState::default(),
    ));
    let state = std::sync::Arc::new(
        meshlet_server::auth::AppState::new(
            mesh,
            meshlet_server::auth::AuthStore::new(pool.clone()),
            meshlet_server::agent::AgentTokenStore::new(pool.clone()),
            meshlet_server::api_token::ApiTokenStore::new(pool),
            false,
        )
        .with_apply_backend(backend),
    );
    let app = meshlet_server::router(state);

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "email": "admin@test.local",
                        "password": "bootstrap-password-123",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "bootstrap must succeed");
    let cookie = res
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .expect("session cookie")
        .to_string();
    Ctx { app, cookie }
}

/// Unified request builder: optional session Cookie and CSRF header (management writes must carry both).
async fn call(
    c: &Ctx,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    csrf: bool,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    if csrf {
        builder = builder.header("x-requested-with", "XMLHttpRequest");
    }
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

async fn create_network(c: &Ctx) -> Value {
    let (status, body) = call(
        c,
        "POST",
        "/api/v1/networks",
        Some(&c.cookie),
        true,
        Some(json!({ "name": "home", "overlay_cidr": OVERLAY })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    body
}

async fn issue_invite(c: &Ctx, network_id: &str) -> String {
    let (status, invite) = call(
        c,
        "POST",
        &format!("/api/v1/networks/{network_id}/invites"),
        Some(&c.cookie),
        true,
        Some(json!({ "max_uses": 1 })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    invite["token"].as_str().unwrap().to_string()
}

async fn enroll_device(c: &Ctx, network_id: &str, name: &str, public_key: &str) -> Value {
    let token = issue_invite(c, network_id).await;
    enroll_with_token(c, &token, name, public_key).await
}

/// Join with an already-issued invite Token (concurrent-join tests need invites pre-issued in bulk).
///
/// Issuing an invite itself **does not change the desired config** (no Peer/route/NAT change), so it records
/// no revision; only an actual device join records one version (§10.1).
async fn enroll_with_token(c: &Ctx, token: &str, name: &str, public_key: &str) -> Value {
    let (status, body) = call(
        c,
        "POST",
        "/api/v1/enroll",
        None,
        false,
        Some(json!({
            "invite_token": token,
            "device_name": name,
            "public_key": public_key,
            "platform": "linux",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    body
}

async fn revisions(c: &Ctx, network_id: &str) -> Value {
    let (status, body) = call(
        c,
        "GET",
        &format!("/api/v1/networks/{network_id}/config-revisions"),
        Some(&c.cookie),
        false,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    body
}

async fn apply(c: &Ctx, network_id: &str, revision: u64) -> (StatusCode, Value) {
    call(
        c,
        "POST",
        &format!("/api/v1/networks/{network_id}/config-revisions/{revision}/apply"),
        Some(&c.cookie),
        true,
        None,
    )
    .await
}

async fn rollback(c: &Ctx, network_id: &str, revision: u64) -> (StatusCode, Value) {
    call(
        c,
        "POST",
        &format!("/api/v1/networks/{network_id}/config-revisions/{revision}/rollback"),
        Some(&c.cookie),
        true,
        None,
    )
    .await
}

#[tokio::test]
async fn create_network_records_pending_revision_and_never_claims_effective() {
    let c = ctx().await;
    let created = create_network(&c).await;

    // ADR-009: config-modification responses must carry revision_id and apply_status.
    assert_eq!(created["revision_id"], 1);
    assert_eq!(created["apply_status"], "pending");

    let list = revisions(&c, created["id"].as_str().unwrap()).await;
    let entries = list.as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["revision"], 1);
    assert_eq!(entries[0]["apply_status"], "pending");
    // DB write ≠ effective: a revision never successfully applied must not get applied_at.
    assert!(entries[0]["applied_at"].is_null());
    assert!(entries[0]["error_summary"].is_null());
    let hash = entries[0]["desired_config_hash"].as_str().unwrap();
    assert_eq!(
        hash.len(),
        64,
        "desired_config_hash must be sha256 hex: {hash}"
    );

    // The network list also reflects apply status, not DB writes.
    let (status, body) = call(&c, "GET", "/api/v1/networks", Some(&c.cookie), false, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap()[0]["apply_status"], "pending");
    assert_eq!(body.as_array().unwrap()[0]["revision_id"], 1);
}

#[tokio::test]
async fn enroll_records_next_revision_with_changed_desired_hash() {
    let c = ctx().await;
    let created = create_network(&c).await;
    let network_id = created["id"].as_str().unwrap().to_string();

    let first_hash = revisions(&c, &network_id).await.as_array().unwrap()[0]["desired_config_hash"]
        .as_str()
        .unwrap()
        .to_string();

    let enroll = enroll_device(&c, &network_id, "laptop", "pub-laptop-0001").await;
    // Joining changes the desired config: new version number + new hash, still pending.
    assert_eq!(enroll["revision_id"], 2);
    assert_eq!(enroll["apply_status"], "pending");

    let list = revisions(&c, &network_id).await;
    let entries = list.as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["revision"], 1);
    assert_eq!(entries[1]["revision"], 2);
    let second_hash = entries[1]["desired_config_hash"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(
        first_hash, second_hash,
        "new device must change the desired config hash"
    );
    assert_eq!(entries[1]["apply_status"], "pending");
}

#[tokio::test]
async fn apply_without_backend_fails_visibly_everywhere() {
    let c = ctx().await;
    let created = create_network(&c).await;
    let network_id = created["id"].as_str().unwrap().to_string();

    // No dataplane backend in this process (WireGuard apply needs CAP_NET_ADMIN) → an explicit failure.
    let (status, body) = apply(&c, &network_id, 1).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revision"], 1);
    assert_eq!(body["apply_status"], "failed");
    assert!(body["error_summary"]
        .as_str()
        .unwrap()
        .contains("no network backend configured"));
    assert!(
        body["applied_at"].is_null(),
        "failed apply must not claim applied_at"
    );

    // The failure is visible in both detail and list views (not only in the call's return value).
    let (status, detail) = call(
        &c,
        "GET",
        &format!("/api/v1/networks/{network_id}/config-revisions/1"),
        Some(&c.cookie),
        false,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["apply_status"], "failed");
    assert!(detail["error_summary"].is_string());
    assert_eq!(
        revisions(&c, &network_id).await.as_array().unwrap()[0]["apply_status"],
        "failed"
    );
}

#[tokio::test]
async fn reapplying_a_failed_revision_is_a_conflict() {
    let c = ctx().await;
    let created = create_network(&c).await;
    let network_id = created["id"].as_str().unwrap().to_string();

    let (status, first) = apply(&c, &network_id, 1).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["apply_status"], "failed");

    // In-place retry is rejected by the state machine (§10.4): the retry path records a new revision.
    let (status, body) = apply(&c, &network_id, 1).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "conflict");
}

#[tokio::test]
async fn rollback_without_backend_stays_unconfirmed_with_diagnostics() {
    let c = ctx().await;
    let created = create_network(&c).await;
    let network_id = created["id"].as_str().unwrap().to_string();

    apply(&c, &network_id, 1).await; // -> failed
    let (status, body) = rollback(&c, &network_id, 1).await;
    assert_eq!(status, StatusCode::OK);
    // Rollback unconfirmed: explicitly left in rollback_pending, with diagnostics merged (apply failure + rollback failure).
    assert_eq!(body["apply_status"], "rollback_pending");
    let summary = body["error_summary"].as_str().unwrap();
    assert!(summary.contains("apply failed") || summary.contains("no network backend configured"));
    assert!(summary.contains("rollback failed"));
}

#[tokio::test]
async fn apply_and_rollback_require_session_and_csrf() {
    let c = ctx().await;
    let created = create_network(&c).await;
    let network_id = created["id"].as_str().unwrap().to_string();

    // No session → 401.
    let (status, _) = call(
        &c,
        "POST",
        &format!("/api/v1/networks/{network_id}/config-revisions/1/apply"),
        None,
        true,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Session present but CSRF header missing → 403 (same line of defense as existing write endpoints).
    let (status, body) = call(
        &c,
        "POST",
        &format!("/api/v1/networks/{network_id}/config-revisions/1/rollback"),
        Some(&c.cookie),
        false,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "forbidden");

    // An auth failure must not pollute revision state.
    assert_eq!(
        revisions(&c, &network_id).await.as_array().unwrap()[0]["apply_status"],
        "pending"
    );
}

#[tokio::test]
async fn unknown_network_and_unknown_revision_are_404() {
    let c = ctx().await;
    let created = create_network(&c).await;
    let network_id = created["id"].as_str().unwrap().to_string();

    let (status, body) = call(
        &c,
        "GET",
        "/api/v1/networks/net-does-not-exist/config-revisions",
        Some(&c.cookie),
        false,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");

    let (status, body) = apply(&c, &network_id, 99).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");
}

// ---------------------------------------------------------------------------
// #62 apply idempotency and rollback safety (§10.3)
// ---------------------------------------------------------------------------

/// Records the calls the backend received (revision identity + ordering), used to assert idempotency and rollback boundaries.
#[derive(Default, Clone)]
struct Calls {
    applied: Vec<u64>,
    rolled_back: Vec<u64>,
    /// Whether apply/rollback was entered concurrently (for the §10.4 serialization assertions).
    max_in_flight: usize,
    in_flight: usize,
}

struct SpyBackend {
    calls: Arc<Mutex<Calls>>,
}

impl ConfigApplyBackend for SpyBackend {
    fn apply(&mut self, revision: &ConfigRevision) -> Result<(), String> {
        let mut c = self.calls.lock().unwrap();
        c.in_flight += 1;
        c.max_in_flight = c.max_in_flight.max(c.in_flight);
        c.applied.push(revision.revision);
        c.in_flight -= 1;
        Ok(())
    }

    fn rollback(&mut self, revision: &ConfigRevision) -> Result<(), String> {
        let mut c = self.calls.lock().unwrap();
        c.in_flight += 1;
        c.max_in_flight = c.max_in_flight.max(c.in_flight);
        c.rolled_back.push(revision.revision);
        c.in_flight -= 1;
        Ok(())
    }
}

fn spy() -> (Arc<Mutex<Calls>>, revision::BackendFactory) {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let factory: revision::BackendFactory = {
        let calls = Arc::clone(&calls);
        Arc::new(move |_, _| {
            Box::new(SpyBackend {
                calls: Arc::clone(&calls),
            })
        })
    };
    (calls, factory)
}

#[derive(Clone)]
struct SlowBackend {
    gate: Arc<tokio::sync::Notify>,
    delay: Duration,
    error: Option<String>,
    entered: Arc<std::sync::atomic::AtomicUsize>,
}

impl ConfigApplyBackend for SlowBackend {
    fn apply(&mut self, _revision: &ConfigRevision) -> Result<(), String> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        self.gate.notify_one();
        std::thread::sleep(self.delay);
        match &self.error {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    fn rollback(&mut self, _revision: &ConfigRevision) -> Result<(), String> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        self.gate.notify_one();
        std::thread::sleep(self.delay);
        Ok(())
    }
}

fn slow_backend(
    delay: Duration,
    error: Option<String>,
) -> (
    Arc<tokio::sync::Notify>,
    Arc<std::sync::atomic::AtomicUsize>,
    revision::BackendFactory,
) {
    let gate = Arc::new(tokio::sync::Notify::new());
    let entered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let factory: revision::BackendFactory = {
        let gate = Arc::clone(&gate);
        let entered = Arc::clone(&entered);
        Arc::new(move |_, _| {
            Box::new(SlowBackend {
                gate: Arc::clone(&gate),
                delay,
                error: error.clone(),
                entered: Arc::clone(&entered),
            })
        })
    };
    (gate, entered, factory)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_kernel_apply_keeps_queries_and_other_networks_responsive() {
    let (gate, entered, factory) = slow_backend(Duration::from_millis(250), None);
    let c = ctx_with_backend(factory).await;
    let home = create_network(&c).await;
    let home_id = home["id"].as_str().unwrap().to_string();
    enroll_device(&c, &home_id, "laptop", "pub-laptop-0001").await;
    let office = call(
        &c,
        "POST",
        "/api/v1/networks",
        Some(&c.cookie),
        true,
        Some(json!({ "name": "office", "overlay_cidr": "10.241.0.0/16" })),
    )
    .await
    .1;
    let office_id = office["id"].as_str().unwrap().to_string();

    let apply_task = tokio::spawn({
        let c = c.clone();
        let home_id = home_id.clone();
        async move { apply(&c, &home_id, 2).await }
    });
    gate.notified().await;

    let query_started = tokio::time::Instant::now();
    let (query_status, _) = call(&c, "GET", "/api/v1/networks", Some(&c.cookie), false, None).await;
    assert_eq!(query_status, StatusCode::OK);
    assert!(query_started.elapsed() < Duration::from_millis(100));

    let office_started = tokio::time::Instant::now();
    let (office_status, office_body) = call(
        &c,
        "GET",
        &format!("/api/v1/networks/{office_id}/config-revisions"),
        Some(&c.cookie),
        false,
        None,
    )
    .await;
    assert_eq!(office_status, StatusCode::OK);
    assert_eq!(office_body.as_array().unwrap().len(), 1);
    assert!(office_started.elapsed() < Duration::from_millis(100));

    let (status, body) = apply_task.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["apply_status"], "applied");
    assert_eq!(entered.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failing_kernel_apply_is_tracked_and_visible() {
    let error = "slow kernel peer handshake rejected";
    let (_, _, factory) = slow_backend(Duration::from_millis(20), Some(error.to_string()));
    let c = ctx_with_backend(factory).await;
    let network = create_network(&c).await;
    let network_id = network["id"].as_str().unwrap().to_string();
    enroll_device(&c, &network_id, "laptop", "pub-laptop-0001").await;

    let (status, body) = apply(&c, &network_id, 2).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["apply_status"], "failed");
    assert_eq!(body["error_summary"], error);
    let detail = revisions(&c, &network_id).await;
    assert_eq!(detail.as_array().unwrap()[1]["apply_status"], "failed");
    assert_eq!(detail.as_array().unwrap()[1]["error_summary"], error);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_kernel_apply_across_networks_runs_in_parallel() {
    let (gate, _, factory) = slow_backend(Duration::from_millis(100), None);
    let c = ctx_with_backend(factory).await;
    let home = create_network(&c).await;
    let home_id = home["id"].as_str().unwrap().to_string();
    let office = call(
        &c,
        "POST",
        "/api/v1/networks",
        Some(&c.cookie),
        true,
        Some(json!({ "name": "office", "overlay_cidr": "10.241.0.0/16" })),
    )
    .await
    .1;
    let office_id = office["id"].as_str().unwrap().to_string();

    let home_apply = tokio::spawn({
        let c = c.clone();
        let home_id = home_id.clone();
        async move { apply(&c, &home_id, 1).await }
    });
    gate.notified().await;
    let office_started = tokio::time::Instant::now();
    let (office_status, _) = apply(&c, &office_id, 1).await;
    let office_elapsed = office_started.elapsed();
    assert_eq!(office_status, StatusCode::OK);
    assert!(
        office_elapsed < Duration::from_millis(250),
        "{office_elapsed:?}"
    );

    let home = home_apply.await.unwrap();
    assert_eq!(home.0, StatusCode::OK);
    assert_eq!(home.1["apply_status"], "applied");
}

#[tokio::test]
async fn reapplying_an_applied_revision_is_idempotent_at_the_api() {
    // §10.3 "re-applying the same version must not break the network": the second apply returns idempotently,
    // the backend is called only once, responses are byte-identical, and no new revision appears.
    let (calls, factory) = spy();
    let c = ctx_with_backend(factory).await;
    let created = create_network(&c).await;
    let network_id = created["id"].as_str().unwrap().to_string();

    let (status, first) = apply(&c, &network_id, 1).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["apply_status"], "applied");
    assert!(first["error_summary"].is_null());

    let (status, second) = apply(&c, &network_id, 1).await;
    assert_eq!(status, StatusCode::OK);
    // Idempotent: responses fully identical (applied_at keeps the first attempt's timestamp).
    assert_eq!(first, second);

    {
        let calls = calls.lock().unwrap();
        assert_eq!(
            calls.applied,
            vec![1],
            "backend must be invoked exactly once"
        );
    }
    assert_eq!(
        revisions(&c, &network_id).await.as_array().unwrap().len(),
        1,
        "re-apply must not record a new revision"
    );
}

/// For backend-failure cases: makes apply land in `failed`, thereby entering a rollback-able state.
struct FailingApply;

impl ConfigApplyBackend for FailingApply {
    fn apply(&mut self, _revision: &ConfigRevision) -> Result<(), String> {
        Err("spy: peer 2 handshake rejected".to_string())
    }

    fn rollback(&mut self, _revision: &ConfigRevision) -> Result<(), String> {
        Ok(())
    }
}

fn failing_factory() -> (Arc<Mutex<Calls>>, revision::BackendFactory) {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let factory: revision::BackendFactory = {
        let calls = Arc::clone(&calls);
        Arc::new(move |_, _| {
            Box::new(FailingApplySpy {
                calls: Arc::clone(&calls),
            })
        })
    };
    (calls, factory)
}

struct FailingApplySpy {
    calls: Arc<Mutex<Calls>>,
}

impl ConfigApplyBackend for FailingApplySpy {
    fn apply(&mut self, revision: &ConfigRevision) -> Result<(), String> {
        self.calls.lock().unwrap().applied.push(revision.revision);
        FailingApply.apply(revision)
    }

    fn rollback(&mut self, revision: &ConfigRevision) -> Result<(), String> {
        let mut c = self.calls.lock().unwrap();
        c.rolled_back.push(revision.revision);
        c.in_flight += 1;
        c.max_in_flight = c.max_in_flight.max(c.in_flight);
        c.in_flight -= 1;
        Ok(())
    }
}

#[tokio::test]
async fn rollback_touches_only_the_failed_revision_it_is_given() {
    // §10.3 "no rollback by deleting all system routes" + "changes stay within owned objects":
    // the backend receives only that one failed revision's identity — the ledger layer has no
    // "wipe everything" command channel, and the API layer must likewise pass no extra object.
    let (calls, factory) = failing_factory();
    let c = ctx_with_backend(factory).await;
    let created = create_network(&c).await;
    let network_id = created["id"].as_str().unwrap().to_string();

    // Add another device (yielding revision 2) and make both revisions fail to apply.
    assert_eq!(apply(&c, &network_id, 1).await.1["apply_status"], "failed");
    enroll_device(&c, &network_id, "laptop", "pub-laptop-0001").await;
    assert_eq!(apply(&c, &network_id, 2).await.1["apply_status"], "failed");

    let (status, body) = rollback(&c, &network_id, 2).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["apply_status"], "rolled_back");

    let calls = calls.lock().unwrap();
    // Exactly one rollback, targeting the failed revision itself: not rev1, not "everything".
    assert_eq!(calls.rolled_back, vec![2]);
}

#[tokio::test]
async fn rolling_back_a_superseded_revision_is_refused_and_backend_is_untouched() {
    // §10.4 cross-damage guard: a failed revision superseded by a newer one never took effect; rolling it
    // back per its intent would touch objects owned by the newer revision → 409, and the backend is **never called**.
    let (calls, factory) = failing_factory();
    let c = ctx_with_backend(factory).await;
    let created = create_network(&c).await;
    let network_id = created["id"].as_str().unwrap().to_string();

    apply(&c, &network_id, 1).await; // rev1 -> failed
    enroll_device(&c, &network_id, "laptop", "pub-laptop-0001").await; // rev2 supersedes rev1
    apply(&c, &network_id, 2).await; // rev2 -> failed

    let (status, body) = rollback(&c, &network_id, 1).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "conflict");
    let message = body["error"]["message"].as_str().unwrap();
    assert!(message.contains("superseded"), "{message}");
    assert!(
        message.contains('2'),
        "error must name the current revision"
    );

    {
        let calls = calls.lock().unwrap();
        assert!(
            calls.rolled_back.is_empty(),
            "refused rollback must not reach the backend: {:?}",
            calls.rolled_back
        );
    }
    // The rejected rollback changes no revision state.
    assert_eq!(
        revisions(&c, &network_id).await.as_array().unwrap()[0]["apply_status"],
        "failed"
    );
}

// ---------------------------------------------------------------------------
// #63 concurrent version ordering (§10.4)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn concurrent_mutations_get_unique_contiguous_revision_numbers() {
    // §10.4 "config changes within the same Network must be version-ordered": concurrent writes are
    // serialized by a per-network mutex; version numbers are unique, contiguous, strictly increasing — no interleaving, no gaps, no duplicates.
    const CONCURRENCY: usize = 12;
    let c = ctx().await;
    let created = create_network(&c).await;
    let network_id = created["id"].as_str().unwrap().to_string();

    // Invites don't change the desired config, so pre-issue them in bulk; then join concurrently —
    // each join changes the Peer config and records one version (§10.1).
    let mut tokens = Vec::new();
    for _ in 0..CONCURRENCY {
        tokens.push(issue_invite(&c, &network_id).await);
    }
    let mut tasks = Vec::new();
    for (i, token) in tokens.into_iter().enumerate() {
        let c = c.clone();
        tasks.push(tokio::spawn(async move {
            let name = format!("dev-{i}");
            enroll_with_token(&c, &token, &name, &format!("pub-{name}-0001")).await
        }));
    }
    let mut ids = Vec::new();
    for task in tasks {
        let body = task.await.unwrap();
        ids.push(body["revision_id"].as_u64().unwrap());
    }
    ids.sort_unstable();
    // Every concurrent request gets a distinct version number (no duplicates).
    ids.dedup();
    assert_eq!(ids.len(), CONCURRENCY, "revision ids must be unique");

    // Revision 1 = network creation; each concurrent join thereafter records one revision.
    let list = revisions(&c, &network_id).await;
    let numbers: Vec<u64> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["revision"].as_u64().unwrap())
        .collect();
    let expected: Vec<u64> = (1..=CONCURRENCY as u64 + 1).collect();
    assert_eq!(numbers, expected, "revisions must be unique and contiguous");
}

#[tokio::test]
async fn concurrent_applies_are_serialized_per_network() {
    // §10.4 no cross-damage to Peers/routes/NAT: applies of the same network enter the backend
    // serialized, only one in flight at any moment; and each revision is applied at most once (idempotency + serialization combined).
    let (calls, factory) = spy();
    let c = ctx_with_backend(factory).await;
    let created = create_network(&c).await;
    let network_id = created["id"].as_str().unwrap().to_string();
    enroll_device(&c, &network_id, "laptop", "pub-laptop-0001").await;

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let c = c.clone();
        let network_id = network_id.clone();
        tasks.push(tokio::spawn(
            async move { apply(&c, &network_id, 2).await.0 },
        ));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap(), StatusCode::OK);
    }

    let calls = calls.lock().unwrap();
    assert_eq!(
        calls.max_in_flight, 1,
        "apply must be serialized within a network"
    );
    assert_eq!(
        calls.applied,
        vec![2],
        "8 concurrent applies of one revision must hit the backend once"
    );
}

#[tokio::test]
async fn revision_numbering_is_independent_across_networks() {
    // §10.4 version ordering is per-network: concurrent changes to different networks don't steal each other's version numbers.
    let c = ctx().await;
    let (status, home) = call(
        &c,
        "POST",
        "/api/v1/networks",
        Some(&c.cookie),
        true,
        Some(json!({ "name": "home", "overlay_cidr": OVERLAY })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, office) = call(
        &c,
        "POST",
        "/api/v1/networks",
        Some(&c.cookie),
        true,
        Some(json!({ "name": "office", "overlay_cidr": "10.241.0.0/16" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(home["revision_id"], 1);
    assert_eq!(office["revision_id"], 1, "per-network numbering");

    // Both networks change once more; each is still at its own version 2.
    enroll_device(&c, home["id"].as_str().unwrap(), "laptop", "pub-laptop-1").await;
    enroll_device(
        &c,
        office["id"].as_str().unwrap(),
        "desktop",
        "pub-desktop-1",
    )
    .await;
    for net in [home["id"].as_str().unwrap(), office["id"].as_str().unwrap()] {
        let numbers: Vec<u64> = revisions(&c, net)
            .await
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["revision"].as_u64().unwrap())
            .collect();
        assert_eq!(numbers, vec![1, 2], "network {net}");
    }
}

#[tokio::test]
async fn old_pending_and_applied_revisions_cannot_publish_new_resources() {
    let (calls, factory) = spy();
    let c = ctx_with_backend(factory).await;
    let network = create_network(&c).await;
    let id = network["id"].as_str().unwrap();
    enroll_device(&c, id, "first", "pub-first").await;
    assert_eq!(apply(&c, id, 1).await.0, StatusCode::CONFLICT);
    assert!(calls.lock().unwrap().applied.is_empty());
    assert_eq!(apply(&c, id, 2).await.1["apply_status"], "applied");
    enroll_device(&c, id, "second", "pub-second").await;
    assert_eq!(apply(&c, id, 2).await.0, StatusCode::CONFLICT);
    assert_eq!(calls.lock().unwrap().applied, vec![2]);
    let current = revisions(&c, id).await;
    assert_eq!(
        current.as_array().unwrap().last().unwrap()["apply_status"],
        "pending"
    );
}

#[tokio::test]
async fn replaying_old_rolled_back_revision_does_not_settle_new_pending_routes() {
    let (calls, factory) = failing_factory();
    let c = ctx_with_backend(factory).await;
    let network = create_network(&c).await;
    let id = network["id"].as_str().unwrap();
    assert_eq!(apply(&c, id, 1).await.1["apply_status"], "failed");
    assert_eq!(rollback(&c, id, 1).await.1["apply_status"], "rolled_back");
    let device = enroll_device(&c, id, "later", "pub-later").await;
    let (status, route) = call(&c, "POST", &format!("/api/v1/networks/{id}/routes"), Some(&c.cookie), true,
        Some(json!({"gateway_device_id":device["device_id"],"destination_cidr":"192.168.90.0/24","return_path_mode":"dual_route"}))).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(rollback(&c, id, 1).await.1["apply_status"], "rolled_back");
    let (_, after) = call(
        &c,
        "GET",
        &format!(
            "/api/v1/networks/{id}/routes/{}",
            route["id"].as_str().unwrap()
        ),
        Some(&c.cookie),
        false,
        None,
    )
    .await;
    assert_eq!(after["status"], "pending");
    assert_eq!(calls.lock().unwrap().rolled_back, vec![1]);
}
