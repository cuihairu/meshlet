//! Integration tests: failure recovery ([archive §17.3](../../docs/review/chatgpt-2026-10-13.md)).
//!
//! After a server restart, state is rebuilt to the expected shape:
//! 1. create network + enroll device + add route + apply -> close the DB and rebuild from the same file ->
//!    networks/device virtual IPs/routes/revision sequence match field by field, numbering/allocation keep rising;
//! 2. a revision stuck in `applying` lands as `failed` after restart per §10.3 (no pretending it succeeded),
//!    while `rollback_pending` is kept retryable;
//! 3. ids of deleted routes are never reused after a restart;
//! 4. presence evidence is judged conservatively after restart — stale evidence must not fabricate `online` (§12.4);
//! 5. bootstrap tokens and pending registration requests (with pending heartbeat evidence) are rebuilt field by field
//!    across restarts, and registration-time agent credentials stay valid (2026-10-15 bootstrap registration).

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

/// Unique temp DB file (isolated by both process and test case; WAL/SHM sidecar files cleaned up too).
/// Uses `CARGO_TARGET_TMPDIR`, which cargo provides to integration tests (writable within the build dir).
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

/// Open (or reopen after a restart) a file-backed DB: run migrations -> §17.3 rebuild of mesh state ->
/// assemble the app. An empty DB goes through bootstrap; after a restart a user already exists, so login —
/// both yield a session cookie (which also proves user/session credentials persist across restarts).
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

    // bootstrap (201 on an empty DB) or login (200 after restart) — take the session from Set-Cookie either way.
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

/// Create a network + invite + enroll one device; returns (network_id, device_id).
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

/// §17.3 acceptance 1: close the DB -> rebuild from the same file -> state matches field by field, numbering keeps incrementing.
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
        // apply takes the no-backend path -> failed (a visible, persisted failure is part of recovery semantics too).
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

    // Restart: rebuild from the same DB (open_app internally goes through persist::load).
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

    // Field-by-field equality: networks (incl. current revision), devices (virtual IP/public key/status), routes,
    // and the revision sequence (contiguous numbers, desired_config_hash and error_summary replayed verbatim).
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

    // Everything keeps incrementing after the restart: the new device gets the next virtual IP (.2 is not reused),
    // revision numbers continue, and the new route id continues (rt-2, not a reissue of rt-1).
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

/// §17.3 acceptance 2 (§10.3, no pretending): a revision stuck in `applying` lands as
/// `failed` + interruption diagnosis after restart; `rollback_pending` is kept retryable.
#[tokio::test]
async fn interrupted_applying_lands_failed_after_restart() {
    let db = db_file("interrupted");
    let network_id;
    {
        let c = open_app(&db).await;
        (network_id, _) = net_with_device(&c).await;
        // Simulate a crash scene: force revision 2 to applying / revision 1 to rollback_pending
        // (once the data plane lands, these become genuine persisted intermediate states).
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
    // applying -> failed, with the error naming the process interruption (outcome unknown, no pretending).
    let (st, rev2) = json_get(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions/2"),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(rev2["apply_status"], "failed");
    let summary = rev2["error_summary"].as_str().unwrap();
    assert!(summary.contains("interrupted"), "summary: {summary}");

    // rollback_pending is preserved as-is: status and the original failure diagnosis replayed verbatim (distinguishable).
    let (st, rev1) = json_get(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions/1"),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(rev1["apply_status"], "rollback_pending");
    assert_eq!(rev1["error_summary"], "apply boom");

    // The converged rev2 (failed) is the current revision -> it is the rollback entry point (§10.4): without a
    // backend the rollback parks at rollback_pending (explicitly unconfirmed, diagnoses merged) — 200, not 404/409.
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
    // rev1, superseded by rev2, is no longer a rollback entry point (§10.4's cross-corruption guard holds across restarts).
    let (st, _) = json_post(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions/1/rollback"),
        json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "superseded revision rejected");

    // Convergence idempotence: restart once more — non-applying states are untouched (rev2 stays at the
    // post-rollback rollback_pending, preserved verbatim; there is no such thing as "converging again").
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

/// §17.3 acceptance 3: route id sequence persisted (mesh_meta) — deleted route ids are never reused after a restart.
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

    // New route after restart: id continues from the sequence (rt-2), rt-1 is not reissued.
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

/// §17.3 acceptance 4 (§12.4 conservative judgment): after a restart, stale evidence must not fabricate online.
#[tokio::test]
async fn presence_is_conservative_after_restart() {
    let db = db_file("presence");
    let network_id;
    {
        let c = open_app(&db).await;
        (network_id, _) = net_with_device(&c).await;
        // Grab the agent token before heartbeating (enroll returns it only once) — replay invite/enroll.
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

        // Heartbeat (with handshake evidence + data-plane measured evidence, §7.5) -> online.
        let mut req = Request::builder()
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
            .unwrap();
        // §12: heartbeat observes the direct-connection source address (ConnectInfo is assembled at the serve layer).
        req.extensions_mut().insert(axum::extract::ConnectInfo(
            "10.240.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
        ));
        let res = c.app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let hb: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(hb["online_state"], "online");

        // Measured evidence is persisted: visible from the same source after restart (§17.3 field-by-field restore).
        let (_, before) = json_get(&c, &format!("/api/v1/networks/{network_id}/devices")).await;
        let laptop = before
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["name"] == "laptop")
            .unwrap();
        assert_eq!(laptop["dataplane_evidence"]["tunnel_mtu"], 1380);
        assert_eq!(laptop["dataplane_evidence"]["mtu_probe_payload"], 1352);

        // Simulate "time passing after the restart": push the evidence timestamps into the distant past (editing
        // the DB directly equals the service being down for a long time — judgment happens at read time, not at startup).
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
    // Data-plane evidence comes back with the device row (restart does not zero the readings; staleness is presence's job).
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

/// Agent API call (Bearer credential, no session/CSRF).
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
    let mut req = builder
        .header("content-type", "application/json")
        .body(body)
        .unwrap();
    // §12: heartbeat observes the direct-connection source address (ConnectInfo is assembled at the serve layer).
    req.extensions_mut().insert(axum::extract::ConnectInfo(
        "10.240.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
    ));
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Object(Default::default()));
    (status, value)
}

/// §17.3 extension (2026-10-15 bootstrap registration): bootstrap tokens and pending requests are rebuilt field by
/// field across restarts, registration-time agent credentials stay valid (heartbeat stays pending), approval still works.
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

        // Bootstrap token -> device self-registration -> pending heartbeat (with data-plane evidence).
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

    // Restart: rebuild from the same DB — bootstrap token metadata and the pending request (incl. heartbeat evidence) restored field by field.
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

    // The registration-time credential still works across the restart: heartbeat stays pending; desired still 404s pending approval.
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

    // Approval works normally after the restart: device registered + exactly one new revision (baseline = the network's initial revision).
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
