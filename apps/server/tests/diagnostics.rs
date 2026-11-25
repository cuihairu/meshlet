//! Integration test: the 13 network diagnostics checks ([archive §12.7](../../docs/review/chatgpt-2026-10-13.md)).
//!
//! 1. Endpoint gates: GET needs a session, POST needs a session + CSRF; unknown network 404;
//! 2. All thirteen checks present, fixed order, grouped by fault layer (tunnel/routing/forwarding/Alias + control plane);
//! 3. **No fake green**: local-machine checks the control plane cannot observe (WireGuard interface/kernel routes/IP
//!    forwarding/firewall/NAT) are always `unavailable` and carry an actionable suggestion;
//! 4. **Registered in the control plane ≠ a healthy tunnel**: device enrolled (③ pass) while handshake is missing (④ fail)
//!    must hold simultaneously; once the heartbeat report is fresh, ④ flips to pass;
//! 5. ⑧⑨⑫ follow gateway presence and the revision state machine (pending→warning, applied→pass,
//!    failed→fail); results are persisted (GET reads the latest snapshot); Alias conflicts use domain-layer detection.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use meshlet_domain::{ConfigApplyBackend, ConfigRevision};
use meshlet_server::revision;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt; // oneshot

const EMAIL: &str = "admin@test.local";
const PASSWORD: &str = "bootstrap-password-123";
const OVERLAY: &str = "10.240.0.0/16";

/// The fixed order and fault layers of the §12.7 thirteen checks.
const EXPECTED: [(&str, &str); 13] = [
    ("api_reachable", "control_plane"),
    ("wg_interface_exists", "tunnel"),
    ("server_peer_configured", "tunnel"),
    ("recent_handshake", "tunnel"),
    ("overlay_route_present", "routing"),
    ("ip_forwarding_enabled", "forwarding"),
    ("firewall_allows_forwarding", "forwarding"),
    ("lan_gateway_agent_online", "routing"),
    ("lan_route_published", "routing"),
    ("alias_prefix_conflict", "alias"),
    ("nat_rules_effective", "alias"),
    ("config_revision_consistent", "control_plane"),
    ("mtu_planned", "tunnel"),
];

/// Local-machine checks the control plane cannot observe (§12.7 ②⑤⑥⑦⑪): always unavailable.
const LOCAL_MACHINE: [&str; 5] = [
    "wg_interface_exists",
    "overlay_route_present",
    "ip_forwarding_enabled",
    "firewall_allows_forwarding",
    "nat_rules_effective",
];

/// A placeholder backend with no data plane: apply/rollback always succeed (for the ⑨⑫ pass paths).
struct OkBackend;

impl ConfigApplyBackend for OkBackend {
    fn apply(&mut self, _revision: &ConfigRevision) -> Result<(), String> {
        Ok(())
    }
    fn rollback(&mut self, _revision: &ConfigRevision) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Clone)]
struct Ctx {
    app: Router,
    cookie: String,
    pool: sqlx::SqlitePool,
}

async fn ctx() -> Ctx {
    ctx_with_backend(revision::unconfigured_backend_factory()).await
}

async fn ctx_with_backend(backend: revision::BackendFactory) -> Ctx {
    let pool = meshlet_server::store::connect("sqlite::memory:")
        .await
        .unwrap();
    let state = build_state(&pool).with_apply_backend(backend);
    ctx_from(state, pool).await
}

/// A ctx with a planned tunnel MTU (§7.5, the input to ⑬).
async fn ctx_with_mtu(mtu: Option<u32>) -> Ctx {
    let pool = meshlet_server::store::connect("sqlite::memory:")
        .await
        .unwrap();
    let state = build_state(&pool).with_tunnel_mtu(mtu);
    ctx_from(state, pool).await
}

/// A revision backend that can apply + a planned tunnel MTU (for the evidence-driven ⑪⑬).
async fn ctx_with_backend_and_mtu(backend: revision::BackendFactory, mtu: Option<u32>) -> Ctx {
    let pool = meshlet_server::store::connect("sqlite::memory:")
        .await
        .unwrap();
    let state = build_state(&pool)
        .with_apply_backend(backend)
        .with_tunnel_mtu(mtu);
    ctx_from(state, pool).await
}

/// A full AppState sharing one pool (audit and credentials in the same db, see auth.rs).
fn build_state(pool: &sqlx::SqlitePool) -> meshlet_server::auth::AppState {
    meshlet_server::auth::AppState::new(
        Arc::new(std::sync::Mutex::new(
            meshlet_server::service::MeshState::default(),
        )),
        meshlet_server::auth::AuthStore::new(pool.clone()),
        meshlet_server::agent::AgentTokenStore::new(pool.clone()),
        meshlet_server::api_token::ApiTokenStore::new(pool.clone()),
        false,
    )
}

/// Assemble the router + bootstrap the admin, returning a logged-in ctx.
async fn ctx_from(state: meshlet_server::auth::AppState, pool: sqlx::SqlitePool) -> Ctx {
    let app = meshlet_server::router(Arc::new(state));
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
    assert_eq!(res.status(), StatusCode::CREATED);
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
    let body = body.map(|v| Body::from(v.to_string())).unwrap_or_default();
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", &c.cookie)
        .header("x-requested-with", "XMLHttpRequest")
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

/// A bare request without auth/CSRF (gate cases).
async fn raw(app: Router, method: &str, uri: &str, cookie: Option<&str>, csrf: bool) -> StatusCode {
    let mut builder = Request::builder().method(method).uri(uri);
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
    res.status()
}

/// Create a network + invite + enroll one device, returning (network_id, device_id, agent_token).
async fn net_with_device(c: &Ctx) -> (String, String, String) {
    let (st, net) = json_post(
        c,
        "/api/v1/networks",
        json!({"name": "home", "overlay_cidr": OVERLAY}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{net}");
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
            "public_key": "pub-key-diagnostics",
            "platform": "linux",
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{device}");
    (
        network_id,
        device["device_id"].as_str().unwrap().to_string(),
        device["agent_token"].as_str().unwrap().to_string(),
    )
}

/// Agent heartbeat (Bearer credential + local handshake reading).
async fn heartbeat(c: &Ctx, agent_token: &str, handshake_at: &str) -> Value {
    heartbeat_with_evidence(c, agent_token, handshake_at, serde_json::Value::Null).await
}

/// Agent heartbeat + measured data-plane evidence (§7.5: kernel readings + large-packet probe).
async fn heartbeat_with_evidence(
    c: &Ctx,
    agent_token: &str,
    handshake_at: &str,
    evidence: Value,
) -> Value {
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/v1/agent/heartbeat")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {agent_token}"))
        .body(Body::from(
            json!({
                "last_handshake_at": handshake_at,
                "dataplane": evidence,
            })
            .to_string(),
        ))
        .unwrap();
    // §12: observe the direct-connect source address on heartbeat (ConnectInfo is assembled at the serve layer).
    req.extensions_mut().insert(axum::extract::ConnectInfo(
        "10.240.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
    ));
    let res = c.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// Trigger diagnostics, asserting 200 and returning the report.
async fn run(c: &Ctx, network_id: &str) -> Value {
    let (st, body) = json_post(
        c,
        &format!("/api/v1/networks/{network_id}/diagnostics"),
        json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    body
}

fn check_of<'a>(report: &'a Value, id: &str) -> &'a Value {
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("check {id} missing in {}", report["checks"]))
}

fn now_stamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

// ---------------------------------------------------------------------------
// Gates and 404
// ---------------------------------------------------------------------------

#[tokio::test]
async fn diagnostics_endpoints_require_auth_and_csrf() {
    let c = ctx().await;
    // No session: both GET/POST get 401 (auth runs before path resolution, so an unknown network hits auth first too).
    assert_eq!(
        raw(
            c.app.clone(),
            "GET",
            "/api/v1/networks/net-x/diagnostics",
            None,
            false
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        raw(
            c.app.clone(),
            "POST",
            "/api/v1/networks/net-x/diagnostics",
            None,
            false
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    // Session without the CSRF header: write requests get 403.
    assert_eq!(
        raw(
            c.app.clone(),
            "POST",
            "/api/v1/networks/net-x/diagnostics",
            Some(&c.cookie),
            false
        )
        .await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn unknown_network_is_404() {
    let c = ctx().await;
    for method in ["GET", "POST"] {
        let (st, body) = call(
            &c,
            method,
            "/api/v1/networks/nope/diagnostics",
            if method == "POST" {
                Some(json!({}))
            } else {
                None
            },
        )
        .await;
        assert_eq!(st, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["error"]["code"], "not_found");
    }
}

#[tokio::test]
async fn get_before_any_run_is_404_and_names_post() {
    let c = ctx().await;
    let (st, net) = json_post(
        &c,
        "/api/v1/networks",
        json!({"name": "home", "overlay_cidr": OVERLAY}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let network_id = net["id"].as_str().unwrap().to_string();
    let (st, body) = json_get(&c, &format!("/api/v1/networks/{network_id}/diagnostics")).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"]["code"], "not_found");
    // The message names the trigger -- it must not pretend results exist.
    assert!(
        body["error"]["message"].as_str().unwrap().contains("POST"),
        "{body}"
    );
}

// ---------------------------------------------------------------------------
// Thirteen-check structure and no fake green
// ---------------------------------------------------------------------------

#[tokio::test]
async fn run_reports_thirteen_checks_in_order_with_layers() {
    let c = ctx().await;
    let (st, net) = json_post(
        &c,
        "/api/v1/networks",
        json!({"name": "home", "overlay_cidr": OVERLAY}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let network_id = net["id"].as_str().unwrap().to_string();

    let report = run(&c, &network_id).await;
    assert_eq!(report["network_id"], network_id);
    assert!(report["checked_at"].as_str().is_some_and(|s| !s.is_empty()));

    // Thirteen checks with fixed order and layers (§12.7 list + tunnel/routing/forwarding/Alias + control plane).
    let checks = report["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 13, "{checks:?}");
    for (i, (id, layer)) in EXPECTED.iter().enumerate() {
        assert_eq!(checks[i]["id"], *id, "position {i}");
        assert_eq!(checks[i]["layer"], *layer, "check {id}");
        assert!(checks[i]["name"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(checks[i]["detail"].as_str().is_some_and(|s| !s.is_empty()));
    }

    // No fake green: local-machine checks are always unavailable (not pass), and the suggestion is non-empty.
    for id in LOCAL_MACHINE {
        let item = check_of(&report, id);
        assert_eq!(item["status"], "unavailable", "{item}");
        assert!(
            item["suggestion"].as_str().is_some_and(|s| !s.is_empty()),
            "unavailable check {id} must carry an actionable suggestion"
        );
        assert!(
            item["detail"].as_str().unwrap().contains("cannot"),
            "unavailable check {id} must say why: {item}"
        );
    }

    // ① is always pass (being able to read the report proves the API is serving).
    assert_eq!(check_of(&report, "api_reachable")["status"], "pass");

    // GET reads the **same** snapshot (not a freshly computed report).
    let (st, again) = json_get(&c, &format!("/api/v1/networks/{network_id}/diagnostics")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(again["checked_at"], report["checked_at"]);
    assert_eq!(again["checks"], report["checks"]);
}

#[tokio::test]
async fn empty_network_honestly_reports_not_applicable() {
    let c = ctx().await;
    let (st, net) = json_post(
        &c,
        "/api/v1/networks",
        json!({"name": "home", "overlay_cidr": OVERLAY}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let network_id = net["id"].as_str().unwrap().to_string();

    let report = run(&c, &network_id).await;
    // No devices: registration/handshake honestly not_applicable (not pass).
    assert_eq!(
        check_of(&report, "server_peer_configured")["status"],
        "not_applicable"
    );
    assert_eq!(
        check_of(&report, "recent_handshake")["status"],
        "not_applicable"
    );
    // No routes: gateway/publication not_applicable.
    assert_eq!(
        check_of(&report, "lan_gateway_agent_online")["status"],
        "not_applicable"
    );
    assert_eq!(
        check_of(&report, "lan_route_published")["status"],
        "not_applicable"
    );
    // No Alias mappings: not_applicable (Phase 4 has no write path, the table is empty).
    assert_eq!(
        check_of(&report, "alias_prefix_conflict")["status"],
        "not_applicable"
    );
    // No devices: no tunnel to size, ⑬ is also not_applicable (not pass).
    assert_eq!(check_of(&report, "mtu_planned")["status"], "not_applicable");
    // Creating the network already recorded revision #1 (pending): config consistency is warning -- the desired config is not confirmed applied.
    let revision_check = check_of(&report, "config_revision_consistent");
    assert_eq!(revision_check["status"], "warning", "{revision_check}");
    assert!(revision_check["detail"].as_str().unwrap().contains("#1"));
}

// ---------------------------------------------------------------------------
// ⑬ planned tunnel MTU follows server config (§7.5)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mtu_check_follows_server_config() {
    // Not explicitly configured (default ctx): warning when devices exist -- the default 1420 risks
    // large-packet blackholing over PPPoE/4G underlays, so the suggestion must give an actionable ping -M do probe command.
    let c = ctx().await;
    let (network_id, _device_id, _token) = net_with_device(&c).await;
    let report = run(&c, &network_id).await;
    let item = check_of(&report, "mtu_planned");
    assert_eq!(item["status"], "warning", "{item}");
    assert!(item["detail"].as_str().unwrap().contains("1420"));
    assert!(item["suggestion"].as_str().unwrap().contains("ping -M do"));

    // Explicitly configured: pass, the detail names the planned value; pass ⇒ no suggestion needed.
    let c = ctx_with_mtu(Some(1380)).await;
    let (network_id, _device_id, _token) = net_with_device(&c).await;
    let report = run(&c, &network_id).await;
    let item = check_of(&report, "mtu_planned");
    assert_eq!(item["status"], "pass", "{item}");
    assert!(item["detail"].as_str().unwrap().contains("1380"));
    assert_eq!(item["suggestion"], "");
}

// ---------------------------------------------------------------------------
// Device-side measured evidence drives ⑪⑬ (§7.5/§12.4: heartbeat carries kernel readings back)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn device_evidence_drives_nat_and_mtu_checks() {
    let c = ctx_with_backend_and_mtu(
        Arc::new(|_, _| Box::new(OkBackend) as Box<dyn meshlet_domain::ConfigApplyBackend + Send>),
        Some(1380),
    )
    .await;
    let (network_id, device_id, token) = net_with_device(&c).await;

    // Alias route + mapping + apply: ⑪ now has something to judge (an Applied Alias route).
    let (st, route) = json_post(
        &c,
        &format!("/api/v1/networks/{network_id}/routes"),
        json!({
            "gateway_device_id": device_id,
            "destination_cidr": "192.168.1.0/24",
            "route_mode": "alias",
            "return_path_mode": "dual_route",
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{route}");
    let (st, alias) = json_post(
        &c,
        &format!("/api/v1/networks/{network_id}/aliases"),
        json!({"lan_route_id": route["id"], "alias_cidr": "10.241.1.0/24"}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{alias}");
    let (st, revs) = json_get(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions"),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let last = revs.as_array().unwrap().last().unwrap()["revision"].clone();
    let (st, applied) = json_post(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions/{last}/apply"),
        json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{applied}");

    // No evidence: ⑪ stays unavailable (not observable from the control plane), ⑬ only evaluates the plan (pass).
    let report = run(&c, &network_id).await;
    let nat = check_of(&report, "nat_rules_effective");
    assert_eq!(nat["status"], "unavailable", "{nat}");
    assert!(nat["detail"].as_str().unwrap().contains("cannot"));
    assert_eq!(check_of(&report, "mtu_planned")["status"], "pass");

    // Gateway evidence "no meshlet NAT rules in the kernel" → ⑪ fail (reported honestly);
    // Interface reading 1300 ≠ planned 1380 → ⑬ fail. The evidence also lands on the device view.
    heartbeat_with_evidence(
        &c,
        &token,
        &now_stamp(),
        json!({"nat_rules_present": false, "tunnel_mtu": 1300}),
    )
    .await;
    let report = run(&c, &network_id).await;
    let nat = check_of(&report, "nat_rules_effective");
    assert_eq!(nat["status"], "fail", "{nat}");
    assert!(
        nat["detail"]
            .as_str()
            .unwrap()
            .contains("no meshlet NAT rules"),
        "{nat}"
    );
    let mtu = check_of(&report, "mtu_planned");
    assert_eq!(mtu["status"], "fail", "{mtu}");
    assert!(
        mtu["detail"].as_str().unwrap().contains("1300"),
        "reading must be named: {mtu}"
    );

    // Healthy evidence: rules in the kernel + reading matches the plan + large-packet probe passes → ⑪⑬ pass.
    heartbeat_with_evidence(
        &c,
        &token,
        &now_stamp(),
        json!({"nat_rules_present": true, "tunnel_mtu": 1380, "mtu_probe_payload": 1352}),
    )
    .await;
    let report = run(&c, &network_id).await;
    assert_eq!(check_of(&report, "nat_rules_effective")["status"], "pass");
    let mtu = check_of(&report, "mtu_planned");
    assert_eq!(mtu["status"], "pass", "{mtu}");
    assert!(mtu["detail"].as_str().unwrap().contains("1352"), "{mtu}");

    // Reading matches but the large-packet probe is unverified → ⑬ warning (path unverified, give the probe command).
    heartbeat_with_evidence(
        &c,
        &token,
        &now_stamp(),
        json!({"nat_rules_present": true, "tunnel_mtu": 1380}),
    )
    .await;
    let report = run(&c, &network_id).await;
    let mtu = check_of(&report, "mtu_planned");
    assert_eq!(mtu["status"], "warning", "{mtu}");
    assert!(
        mtu["suggestion"].as_str().unwrap().contains("ping -M do"),
        "{mtu}"
    );

    // The device view surfaces the latest evidence (console and diagnostics share the source).
    let (st, devices) = json_get(&c, &format!("/api/v1/networks/{network_id}/devices")).await;
    assert_eq!(st, StatusCode::OK);
    let view = devices
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["id"] == device_id.as_str())
        .unwrap();
    assert_eq!(view["dataplane_evidence"]["tunnel_mtu"], 1380);
    assert_eq!(view["dataplane_evidence"]["nat_rules_present"], true);
}

#[tokio::test]
async fn heartbeat_without_evidence_keeps_previous_readings() {
    // Evidence follows the same discipline as the handshake time: when the request omits it, the previous reading is kept (last known reading).
    let c = ctx_with_mtu(Some(1380)).await;
    let (network_id, _device_id, token) = net_with_device(&c).await;
    heartbeat_with_evidence(
        &c,
        &token,
        &now_stamp(),
        json!({"tunnel_mtu": 1380, "mtu_probe_payload": 1352}),
    )
    .await;
    heartbeat(&c, &token, &now_stamp()).await; // without dataplane fields
    let (st, devices) = json_get(&c, &format!("/api/v1/networks/{network_id}/devices")).await;
    assert_eq!(st, StatusCode::OK);
    let view = devices.as_array().unwrap().first().unwrap();
    assert_eq!(view["dataplane_evidence"]["tunnel_mtu"], 1380);
    assert_eq!(view["dataplane_evidence"]["mtu_probe_payload"], 1352);
}

// ---------------------------------------------------------------------------
// Registered in the control plane ≠ a healthy tunnel (§12.4 reading discipline)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registration_without_handshake_is_not_a_healthy_tunnel() {
    let c = ctx().await;
    let (network_id, _device_id, _token) = net_with_device(&c).await;

    let report = run(&c, &network_id).await;
    // ③ registered (pass) -- but the detail must state it is "registration only".
    let peer = check_of(&report, "server_peer_configured");
    assert_eq!(peer["status"], "pass", "{peer}");
    assert!(
        peer["detail"]
            .as_str()
            .unwrap()
            .contains("registration only"),
        "③ must not claim tunnel health: {peer}"
    );
    // ④ handshake never observed (fail) -- both checks hold at once; registration does not vouch for the tunnel.
    let handshake = check_of(&report, "recent_handshake");
    assert_eq!(handshake["status"], "fail", "{handshake}");
    assert!(
        handshake["detail"].as_str().unwrap().contains("never"),
        "{handshake}"
    );
    assert!(!handshake["suggestion"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn fresh_handshake_and_agent_report_flip_the_checks() {
    let c = ctx().await;
    let (network_id, _device_id, token) = net_with_device(&c).await;

    // The heartbeat carries the local handshake reading: fresh agent report → device online; handshake within the window → ④ pass.
    let hb = heartbeat(&c, &token, &now_stamp()).await;
    assert_eq!(hb["online_state"], "online");

    let report = run(&c, &network_id).await;
    let handshake = check_of(&report, "recent_handshake");
    assert_eq!(handshake["status"], "pass", "{handshake}");
    assert!(handshake["detail"].as_str().unwrap().contains("fresh"));
}

// ---------------------------------------------------------------------------
// Gateway presence and the revision state machine drive ⑧⑨⑫
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gateway_online_and_revision_state_drive_route_checks() {
    let c = ctx_with_backend(Arc::new(|_, _| {
        Box::new(OkBackend) as Box<dyn meshlet_domain::ConfigApplyBackend + Send>
    }))
    .await;
    let (network_id, _device_id, token) = net_with_device(&c).await;
    heartbeat(&c, &token, &now_stamp()).await; // gateway agent report fresh → online
    let (st, route) = json_post(
        &c,
        &format!("/api/v1/networks/{network_id}/routes"),
        json!({
            "gateway_device_id": _device_id,
            "destination_cidr": "192.168.1.0/24",
            "return_path_mode": "dual_route",
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{route}");

    // Revision #3 (route creation) not yet applied: ⑧ pass (gateway online), ⑨ warning, ⑫ warning.
    let report = run(&c, &network_id).await;
    assert_eq!(
        check_of(&report, "lan_gateway_agent_online")["status"],
        "pass"
    );
    assert_eq!(
        check_of(&report, "lan_route_published")["status"],
        "warning"
    );
    assert_eq!(
        check_of(&report, "config_revision_consistent")["status"],
        "warning"
    );

    // Apply succeeds (OkBackend): ⑨ pass, ⑫ pass -- the detail still notes this is the control-plane view only.
    let (st, applied) = json_post(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions/3/apply"),
        json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(applied["apply_status"], "applied");

    let report = run(&c, &network_id).await;
    let published = check_of(&report, "lan_route_published");
    assert_eq!(published["status"], "pass", "{published}");
    assert!(
        published["detail"]
            .as_str()
            .unwrap()
            .contains("control-plane publication only"),
        "⑨ must not claim kernel state: {published}"
    );
    assert_eq!(
        check_of(&report, "config_revision_consistent")["status"],
        "pass"
    );
}

#[tokio::test]
async fn failed_apply_flags_route_and_revision_checks() {
    let c = ctx().await; // default placeholder backend: apply fails deterministically
    let (network_id, _device_id, token) = net_with_device(&c).await;
    heartbeat(&c, &token, &now_stamp()).await;
    let (st, _route) = json_post(
        &c,
        &format!("/api/v1/networks/{network_id}/routes"),
        json!({
            "gateway_device_id": _device_id,
            "destination_cidr": "192.168.1.0/24",
            "return_path_mode": "dual_route",
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, applied) = json_post(
        &c,
        &format!("/api/v1/networks/{network_id}/config-revisions/3/apply"),
        json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(applied["apply_status"], "failed");

    let report = run(&c, &network_id).await;
    // ⑨: route recorded but apply failed -- fail (recorded ≠ published).
    let published = check_of(&report, "lan_route_published");
    assert_eq!(published["status"], "fail", "{published}");
    // ⑫: the failed revision carries an error_summary (failure is visible, §10.3).
    let revision_check = check_of(&report, "config_revision_consistent");
    assert_eq!(revision_check["status"], "fail", "{revision_check}");
    assert!(
        revision_check["detail"]
            .as_str()
            .unwrap()
            .contains("no network backend configured"),
        "{revision_check}"
    );
}

// ---------------------------------------------------------------------------
// Snapshot persistence
// ---------------------------------------------------------------------------

#[tokio::test]
async fn runs_are_persisted_get_returns_the_latest() {
    let c = ctx().await;
    let (network_id, _device_id, token) = net_with_device(&c).await;

    // First run: device registered but handshake never observed -- ④ fail.
    let first = run(&c, &network_id).await;
    assert_eq!(check_of(&first, "recent_handshake")["status"], "fail");

    // Second run after the heartbeat reports a fresh handshake: ④ flips to pass -- the two snapshots differ in content
    // (not in time: db timestamps are second-precision, two runs within the same second share a timestamp).
    heartbeat(&c, &token, &now_stamp()).await;
    let second = run(&c, &network_id).await;
    assert_eq!(check_of(&second, "recent_handshake")["status"], "pass");
    assert_ne!(second["checks"], first["checks"]);

    // GET returns the **latest** one (the ④ pass snapshot, not the first run's fail snapshot).
    let (st, latest) = json_get(&c, &format!("/api/v1/networks/{network_id}/diagnostics")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(check_of(&latest, "recent_handshake")["status"], "pass");
    assert_eq!(latest["checks"], second["checks"]);

    // GET reads the snapshot: two consecutive reads agree (no implicit recompute).
    let (st, again) = json_get(&c, &format!("/api/v1/networks/{network_id}/diagnostics")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(again, latest);
}

// ---------------------------------------------------------------------------
// Alias conflicts (§12.7 item 10, domain-layer detection)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn alias_conflicts_detected_when_mappings_exist() {
    let c = ctx().await;
    let (network_id, device_id, _token) = net_with_device(&c).await;
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

    // Insert two alias mapping rows directly (simulating a dirty/hand-edited db -- the service write path
    // already rejects such overlaps at creation, the normal API cannot reach this state; the FK points at the just-created route),
    // building a bad config of "alias overlapping the overlay + aliases overlapping each other".
    for (id, alias_cidr) in [("al-1", "10.240.1.0/24"), ("al-2", "10.240.1.0/24")] {
        sqlx::query(
            "INSERT INTO alias_mappings (id, network_id, lan_route_id, alias_cidr, target_cidr, translation_mode, status, created_at)
             VALUES (?, ?, ?, ?, '192.168.1.0/24', 'dnat_snat', 'pending', '2026-10-15T00:00:00Z')",
        )
        .bind(id)
        .bind(&network_id)
        .bind(&route_id)
        .bind(alias_cidr)
        .execute(&c.pool)
        .await
        .unwrap();
    }

    let report = run(&c, &network_id).await;
    let alias_check = check_of(&report, "alias_prefix_conflict");
    assert_eq!(alias_check["status"], "fail", "{alias_check}");
    let detail = alias_check["detail"].as_str().unwrap();
    // The domain-layer conflict detail names the counterpart (ADR-004/§8.3, no silence).
    assert!(detail.contains("overlaps overlay"), "{detail}");
    assert!(detail.contains("overlaps alias"), "{detail}");
}
