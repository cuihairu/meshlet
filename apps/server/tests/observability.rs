//! Integration test: structured logging and metrics ([archive §17.1/§17.2](../../docs/review/chatgpt-2026-10-13.md)).
//!
//! Acceptance: §17.1 all eight fields present (structured fields, not string concatenation); §17.2 eight metrics observable,
//! with two independent sources (control-plane counters and data-plane gauges) each faithfully reflecting state.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt; // oneshot

const PASSWORD: &str = "bootstrap-password-123";
const OVERLAY: &str = "10.240.0.0/16";

#[derive(Clone)]
struct Ctx {
    app: Router,
    cookie: String,
}

async fn ctx() -> Ctx {
    // Install the log capture (idempotent): every op_log! / access log afterwards goes into the shared buffer.
    meshlet_server::telemetry::log_capture::install();
    let pool = meshlet_server::store::connect("sqlite::memory:")
        .await
        .unwrap();
    let mesh = std::sync::Arc::new(std::sync::Mutex::new(
        meshlet_server::service::MeshState::default(),
    ));
    let state = std::sync::Arc::new(meshlet_server::auth::AppState::new(
        mesh,
        meshlet_server::auth::AuthStore::new(pool.clone()),
        meshlet_server::agent::AgentTokenStore::new(pool.clone()),
        meshlet_server::api_token::ApiTokenStore::new(pool),
        false,
    ));
    let app = meshlet_server::router(state);

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "email": "admin@test.local", "password": PASSWORD }).to_string(),
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

async fn write(c: &Ctx, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    call(c, method, uri, Some(&c.cookie), true, body).await
}

/// Fetch the metrics text (admin-plane session; the endpoint is Prometheus plaintext, no JSON parsing).
async fn metrics(c: &Ctx) -> String {
    let res = c
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/system/metrics")
                .header("cookie", &c.cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(status, StatusCode::OK, "metrics endpoint failed");
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Captured structured log lines (only the `meshlet_server` target; dependency noise filtered out).
fn log_lines() -> Vec<Value> {
    meshlet_server::telemetry::log_capture::lines()
        .into_iter()
        .filter(|l| l["operation"].is_string())
        .collect()
}

fn events_with_operation<'a>(lines: &'a [Value], operation: &str) -> Vec<&'a Value> {
    lines
        .iter()
        .filter(|l| l["operation"].as_str() == Some(operation))
        .collect()
}

/// Locate events by operation + network (tests run in parallel, so instead of clearing the buffer we match by unique content).
fn find_event<'a>(lines: &'a [Value], operation: &str, network_id: &str) -> Option<&'a Value> {
    lines.iter().find(|l| {
        l["operation"].as_str() == Some(operation) && l["network_id"].as_str() == Some(network_id)
    })
}

fn field<'a>(line: &'a Value, key: &str) -> &'a Value {
    line.get(key).unwrap_or(&Value::Null)
}

/// Every captured event must carry the §17.1 eight fields (presence is enough, empty string counts as complete).
fn assert_eight_fields(line: &Value) {
    for key in [
        "time",
        "component",
        "operation",
        "network_id",
        "device_id",
        "config_revision",
        "error_category",
        "result",
    ] {
        assert!(
            line.get(key).is_some(),
            "log line missing field {key}: {line}"
        );
    }
}

/// The metrics endpoint is admin data: unauthenticated callers must not fetch it.
#[tokio::test]
async fn metrics_endpoint_requires_authentication() {
    let c = ctx().await;
    let (status, body) = call(&c, "GET", "/api/v1/system/metrics", None, false, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "unauthorized");
}

/// §17.2 control-plane counters: metrics really appear after operations advance (not static zeros).
#[tokio::test]
async fn control_plane_counters_reflect_operations() {
    let c = ctx().await;

    let (status, network) = write(
        &c,
        "POST",
        "/api/v1/networks",
        Some(json!({ "name": "home", "overlay_cidr": OVERLAY })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let network_id = network["id"].as_str().unwrap();

    // Config apply: no data-plane backend → deterministic failure (counted as failed).
    let (status, revisions) = call(
        &c,
        "GET",
        &format!("/api/v1/networks/{network_id}/config-revisions"),
        Some(&c.cookie),
        false,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let latest = revisions.as_array().unwrap().last().unwrap()["revision"]
        .as_u64()
        .unwrap();
    let (status, _) = write(
        &c,
        "POST",
        &format!("/api/v1/networks/{network_id}/config-revisions/{latest}/apply"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let text = metrics(&c).await;
    // Metrics 4/5: config-apply failure counts (counted by state-machine outcome, not by response code).
    assert!(
        text.contains("meshlet_config_apply_total{result=\"applied\"} 0"),
        "applied counter missing: {text}"
    );
    assert!(
        text.contains("meshlet_config_apply_total{result=\"failed\"} 1"),
        "failed counter missing: {text}"
    );
    // The success ratio is reported when there are samples (0/1 = 0).
    assert!(
        text.contains("meshlet_config_apply_success_ratio 0.0000"),
        "success ratio missing: {text}"
    );
    // Metric 8: server-side interface status (HTTP requests counted by route template; the metrics
    // endpoint's own request is only counted after rendering, so assertions use an earlier completed request).
    assert!(
        text.contains("meshlet_http_requests_total{method=\"POST\",route=\"/api/v1/networks\",status_class=\"2xx\"} 1"),
        "http requests counter missing: {text}"
    );
    let bytes_line = text
        .lines()
        .find(|l| l.starts_with("meshlet_http_response_bytes_total "))
        .expect("response bytes counter missing");
    let response_bytes: u64 = bytes_line.rsplit(' ').next().unwrap().parse().unwrap();
    assert!(
        response_bytes > 0,
        "response bytes must be counted: {bytes_line}"
    );
    // Control-plane gauges (all zero with no devices, but they must appear).
    assert!(text.contains("meshlet_devices_online 0"));
    assert!(text.contains("meshlet_devices_active 0"));
    assert!(text.contains("meshlet_alias_apply_status 0"));

    // §17.1 domain events: create_network carries network_id + config_revision.
    let lines = log_lines();
    let line =
        find_event(&lines, "create_network", network_id).expect("create_network event missing");
    assert_eight_fields(line);
    assert_eq!(field(line, "component"), "network");
    assert_eq!(field(line, "device_id"), "");
    assert_eq!(field(line, "result"), "ok");
    assert_eq!(field(line, "error_category"), "none");
}

/// §17.1 access logs: one entry per routed request, route template as operation, status derives the result.
#[tokio::test]
async fn access_log_lines_carry_route_template_and_status() {
    let c = ctx().await;

    // Both a 200 and a 404 (unauthenticated admin endpoint) must leave access logs.
    let _ = call(&c, "GET", "/api/v1/audit", Some(&c.cookie), false, None).await;
    let _ = call(&c, "GET", "/api/v1/audit", None, false, None).await;

    let lines = log_lines();
    let access_ok = events_with_operation(&lines, "/api/v1/audit");
    assert!(
        access_ok
            .iter()
            .any(|l| field(l, "result") == "ok" && field(l, "error_category") == "none"),
        "200 access log missing: {lines:?}"
    );
    assert!(
        access_ok
            .iter()
            .any(|l| field(l, "result") == "error" && field(l, "error_category") == "unauthorized"),
        "401 access log missing: {lines:?}"
    );
    for l in &access_ok {
        assert_eq!(field(l, "component"), "http");
        assert_eq!(field(l, "network_id"), "");
        assert_eight_fields(l);
    }
}

/// §17.2 data-plane gauges: after a device joins + heartbeats (carrying handshake readings), the online/active/handshake metrics
/// are computed on the fly from MeshState, so both independent sources (control-plane roster vs data-plane handshake) show up.
#[tokio::test]
async fn data_plane_gauges_are_computed_from_state() {
    let c = ctx().await;

    let (status, network) = write(
        &c,
        "POST",
        "/api/v1/networks",
        Some(json!({ "name": "home", "overlay_cidr": OVERLAY })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let network_id = network["id"].as_str().unwrap();

    let (status, invite) = write(
        &c,
        "POST",
        &format!("/api/v1/networks/{network_id}/invites"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, enrolled) = call(
        &c,
        "POST",
        "/api/v1/enroll",
        None,
        false,
        Some(json!({
            "invite_token": invite["token"],
            "device_name": "gateway",
            "public_key": "pub-observability-1",
            "platform": "linux",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let device_id = enrolled["device_id"].as_str().unwrap();
    let agent_token = enrolled["agent_token"].as_str().unwrap();

    // The heartbeat carries current handshake readings: tunnel evidence and agent evidence are both fresh.
    let now = meshlet_server::service::now();
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/v1/agent/heartbeat")
        .header("authorization", format!("Bearer {agent_token}"))
        .header("content-type", "application/json")
        .body(Body::from(json!({ "last_handshake_at": now }).to_string()))
        .unwrap();
    // §12: observe the direct-connect source address on heartbeat (ConnectInfo is assembled at the serve layer).
    req.extensions_mut().insert(axum::extract::ConnectInfo(
        "10.240.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
    ));
    let res = c.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let text = metrics(&c).await;
    // Metrics 1/2: online device count (agent evidence) and active peer count (Active in the roster).
    assert!(
        text.contains("meshlet_devices_online 1"),
        "devices_online gauge missing: {text}"
    );
    assert!(
        text.contains("meshlet_devices_active 1"),
        "devices_active gauge missing: {text}"
    );
    // Metric 3: last handshake time (Unix seconds > 0) and devices with recent handshakes (data-plane evidence).
    assert!(
        text.contains("meshlet_devices_with_recent_handshake 1"),
        "recent-handshake gauge missing: {text}"
    );
    let ts_line = text
        .lines()
        .find(|l| l.starts_with("meshlet_last_handshake_timestamp_seconds "))
        .expect("last_handshake gauge missing");
    let ts: i64 = ts_line.rsplit(' ').next().unwrap().parse().unwrap();
    assert!(
        ts > 0,
        "last handshake timestamp must be positive: {ts_line}"
    );
    // Metric 7: interface status (1 as soon as there is recent handshake evidence).
    assert!(
        text.contains("meshlet_interface_up 1"),
        "interface_up gauge missing: {text}"
    );

    // §17.1 agent events: device component, device_id populated, network_id filled when applicable.
    let lines = log_lines();
    let line = find_event(&lines, "heartbeat", network_id).expect("heartbeat event missing");
    assert_eight_fields(line);
    assert_eq!(field(line, "component"), "agent");
    assert_eq!(field(line, "device_id"), device_id);
    assert_eq!(field(line, "result"), "ok");
}

/// §17.2 route conflict count: only "destination segment overlap" conflicts are counted; a 409 for an inactive device does not count.
#[tokio::test]
async fn route_conflict_counter_counts_only_conflicts() {
    let c = ctx().await;

    let (status, network) = write(
        &c,
        "POST",
        "/api/v1/networks",
        Some(json!({ "name": "home", "overlay_cidr": OVERLAY })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let network_id = network["id"].as_str().unwrap();

    let (status, invite) = write(
        &c,
        "POST",
        &format!("/api/v1/networks/{network_id}/invites"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, enrolled) = call(
        &c,
        "POST",
        "/api/v1/enroll",
        None,
        false,
        Some(json!({
            "invite_token": invite["token"],
            "device_name": "gateway",
            "public_key": "pub-observability-2",
            "platform": "linux",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let device_id = enrolled["device_id"].as_str().unwrap();

    // A normal route creation: not a conflict.
    let (status, _) = write(
        &c,
        "POST",
        &format!("/api/v1/networks/{network_id}/routes"),
        Some(json!({
            "gateway_device_id": device_id,
            "destination_cidr": "192.168.10.0/24",
            "return_path_mode": "dual_route",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let text = metrics(&c).await;
    assert!(
        text.contains("meshlet_route_conflicts_total 0"),
        "conflict counter must start at 0: {text}"
    );

    // Overlapping an existing route: RouteConflict → count 1.
    let (status, _) = write(
        &c,
        "POST",
        &format!("/api/v1/networks/{network_id}/routes"),
        Some(json!({
            "gateway_device_id": device_id,
            "destination_cidr": "192.168.10.128/25",
            "return_path_mode": "dual_route",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let text = metrics(&c).await;
    assert!(
        text.contains("meshlet_route_conflicts_total 1"),
        "conflict counter must be 1: {text}"
    );

    // Revoked device → inactive gateway: still a 409, but not a route conflict, so the counter stays put.
    let (status, _) = write(
        &c,
        "POST",
        &format!("/api/v1/networks/{network_id}/devices/{device_id}/revoke"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (status, _) = write(
        &c,
        "POST",
        &format!("/api/v1/networks/{network_id}/routes"),
        Some(json!({
            "gateway_device_id": device_id,
            "destination_cidr": "192.168.20.0/24",
            "return_path_mode": "dual_route",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let text = metrics(&c).await;
    assert!(
        text.contains("meshlet_route_conflicts_total 1"),
        "inactive-gateway 409 must not be counted as conflict: {text}"
    );

    // Overlapping the overlay: a second conflict path → count 2.
    let (status, invite2) = write(
        &c,
        "POST",
        &format!("/api/v1/networks/{network_id}/invites"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, enrolled2) = call(
        &c,
        "POST",
        "/api/v1/enroll",
        None,
        false,
        Some(json!({
            "invite_token": invite2["token"],
            "device_name": "edge",
            "public_key": "pub-observability-3",
            "platform": "linux",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let edge_id = enrolled2["device_id"].as_str().unwrap();
    let (status, _) = write(
        &c,
        "POST",
        &format!("/api/v1/networks/{network_id}/routes"),
        Some(json!({
            "gateway_device_id": edge_id,
            "destination_cidr": "10.240.1.0/24",
            "return_path_mode": "dual_route",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let text = metrics(&c).await;
    assert!(
        text.contains("meshlet_route_conflicts_total 2"),
        "overlay-overlap conflict must be counted: {text}"
    );

    // §17.1: all three rejection paths (segment overlap / inactive gateway / overlay overlap)
    // leave error events, but only "destination segment overlap" feeds the conflict metric (asserted above).
    let lines = log_lines();
    let conflicts = events_with_operation(&lines, "create_route")
        .into_iter()
        .filter(|l| field(l, "result") == "error" && field(l, "network_id") == network_id)
        .collect::<Vec<_>>();
    assert_eq!(conflicts.len(), 3, "three rejected creates: {conflicts:?}");
    for l in conflicts {
        assert_eq!(field(l, "error_category"), "conflict");
        assert_eight_fields(l);
    }
}

/// §17.1 successful and failed logins both leave structured logs; failures carry the unauthorized category.
#[tokio::test]
async fn auth_events_are_structured() {
    let c = ctx().await;

    let (status, _) = call(
        &c,
        "POST",
        "/api/v1/auth/login",
        None,
        false,
        Some(json!({ "email": "admin@test.local", "password": "wrong-guess" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(
        &c,
        "POST",
        "/api/v1/auth/login",
        None,
        false,
        Some(json!({ "email": "admin@test.local", "password": PASSWORD })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let lines = log_lines();
    let logins = events_with_operation(&lines, "login");
    assert!(
        logins
            .iter()
            .any(|l| field(l, "result") == "error" && field(l, "error_category") == "unauthorized"),
        "failed login event missing: {lines:?}"
    );
    assert!(
        logins
            .iter()
            .any(|l| field(l, "result") == "ok" && field(l, "error_category") == "none"),
        "successful login event missing: {lines:?}"
    );
    for l in &logins {
        assert_eq!(field(l, "component"), "auth");
        assert_eight_fields(l);
    }
}
