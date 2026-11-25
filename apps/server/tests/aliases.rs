//! Integration test: Alias mapping create/delete (§12.6 ownership and cleanup / ADR-006).
//!
//! End to end: alias-mode route → POST Alias (target is derived from the bound route, the client cannot
//! specify it; prefix lengths must match; must not overlap the overlay, an existing Alias, or an existing route's destination) → list /
//! detail → deletion cleans up the whole unit (Alias + bound route, one revision) → route deletion / device
//! revocation cascade cleanup → rebuild after restart. The written data flows into diagnostics check 10 (§12.7).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt; // oneshot

const OVERLAY: &str = "10.240.0.0/16";

// ---------------------------------------------------------------------------
// Helpers (same shape as routes.rs)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Ctx {
    app: Router,
    cookie: String,
}

async fn ctx() -> Ctx {
    let pool = meshlet_server::store::connect("sqlite::memory:")
        .await
        .unwrap();
    let state = std::sync::Arc::new(meshlet_server::auth::AppState::new(
        meshlet_server::service::SharedState::default(),
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
                    json!({"email": "admin@test.local", "password": "bootstrap-password-123"})
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

async fn json_post(c: &Ctx, uri: &str, body: Value) -> (StatusCode, Value) {
    call(c, "POST", uri, Some(&c.cookie), true, Some(body)).await
}

async fn json_get(c: &Ctx, uri: &str) -> (StatusCode, Value) {
    call(c, "GET", uri, Some(&c.cookie), false, None).await
}

async fn json_delete(c: &Ctx, uri: &str) -> (StatusCode, Value) {
    call(c, "DELETE", uri, Some(&c.cookie), true, None).await
}

async fn net_with_device(c: &Ctx, name: &str, overlay: &str) -> (String, String) {
    let (st, network) = json_post(
        c,
        "/api/v1/networks",
        json!({"name": name, "overlay_cidr": overlay}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let network_id = network["id"].as_str().unwrap().to_string();
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
            "device_name": format!("gw-{name}"),
            "public_key": format!("pub-key-alias-{name}"),
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

/// Create an alias-mode route (destination = the real LAN segment).
async fn alias_route(c: &Ctx, network_id: &str, gateway: &str, destination: &str) -> String {
    let (st, route) = json_post(
        c,
        &format!("/api/v1/networks/{network_id}/routes"),
        json!({
            "gateway_device_id": gateway,
            "destination_cidr": destination,
            "route_mode": "alias",
            "return_path_mode": "dual_route",
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{route}");
    route["id"].as_str().unwrap().to_string()
}

async fn create_alias(
    c: &Ctx,
    network_id: &str,
    route_id: &str,
    alias_cidr: &str,
) -> (StatusCode, Value) {
    json_post(
        c,
        &format!("/api/v1/networks/{network_id}/aliases"),
        json!({"lan_route_id": route_id, "alias_cidr": alias_cidr}),
    )
    .await
}

/// Build a complete unit: network + device + alias route (192.168.1.0/24) + Alias
/// (10.0.1.0/24). Returns (network_id, device_id, route_id, alias_id).
async fn unit(c: &Ctx) -> (String, String, String, String) {
    let (network_id, device_id) = net_with_device(c, "home", OVERLAY).await;
    let route_id = alias_route(c, &network_id, &device_id, "192.168.1.0/24").await;
    let (st, alias) = create_alias(c, &network_id, &route_id, "10.0.1.0/24").await;
    assert_eq!(st, StatusCode::CREATED, "{alias}");
    (
        network_id,
        device_id,
        route_id,
        alias["id"].as_str().unwrap().to_string(),
    )
}

async fn alias_list(c: &Ctx, network_id: &str) -> Vec<Value> {
    let (st, body) = json_get(c, &format!("/api/v1/networks/{network_id}/aliases")).await;
    assert_eq!(st, StatusCode::OK);
    body.as_array().unwrap().clone()
}

async fn revision_count(c: &Ctx, network_id: &str) -> usize {
    let (st, body) = json_get(
        c,
        &format!("/api/v1/networks/{network_id}/config-revisions"),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    body.as_array().unwrap().len()
}

// ---------------------------------------------------------------------------
// Creation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_alias_derives_target_and_records_revision() {
    let c = ctx().await;
    let (network_id, _device_id, route_id, _) = unit(&c).await;

    // net=1, enroll=2, route=3, alias=4; the target is derived from the route (192.168.1.0/24).
    let list = alias_list(&c, &network_id).await;
    assert_eq!(list.len(), 1);
    let alias = &list[0];
    assert_eq!(alias["id"], "al-2");
    assert_eq!(alias["network_id"], network_id.as_str());
    assert_eq!(alias["lan_route_id"], route_id.as_str());
    assert_eq!(alias["alias_cidr"], "10.0.1.0/24");
    assert_eq!(alias["target_cidr"], "192.168.1.0/24");
    // translation_mode defaults to dnat_snat (ADR-006); a DB write is not an apply → pending.
    assert_eq!(alias["translation_mode"], "dnat_snat");
    assert_eq!(alias["status"], "pending");
    assert_eq!(alias["revision_id"], 4);
    assert_eq!(alias["apply_status"], "pending");

    // Detail matches the list; another network's list is empty (per-network isolation).
    let (st, detail) = json_get(&c, &format!("/api/v1/networks/{network_id}/aliases/al-2")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(detail, *alias);
    let (other_net, _) = net_with_device(&c, "away", "10.241.0.0/16").await;
    assert!(alias_list(&c, &other_net).await.is_empty());
}

#[tokio::test]
async fn prefix_length_must_equal_target_and_must_differ() {
    let c = ctx().await;
    let (network_id, device_id) = net_with_device(&c, "home", OVERLAY).await;
    let route_id = alias_route(&c, &network_id, &device_id, "192.168.1.0/24").await;

    // Equal-length requirement (ADR-006): /23 ≠ /24 → 400, the message names both prefix lengths.
    let (st, body) = create_alias(&c, &network_id, &route_id, "10.0.2.0/23").await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
    let message = body["error"]["message"].as_str().unwrap();
    assert!(message.contains("prefix length mismatch"), "{message}");

    // A segment identical to the target has no translation semantics → 400.
    let (st, body) = create_alias(&c, &network_id, &route_id, "192.168.1.0/24").await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
    let message = body["error"]["message"].as_str().unwrap();
    assert!(message.contains("must not equal"), "{message}");
}

#[tokio::test]
async fn alias_binds_only_alias_mode_routes_of_this_network() {
    let c = ctx().await;
    let (network_id, device_id) = net_with_device(&c, "home", OVERLAY).await;

    // A direct-mode route cannot be bound (§5: alias mode means "via a virtual prefix").
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
    let (st, body) = create_alias(&c, &network_id, &route_id, "10.0.1.0/24").await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
    let message = body["error"]["message"].as_str().unwrap();
    assert!(message.contains("route_mode"), "{message}");

    // Unknown route → 404; a route from another network is also 404.
    let (st, _) = create_alias(&c, &network_id, "rt-999", "10.0.1.0/24").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (other_net, other_dev) = net_with_device(&c, "away", "10.241.0.0/16").await;
    let other_route = alias_route(&c, &other_net, &other_dev, "192.168.9.0/24").await;
    let (st, _) = create_alias(&c, &network_id, &other_route, "10.0.1.0/24").await;
    assert_eq!(
        st,
        StatusCode::NOT_FOUND,
        "route belongs to another network"
    );
}

#[tokio::test]
async fn overlapping_prefixes_are_conflicts_naming_the_counterpart() {
    let c = ctx().await;
    let (network_id, device_id) = net_with_device(&c, "home", OVERLAY).await;
    let route1 = alias_route(&c, &network_id, &device_id, "192.168.1.0/24").await;
    let route2 = alias_route(&c, &network_id, &device_id, "192.168.2.0/24").await;

    // (1) Overlapping the overlay → 409.
    let (st, body) = create_alias(&c, &network_id, &route1, "10.240.5.0/24").await;
    assert_eq!(st, StatusCode::CONFLICT, "{body}");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("overlaps overlay"));

    // (2) Overlapping an existing route's destination (the virtual prefix must stay disjoint from the real LAN space) → 409.
    let (st, body) = create_alias(&c, &network_id, &route1, "192.168.2.0/24").await;
    assert_eq!(st, StatusCode::CONFLICT, "{body}");
    let message = body["error"]["message"].as_str().unwrap();
    assert!(
        message.contains(&route2) && message.contains("192.168.2.0/24"),
        "must name the conflicting route: {message}"
    );

    // (3) Overlapping an existing Alias → 409, the message names the other Alias (under the equal-length constraint, overlap means the same segment).
    let (st, first) = create_alias(&c, &network_id, &route1, "10.0.1.0/24").await;
    assert_eq!(st, StatusCode::CREATED);
    let first_id = first["id"].as_str().unwrap().to_string();
    let (st, body) = create_alias(&c, &network_id, &route2, "10.0.1.0/24").await;
    assert_eq!(st, StatusCode::CONFLICT, "{body}");
    let message = body["error"]["message"].as_str().unwrap();
    assert!(
        message.contains(&first_id) && message.contains("10.0.1.0/24"),
        "must name the existing alias: {message}"
    );

    // (4) Binding the same route twice → 409 (one-to-one unit, §12.6).
    let (st, body) = create_alias(&c, &network_id, &route1, "10.0.2.0/24").await;
    assert_eq!(st, StatusCode::CONFLICT, "{body}");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("one mapping per route"));
}

#[tokio::test]
async fn rejected_create_leaves_no_trace() {
    let c = ctx().await;
    let (network_id, device_id, _route_id, _) = unit(&c).await;

    // After an overlap rejection: the list is unchanged and no new revision is created (§8.3 rejects before any state change).
    let other_route = alias_route(&c, &network_id, &device_id, "192.168.2.0/24").await;
    let before = revision_count(&c, &network_id).await;
    let (st, _) = create_alias(&c, &network_id, &other_route, "10.0.1.0/24").await;
    assert_eq!(st, StatusCode::CONFLICT);

    assert_eq!(alias_list(&c, &network_id).await.len(), 1);
    assert_eq!(
        revision_count(&c, &network_id).await,
        before,
        "rejected create records no revision"
    );
}

// ---------------------------------------------------------------------------
// Deletion and cascade (§12.6 ownership)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_alias_removes_the_whole_unit_in_one_revision() {
    let c = ctx().await;
    let (network_id, _device_id, route_id, alias_id) = unit(&c).await;
    let before = revision_count(&c, &network_id).await;

    let (st, _) = json_delete(
        &c,
        &format!("/api/v1/networks/{network_id}/aliases/{alias_id}"),
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);

    // The whole unit: Alias and bound route disappear together.
    assert!(alias_list(&c, &network_id).await.is_empty());
    let (st, _) = json_get(
        &c,
        &format!("/api/v1/networks/{network_id}/aliases/{alias_id}"),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = json_get(
        &c,
        &format!("/api/v1/networks/{network_id}/routes/{route_id}"),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    // Exactly one new revision (deleting the Alias and deleting the route are not two changes).
    assert_eq!(revision_count(&c, &network_id).await, before + 1);

    // Deleting again → 404; an Alias under an unknown network → 404.
    let (st, _) = json_delete(
        &c,
        &format!("/api/v1/networks/{network_id}/aliases/{alias_id}"),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = json_delete(&c, &format!("/api/v1/networks/net-x/aliases/{alias_id}")).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn deleting_route_cascades_its_alias() {
    let c = ctx().await;
    let (network_id, _device_id, route_id, alias_id) = unit(&c).await;

    let (st, _) = json_delete(
        &c,
        &format!("/api/v1/networks/{network_id}/routes/{route_id}"),
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);

    // The route is gone, so the Alias bound to it must not be left orphaned.
    assert!(alias_list(&c, &network_id).await.is_empty());
    let (st, _) = json_get(
        &c,
        &format!("/api/v1/networks/{network_id}/aliases/{alias_id}"),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn revoking_device_cascades_routes_and_aliases() {
    let c = ctx().await;
    let (network_id, device_id, _route_id, _alias_id) = unit(&c).await;

    let (st, _) = json_post(
        &c,
        &format!("/api/v1/networks/{network_id}/devices/{device_id}/revoke"),
        json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::ACCEPTED);

    // §11.5 + §12.6: revoking the gateway clears its routes and bound Aliases along with it.
    assert!(alias_list(&c, &network_id).await.is_empty());
    let (st, routes) = json_get(&c, &format!("/api/v1/networks/{network_id}/routes")).await;
    assert_eq!(st, StatusCode::OK);
    assert!(routes.as_array().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Restart rebuild (§17.3)
// ---------------------------------------------------------------------------

static DB_SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn db_file(tag: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "meshlet-aliases-{}-{tag}-{}.db",
        std::process::id(),
        DB_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ))
}

fn cleanup_db(path: &std::path::Path) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

/// File-backed db + restart rebuild (same shape as recovery.rs: boot → bootstrap or login).
async fn open_app(db: &std::path::Path) -> Ctx {
    let url = format!("sqlite:{}", db.display());
    let pool = meshlet_server::store::connect(&url).await.unwrap();
    let boot = meshlet_server::persist::load(&pool, meshlet_domain::PresenceThresholds::default())
        .await
        .unwrap();
    let state = std::sync::Arc::new(meshlet_server::auth::AppState::new(
        std::sync::Arc::new(std::sync::Mutex::new(boot.mesh)),
        meshlet_server::auth::AuthStore::new(pool.clone()),
        meshlet_server::agent::AgentTokenStore::new(pool.clone()),
        meshlet_server::api_token::ApiTokenStore::new(pool),
        false,
    ));
    let app = meshlet_server::router(state);
    let auth_body = || {
        Body::from(
            json!({"email": "admin@test.local", "password": "bootstrap-password-123"}).to_string(),
        )
    };
    // bootstrap (201 on an empty db) or login (after restart) -- the session comes from Set-Cookie either way.
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/bootstrap")
                .header("content-type", "application/json")
                .body(auth_body())
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
                    .body(auth_body())
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
    Ctx { app, cookie }
}

#[tokio::test]
async fn restart_rebuilds_aliases_and_never_reuses_ids() {
    let db = db_file("restart");
    let c = open_app(&db).await;
    let (network_id, device_id, route_id, alias_id) = unit(&c).await;
    let before = alias_list(&c, &network_id).await;
    drop(c);

    // Restart: Aliases are rebuilt field by field.
    let c = open_app(&db).await;
    let after = alias_list(&c, &network_id).await;
    assert_eq!(after.len(), 1, "alias survives restart");
    assert_eq!(after[0], before[0], "field-by-field rebuild");

    // Rebuild after deletion: the id sequence never rolls back (al-2 is not reused; new route rt-3, new Alias al-4).
    let (st, _) = json_delete(
        &c,
        &format!("/api/v1/networks/{network_id}/aliases/{alias_id}"),
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let route_id2 = alias_route(&c, &network_id, &device_id, "192.168.3.0/24").await;
    assert_ne!(route_id2, route_id);
    assert!(route_id2.starts_with("rt-"), "{route_id2}");
    let (st, alias2) = create_alias(&c, &network_id, &route_id2, "10.0.3.0/24").await;
    assert_eq!(st, StatusCode::CREATED, "{alias2}");
    assert_ne!(alias2["id"].as_str().unwrap(), alias_id);
    assert!(
        alias2["id"].as_str().unwrap().starts_with("al-"),
        "{}",
        alias2["id"]
    );

    cleanup_db(&db);
}

// ---------------------------------------------------------------------------
// Diagnostics integration (§12.7 item 10)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn write_path_aliases_flow_into_diagnostics_check() {
    let c = ctx().await;
    let (network_id, _device_id, _route_id, _alias_id) = unit(&c).await;

    // Clean Aliases produced by the write path: item 10 passes the per-entry check (no longer not_applicable).
    let (st, report) = json_post(
        &c,
        &format!("/api/v1/networks/{network_id}/diagnostics"),
        json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{report}");
    let check = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|chk| chk["id"] == "alias_prefix_conflict")
        .expect("alias check present");
    assert_eq!(check["status"], "pass", "{check}");
    assert!(
        check["detail"]
            .as_str()
            .unwrap()
            .contains("1 alias mapping"),
        "{check}"
    );
}

// ---------------------------------------------------------------------------
// Gates
// ---------------------------------------------------------------------------

#[tokio::test]
async fn alias_endpoints_require_auth_and_csrf() {
    let c = ctx().await;
    let (network_id, _device_id, _route_id, _) = unit(&c).await;

    // No session → 401; a write missing the CSRF header → 403.
    let (st, _) = call(
        &c,
        "GET",
        &format!("/api/v1/networks/{network_id}/aliases"),
        None,
        false,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (st, _) = call(
        &c,
        "POST",
        &format!("/api/v1/networks/{network_id}/aliases"),
        Some(&c.cookie),
        false,
        Some(json!({"lan_route_id": "rt-1", "alias_cidr": "10.0.9.0/24"})),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, _) = call(
        &c,
        "DELETE",
        &format!("/api/v1/networks/{network_id}/aliases/al-2"),
        Some(&c.cookie),
        false,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}
