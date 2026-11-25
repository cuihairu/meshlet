//! Integration tests: LAN route create/delete (the external API controls "route add/remove" entries, ADR-005).
//!
//! End to end: network + enrolled device as gateway -> POST route (return path mode required) ->
//! list / detail / delete. Routes belong to desired config: each create/delete records one revision (ADR-009),
//! and the response carries `revision_id` + `apply_status` — a DB write is not an effect; status waits for an explicit apply.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt; // oneshot

const OVERLAY: &str = "10.240.0.0/16";

#[derive(Clone)]
struct Ctx {
    app: Router,
    cookie: String,
    pool: sqlx::SqlitePool,
}

async fn ctx() -> Ctx {
    let pool = meshlet_server::store::connect("sqlite::memory:")
        .await
        .unwrap();
    let state = std::sync::Arc::new(meshlet_server::auth::AppState::new(
        meshlet_server::service::SharedState::default(),
        meshlet_server::auth::AuthStore::new(pool.clone()),
        meshlet_server::agent::AgentTokenStore::new(pool.clone()),
        meshlet_server::api_token::ApiTokenStore::new(pool.clone()),
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
    Ctx { app, cookie, pool }
}

async fn call(
    c: &Ctx,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    bearer: Option<&str>,
    csrf: bool,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    if let Some(bearer) = bearer {
        builder = builder.header("authorization", format!("Bearer {bearer}"));
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
    call(c, "POST", uri, Some(&c.cookie), None, true, Some(body)).await
}

async fn json_get(c: &Ctx, uri: &str) -> (StatusCode, Value) {
    call(c, "GET", uri, Some(&c.cookie), None, false, None).await
}

async fn json_delete(c: &Ctx, uri: &str) -> (StatusCode, Value) {
    call(c, "DELETE", uri, Some(&c.cookie), None, true, None).await
}

async fn create_network(c: &Ctx, name: &str, overlay: &str) -> String {
    let (st, body) = json_post(
        c,
        "/api/v1/networks",
        json!({"name": name, "overlay_cidr": overlay}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    body["id"].as_str().unwrap().to_string()
}

/// Create an invite + enroll one device; returns device_id (safe to call repeatedly on the same network).
async fn enroll(c: &Ctx, network_id: &str, name: &str, public_key: &str) -> String {
    let (st, invite) = json_post(
        c,
        &format!("/api/v1/networks/{network_id}/invites"),
        json!({"max_uses": 1}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{invite}");
    let (st, device) = json_post(
        c,
        "/api/v1/enroll",
        json!({
            "invite_token": invite["token"].as_str().unwrap(),
            "device_name": name,
            "public_key": public_key,
            "platform": "linux",
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{device}");
    device["device_id"].as_str().unwrap().to_string()
}

/// Create a network + invite + enroll one device; returns (network_id, device_id).
async fn net_with_device(c: &Ctx, name: &str, overlay: &str) -> (String, String) {
    let network_id = create_network(c, name, overlay).await;
    let device_id = enroll(
        c,
        &network_id,
        &format!("gw-{name}"),
        "pub-key-route-gateway",
    )
    .await;
    (network_id, device_id)
}

fn route_body(gateway: &str, destination: &str) -> Value {
    json!({
        "gateway_device_id": gateway,
        "destination_cidr": destination,
        "return_path_mode": "dual_route",
    })
}

#[tokio::test]
async fn create_route_records_pending_revision_and_carries_status() {
    let c = ctx().await;
    let (network_id, device_id) = net_with_device(&c, "home", OVERLAY).await;

    // net=1, enroll=2; the route is the third desired-config change -> revision 3.
    let (st, route) = json_post(
        &c,
        &format!("/api/v1/networks/{network_id}/routes"),
        route_body(&device_id, "192.168.1.0/24"),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    assert!(route["id"].as_str().unwrap().starts_with("rt-"));
    assert_eq!(route["network_id"], network_id.as_str());
    assert_eq!(route["gateway_device_id"], device_id.as_str());
    assert_eq!(route["destination_cidr"], "192.168.1.0/24");
    // ADR-005: the return path mode must be given explicitly; route_mode defaults to direct.
    assert_eq!(route["route_mode"], "direct");
    assert_eq!(route["return_path_mode"], "dual_route");
    // A DB write is not an effect: the new route waits for an explicit apply (ADR-009).
    assert_eq!(route["status"], "pending");
    assert_eq!(route["revision_id"], 3);
    assert_eq!(route["apply_status"], "pending");
}

#[tokio::test]
async fn destination_must_parse_and_not_overlap_the_overlay() {
    let c = ctx().await;
    let (network_id, device_id) = net_with_device(&c, "home", OVERLAY).await;
    let uri = format!("/api/v1/networks/{network_id}/routes");

    // Invalid CIDR -> 400.
    let (st, body) = json_post(&c, &uri, route_body(&device_id, "banana")).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "validation_failed");
    // Equal to the overlay or a subnet of it -> 409 (the overlay's own prefixes do not belong in the route table).
    for dst in [OVERLAY, "10.240.0.0/24"] {
        let (st, body) = json_post(&c, &uri, route_body(&device_id, dst)).await;
        assert_eq!(st, StatusCode::CONFLICT, "dst={dst}");
        assert_eq!(body["error"]["code"], "conflict");
    }
}

#[tokio::test]
async fn gateway_must_be_an_active_device_of_the_same_network() {
    let c = ctx().await;
    let (network_id, _device_id) = net_with_device(&c, "home", OVERLAY).await;
    // A device from another network is not a valid gateway.
    let (other_net, other_dev) = net_with_device(&c, "away", "10.241.0.0/16").await;

    let uri = format!("/api/v1/networks/{network_id}/routes");
    let (st, _) = json_post(&c, &uri, route_body("dev-999", "192.168.1.0/24")).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = json_post(&c, &uri, route_body(&other_dev, "192.168.1.0/24")).await;
    assert_eq!(
        st,
        StatusCode::NOT_FOUND,
        "device belongs to another network"
    );

    // A revoked device cannot act as a gateway.
    let (st, _) = json_post(
        &c,
        &format!("/api/v1/networks/{other_net}/devices/{other_dev}/revoke"),
        json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::ACCEPTED);
    let (st, _) = json_post(
        &c,
        &format!("/api/v1/networks/{other_net}/routes"),
        route_body(&other_dev, "192.168.2.0/24"),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
}

#[tokio::test]
async fn overlapping_destination_in_same_network_is_conflict() {
    let c = ctx().await;
    let (network_id, device_id) = net_with_device(&c, "home", OVERLAY).await;
    let uri = format!("/api/v1/networks/{network_id}/routes");

    let (st, route) = json_post(&c, &uri, route_body(&device_id, "192.168.1.0/24")).await;
    assert_eq!(st, StatusCode::CREATED);
    let route_id = route["id"].as_str().unwrap().to_string();

    // Exact duplicate prefix: 409 and the error names the conflicting party (existing route id + prefix, §8.3).
    let (st, body) = json_post(&c, &uri, route_body(&device_id, "192.168.1.0/24")).await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "conflict");
    let message = body["error"]["message"].as_str().unwrap();
    assert!(
        message.contains(&route_id) && message.contains("192.168.1.0/24"),
        "conflict message must name the existing route: {message}"
    );
    // An overlapping subnet conflicts too.
    let (st, _) = json_post(&c, &uri, route_body(&device_id, "192.168.1.0/25")).await;
    assert_eq!(st, StatusCode::CONFLICT);
    // Unknown gateways retain their 404 contract. Valid gateways cannot publish
    // a conflicting forwarding prefix from a different network in the same host.
    let other = create_network(&c, "m", "10.242.0.0/16").await;
    let uri = format!("/api/v1/networks/{other}/routes");
    let (st, _) = json_post(&c, &uri, route_body("dev-999", "192.168.1.0/24")).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let gateway = enroll(&c, &other, "other-gateway", "pub-other").await;
    let (st, _) = json_post(&c, &uri, route_body(&gateway, "192.168.1.0/24")).await;
    assert_eq!(st, StatusCode::CONFLICT);
}

/// ADR-006 flagship scenario: two sites each have a 192.168.1.0/24, both reachable via their own Alias.
/// Two Alias-mode routes with the same real prefix must both be accepted — the externally visible forwarding
/// prefix is the Alias (uniqueness guaranteed by `alias_alias_overlap` at alias creation), the real prefix never
/// enters the tunnel forwarding surface; but a same-prefix Direct route still conflicts (only one direct forwarder).
#[tokio::test]
async fn dual_alias_routes_share_the_same_real_lan() {
    let c = ctx().await;
    let network_id = create_network(&c, "home", OVERLAY).await;
    let uri = format!("/api/v1/networks/{network_id}/routes");

    // Two gateway devices: each from its own invite (invites are single-use).
    let site1 = enroll(&c, &network_id, "site1-gw", "pub-key-site1").await;
    let site2 = enroll(&c, &network_id, "site2-gw", "pub-key-site2").await;
    let alias_body = |gateway: &str| {
        json!({
            "gateway_device_id": gateway,
            "destination_cidr": "192.168.1.0/24",
            "return_path_mode": "controlled_snat",
            "route_mode": "alias",
        })
    };

    let (st, r1) = json_post(&c, &uri, alias_body(&site1)).await;
    assert_eq!(st, StatusCode::CREATED, "{r1}");
    let (st, r2) = json_post(&c, &uri, alias_body(&site2)).await;
    assert_eq!(
        st,
        StatusCode::CREATED,
        "same real lan at a second site: {r2}"
    );
    assert_ne!(r1["id"], r2["id"], "each site keeps its own route");

    // A third same-prefix route in Direct mode -> 409 naming the conflicting party (a direct real prefix has a single forwarder).
    let (st, body) = json_post(&c, &uri, route_body(&site2, "192.168.1.0/24")).await;
    assert_eq!(st, StatusCode::CONFLICT);
    let message = body["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("192.168.1.0/24") && message.contains("rt-1"),
        "conflict message must name the existing route: {message}"
    );
}

/// §8.3 "never overwrite an existing route": a rejected create leaves no trace — the route list is unchanged and
/// no new revision is produced (the rejection happens before any state change).
#[tokio::test]
async fn rejected_route_create_overwrites_nothing() {
    let c = ctx().await;
    let (network_id, device_id) = net_with_device(&c, "home", OVERLAY).await;
    let uri = format!("/api/v1/networks/{network_id}/routes");

    let (st, route) = json_post(&c, &uri, route_body(&device_id, "192.168.1.0/24")).await;
    assert_eq!(st, StatusCode::CREATED);
    let revisions_uri = format!("/api/v1/networks/{network_id}/config-revisions");
    let (_, before) = json_get(&c, &revisions_uri).await;
    let before_count = before.as_array().unwrap().len();

    for dst in ["192.168.1.0/24", "192.168.1.0/25", OVERLAY] {
        let (st, _) = json_post(&c, &uri, route_body(&device_id, dst)).await;
        assert_eq!(st, StatusCode::CONFLICT, "dst={dst}");
    }

    let (_, list) = json_get(&c, &uri).await;
    let list = list.as_array().unwrap();
    assert_eq!(list.len(), 1, "only the original route remains: {list:?}");
    assert_eq!(list[0]["id"], route["id"].as_str().unwrap());
    assert_eq!(list[0]["destination_cidr"], "192.168.1.0/24");
    let (_, after) = json_get(&c, &revisions_uri).await;
    assert_eq!(
        after.as_array().unwrap().len(),
        before_count,
        "a rejected create records no revision"
    );
}

#[tokio::test]
async fn list_and_detail_are_scoped_to_the_network() {
    let c = ctx().await;
    let (network_id, device_id) = net_with_device(&c, "home", OVERLAY).await;
    let other = create_network(&c, "away", "10.241.0.0/16").await;

    let (st, route) = json_post(
        &c,
        &format!("/api/v1/networks/{network_id}/routes"),
        route_body(&device_id, "192.168.1.0/24"),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let route_id = route["id"].as_str().unwrap().to_string();

    let (st, list) = json_get(&c, &format!("/api/v1/networks/{network_id}/routes")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 1);
    let (st, list) = json_get(&c, &format!("/api/v1/networks/{other}/routes")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 0);

    let (st, detail) = json_get(
        &c,
        &format!("/api/v1/networks/{network_id}/routes/{route_id}"),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(detail["id"], route_id.as_str());
    // Routes do not leak across networks.
    let (st, _) = json_get(&c, &format!("/api/v1/networks/{other}/routes/{route_id}")).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_route_removes_it_and_records_a_revision() {
    let c = ctx().await;
    let (network_id, device_id) = net_with_device(&c, "home", OVERLAY).await;
    let uri = format!("/api/v1/networks/{network_id}/routes");

    let (st, route) = json_post(&c, &uri, route_body(&device_id, "192.168.1.0/24")).await;
    assert_eq!(st, StatusCode::CREATED);
    let route_id = route["id"].as_str().unwrap().to_string();

    let (st, _) = json_delete(
        &c,
        &format!("/api/v1/networks/{network_id}/routes/{route_id}"),
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (_, list) = json_get(&c, &uri).await;
    assert_eq!(list.as_array().unwrap().len(), 0);

    // A delete is also a desired-config change -> a new revision; creating again keeps incrementing.
    let (st, route) = json_post(&c, &uri, route_body(&device_id, "192.168.2.0/24")).await;
    assert_eq!(st, StatusCode::CREATED);
    assert_eq!(
        route["revision_id"], 5,
        "net=1 enroll=2 create=3 delete=4 create=5"
    );
    // Duplicate delete -> 404.
    let (st, _) = json_delete(
        &c,
        &format!("/api/v1/networks/{network_id}/routes/{route_id}"),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn route_writes_require_write_scope_and_csrf() {
    let c = ctx().await;
    let (network_id, device_id) = net_with_device(&c, "home", OVERLAY).await;
    let uri = format!("/api/v1/networks/{network_id}/routes");

    // No credentials -> 401.
    let (st, body) = call(
        &c,
        "POST",
        &uri,
        None,
        None,
        true,
        Some(route_body(&device_id, "192.168.1.0/24")),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "unauthorized");

    // Cookie session but missing CSRF header -> 403 (the write-request guard grants no exemption).
    let (st, body) = call(
        &c,
        "POST",
        &uri,
        Some(&c.cookie),
        None,
        false,
        Some(route_body(&device_id, "192.168.1.0/24")),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "forbidden");

    // A read token cannot create routes.
    let (st, created) = call(
        &c,
        "POST",
        "/api/v1/auth/tokens",
        Some(&c.cookie),
        None,
        true,
        Some(json!({"name": "reader", "scopes": "read"})),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let token = created["token"].as_str().unwrap().to_string();

    // A read token can read but not write routes (least privilege).
    let (st, _) = call(&c, "GET", &uri, None, Some(&token), false, None).await;
    assert_eq!(st, StatusCode::OK);
    let (st, body) = call(
        &c,
        "POST",
        &uri,
        None,
        Some(&token),
        true,
        Some(route_body(&device_id, "192.168.1.0/24")),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "forbidden");
}

#[tokio::test]
async fn unknown_network_is_404_for_all_route_operations() {
    let c = ctx().await;
    let (st, body) = json_get(&c, "/api/v1/networks/nope/routes").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");
    let (st, _) = json_post(
        &c,
        "/api/v1/networks/nope/routes",
        route_body("dev-1", "192.168.1.0/24"),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = json_delete(&c, "/api/v1/networks/nope/routes/rt-1").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = json_get(&c, "/api/v1/networks/nope/routes/rt-1").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn host_forward_creates_and_removes_a_single_host_unit() {
    let c = ctx().await;
    let (network_id, device_id) = net_with_device(&c, "home", OVERLAY).await;
    let uri = format!("/api/v1/networks/{network_id}/host-forwards");
    let body = json!({
        "gateway_device_id": device_id,
        "target_ipv4": "192.168.1.23",
        "alias_ipv4": "10.241.1.23",
    });

    let (st, view) = json_post(&c, &uri, body.clone()).await;
    assert_eq!(st, StatusCode::CREATED, "{view}");
    assert_eq!(view["target_ipv4"], "192.168.1.23");
    assert_eq!(view["alias_ipv4"], "10.241.1.23");
    assert_eq!(view["translation_mode"], "dnat_snat");
    assert_eq!(view["status"], "pending");
    assert_eq!(view["revision_id"], 3);
    assert_eq!(view["apply_status"], "pending");
    let alias_id = view["id"].as_str().unwrap().to_string();

    // A Host Forward is a /32: one virtual host maps one real host, with no protocol/port trimming.
    let (routes_st, routes) = json_get(&c, &format!("/api/v1/networks/{network_id}/routes")).await;
    assert_eq!(routes_st, StatusCode::OK);
    let route = routes
        .as_array()
        .unwrap()
        .iter()
        .find(|route| route["destination_cidr"] == "192.168.1.23/32")
        .expect("/32 route");
    assert_eq!(route["route_mode"], "alias");
    assert_eq!(route["gateway_device_id"], device_id.as_str());
    let route_id = route["id"].as_str().unwrap().to_string();

    // Conflicts must happen before any state change: recreating the same alias /32 -> 409, and no new revision.
    let revisions_before = revision_count(&c, &network_id).await;
    let (st, error) = json_post(&c, &uri, body).await;
    assert_eq!(st, StatusCode::CONFLICT, "{error}");
    let message = error["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("overlaps existing alias") || message.contains("overlaps existing route"),
        "conflict names the existing unit: {error}"
    );
    assert_eq!(revision_count(&c, &network_id).await, revisions_before);

    // Deleting a Host Forward = one revision covering the alias + its bound route.
    let (st, _) = json_delete(
        &c,
        &format!("/api/v1/networks/{network_id}/host-forwards/{alias_id}"),
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (routes_st, routes) = json_get(&c, &format!("/api/v1/networks/{network_id}/routes")).await;
    assert_eq!(routes_st, StatusCode::OK);
    assert!(!routes
        .as_array()
        .unwrap()
        .iter()
        .any(|route| route["id"] == route_id.as_str()));
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

async fn forwarding_snapshot(c: &Ctx, networks: &[&str]) -> Value {
    let mut memory = Vec::new();
    for net in networks {
        for resource in ["routes", "aliases", "config-revisions"] {
            let (status, value) = json_get(c, &format!("/api/v1/networks/{net}/{resource}")).await;
            assert_eq!(status, StatusCode::OK);
            memory.push(value);
        }
    }
    let persisted: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM lan_routes), (SELECT COUNT(*) FROM alias_mappings), (SELECT COUNT(*) FROM config_revisions)"
    ).fetch_one(&c.pool).await.unwrap();
    json!({"memory": memory, "persisted": persisted})
}

#[tokio::test]
async fn host_forward_conflicts_do_not_write_partial_state() {
    let c = ctx().await;
    let (home, gateway) = net_with_device(&c, "home", OVERLAY).await;
    let (other, other_gateway) = net_with_device(&c, "other", "10.242.0.0/16").await;
    // Other-network Direct, Alias and Host Forward reserves are all visible.
    let (status, _) = json_post(
        &c,
        &format!("/api/v1/networks/{other}/routes"),
        route_body(&other_gateway, "10.250.1.0/24"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let mut route = route_body(&other_gateway, "192.168.70.0/24");
    route["route_mode"] = json!("alias");
    let (status, route) = json_post(&c, &format!("/api/v1/networks/{other}/routes"), route).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = json_post(
        &c,
        &format!("/api/v1/networks/{other}/aliases"),
        json!({"lan_route_id": route["id"], "alias_cidr": "10.250.2.0/24"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = json_post(&c, &format!("/api/v1/networks/{other}/host-forwards"), json!({"gateway_device_id": other_gateway, "target_ipv4":"192.168.71.5", "alias_ipv4":"10.250.3.5"})).await;
    assert_eq!(status, StatusCode::CREATED);
    for alias in ["10.242.1.5", "10.250.1.5", "10.250.2.5", "10.250.3.5"] {
        let before = forwarding_snapshot(&c, &[&home, &other]).await;
        let (status, error) = json_post(
            &c,
            &format!("/api/v1/networks/{home}/host-forwards"),
            json!({"gateway_device_id":gateway, "target_ipv4":"192.168.80.5", "alias_ipv4":alias}),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{alias}: {error}");
        assert_eq!(forwarding_snapshot(&c, &[&home, &other]).await, before);
    }
}
