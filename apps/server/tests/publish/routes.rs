//! Ports and HTTP routes: port conflicts are judged **per device** (same device + same port is 409, another
//! device on the same port is legal); HTTP route create-list-get-delete round trip and dedup; one HTTP listener
//! per device, one termination mode; TLS passthrough rejects the capabilities it cannot enforce (token / path prefix).

use axum::http::StatusCode;
use serde_json::json;

use super::*;

#[tokio::test]
async fn port_conflict_is_judged_per_device() {
    let ctx = memory_ctx().await;
    let (network_id, device_a, _) = provision(&ctx, "edge-a").await;
    let (device_b, _) = add_device(&ctx, &network_id, "edge-b", "test-public-key-2").await;

    let uri = format!("/api/v1/networks/{network_id}/publish/forwards");
    let forward = |protocol: &str, device_id: &str| {
        json!({
            "device_id": device_id,
            "protocol": protocol,
            "listener_address": "127.0.0.1:9100",
            "backend_address": "127.0.0.1:3100",
            "allowed_source_cidrs": ["10.240.0.0/16"]
        })
    };

    let (status, _, raw) = post(&ctx, &uri, forward("tcp", &device_a)).await;
    assert_eq!(status, StatusCode::CREATED, "first: {raw}");
    // Same device, same protocol, same listener: 409.
    let (status, body, _) = post(&ctx, &uri, forward("tcp", &device_a)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    // Same device, same listener, different protocol: legal (different sockets).
    let (status, _, raw) = post(&ctx, &uri, forward("udp", &device_a)).await;
    assert_eq!(status, StatusCode::CREATED, "udp on the same port: {raw}");
    // Same network, another device on the same port: legal (port conflicts are judged per device).
    let (status, _, raw) = post(&ctx, &uri, forward("tcp", &device_b)).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "another device may bind it: {raw}"
    );
}

#[tokio::test]
async fn http_route_lifecycle_and_duplicate_rejected() {
    let ctx = memory_ctx().await;
    let (network_id, device_id, _) = provision(&ctx, "edge-1").await;
    let uri = format!("/api/v1/networks/{network_id}/publish/http-routes");

    let (status, created, raw) = post(
        &ctx,
        &uri,
        json!({
            "device_id": device_id,
            "hostname": "app.mesh",
            "path_prefix": "/api",
            "backend_address": "127.0.0.1:8080",
            "listener_address": "127.0.0.1:80",
            "allowed_source_cidrs": ["10.240.0.0/16"],
            "allowed_bearer_tokens": ["s3cret"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create: {raw}");
    assert_eq!(created["id"].as_str().unwrap(), "hr-1");
    assert_eq!(created["hostname"], "app.mesh");
    assert_eq!(created["path_prefix"], "/api");
    assert_eq!(created["tls_passthrough"], false);
    assert_eq!(created["allowed_bearer_token_count"], 1);
    assert!(!raw.contains("s3cret"), "tokens must not be echoed: {raw}");

    // A publish object with neither a source CIDR nor a bearer token is always rejected (it would be open to everyone).
    let (status, body, _) = post(
        &ctx,
        &uri,
        json!({
            "device_id": device_id,
            "hostname": "open.mesh",
            "path_prefix": "/",
            "backend_address": "127.0.0.1:8082",
            "listener_address": "127.0.0.1:80"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // Hostname is case-insensitive + same path_prefix: 409.
    let (status, body, _) = post(
        &ctx,
        &uri,
        json!({
            "device_id": device_id,
            "hostname": "App.Mesh",
            "path_prefix": "/api",
            "backend_address": "127.0.0.1:8081",
            "listener_address": "127.0.0.1:80",
            "allowed_source_cidrs": ["10.240.0.0/16"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "duplicate route: {body}");

    let (status, detail) = get(&ctx, &format!("{uri}/hr-1")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["backend_address"], "127.0.0.1:8080");
    let (status, body) = delete(&ctx, &format!("{uri}/hr-1")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = get(&ctx, &format!("{uri}/hr-1")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

/// A device may have only one HTTP listener and one termination mode: the plan carries a single `http_listener`, so
/// a second listener address would not bind; mixing in a TLS route flips the whole device into SNI sniffing.
/// Silent dropping is unacceptable — always 409 (the same stance as the DNS socket).
#[tokio::test]
async fn http_route_shares_one_listener_and_mode_per_device() {
    let ctx = memory_ctx().await;
    let (network_id, device_id, _) = provision(&ctx, "edge-1").await;
    let uri = format!("/api/v1/networks/{network_id}/publish/http-routes");
    let route = json!({
        "device_id": device_id,
        "hostname": "one.mesh",
        "path_prefix": "/",
        "backend_address": "127.0.0.1:8080",
        "listener_address": "127.0.0.1:80",
        "allowed_source_cidrs": ["10.240.0.0/16"],
        "tls_passthrough": false
    });

    let (status, created, raw) = post(&ctx, &uri, route.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "baseline: {raw}");
    assert_eq!(created["id"], "hr-1");

    // Same device, different listener: the plan binds only the first route's address -> 409.
    let mut other_listener = route.clone();
    other_listener["hostname"] = json!("port.mesh");
    other_listener["listener_address"] = json!("127.0.0.1:81");
    let (status, body, _) = post(&ctx, &uri, other_listener).await;
    assert_eq!(status, StatusCode::CONFLICT, "two listeners: {body}");
    assert!(
        body.to_string().contains("one http listener per device"),
        "{body}"
    );

    // Same device, mixing in a TLS route: flips the whole device into SNI sniffing -> 409.
    let mut tls = route.clone();
    tls["hostname"] = json!("tls.mesh");
    tls["tls_passthrough"] = json!(true);
    let (status, body, _) = post(&ctx, &uri, tls).await;
    assert_eq!(status, StatusCode::CONFLICT, "mixed tls: {body}");
    assert!(
        body.to_string().contains("one termination mode per device"),
        "{body}"
    );

    // Same listener, same mode: legal (multiple hostnames share one listener).
    let mut second = route.clone();
    second["hostname"] = json!("two.mesh");
    let (status, second_created, raw) = post(&ctx, &uri, second).await;
    assert_eq!(status, StatusCode::CREATED, "same listener+mode: {raw}");
    assert_eq!(second_created["id"], "hr-2");

    // A different device is unaffected (listener/mode are both judged per device).
    let (device_b, _) = add_device(&ctx, &network_id, "edge-2", "test-public-key-2").await;
    let mut on_other = route.clone();
    on_other["device_id"] = json!(device_b);
    on_other["hostname"] = json!("other.mesh");
    on_other["listener_address"] = json!("127.0.0.1:8081");
    on_other["tls_passthrough"] = json!(true);
    let (status, other_created, raw) = post(&ctx, &uri, on_other).await;
    assert_eq!(status, StatusCode::CREATED, "other device: {raw}");
    assert_eq!(other_created["tls_passthrough"], true);

    let (status, list) = get(&ctx, &uri).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 3);
}

/// M1 rename and capability rejection. Passthrough is SNI sniffing + raw TLS byte forwarding; meshlet holds no
/// certificates and does not decrypt: capabilities it cannot enforce (bearer token, non-`/` path prefix) are rejected
/// at create time with 409 rather than silently ignored; the legacy field name `tls_termination` is still mapped.
#[tokio::test]
async fn tls_passthrough_rejects_capabilities_it_cannot_enforce() {
    let ctx = memory_ctx().await;
    let (network_id, device_id, _) = provision(&ctx, "edge-1").await;
    let uri = format!("/api/v1/networks/{network_id}/publish/http-routes");

    // Legacy field mapping: the request carries `tls_termination` (pre-M1 callers), and the response only emits the new name.
    let (status, created, raw) = post(
        &ctx,
        &uri,
        json!({
            "device_id": device_id,
            "hostname": "legacy.mesh",
            "path_prefix": "/",
            "backend_address": "127.0.0.1:8443",
            "listener_address": "127.0.0.1:443",
            "allowed_source_cidrs": ["10.240.0.0/16"],
            "tls_termination": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "legacy field alias: {raw}");
    assert_eq!(created["tls_passthrough"], true);
    assert!(created.get("tls_termination").is_none());

    // Writing both names at once is self-contradictory (the alias maps to one field): the request parsing layer
    // rejects duplicate fields (422, not an application error, body not a JSON envelope).
    let (status, body, _) = post(
        &ctx,
        &uri,
        json!({
            "device_id": device_id,
            "hostname": "both.mesh",
            "path_prefix": "/",
            "backend_address": "127.0.0.1:8446",
            "listener_address": "127.0.0.1:443",
            "allowed_source_cidrs": ["10.240.0.0/16"],
            "tls_passthrough": true,
            "tls_termination": true
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "both old and new name: {body}"
    );

    // A token can never be verified on opaque TLS bytes -> 409.
    let (status, body, _) = post(
        &ctx,
        &uri,
        json!({
            "device_id": device_id,
            "hostname": "token.mesh",
            "path_prefix": "/",
            "backend_address": "127.0.0.1:8444",
            "listener_address": "127.0.0.1:443",
            "allowed_source_cidrs": ["10.240.0.0/16"],
            "allowed_bearer_tokens": ["s3cret"],
            "tls_passthrough": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("never terminates TLS"), "{body}");

    // A path prefix never participates in matching under SNI routing -> 409.
    let (status, body, _) = post(
        &ctx,
        &uri,
        json!({
            "device_id": device_id,
            "hostname": "path.mesh",
            "path_prefix": "/api",
            "backend_address": "127.0.0.1:8445",
            "listener_address": "127.0.0.1:443",
            "allowed_source_cidrs": ["10.240.0.0/16"],
            "tls_passthrough": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("never matches a path"), "{body}");

    // Plain HTTP routes are unaffected: tokens and path prefixes work as usual (use a different device to dodge the mode 409).
    let (device_b, _) = add_device(&ctx, &network_id, "edge-2", "test-public-key-2").await;
    let (status, created, raw) = post(
        &ctx,
        &uri,
        json!({
            "device_id": device_b,
            "hostname": "plain.mesh",
            "path_prefix": "/api",
            "backend_address": "127.0.0.1:8080",
            "listener_address": "127.0.0.1:80",
            "allowed_source_cidrs": ["10.240.0.0/16"],
            "allowed_bearer_tokens": ["s3cret"],
            "tls_passthrough": false
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "plain keeps features: {raw}");
    assert_eq!(created["tls_passthrough"], false);
    assert_eq!(created["allowed_bearer_token_count"], 1);
}
