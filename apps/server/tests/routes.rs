//! 集成测试：LAN 路由增删（外部 API 控制「路由增删」条目，ADR-005）。
//!
//! 端到端：网络 + 已加入设备作网关 → POST 路由（返回路径模式必选）→
//! 列表 / 详情 / 删除。路由属于期望配置：增删各记录一个修订（ADR-009），
//! 响应携带 `revision_id` + `apply_status`——DB 写入 ≠ 生效，状态待显式 apply。

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

/// 建网络 + 邀请 + 加入一台设备，返回 (network_id, device_id)。
async fn net_with_device(c: &Ctx, name: &str, overlay: &str) -> (String, String) {
    let network_id = create_network(c, name, overlay).await;
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
            "public_key": "pub-key-route-gateway",
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

    // net=1、enroll=2，路由是第三次期望配置变更 → revision 3。
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
    // ADR-005：返回路径模式必须显式给定；route_mode 缺省 direct。
    assert_eq!(route["route_mode"], "direct");
    assert_eq!(route["return_path_mode"], "dual_route");
    // DB 写入 ≠ 生效：新路由待显式 apply（ADR-009）。
    assert_eq!(route["status"], "pending");
    assert_eq!(route["revision_id"], 3);
    assert_eq!(route["apply_status"], "pending");
}

#[tokio::test]
async fn destination_must_parse_and_not_overlap_the_overlay() {
    let c = ctx().await;
    let (network_id, device_id) = net_with_device(&c, "home", OVERLAY).await;
    let uri = format!("/api/v1/networks/{network_id}/routes");

    // 非法 CIDR → 400。
    let (st, body) = json_post(&c, &uri, route_body(&device_id, "banana")).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "validation_failed");
    // 与 overlay 相同或为其子网 → 409（overlay 自己的路由不该进路由表）。
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
    // 另一个网络里的设备不是合法网关。
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

    // 已撤销设备不能当网关。
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

    // 同网段重复：409 且错误消息点名冲突对端（既有路由 id + 网段，§8.3）。
    let (st, body) = json_post(&c, &uri, route_body(&device_id, "192.168.1.0/24")).await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "conflict");
    let message = body["error"]["message"].as_str().unwrap();
    assert!(
        message.contains(&route_id) && message.contains("192.168.1.0/24"),
        "conflict message must name the existing route: {message}"
    );
    // 子网重叠同样冲突。
    let (st, _) = json_post(&c, &uri, route_body(&device_id, "192.168.1.0/25")).await;
    assert_eq!(st, StatusCode::CONFLICT);
    // 其他网络不受影响。
    let (st, _) = json_post(
        &c,
        &format!(
            "/api/v1/networks/{}/routes",
            create_network(&c, "m", "10.242.0.0/16").await
        ),
        route_body("dev-999", "192.168.1.0/24"),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

/// §8.3「不覆盖已有路由」：被拒绝的创建不留下任何痕迹——路由列表不变、
/// 不产生新修订（拒绝发生在任何状态变更之前）。
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
    // 路由不串网络。
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

    // 删除也是期望配置变更 → 新修订；再建路由版本继续递增。
    let (st, route) = json_post(&c, &uri, route_body(&device_id, "192.168.2.0/24")).await;
    assert_eq!(st, StatusCode::CREATED);
    assert_eq!(
        route["revision_id"], 5,
        "net=1 enroll=2 create=3 delete=4 create=5"
    );
    // 重复删除 → 404。
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

    // 无凭证 → 401。
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

    // Cookie 会话但缺 CSRF 头 → 403（写请求防线不豁免）。
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

    // read token 不能写路由。
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

    // read token 可以读，不能写路由（最小权限）。
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
