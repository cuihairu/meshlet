//! 集成测试：Alias 映射增删（§12.6 所有权与清理 / ADR-006）。
//!
//! 端到端：alias 模式路由 → POST Alias（target 由绑定路由推导，客户端不可
//! 指定；前缀等长；与 overlay/既有 Alias/既有路由目的网段不重叠）→ 列表/
//! 详情 → 删除即整单元清理（Alias + 绑定路由，一个修订）→ 路由删除/设备
//! 撤销级联清理 → 重启重建。写入的数据流入诊断第 10 项（§12.7）。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt; // oneshot

const OVERLAY: &str = "10.240.0.0/16";

// ---------------------------------------------------------------------------
// 助手（与 routes.rs 同构）
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

/// 建一条 alias 模式路由（目的网段 = 真实 LAN 网段）。
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

/// 建一个完整单元：网络 + 设备 + alias 路由（192.168.1.0/24）+ Alias
/// （10.0.1.0/24）。返回 (network_id, device_id, route_id, alias_id)。
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
// 创建
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_alias_derives_target_and_records_revision() {
    let c = ctx().await;
    let (network_id, _device_id, route_id, _) = unit(&c).await;

    // net=1、enroll=2、路由=3、alias=4；target 由路由推导（192.168.1.0/24）。
    let list = alias_list(&c, &network_id).await;
    assert_eq!(list.len(), 1);
    let alias = &list[0];
    assert_eq!(alias["id"], "al-2");
    assert_eq!(alias["network_id"], network_id.as_str());
    assert_eq!(alias["lan_route_id"], route_id.as_str());
    assert_eq!(alias["alias_cidr"], "10.0.1.0/24");
    assert_eq!(alias["target_cidr"], "192.168.1.0/24");
    // translation_mode 缺省 dnat_snat（ADR-006）；DB 写入 ≠ 生效 → pending。
    assert_eq!(alias["translation_mode"], "dnat_snat");
    assert_eq!(alias["status"], "pending");
    assert_eq!(alias["revision_id"], 4);
    assert_eq!(alias["apply_status"], "pending");

    // 详情与列表一致；另一网络的列表为空（按网络隔离）。
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

    // 等长要求（ADR-006）：/23 ≠ /24 → 400，消息点名两侧前缀长度。
    let (st, body) = create_alias(&c, &network_id, &route_id, "10.0.2.0/23").await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
    let message = body["error"]["message"].as_str().unwrap();
    assert!(message.contains("prefix length mismatch"), "{message}");

    // 与 target 相同的网段没有翻译语义 → 400。
    let (st, body) = create_alias(&c, &network_id, &route_id, "192.168.1.0/24").await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
    let message = body["error"]["message"].as_str().unwrap();
    assert!(message.contains("must not equal"), "{message}");
}

#[tokio::test]
async fn alias_binds_only_alias_mode_routes_of_this_network() {
    let c = ctx().await;
    let (network_id, device_id) = net_with_device(&c, "home", OVERLAY).await;

    // direct 模式路由不能被绑定（§5：alias 模式即「经虚拟前缀」）。
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

    // 未知路由 → 404；另一网络的路由同样 404。
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

    // ① 与 overlay 重叠 → 409。
    let (st, body) = create_alias(&c, &network_id, &route1, "10.240.5.0/24").await;
    assert_eq!(st, StatusCode::CONFLICT, "{body}");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("overlaps overlay"));

    // ② 与既有路由目的网段重叠（虚拟前缀必须与真实 LAN 空间隔离）→ 409。
    let (st, body) = create_alias(&c, &network_id, &route1, "192.168.2.0/24").await;
    assert_eq!(st, StatusCode::CONFLICT, "{body}");
    let message = body["error"]["message"].as_str().unwrap();
    assert!(
        message.contains(&route2) && message.contains("192.168.2.0/24"),
        "must name the conflicting route: {message}"
    );

    // ③ 与既有 Alias 重叠 → 409，消息点名对端 Alias（等长约束下重叠即同段）。
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

    // ④ 同一路由重复绑定 → 409（一对一单元，§12.6）。
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

    // 重叠拒绝后：列表不变、不产生新修订（§8.3 拒绝先于任何状态变更）。
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
// 删除与级联（§12.6 所有权）
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

    // 整单元：Alias 与绑定路由同时消失。
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
    // 恰好一个新修订（删 Alias 与删路由不是两次变更）。
    assert_eq!(revision_count(&c, &network_id).await, before + 1);

    // 再删 → 404；未知网络的 Alias → 404。
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

    // 路由没了，绑定它的 Alias 不能留下孤儿。
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

    // §11.5 + §12.6：撤销网关 = 其路由与绑定 Alias 一并清空。
    assert!(alias_list(&c, &network_id).await.is_empty());
    let (st, routes) = json_get(&c, &format!("/api/v1/networks/{network_id}/routes")).await;
    assert_eq!(st, StatusCode::OK);
    assert!(routes.as_array().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// 重启重建（§17.3）
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

/// 文件库 + 重启重建（recovery.rs 同构：boot → bootstrap 或 login）。
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
    // bootstrap（空库 201）或 login（重启后）——都从 Set-Cookie 取会话。
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

    // 重启：Alias 逐字段重建。
    let c = open_app(&db).await;
    let after = alias_list(&c, &network_id).await;
    assert_eq!(after.len(), 1, "alias survives restart");
    assert_eq!(after[0], before[0], "field-by-field rebuild");

    // 删除后重建：id 序列不回退（al-2 不复用；新路由 rt-3、新 Alias al-4）。
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
// 诊断联动（§12.7 第 10 项）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn write_path_aliases_flow_into_diagnostics_check() {
    let c = ctx().await;
    let (network_id, _device_id, _route_id, _alias_id) = unit(&c).await;

    // 写路径产生的干净 Alias：第 10 项逐条检查通过（不再 not_applicable）。
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
// 门禁
// ---------------------------------------------------------------------------

#[tokio::test]
async fn alias_endpoints_require_auth_and_csrf() {
    let c = ctx().await;
    let (network_id, _device_id, _route_id, _) = unit(&c).await;

    // 无会话 → 401；写缺 CSRF 头 → 403。
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
