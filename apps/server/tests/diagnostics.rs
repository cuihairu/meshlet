//! 集成测试：网络诊断 12 项检查（[存档 §12.7](../../docs/review/chatgpt-2026-10-13.md)）。
//!
//! 1. 端点门禁：GET 需会话，POST 需会话 + CSRF；未知网络 404；
//! 2. 十二项齐全、顺序固定、按故障层归类（隧道/路由/转发/Alias + 控制面）；
//! 3. **不假绿**：控制面观测不到的本机检查（WireGuard 接口/内核路由/IP
//!    forwarding/防火墙/NAT）恒 `unavailable` 并带可执行建议；
//! 4. **控制面在册 ≠ 隧道正常**：设备已注册（③ pass）同时握手缺失（④ fail）
//!    必须共存；心跳上报新鲜后 ④ 转 pass；
//! 5. ⑧⑨⑫ 跟随网关 presence 与修订状态机（pending→warning、applied→pass、
//!    failed→fail）；结果持久化（GET 读最近快照）；Alias 冲突用域层检测。

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

/// §12.7 十二项的固定顺序与故障层。
const EXPECTED: [(&str, &str); 12] = [
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
];

/// 控制面观测不到的本机检查（§12.7 ②⑤⑥⑦⑪）：恒 unavailable。
const LOCAL_MACHINE: [&str; 5] = [
    "wg_interface_exists",
    "overlay_route_present",
    "ip_forwarding_enabled",
    "firewall_allows_forwarding",
    "nat_rules_effective",
];

/// 无数据面的占位 backend：apply/rollback 恒成功（⑨⑫ pass 路径用）。
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
    let state = Arc::new(
        meshlet_server::auth::AppState::new(
            Arc::new(std::sync::Mutex::new(
                meshlet_server::service::MeshState::default(),
            )),
            meshlet_server::auth::AuthStore::new(pool.clone()),
            meshlet_server::agent::AgentTokenStore::new(pool.clone()),
            meshlet_server::api_token::ApiTokenStore::new(pool.clone()),
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

/// 无认证/无 CSRF 的裸请求（门禁用例）。
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

/// 建网 + 邀请 + 加入一台设备，返回 (network_id, device_id, agent_token)。
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

/// agent 心跳（Bearer 凭证 + 本地握手读数）。
async fn heartbeat(c: &Ctx, agent_token: &str, handshake_at: &str) -> Value {
    let res = c
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/heartbeat")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {agent_token}"))
                .body(Body::from(
                    json!({ "last_handshake_at": handshake_at }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// 触发诊断，断言 200 并返回报告。
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
// 门禁与 404
// ---------------------------------------------------------------------------

#[tokio::test]
async fn diagnostics_endpoints_require_auth_and_csrf() {
    let c = ctx().await;
    // 无会话：GET/POST 都 401（认证在路径解析之前，未知网络同样先撞认证）。
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
    // 有会话无 CSRF 头：写请求 403。
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
    // 消息点名触发方式——不假称「有结果」。
    assert!(
        body["error"]["message"].as_str().unwrap().contains("POST"),
        "{body}"
    );
}

// ---------------------------------------------------------------------------
// 十二项结构与不假绿
// ---------------------------------------------------------------------------

#[tokio::test]
async fn run_reports_twelve_checks_in_order_with_layers() {
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

    // 十二项、顺序与层固定（§12.7 列表 + 隧道/路由/转发/Alias + 控制面）。
    let checks = report["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 12, "{checks:?}");
    for (i, (id, layer)) in EXPECTED.iter().enumerate() {
        assert_eq!(checks[i]["id"], *id, "position {i}");
        assert_eq!(checks[i]["layer"], *layer, "check {id}");
        assert!(checks[i]["name"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(checks[i]["detail"].as_str().is_some_and(|s| !s.is_empty()));
    }

    // 不假绿：本机检查恒 unavailable（不是 pass），且建议非空。
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

    // ① 恒 pass（能读到报告即证明 API 在服务）。
    assert_eq!(check_of(&report, "api_reachable")["status"], "pass");

    // GET 读到的是**同一份**快照（不是现算的新报告）。
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
    // 无设备：注册/握手如实 not_applicable（不是 pass）。
    assert_eq!(
        check_of(&report, "server_peer_configured")["status"],
        "not_applicable"
    );
    assert_eq!(
        check_of(&report, "recent_handshake")["status"],
        "not_applicable"
    );
    // 无路由：网关/发布 not_applicable。
    assert_eq!(
        check_of(&report, "lan_gateway_agent_online")["status"],
        "not_applicable"
    );
    assert_eq!(
        check_of(&report, "lan_route_published")["status"],
        "not_applicable"
    );
    // 无 Alias 映射：not_applicable（Phase 4 无写路径，表为空）。
    assert_eq!(
        check_of(&report, "alias_prefix_conflict")["status"],
        "not_applicable"
    );
    // 建网已记录修订 #1（pending）：配置一致性是 warning——期望配置未确认应用。
    let revision_check = check_of(&report, "config_revision_consistent");
    assert_eq!(revision_check["status"], "warning", "{revision_check}");
    assert!(revision_check["detail"].as_str().unwrap().contains("#1"));
}

// ---------------------------------------------------------------------------
// 控制面在册 ≠ 隧道正常（§12.4 判读纪律）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registration_without_handshake_is_not_a_healthy_tunnel() {
    let c = ctx().await;
    let (network_id, _device_id, _token) = net_with_device(&c).await;

    let report = run(&c, &network_id).await;
    // ③ 已注册（pass）——但 detail 必须点名「只是控制面在册」。
    let peer = check_of(&report, "server_peer_configured");
    assert_eq!(peer["status"], "pass", "{peer}");
    assert!(
        peer["detail"]
            .as_str()
            .unwrap()
            .contains("registration only"),
        "③ must not claim tunnel health: {peer}"
    );
    // ④ 从未观测到握手（fail）——两项检查同时成立，注册不给隧道背书。
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

    // 心跳携带本地握手读数：agent 上报新鲜 → 设备 online；握手在窗口内 → ④ pass。
    let hb = heartbeat(&c, &token, &now_stamp()).await;
    assert_eq!(hb["online_state"], "online");

    let report = run(&c, &network_id).await;
    let handshake = check_of(&report, "recent_handshake");
    assert_eq!(handshake["status"], "pass", "{handshake}");
    assert!(handshake["detail"].as_str().unwrap().contains("fresh"));
}

// ---------------------------------------------------------------------------
// 网关 presence 与修订状态机驱动 ⑧⑨⑫
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gateway_online_and_revision_state_drive_route_checks() {
    let c = ctx_with_backend(Arc::new(|| Box::new(OkBackend))).await;
    let (network_id, _device_id, token) = net_with_device(&c).await;
    heartbeat(&c, &token, &now_stamp()).await; // 网关 agent 上报新鲜 → online
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

    // 修订 #3（建路由）尚未 apply：⑧ pass（网关在线）、⑨ warning、⑫ warning。
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

    // apply 成功（OkBackend）：⑨ pass、⑫ pass——detail 仍注明这只是控制面口径。
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
    let c = ctx().await; // 默认占位 backend：apply 确定性失败
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
    // ⑨：路由已记录但 apply 失败——fail（记录 ≠ 发布）。
    let published = check_of(&report, "lan_route_published");
    assert_eq!(published["status"], "fail", "{published}");
    // ⑫：失败修订带 error_summary（失败可见，§10.3）。
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
// 快照持久化
// ---------------------------------------------------------------------------

#[tokio::test]
async fn runs_are_persisted_get_returns_the_latest() {
    let c = ctx().await;
    let (network_id, _device_id, token) = net_with_device(&c).await;

    // 第一跑：设备已注册但从未握手——④ fail。
    let first = run(&c, &network_id).await;
    assert_eq!(check_of(&first, "recent_handshake")["status"], "fail");

    // 心跳上报新鲜握手后第二跑：④ 翻 pass——两份快照内容可区分
    // （不用时刻区分：库内时间戳是秒精度，同秒内两跑时刻相同）。
    heartbeat(&c, &token, &now_stamp()).await;
    let second = run(&c, &network_id).await;
    assert_eq!(check_of(&second, "recent_handshake")["status"], "pass");
    assert_ne!(second["checks"], first["checks"]);

    // GET 取**最近**一份（④ pass 的那份，不是第一跑的 fail 快照）。
    let (st, latest) = json_get(&c, &format!("/api/v1/networks/{network_id}/diagnostics")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(check_of(&latest, "recent_handshake")["status"], "pass");
    assert_eq!(latest["checks"], second["checks"]);

    // GET 是读快照：连读两次结果一致（不隐式重算）。
    let (st, again) = json_get(&c, &format!("/api/v1/networks/{network_id}/diagnostics")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(again, latest);
}

// ---------------------------------------------------------------------------
// Alias 冲突（§12.7 第 10 项，域层检测）
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

    // 直接落两行 alias 映射（模拟脏库/手改库——服务写路径在创建时已拒绝
    // 这类重叠，正常 API 到不了这里；FK 指向刚建的路由），
    // 造一个「alias 与 overlay 重叠 + alias 互叠」的坏配置。
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
    // 域层冲突明细点名对端（ADR-004/§8.3 不静默）。
    assert!(detail.contains("overlaps overlay"), "{detail}");
    assert!(detail.contains("overlaps alias"), "{detail}");
}
