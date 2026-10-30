//! 集成测试：结构化日志与指标（[存档 §17.1/§17.2](../../docs/review/chatgpt-2026-10-13.md)）。
//!
//! 验收：§17.1 八字段齐全（结构化字段，非拼串）；§17.2 八项指标可观测，
//! 控制面计数器与数据面量规两条独立来源都真实反映状态。

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
    // 安装日志捕获（幂等）：之后所有 op_log! / 访问日志都进共享缓冲。
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

/// 抓取指标文本（管理面会话；端点是 Prometheus 纯文本，不做 JSON 解析）。
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

/// 已捕获的结构化日志行（仅 `meshlet_server` 目标；依赖噪声已过滤）。
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

/// 按操作 + 网络定位事件（测试并行跑，不用清空缓冲而是按内容唯一匹配）。
fn find_event<'a>(lines: &'a [Value], operation: &str, network_id: &str) -> Option<&'a Value> {
    lines.iter().find(|l| {
        l["operation"].as_str() == Some(operation) && l["network_id"].as_str() == Some(network_id)
    })
}

fn field<'a>(line: &'a Value, key: &str) -> &'a Value {
    line.get(key).unwrap_or(&Value::Null)
}

/// 每个已捕获的事件都必须带 §17.1 八字段（字段存在，值为空串也是齐全）。
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

/// 指标端点是管理数据：未认证不得抓取。
#[tokio::test]
async fn metrics_endpoint_requires_authentication() {
    let c = ctx().await;
    let (status, body) = call(&c, "GET", "/api/v1/system/metrics", None, false, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "unauthorized");
}

/// §17.2 控制面计数器：操作推进后指标真实出现（非静态零值）。
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

    // 配置应用：无数据面 backend → 确定性失败（计入 failed）。
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
    // 指标 4/5：配置应用失败数（以状态机结论计数，不凭响应码）。
    assert!(
        text.contains("meshlet_config_apply_total{result=\"applied\"} 0"),
        "applied counter missing: {text}"
    );
    assert!(
        text.contains("meshlet_config_apply_total{result=\"failed\"} 1"),
        "failed counter missing: {text}"
    );
    // 成功率在有样本时给出（0/1 = 0）。
    assert!(
        text.contains("meshlet_config_apply_success_ratio 0.0000"),
        "success ratio missing: {text}"
    );
    // 指标 8：服务端接口状态（HTTP 请求按路由模板计数；指标端点自身那次
    // 请求在渲染之后才计入，断言用先前已完成的请求）。
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
    // 控制面量规（无设备时全部为零，但必须出现）。
    assert!(text.contains("meshlet_devices_online 0"));
    assert!(text.contains("meshlet_devices_active 0"));
    assert!(text.contains("meshlet_alias_apply_status 0"));

    // §17.1 领域事件：create_network 携带 network_id + config_revision。
    let lines = log_lines();
    let line =
        find_event(&lines, "create_network", network_id).expect("create_network event missing");
    assert_eight_fields(line);
    assert_eq!(field(line, "component"), "network");
    assert_eq!(field(line, "device_id"), "");
    assert_eq!(field(line, "result"), "ok");
    assert_eq!(field(line, "error_category"), "none");
}

/// §17.1 访问日志：每个已路由请求一条，路由模板为 operation，状态派生结果。
#[tokio::test]
async fn access_log_lines_carry_route_template_and_status() {
    let c = ctx().await;

    // 一个 200 与一个 404（未认证的管理端点）都要留访问日志。
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

/// §17.2 数据面量规：设备加入 + 心跳（带握手读数）后，在线/活跃/握手指标
/// 从 MeshState 现算——两条独立来源（控制面在册 vs 数据面握手）都出现。
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

    // 心跳携带当前握手读数：隧道证据 + agent 证据同时新鲜。
    let now = meshlet_server::service::now();
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/v1/agent/heartbeat")
        .header("authorization", format!("Bearer {agent_token}"))
        .header("content-type", "application/json")
        .body(Body::from(json!({ "last_handshake_at": now }).to_string()))
        .unwrap();
    // §12：heartbeat 观测直连源地址（ConnectInfo 装配于 serve 层）。
    req.extensions_mut().insert(axum::extract::ConnectInfo(
        "10.240.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
    ));
    let res = c.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let text = metrics(&c).await;
    // 指标 1/2：在线设备数（agent 证据）与活跃 Peer 数（在册 Active）。
    assert!(
        text.contains("meshlet_devices_online 1"),
        "devices_online gauge missing: {text}"
    );
    assert!(
        text.contains("meshlet_devices_active 1"),
        "devices_active gauge missing: {text}"
    );
    // 指标 3：最近握手时间（Unix 秒 > 0）与近期握手设备数（数据面证据）。
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
    // 指标 7：接口状态（有近期握手证据即 1）。
    assert!(
        text.contains("meshlet_interface_up 1"),
        "interface_up gauge missing: {text}"
    );

    // §17.1 agent 事件：device 组件，device_id 齐全，network_id 适用时填。
    let lines = log_lines();
    let line = find_event(&lines, "heartbeat", network_id).expect("heartbeat event missing");
    assert_eight_fields(line);
    assert_eq!(field(line, "component"), "agent");
    assert_eq!(field(line, "device_id"), device_id);
    assert_eq!(field(line, "result"), "ok");
}

/// §17.2 路由冲突数：只计「目的网段重叠」类冲突；设备未激活的 409 不计。
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

    // 正常路由创建：不算冲突。
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

    // 与既有路由重叠：RouteConflict → 计数 1。
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

    // 撤销设备 → 网关未激活：仍是 409，但不是路由冲突，计数不动。
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

    // 与 overlay 重叠：第二条冲突路径 → 计数 2。
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

    // §17.1：三条拒绝路径（网段重叠 / 网关未激活 / 与 overlay 重叠）都留
    // error 事件；其中只有「目的网段重叠」计入冲突指标（上文已断言）。
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

/// §17.1 登录成功/失败都留结构化日志；失败带 unauthorized 类别。
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
