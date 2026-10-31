//! 集成测试：P2P 直连候选端点下发（§12 任务书 ①）。
//!
//! 端到端路径：设备心跳携带 `direct`（监听端口 + LAN 地址，agent 自己枚举）→
//! server 记录观测源地址（连接 socket）+ 上报 → `GET /api/v1/networks/{id}/
//! peers/endpoints`（Bearer 凭证）返回可直连 peer 列表。断言重点：
//! - 凭证缺失/伪造 → 401（agent API 认证边界，§13.5）；
//! - 返回按 device_id 确定性排序、排除自身；
//! - 同内网观测（源地址为私网）不伪造公网候选（打洞误导防护，域层口径）；
//! - 公网观测源地址 → 附加公网候选；
//! - 未上报 `direct` 的设备不在列表（不可直连，避免死载荷）。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use meshlet_domain::PresenceThresholds;
use std::sync::Arc;
use tower::ServiceExt; // oneshot

const OVERLAY: &str = "10.240.0.0/16";

#[derive(Clone)]
struct Ctx {
    app: Router,
    cookie: String,
    network_id: String,
}

struct OkBackend;

impl meshlet_domain::ConfigApplyBackend for OkBackend {
    fn apply(&mut self, _revision: &meshlet_domain::ConfigRevision) -> Result<(), String> {
        Ok(())
    }
    fn rollback(&mut self, _revision: &meshlet_domain::ConfigRevision) -> Result<(), String> {
        Ok(())
    }
}

/// 构建 router（数据面默认关：本端点不依赖数据面开关）。
async fn app() -> Router {
    let pool = meshlet_server::store::connect("sqlite::memory:")
        .await
        .unwrap();
    let mesh = Arc::new(std::sync::Mutex::new(
        meshlet_server::service::MeshState::new(PresenceThresholds::default()),
    ));
    let state = Arc::new(
        meshlet_server::auth::AppState::new(
            mesh,
            meshlet_server::auth::AuthStore::new(pool.clone()),
            meshlet_server::agent::AgentTokenStore::new(pool.clone()),
            meshlet_server::api_token::ApiTokenStore::new(pool),
            false,
        )
        .with_dataplane(meshlet_config::DataPlaneConfig::default())
        .with_apply_backend(Arc::new(|_, _| Box::new(OkBackend))),
    );
    meshlet_server::router(state)
}

async fn res_body(res: axum::response::Response) -> serde_json::Value {
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn admin(
    app: &Router,
    cookie: &str,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header("cookie", cookie)
                .header("x-requested-with", "XMLHttpRequest")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    (res.status(), res_body(res).await)
}

/// bootstrap → 建网络 → 建邀请 → 首台设备加入。返回 ctx 与首台设备 agent_token。
async fn bootstrap(name: &str, public_key: &str) -> (Ctx, String) {
    let app = app().await;
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "email": "admin@test.local",
                        "password": "bootstrap-password-123",
                    })
                    .to_string(),
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

    let (st, net) = admin(
        &app,
        &cookie,
        "/api/v1/networks",
        serde_json::json!({ "name": "home", "overlay_cidr": OVERLAY }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{net}");
    let network_id = net["id"].as_str().unwrap().to_string();
    let ctx = Ctx {
        app,
        cookie,
        network_id,
    };
    let (_, token) = enroll(&ctx, name, public_key).await;
    (ctx, token)
}

/// 用新邀请再入一台设备（返回 device_id、agent_token）。
async fn enroll(ctx: &Ctx, name: &str, public_key: &str) -> (String, String) {
    let (st, invite) = admin(
        &ctx.app,
        &ctx.cookie,
        &format!("/api/v1/networks/{}/invites", ctx.network_id),
        serde_json::json!({ "max_uses": 5 }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{invite}");
    let invite_token = invite["token"].as_str().unwrap().to_string();
    let res = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/enroll")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "invite_token": invite_token,
                        "device_name": name,
                        "public_key": public_key,
                        "platform": "linux",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let enroll = res_body(res).await;
    (
        enroll["device_id"].as_str().unwrap().to_string(),
        enroll["agent_token"].as_str().unwrap().to_string(),
    )
}

/// `POST /api/v1/agent/heartbeat` 带直连候选（`lan` + `listen_port`），源地址
/// `src` 模拟 hub 观测到的连接地址。
async fn heartbeat(
    app: &Router,
    token: &str,
    lan: &[&str],
    listen_port: u16,
    src: &str,
) -> StatusCode {
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/v1/agent/heartbeat")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "last_handshake_at": null,
                "dataplane": null,
                "direct": { "listen_port": listen_port, "lan_addrs": lan },
            })
            .to_string(),
        ))
        .unwrap();
    req.extensions_mut().insert(axum::extract::ConnectInfo(
        src.parse::<std::net::SocketAddr>().unwrap(),
    ));
    app.clone().oneshot(req).await.unwrap().status()
}

/// `GET /api/v1/networks/{network_id}/peers/endpoints`（Bearer 凭证）。
async fn peers(
    app: &Router,
    token: Option<&str>,
    network_id: &str,
) -> (StatusCode, serde_json::Value) {
    let mut builder =
        Request::builder().uri(format!("/api/v1/networks/{network_id}/peers/endpoints"));
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let res = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    (res.status(), res_body(res).await)
}

#[tokio::test]
async fn peers_endpoints_requires_a_valid_agent_token() {
    let (ctx, _) = bootstrap("edge-1", "pub-edge-aaaa-0001").await;
    for missing in [None, Some("00".repeat(32))] {
        let (st, body) = peers(&ctx.app, missing.as_deref(), &ctx.network_id).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"]["code"], "unauthorized");
    }
}

#[tokio::test]
async fn peers_endpoints_returns_ordered_peers_excluding_self() {
    let (ctx, a_token) = bootstrap("edge-a", "pub-edge-a").await;
    let (b_id, b_token) = enroll(&ctx, "peer-b", "pub-peer-b").await;
    let (c_id, c_token) = enroll(&ctx, "peer-c", "pub-peer-c").await;

    // B、C 都上报直连候选（同内网观测：源地址为私网）。
    assert_eq!(
        heartbeat(
            &ctx.app,
            &b_token,
            &["192.168.1.51"],
            51820,
            "192.168.1.11:40001"
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        heartbeat(
            &ctx.app,
            &c_token,
            &["192.168.1.52"],
            51820,
            "192.168.1.12:40002"
        )
        .await,
        StatusCode::OK
    );

    let (st, body) = peers(&ctx.app, Some(&a_token), &ctx.network_id).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let arr = body.as_array().unwrap();
    // 自身被排除，只返回 B、C。
    assert_eq!(arr.len(), 2, "{body}");
    let ids: Vec<&str> = arr
        .iter()
        .map(|p| p["device_id"].as_str().unwrap())
        .collect();
    let mut sorted = vec![b_id.as_str(), c_id.as_str()];
    sorted.sort();
    assert_eq!(ids, sorted, "deterministic ordering: {body}");
    // 每项带对端公钥与虚拟 IP。
    for p in arr {
        assert!(p["public_key"].as_str().unwrap().len() >= 9, "{body}");
        assert!(
            p["virtual_ipv4"].as_str().unwrap().starts_with("10.240.0."),
            "{body}"
        );
        assert!(!p["endpoints"].as_array().unwrap().is_empty(), "{body}");
    }
}

#[tokio::test]
async fn same_lan_observation_never_fabricates_a_public_candidate() {
    let (ctx, a_token) = bootstrap("edge-same-lan", "pub-edge-same").await;
    let (b_id, b_token) = enroll(&ctx, "peer-same-lan", "pub-peer-same").await;
    // B 同内网：hub 观测源地址为私网（192.168.1.11）——标成 public 只会误导打洞。
    assert_eq!(
        heartbeat(
            &ctx.app,
            &b_token,
            &["192.168.1.51"],
            51820,
            "192.168.1.11:40001"
        )
        .await,
        StatusCode::OK
    );
    let (st, body) = peers(&ctx.app, Some(&a_token), &ctx.network_id).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let arr = body.as_array().unwrap();
    assert_eq!(arr.len(), 1, "{body}");
    assert_eq!(arr[0]["device_id"], b_id, "{body}");
    let eps = arr[0]["endpoints"].as_array().unwrap();
    // 只有 LAN 候选，无 public。
    assert_eq!(eps.len(), 1, "{body}");
    assert_eq!(eps[0]["ip"], "192.168.1.51");
    assert_eq!(eps[0]["port"], 51820);
    assert_eq!(eps[0]["kind"], "lan");
}

#[tokio::test]
async fn public_observation_yields_public_candidate_after_lan() {
    let (ctx, a_token) = bootstrap("edge-pub", "pub-edge-pub").await;
    let (_, b_token) = enroll(&ctx, "peer-pub", "pub-peer-pub").await;
    // B 公网：hub 观测源地址非私网 → LAN 候选之后附加 public 候选。
    assert_eq!(
        heartbeat(
            &ctx.app,
            &b_token,
            &["192.168.1.51"],
            51820,
            "203.0.113.7:40001"
        )
        .await,
        StatusCode::OK
    );
    let (st, body) = peers(&ctx.app, Some(&a_token), &ctx.network_id).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let eps = body[0]["endpoints"].as_array().unwrap();
    assert_eq!(eps.len(), 2, "{body}");
    assert_eq!(eps[0]["kind"], "lan");
    assert_eq!(eps[1]["kind"], "public");
    assert_eq!(eps[1]["ip"], "203.0.113.7");
    assert_eq!(eps[1]["port"], 51820);
}

#[tokio::test]
async fn device_without_report_is_excluded() {
    let (ctx, a_token) = bootstrap("edge-noreport", "pub-edge-noreport").await;
    let (_, b_token) = enroll(&ctx, "peer-noreport", "pub-peer-noreport").await;
    // B 已注册但从未上报 direct → 不可直连，从列表排除（避免死载荷）。
    let _ = b_token;
    let (st, body) = peers(&ctx.app, Some(&a_token), &ctx.network_id).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(body.as_array().unwrap().is_empty(), "{body}");
}

#[tokio::test]
async fn peers_endpoints_rejects_wrong_network() {
    let (ctx, a_token) = bootstrap("edge-wrong", "pub-edge-wrong").await;
    let (st, body) = peers(&ctx.app, Some(&a_token), "net-000000").await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"]["code"], "not_found");
}

/// `GET /api/v1/agent/device/peers/endpoints`：agent 凭证即身份，无需网络 ID。
async fn agent_peers(app: &Router, token: Option<&str>) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().uri("/api/v1/agent/device/peers/endpoints");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let res = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    (res.status(), res_body(res).await)
}

#[tokio::test]
async fn agent_scoped_endpoints_uses_the_tokens_device_without_a_network_path() {
    let (ctx, a_token) = bootstrap("edge-a", "pub-edge-a").await;
    let (_, b_token) = enroll(&ctx, "peer-b", "pub-peer-b").await;

    // 无凭证 → 401（agent API 认证边界）。
    let (st, body) = agent_peers(&ctx.app, None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "{body}");

    // B 上报直连候选；A 用**自己的**凭证拉取，看到 B（A 自身被排除）。
    assert_eq!(
        heartbeat(
            &ctx.app,
            &b_token,
            &["192.168.1.51"],
            51820,
            "192.168.1.11:40001"
        )
        .await,
        StatusCode::OK
    );
    let (st, body) = agent_peers(&ctx.app, Some(&a_token)).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let arr = body.as_array().unwrap();
    assert_eq!(arr.len(), 1, "{body}");
    assert_eq!(arr[0]["public_key"], "pub-peer-b", "{body}");
    assert_eq!(arr[0]["virtual_ipv4"], "10.240.0.3", "{body}");
    assert_eq!(arr[0]["endpoints"][0]["kind"], "lan", "{body}");
}

#[tokio::test]
async fn agent_scoped_endpoints_excludes_self_and_unreported() {
    let (ctx, a_token) = bootstrap("edge-a", "pub-edge-a").await;
    // 仅 A 上报：A 拉取候选时自身被排除 → 空列表（没有其他可直连设备）。
    assert_eq!(
        heartbeat(
            &ctx.app,
            &a_token,
            &["192.168.1.50"],
            51820,
            "192.168.1.10:40001"
        )
        .await,
        StatusCode::OK
    );
    let (st, body) = agent_peers(&ctx.app, Some(&a_token)).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(body.as_array().unwrap().is_empty(), "{body}");
}
