//! 集成测试：设备数据面计划下发（[ADR-007](../../docs/decisions/adr-007-linux-network-backend.md)）。
//!
//! 端到端路径：加入（拿到 agent_token）→ `GET /api/v1/agent/device/desired`
//! （Bearer 凭证）→ 拿回**结构化配置对象**（§16.4：类型化隧道/路由/NAT +
//! `desired_config_hash`，绝无 Shell 命令）。断言重点：
//! - 计划不含私钥（ADR-010：`private_key` 恒为 `null`，agent 本地注入）；
//! - 自己发布的 LAN 不回灌 AllowedIPs（避免环路，§7.2）；
//! - 网关设备拿到 Alias NAT 规则（所有权注释定位，§12.6）；
//! - 服务端 `[dataplane] enabled = false` → 503（不返回空计划冒充「已生效」）。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use meshlet_domain::PresenceThresholds;
use std::path::Path;
use std::sync::Arc;
use tower::ServiceExt; // oneshot

const OVERLAY: &str = "10.240.0.0/16";

#[derive(Clone)]
struct Ctx {
    app: Router,
    cookie: String,
    network_id: String,
}

/// `wg` 可用（真推导 hub 公钥需要）；不可用时相关用例打印 `SKIP:` 正常返回，
/// CI 无 wireguard-tools 仍全绿。
fn wg_available() -> bool {
    match std::process::Command::new("wg").arg("--version").output() {
        Ok(o) if o.status.success() => true,
        _ => {
            eprintln!("SKIP: wireguard-tools (wg) not installed");
            false
        }
    }
}

/// 生成一个 hub 私钥文件（ADR-010：仅本地，服务端不落库）。
fn write_hub_key(dir: &Path) -> Option<std::path::PathBuf> {
    let out = match std::process::Command::new("wg").arg("genkey").output() {
        Ok(o) if o.status.success() => o,
        _ => {
            eprintln!("SKIP: wg genkey failed");
            return None;
        }
    };
    let path = dir.join("hub.key");
    std::fs::write(&path, &out.stdout).ok()?;
    Some(path)
}

/// 永远成功的 apply 桩：本文件只验「计划推导」，不碰内核（数据面真应用由
/// [`meshlet_network`] 的 netns 集成测试覆盖）。
struct OkBackend;

impl meshlet_domain::ConfigApplyBackend for OkBackend {
    fn apply(&mut self, _revision: &meshlet_domain::ConfigRevision) -> Result<(), String> {
        Ok(())
    }
    fn rollback(&mut self, _revision: &meshlet_domain::ConfigRevision) -> Result<(), String> {
        Ok(())
    }
}

/// 构建 router：`dataplane` 参数模拟服务端 `[dataplane]` 配置。
async fn app(dataplane: meshlet_config::DataPlaneConfig) -> Router {
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
        .with_dataplane(dataplane)
        .with_apply_backend(Arc::new(|_, _| Box::new(OkBackend))),
    );
    meshlet_server::router(state)
}

async fn res_body(res: axum::response::Response) -> serde_json::Value {
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// GET /agent/device/desired（Bearer 凭证；agent API，无 CSRF）。
async fn desired(app: &Router, agent_token: Option<&str>) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().uri("/api/v1/agent/device/desired");
    if let Some(token) = agent_token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let res = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    (res.status(), res_body(res).await)
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

/// bootstrap → 建网络 → 建邀请 → 设备加入。返回 ctx 与 agent_token。
async fn bootstrap_with_device(
    dataplane: meshlet_config::DataPlaneConfig,
    public_key: &str,
) -> (Ctx, String) {
    let app = app(dataplane).await;

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

    let (st, invite) = admin(
        &app,
        &cookie,
        &format!("/api/v1/networks/{network_id}/invites"),
        serde_json::json!({ "max_uses": 5 }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{invite}");
    let invite_token = invite["token"].as_str().unwrap().to_string();

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/enroll")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "invite_token": invite_token,
                        "device_name": "edge",
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
    let agent_token = enroll["agent_token"].as_str().unwrap().to_string();

    (
        Ctx {
            app,
            cookie,
            network_id,
        },
        agent_token,
    )
}

/// 用同一邀请再入一台设备（返回 device_id、agent_token）。
async fn enroll_extra(ctx: &Ctx, public_key: &str) -> (String, String) {
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
                        "device_name": "peer",
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

/// 建一条 LAN 路由（`route_mode`：`direct` / `alias`）。
async fn create_route(ctx: &Ctx, gateway: &str, destination: &str, mode: &str) -> String {
    let (st, route) = admin(
        &ctx.app,
        &ctx.cookie,
        &format!("/api/v1/networks/{}/routes", ctx.network_id),
        serde_json::json!({
            "gateway_device_id": gateway,
            "destination_cidr": destination,
            "route_mode": mode,
            "return_path_mode": "dual_route",
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{route}");
    route["id"].as_str().unwrap().to_string()
}

/// 建一个 Alias 映射（返回 alias_id）。
async fn create_alias(ctx: &Ctx, route_id: &str, alias_cidr: &str) -> String {
    let (st, alias) = admin(
        &ctx.app,
        &ctx.cookie,
        &format!("/api/v1/networks/{}/aliases", ctx.network_id),
        serde_json::json!({ "lan_route_id": route_id, "alias_cidr": alias_cidr }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{alias}");
    alias["id"].as_str().unwrap().to_string()
}

/// 应用当前最新修订（backend 桩成功）→ 期望项状态收敛为 `applied`（§10.1）。
async fn apply_current(ctx: &Ctx) -> serde_json::Value {
    let res = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/networks/{}/config-revisions",
                    ctx.network_id
                ))
                .header("cookie", &ctx.cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let list = res_body(res).await;
    let latest = list
        .as_array()
        .unwrap()
        .last()
        .expect("one revision")
        .clone();
    let revision = latest["revision"].as_u64().unwrap();

    let (st, view) = admin(
        &ctx.app,
        &ctx.cookie,
        &format!(
            "/api/v1/networks/{}/config-revisions/{revision}/apply",
            ctx.network_id
        ),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{view}");
    assert_eq!(view["apply_status"], "applied", "{view}");
    view
}

#[tokio::test]
async fn desired_plan_returns_503_when_server_dataplane_disabled() {
    // 数据面未开启时不返回空计划——agent 据此重试而不是把「未配置」当「已生效」。
    let (ctx, token) = bootstrap_with_device(
        meshlet_config::DataPlaneConfig::default(),
        "pub-edge-aaaa-0001",
    )
    .await;
    let (st, body) = desired(&ctx.app, Some(&token)).await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["code"], "dataplane_not_configured");
}

#[tokio::test]
async fn desired_plan_requires_a_valid_agent_token() {
    let (ctx, _) = bootstrap_with_device(
        meshlet_config::DataPlaneConfig::default(),
        "pub-edge-aaaa-0002",
    )
    .await;
    for missing in [None, Some("00".repeat(32))] {
        let (st, body) = desired(&ctx.app, missing.as_deref()).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"]["code"], "unauthorized");
    }
}

#[tokio::test]
async fn desired_plan_carries_a_structured_plan_without_private_key() {
    if !wg_available() {
        return;
    }
    let dir = std::env::temp_dir().join("meshlet-agent-plan-test");
    std::fs::create_dir_all(&dir).unwrap();
    let key_file = write_hub_key(&dir).unwrap();
    let dp = meshlet_config::DataPlaneConfig {
        private_key_file: Some(key_file.to_string_lossy().to_string()),
        ..dataplane_on()
    };
    let (ctx, token) = bootstrap_with_device(dp, "pub-edge-aaaa-0003").await;

    let (st, plan) = desired(&ctx.app, Some(&token)).await;
    assert_eq!(st, StatusCode::OK, "{plan}");

    // 隧道：本设备虚拟 IP + 单一 hub peer，AllowedIPs 恰好覆盖 Overlay。
    assert_eq!(plan["tunnel"]["name"], "wg0");
    assert_eq!(plan["tunnel"]["address_prefix"], 16);
    assert!(
        plan["tunnel"]["address"]
            .as_str()
            .unwrap()
            .starts_with("10.240.0."),
        "overlay address: {plan}"
    );
    // ADR-010：服务端永不携带私钥——agent 本地注入。
    assert!(plan["tunnel"]["private_key"].is_null(), "{plan}");
    assert_eq!(plan["tunnel"]["peers"].as_array().unwrap().len(), 1);
    let peer = &plan["tunnel"]["peers"][0];
    assert!(
        peer["public_key"].as_str().unwrap().len() >= 40,
        "hub public key derived on the fly: {plan}"
    );
    let allowed: Vec<_> = peer["allowed_ips"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(allowed, vec![OVERLAY]);

    assert!(plan["routes"].as_array().unwrap().is_empty());
    assert!(plan["nat_rules"].as_array().unwrap().is_empty());
    // 期望配置哈希：与修订簿记同一来源（§10.1 有变更才重放）。
    let hash = plan["desired_config_hash"].as_str().unwrap();
    assert_eq!(hash.len(), 64, "sha256 hex: {plan}");

    // 同一凭证重复拉取 = 同一计划（计划推导是确定性的）。
    let (st2, plan2) = desired(&ctx.app, Some(&token)).await;
    assert_eq!(st2, StatusCode::OK);
    assert_eq!(plan, plan2);

    std::fs::remove_file(&key_file).ok();
    std::fs::remove_dir(&dir).ok();
}

#[tokio::test]
async fn plan_grows_only_after_the_revision_is_applied() {
    if !wg_available() {
        return;
    }
    let dir = std::env::temp_dir().join("meshlet-agent-plan-routes");
    std::fs::create_dir_all(&dir).unwrap();
    let key_file = write_hub_key(&dir).unwrap();
    let dp = meshlet_config::DataPlaneConfig {
        private_key_file: Some(key_file.to_string_lossy().to_string()),
        ..dataplane_on()
    };
    let (ctx, token) = bootstrap_with_device(dp, "pub-edge-aaaa-0004").await;

    let (peer_id, _) = enroll_extra(&ctx, "pub-peer-bbbb-0004").await;
    create_route(&ctx, &peer_id, "192.168.20.0/24", "direct").await;

    // 期望项只写了账本、尚未下发内核（§10.1）→ 不进计划：agent 不会拿到
    // 一个还没生效的远端网段去转发。
    let (st, pending_plan) = desired(&ctx.app, Some(&token)).await;
    assert_eq!(st, StatusCode::OK, "{pending_plan}");
    assert!(
        pending_plan["routes"].as_array().unwrap().is_empty(),
        "unapplied route must stay out of the plan: {pending_plan}"
    );
    assert_eq!(
        pending_plan["tunnel"]["peers"][0]["allowed_ips"],
        serde_json::json!([OVERLAY]),
        "{pending_plan}"
    );

    apply_current(&ctx).await;

    let (st, plan) = desired(&ctx.app, Some(&token)).await;
    assert_eq!(st, StatusCode::OK, "{plan}");

    let allowed: Vec<_> = plan["tunnel"]["peers"][0]["allowed_ips"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(allowed, vec![OVERLAY, "192.168.20.0/24"]);

    let routes = plan["routes"].as_array().unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0]["destination"], "192.168.20.0/24");
    assert_eq!(routes[0]["interface"], "wg0");
    assert!(
        routes[0]["gateway"]
            .as_str()
            .unwrap()
            .starts_with("10.240.0."),
        "via gateway device virtual ip: {plan}"
    );

    // 期望配置哈希不随「是否已应用」变化（哈希描述期望，不是生效状态）——
    // 应用前后同一个期望配置的哈希必须相同。
    assert_eq!(
        plan["desired_config_hash"],
        pending_plan["desired_config_hash"]
    );

    std::fs::remove_file(&key_file).ok();
    std::fs::remove_dir(&dir).ok();
}

#[tokio::test]
async fn gateway_plan_carries_alias_nat_rules_and_hides_own_lan() {
    if !wg_available() {
        return;
    }
    let dir = std::env::temp_dir().join("meshlet-agent-plan-nat");
    std::fs::create_dir_all(&dir).unwrap();
    let key_file = write_hub_key(&dir).unwrap();
    let dp = meshlet_config::DataPlaneConfig {
        private_key_file: Some(key_file.to_string_lossy().to_string()),
        ..dataplane_on()
    };
    let (ctx, token) = bootstrap_with_device(dp, "pub-gw-cccc-0005").await;

    // 本设备是网关：alias 模式路由 + 等长前缀映射。
    let my_id = own_device_id(&ctx).await;
    let route_id = create_route(&ctx, &my_id, "192.168.30.0/24", "alias").await;
    let alias_id = create_alias(&ctx, &route_id, "10.241.30.0/24").await;
    apply_current(&ctx).await;

    let (st, plan) = desired(&ctx.app, Some(&token)).await;
    assert_eq!(st, StatusCode::OK, "{plan}");

    // 自己发布的真实 LAN 不进自己的 AllowedIPs（避免环路，§7.2）；Alias
    // 前缀也不进——那是别的设备要发往的前缀，不是本设备要转发的。
    let allowed: Vec<_> = plan["tunnel"]["peers"][0]["allowed_ips"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(allowed, vec![OVERLAY], "{plan}");

    // DNAT（alias→target）+ 受控 SNAT（target→网关 LAN 地址），两条都带所有权注释。
    let nat = plan["nat_rules"].as_array().unwrap();
    assert_eq!(nat.len(), 2, "{plan}");
    assert_eq!(nat[0]["chain"], "prerouting");
    assert_eq!(nat[0]["match_dest"], "10.241.30.0/24");
    assert_eq!(nat[0]["action"]["net_map"]["to"], "192.168.30.0/24");
    assert_eq!(nat[1]["chain"], "postrouting");
    assert_eq!(nat[1]["match_dest"], "192.168.30.0/24");
    assert_eq!(nat[1]["action"], "snat_to_gateway_lan");
    let owner = format!("meshlet alias {alias_id}");
    assert!(
        nat.iter().all(|r| r["owner"] == owner),
        "ownership comment: {plan}"
    );

    // 删除映射 = 整单元清理（§12.6）：计划里的 NAT 随之撤下。
    let res = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/networks/{}/aliases/{alias_id}",
                    ctx.network_id
                ))
                .header("cookie", &ctx.cookie)
                .header("x-requested-with", "XMLHttpRequest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    apply_current(&ctx).await;
    let (st, after) = desired(&ctx.app, Some(&token)).await;
    assert_eq!(st, StatusCode::OK, "{after}");
    assert!(
        after["nat_rules"].as_array().unwrap().is_empty(),
        "deleted alias must drop its nat rules: {after}"
    );

    std::fs::remove_file(&key_file).ok();
    std::fs::remove_dir(&dir).ok();
}

#[tokio::test]
async fn host_forward_plan_carries_full_host_nat_rules() {
    if !wg_available() {
        return;
    }
    let dir = std::env::temp_dir().join("meshlet-agent-plan-host-forward");
    std::fs::create_dir_all(&dir).unwrap();
    let key_file = write_hub_key(&dir).unwrap();
    let dp = meshlet_config::DataPlaneConfig {
        private_key_file: Some(key_file.to_string_lossy().to_string()),
        ..dataplane_on()
    };
    let (ctx, token) = bootstrap_with_device(dp, "pub-gw-host-0008").await;
    let gateway = own_device_id(&ctx).await;

    let (st, view) = admin(
        &ctx.app,
        &ctx.cookie,
        &format!("/api/v1/networks/{}/host-forwards", ctx.network_id),
        serde_json::json!({
            "gateway_device_id": gateway,
            "target_ipv4": "192.168.40.23",
            "alias_ipv4": "10.241.40.23",
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{view}");
    let alias_id = view["id"].as_str().unwrap().to_string();
    apply_current(&ctx).await;

    let (st, plan) = desired(&ctx.app, Some(&token)).await;
    assert_eq!(st, StatusCode::OK, "{plan}");
    let nat = plan["nat_rules"].as_array().unwrap();
    assert_eq!(nat.len(), 2, "{plan}");
    assert_eq!(nat[0]["match_dest"], "10.241.40.23/32");
    assert_eq!(nat[0]["action"]["net_map"]["to"], "192.168.40.23/32");
    assert_eq!(nat[1]["match_dest"], "192.168.40.23/32");
    assert_eq!(nat[1]["action"], "snat_to_gateway_lan");
    assert!(nat
        .iter()
        .all(|rule| rule["owner"] == format!("meshlet alias {alias_id}")));

    let res = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/networks/{}/host-forwards/{alias_id}",
                    ctx.network_id
                ))
                .header("cookie", &ctx.cookie)
                .header("x-requested-with", "XMLHttpRequest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    apply_current(&ctx).await;
    let (st, after) = desired(&ctx.app, Some(&token)).await;
    assert_eq!(st, StatusCode::OK, "{after}");
    assert!(after["nat_rules"].as_array().unwrap().is_empty());

    std::fs::remove_file(&key_file).ok();
    std::fs::remove_dir(&dir).ok();
}

#[tokio::test]
async fn desired_plan_fails_visibly_when_hub_key_file_missing() {
    // 开启数据面但未配私钥文件：明确 500，不返回空计划。
    let (ctx, token) = bootstrap_with_device(dataplane_on(), "pub-edge-dddd-0006").await;
    let (st, body) = desired(&ctx.app, Some(&token)).await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("private_key_file"));
}

#[tokio::test]
async fn revoked_device_cannot_fetch_a_plan() {
    // 撤销设备 → 其 agent 凭证失效（§11.5）→ 401。
    let (ctx, token) = bootstrap_with_device(
        meshlet_config::DataPlaneConfig::default(),
        "pub-edge-eeee-0007",
    )
    .await;
    let (st, list) = {
        let res = ctx
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/networks/{}/devices", ctx.network_id))
                    .header("cookie", &ctx.cookie)
                    .header("x-requested-with", "XMLHttpRequest")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        (res.status(), res_body(res).await)
    };
    assert_eq!(st, StatusCode::OK, "{list}");
    let my_id = list[0]["id"].as_str().unwrap().to_string();

    let res = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/networks/{}/devices/{}/revoke",
                    ctx.network_id, my_id
                ))
                .header("cookie", &ctx.cookie)
                .header("x-requested-with", "XMLHttpRequest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);

    let (st, body) = desired(&ctx.app, Some(&token)).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "{body}");
}

/// 开启数据面的默认配置（测试用）。
fn dataplane_on() -> meshlet_config::DataPlaneConfig {
    meshlet_config::DataPlaneConfig {
        enabled: true,
        ..meshlet_config::DataPlaneConfig::default()
    }
}

/// 本 ctx 网络的设备列表首项（bootstrap 加入的那台）。
async fn own_device_id(ctx: &Ctx) -> String {
    let res = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/networks/{}/devices", ctx.network_id))
                .header("cookie", &ctx.cookie)
                .header("x-requested-with", "XMLHttpRequest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let list = res_body(res).await;
    list[0]["id"].as_str().unwrap().to_string()
}
