//! Shared production-style boot helpers for hub restart and recovery tests.
#![cfg(target_os = "linux")]
use super::single_instance_support::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use meshlet_network::{DevicePlan, SystemBackend};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};
use tower::ServiceExt;

pub(super) async fn desired_plan(app: &Router, token: &str) -> DevicePlan {
    let (status, body) = request(
        app,
        "GET",
        "/api/v1/agent/device/desired",
        Value::Null,
        None,
        Some(token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    serde_json::from_value(body).unwrap()
}

// ------------------------------------------------------------------ M3 故障矩阵
//
// 每个场景都是独立的 `#[tokio::test]`，共用下面的启动器：按生产启动路径连库、
// `persist::load` 装载 mesh、注入 netns 后端，再建一个网络 + 两台设备并收敛。

/// 已启动的服务与一个已收敛的网络（hub 已应用，两台设备已应用并回执）。
pub(super) struct Boot {
    pub(super) app: Router,
    pub(super) cookie: String,
    pub(super) state: Arc<meshlet_server::auth::AppState>,
    pub(super) shared: Arc<Mutex<meshlet_server::service::MeshState>>,
    pub(super) pool: sqlx::sqlite::SqlitePool,
    pub(super) network: String,
    pub(super) tokens: Vec<String>,
    pub(super) keys: Vec<String>,
    pub(super) device_ids: Vec<String>,
}

/// 按生产启动路径构建服务：连库 → `persist::load` → 注入沙箱后端。库里有存量
/// 时 mesh 直接来自库（恢复/重启场景靠这一点），空库则 mesh 为空。
pub(super) async fn boot_app(sandbox: &Sandbox, key_file: &str) -> Boot {
    let (private, _) = meshlet_network::keys::generate_keypair().unwrap();
    let path = sandbox.dir.join(key_file);
    std::fs::write(&path, private).unwrap();
    let dataplane = meshlet_config::DataPlaneConfig {
        enabled: true,
        interface: "wg0".into(),
        listen_port: Some(51820),
        private_key_file: Some(path.to_string_lossy().into_owned()),
    };
    let hub_ns = sandbox.names[0].clone();
    let factory = meshlet_server::revision::hub_backend_factory_with(
        dataplane.clone(),
        Some(1380),
        move || SystemBackend::new().with_netns(hub_ns.clone()).with_sudo(),
    );
    let pool = meshlet_server::store::connect(&format!(
        "sqlite:{}",
        sandbox.dir.join("state.db").display()
    ))
    .await
    .unwrap();
    let loaded = meshlet_server::persist::load(&pool, Default::default())
        .await
        .unwrap();
    let shared = Arc::new(Mutex::new(loaded.mesh));
    let state = Arc::new(
        meshlet_server::auth::AppState::new(
            shared.clone(),
            meshlet_server::auth::AuthStore::new(pool.clone()),
            meshlet_server::agent::AgentTokenStore::new(pool.clone()),
            meshlet_server::api_token::ApiTokenStore::new(pool.clone()),
            false,
        )
        .with_dataplane(dataplane)
        .with_tunnel_mtu(Some(1380))
        .with_apply_backend(factory),
    );
    let app = meshlet_server::router(state.clone());
    // 全新库走 bootstrap；已有管理员（从备份恢复后重启）改走登录——拿到的
    // 是同一种会话，与真实运维流程一致。
    let credentials = json!({"email":"admin@test.local","password":"single-instance-password"});
    let mut response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(credentials.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    if response.status() == StatusCode::CONFLICT {
        response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(credentials.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
    }
    assert!(
        response.status() == StatusCode::CREATED || response.status() == StatusCode::OK,
        "bootstrap/login failed: {}",
        response.status()
    );
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    Boot {
        app,
        cookie,
        state,
        shared,
        pool,
        network: String::new(),
        tokens: Vec::new(),
        keys: Vec::new(),
        device_ids: Vec::new(),
    }
}

/// 建一个网络 + 邀请 + 两台设备，hub 应用，两台设备应用并回执。
pub(super) async fn boot_network(sandbox: &Sandbox, key_file: &str) -> Boot {
    let mut boot = boot_app(sandbox, key_file).await;
    let network = admin(
        &boot.app,
        &boot.cookie,
        "/api/v1/networks",
        json!({"name":"net-fault","overlay_cidr":"10.240.0.0/24"}),
    )
    .await;
    boot.network = network["id"].as_str().unwrap().to_owned();
    let invite = admin(
        &boot.app,
        &boot.cookie,
        &format!("/api/v1/networks/{}/invites", boot.network),
        json!({"max_uses":4}),
    )
    .await;
    for i in 0..2 {
        let (private, public) = meshlet_network::keys::generate_keypair().unwrap();
        let (status, device) = request(
            &boot.app,
            "POST",
            "/api/v1/enroll",
            json!({"invite_token":invite["token"],"device_name":format!("fault-{i}"),"public_key":public,"platform":"linux"}),
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{device}");
        boot.tokens
            .push(device["agent_token"].as_str().unwrap().to_owned());
        boot.keys.push(private);
        boot.device_ids
            .push(device["device_id"].as_str().unwrap().to_owned());
    }
    let view = apply(&boot.app, &boot.cookie, &boot.network).await;
    assert_eq!(view["apply_status"], "applied", "{view}");
    converge_device(sandbox, &boot, 0).await;
    converge_device(sandbox, &boot, 1).await;
    assert!(ping(&sandbox.names[1], "10.240.0.3"));
    boot
}

/// 设备端拉取期望、注入真实 underlay endpoint、应用、回执。
pub(super) async fn converge_device(sandbox: &Sandbox, boot: &Boot, index: usize) -> DevicePlan {
    let plan = desired_plan(&boot.app, &boot.tokens[index]).await;
    let mut local = plan.clone();
    local.tunnel.peers[0].endpoint =
        Some(format!("172.31.{}.1:{}", index + 1, plan.hub_port.unwrap()));
    local.tunnel.peers[0].persistent_keepalive_secs = Some(1);
    let mut backend = SystemBackend::new()
        .with_netns(sandbox.names[index + 1].clone())
        .with_sudo();
    backend
        .apply_device_plan_sync(
            &local,
            Some(boot.keys[index].clone()),
            None,
            &BTreeSet::new(),
        )
        .unwrap();
    let (status, _) = request(
        &boot.app,
        "POST",
        "/api/v1/agent/device/applied",
        json!({"desired_revision":plan.desired_revision,"plan_hash":plan.desired_config_hash,"error":null}),
        None,
        Some(&boot.tokens[index]),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    plan
}

/// 恢复日志（`hub_deployments.plan_json`）里的 hub 部署，供断言被撤销设备
/// 是否仍然被记账。
pub(super) async fn journal_plan(pool: &sqlx::SqlitePool, network: &str) -> Value {
    let json: String =
        sqlx::query_scalar("SELECT plan_json FROM hub_deployments WHERE network_id=?")
            .bind(network)
            .fetch_one(pool)
            .await
            .unwrap();
    serde_json::from_str(&json).unwrap()
}

pub(super) fn wg_own_public_key(sandbox: &Sandbox, index: usize) -> String {
    let out = ns(&sandbox.names[index], &["wg", "show", "wg0", "public-key"]);
    assert!(
        out.status.success(),
        "wg show: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// WireGuard peer 身份行（peer 公钥 + allowed-ips），排序后作为重启/变更前后
/// 的逐字段比对基准。endpoints、handshake 时间等易变字段不参与比对。
pub(super) fn wg_identity_lines(sandbox: &Sandbox, index: usize) -> Vec<String> {
    let out = ns(&sandbox.names[index], &["wg", "show", "wg0"]);
    assert!(
        out.status.success(),
        "wg show: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut lines = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|line| line.starts_with("peer:") || line.starts_with("  allowed ips:"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    lines.sort();
    lines
}

pub(super) fn sorted_lines(sandbox: &Sandbox, index: usize, args: &[&str]) -> Vec<String> {
    let out = ns(&sandbox.names[index], args);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut lines = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect::<Vec<_>>();
    lines.sort();
    lines
}

/// 设备上所有权注释为 Meshlet 的 NAT 规则行（两条链合并，排序）。
pub(super) fn meshlet_nat_lines(sandbox: &Sandbox, index: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for chain in ["PREROUTING", "POSTROUTING"] {
        let out = ns(
            &sandbox.names[index],
            &["iptables", "-t", "nat", "-S", chain],
        );
        assert!(
            out.status.success(),
            "iptables -S {chain}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if line.contains("meshlet") {
                lines.push(line.to_string());
            }
        }
    }
    lines.sort();
    lines
}
