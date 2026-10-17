//! One server, two networks, one hub namespace. Real WireGuard/firewall evidence.
#![cfg(target_os = "linux")]
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use meshlet_network::{DevicePlan, SystemBackend};
use serde_json::{json, Value};
use std::{
    process::{Command, Output},
    sync::{Arc, Mutex},
};
use tower::ServiceExt;

fn sudo(args: &[&str]) -> Output {
    Command::new("sudo")
        .arg("-n")
        .args(args)
        .output()
        .expect("sudo")
}
fn require(args: &[&str]) {
    let out = sudo(args);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
fn ns(name: &str, args: &[&str]) -> Output {
    let mut command = vec!["ip", "netns", "exec", name];
    command.extend(args);
    sudo(&command)
}
fn net(name: &str, args: &[&str]) {
    let out = ns(name, args);
    assert!(
        out.status.success(),
        "{name} {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
struct Sandbox {
    names: Vec<String>,
    dir: std::path::PathBuf,
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        for name in &self.names {
            let _ = sudo(&["ip", "netns", "del", name]);
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
fn setup() -> Option<Sandbox> {
    let ready = sudo(&["true"]).status.success()
        && Command::new("wg")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success());
    if !ready {
        assert!(
            std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
            "kernel prerequisites required"
        );
        eprintln!("SKIP: single-instance test needs sudo and WireGuard");
        return None;
    }
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let suffix = std::process::id() * 10 + NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let sandbox = Sandbox {
        names: (0..7).map(|i| format!("mlsi{suffix}-{i}")).collect(),
        dir: std::env::temp_dir().join(format!("meshlet-single-{suffix}")),
    };
    std::fs::create_dir_all(&sandbox.dir).unwrap();
    for name in &sandbox.names {
        require(&["ip", "netns", "add", name]);
        net(name, &["ip", "link", "set", "lo", "up"]);
    }
    for i in 1..5 {
        let left = format!("ms{suffix}a{i}");
        let right = format!("ms{suffix}b{i}");
        require(&[
            "ip", "link", "add", &left, "type", "veth", "peer", "name", &right,
        ]);
        require(&["ip", "link", "set", &left, "netns", &sandbox.names[0]]);
        require(&["ip", "link", "set", &right, "netns", &sandbox.names[i]]);
        for (name, device, addr) in [
            (&sandbox.names[0], &left, format!("172.31.{i}.1/30")),
            (&sandbox.names[i], &right, format!("172.31.{i}.2/30")),
        ] {
            net(name, &["ip", "addr", "add", &addr, "dev", device]);
            net(name, &["ip", "link", "set", device, "up"]);
            net(
                name,
                &[
                    "ethtool", "-K", device, "gro", "off", "gso", "off", "tso", "off",
                ],
            );
        }
    }
    for (i, lan) in [60, 61].iter().enumerate() {
        let left = format!("ml{suffix}a{i}");
        let right = format!("ml{suffix}b{i}");
        require(&[
            "ip", "link", "add", &left, "type", "veth", "peer", "name", &right,
        ]);
        require(&["ip", "link", "set", &left, "netns", &sandbox.names[1]]);
        require(&["ip", "link", "set", &right, "netns", &sandbox.names[5 + i]]);
        for (name, device, address) in [
            (&sandbox.names[1], &left, format!("192.168.{lan}.1/24")),
            (&sandbox.names[5 + i], &right, format!("192.168.{lan}.5/24")),
        ] {
            net(name, &["ip", "addr", "add", &address, "dev", device]);
            net(name, &["ip", "link", "set", device, "up"]);
            net(
                name,
                &[
                    "ethtool", "-K", device, "gro", "off", "gso", "off", "tso", "off",
                ],
            );
        }
    }
    Some(sandbox)
}
async fn request(
    app: &Router,
    method: &str,
    path: &str,
    body: Value,
    cookie: Option<&str>,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(cookie) = cookie {
        req = req
            .header("cookie", cookie)
            .header("x-requested-with", "XMLHttpRequest");
    }
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
async fn admin(app: &Router, cookie: &str, path: &str, body: Value) -> Value {
    let (status, value) = request(app, "POST", path, body, Some(cookie), None).await;
    assert!(status.is_success(), "{path}: {status} {value}");
    value
}
async fn apply(app: &Router, cookie: &str, network: &str) -> Value {
    let (_, revisions) = request(
        app,
        "GET",
        &format!("/api/v1/networks/{network}/config-revisions"),
        Value::Null,
        Some(cookie),
        None,
    )
    .await;
    let revision = revisions.as_array().unwrap().last().unwrap()["revision"]
        .as_u64()
        .unwrap();
    admin(
        app,
        cookie,
        &format!("/api/v1/networks/{network}/config-revisions/{revision}/apply"),
        json!({}),
    )
    .await
}
async fn apply_revision(app: &Router, cookie: &str, network: &str, revision: u64) -> Value {
    admin(
        app,
        cookie,
        &format!("/api/v1/networks/{network}/config-revisions/{revision}/apply"),
        json!({}),
    )
    .await
}
fn ping(name: &str, target: &str) -> bool {
    ns(name, &["ping", "-c", "2", "-W", "1", target])
        .status
        .success()
}

fn reconnects(name: &str, target: &str) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(35);
    while std::time::Instant::now() < deadline {
        if ping(name, target) {
            return true;
        }
    }
    false
}

#[tokio::test(flavor = "multi_thread")]
async fn two_networks_isolate_reconcile_and_rollback_on_one_hub() {
    let Some(sandbox) = setup() else {
        return;
    };
    let (private, _) = meshlet_network::keys::generate_keypair().unwrap();
    let path = sandbox.dir.join("hub.key");
    std::fs::write(&path, private).unwrap();
    let cfg = meshlet_config::DataPlaneConfig {
        enabled: true,
        interface: "wg0".into(),
        listen_port: Some(51820),
        private_key_file: Some(path.to_string_lossy().into_owned()),
    };
    let hub_ns = sandbox.names[0].clone();
    let factory =
        meshlet_server::revision::hub_backend_factory_with(cfg.clone(), Some(1380), move || {
            SystemBackend::new().with_netns(hub_ns.clone()).with_sudo()
        });
    let pool = meshlet_server::store::connect(&format!(
        "sqlite:{}",
        sandbox.dir.join("state.db").display()
    ))
    .await
    .unwrap();
    let shared = Arc::new(Mutex::new(meshlet_server::service::MeshState::default()));
    let state = Arc::new(
        meshlet_server::auth::AppState::new(
            shared.clone(),
            meshlet_server::auth::AuthStore::new(pool.clone()),
            meshlet_server::agent::AgentTokenStore::new(pool.clone()),
            meshlet_server::api_token::ApiTokenStore::new(pool.clone()),
            false,
        )
        .with_dataplane(cfg.clone())
        .with_tunnel_mtu(Some(1380))
        .with_apply_backend(factory.clone()),
    );
    let app = meshlet_server::router(state.clone());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email":"admin@test.local","password":"single-instance-password"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let mut networks = Vec::new();
    let mut tokens = Vec::new();
    let mut keys = Vec::new();
    let mut device_ids = Vec::new();
    for (n, cidr) in ["10.240.0.0/24", "10.242.0.0/24"].iter().enumerate() {
        let network = admin(
            &app,
            &cookie,
            "/api/v1/networks",
            json!({"name":format!("net-{n}"),"overlay_cidr":cidr}),
        )
        .await;
        let id = network["id"].as_str().unwrap().to_owned();
        let invite = admin(
            &app,
            &cookie,
            &format!("/api/v1/networks/{id}/invites"),
            json!({"max_uses":4}),
        )
        .await;
        for i in 0..2 {
            let (private, public) = meshlet_network::keys::generate_keypair().unwrap();
            let (status, device) = request(&app, "POST", "/api/v1/enroll", json!({"invite_token":invite["token"],"device_name":format!("device-{n}-{i}"),"public_key":public,"platform":"linux"}), None, None).await;
            assert_eq!(status, StatusCode::CREATED, "{device}");
            tokens.push(device["agent_token"].as_str().unwrap().to_owned());
            keys.push(private);
            device_ids.push(device["device_id"].as_str().unwrap().to_owned());
        }
        networks.push(id);
    }
    for id in &networks {
        let view = apply(&app, &cookie, id).await;
        assert_eq!(view["apply_status"], "applied", "{view}");
        assert_eq!(view["convergence"]["device_apply_status"], "pending");
    }
    let mut plans = Vec::new();
    for i in 0..4 {
        let (status, body) = request(
            &app,
            "GET",
            "/api/v1/agent/device/desired",
            Value::Null,
            None,
            Some(&tokens[i]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let plan: DevicePlan = serde_json::from_value(body).unwrap();
        let mut local = plan.clone();
        local.tunnel.peers[0].endpoint =
            Some(format!("172.31.{}.1:{}", i + 1, plan.hub_port.unwrap()));
        local.tunnel.peers[0].persistent_keepalive_secs = Some(1);
        let mut backend = SystemBackend::new()
            .with_netns(sandbox.names[i + 1].clone())
            .with_sudo();
        backend
            .apply_device_plan_sync(&local, Some(keys[i].clone()), None)
            .unwrap();
        let (status, _) = request(&app, "POST", "/api/v1/agent/device/applied", json!({"desired_revision":plan.desired_revision,"plan_hash":plan.desired_config_hash,"error":null}), None, Some(&tokens[i])).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        plans.push(local);
    }
    assert!(ping(&sandbox.names[1], "10.240.0.3"));
    assert!(ping(&sandbox.names[3], "10.242.0.3"));
    // A malicious client adds B's routes/AllowedIPs; hub enforcement still denies it.
    let mut malicious = plans[0].clone();
    malicious.tunnel.peers[0]
        .allowed_ips
        .push("10.242.0.0/24".parse().unwrap());
    let mut backend = SystemBackend::new()
        .with_netns(sandbox.names[1].clone())
        .with_sudo();
    backend
        .apply_device_plan_sync(&malicious, Some(keys[0].clone()), None)
        .unwrap();
    net(
        &sandbox.names[1],
        &["ip", "route", "replace", "10.242.0.0/24", "dev", "wg0"],
    );
    assert!(!ping(&sandbox.names[1], "10.242.0.3"));
    assert!(!ping(&sandbox.names[1], "10.242.0.1"));
    // Reapply A; B's peers and tunnel survive.
    apply(&app, &cookie, &networks[0]).await;
    assert!(ping(&sandbox.names[3], "10.242.0.3"));
    // Delete A's kernel interface and rebuild state from SQLite, simulating a reboot.
    net(&sandbox.names[0], &["ip", "link", "del", "wg0"]);
    let loaded = meshlet_server::persist::load(&pool, Default::default())
        .await
        .unwrap();
    *shared.lock().unwrap() = loaded.mesh;
    meshlet_server::convergence::recover_once(state.clone())
        .await
        .unwrap();
    assert!(reconnects(&sandbox.names[1], "10.240.0.3"));
    assert!(ping(&sandbox.names[3], "10.242.0.3"));
    // Migration from a version-eight Applied database: no journal exists yet.
    sqlx::query("DELETE FROM hub_deployments WHERE network_id=?")
        .bind(&networks[0])
        .execute(&pool)
        .await
        .unwrap();
    *shared.lock().unwrap() = meshlet_server::persist::load(&pool, Default::default())
        .await
        .unwrap()
        .mesh;
    meshlet_server::convergence::recover_once(state.clone())
        .await
        .unwrap();
    let journal: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM hub_deployments WHERE network_id=?")
            .bind(&networks[0])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(journal, 1);
    assert!(ping(&sandbox.names[1], "10.240.0.3"));
    // A new plan fails after changing peers: restore the prior working plan, not a sweep.
    net(
        &sandbox.names[0],
        &["ip", "route", "add", "192.168.99.0/24", "dev", "lo"],
    );
    let route = admin(&app, &cookie, &format!("/api/v1/networks/{}/routes", networks[0]), json!({"gateway_device_id":device_ids[0],"destination_cidr":"192.168.99.0/24","route_mode":"direct","return_path_mode":"dual_route"})).await;
    let failed = apply(&app, &cookie, &networks[0]).await;
    assert_eq!(failed["apply_status"], "failed", "{failed}");
    let rolled = admin(
        &app,
        &cookie,
        &format!(
            "/api/v1/networks/{}/config-revisions/{}/rollback",
            networks[0], route["revision_id"]
        ),
        json!({}),
    )
    .await;
    assert_eq!(rolled["apply_status"], "rolled_back", "{rolled}");
    assert!(ping(&sandbox.names[1], "10.240.0.3"));
    assert!(ping(&sandbox.names[3], "10.242.0.3"));
    let (_, routes) = request(
        &app,
        "GET",
        &format!("/api/v1/networks/{}/routes", networks[0]),
        Value::Null,
        Some(&cookie),
        None,
    )
    .await;
    assert!(routes.as_array().unwrap().is_empty());
    assert!(ns(
        &sandbox.names[0],
        &["ip", "route", "show", "exact", "192.168.99.0/24"]
    )
    .stdout
    .windows(6)
    .any(|w| w == b"dev lo"));
    // Direct controlled SNAT through a gateway with two distinct LAN interfaces.
    let mut route_ids = Vec::new();
    for lan in [60, 61] {
        let route = admin(&app, &cookie, &format!("/api/v1/networks/{}/routes", networks[0]), json!({"gateway_device_id":device_ids[0],"destination_cidr":format!("192.168.{lan}.0/24"),"route_mode":"direct","return_path_mode":"controlled_snat"})).await;
        route_ids.push(route["id"].as_str().unwrap().to_owned());
    }
    assert_eq!(
        apply(&app, &cookie, &networks[0]).await["apply_status"],
        "applied"
    );
    let mut gateway_plan = None;
    for i in 0..2 {
        let (status, body) = request(
            &app,
            "GET",
            "/api/v1/agent/device/desired",
            Value::Null,
            None,
            Some(&tokens[i]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let plan: DevicePlan = serde_json::from_value(body).unwrap();
        let mut local = plan.clone();
        local.tunnel.peers[0].endpoint = Some(format!("172.31.{}.1:51820", i + 1));
        let mut backend = SystemBackend::new()
            .with_netns(sandbox.names[i + 1].clone())
            .with_sudo();
        backend
            .apply_device_plan_sync(&local, Some(keys[i].clone()), None)
            .unwrap();
        if i == 0 {
            gateway_plan = Some(plan);
        }
    }
    assert!(reconnects(&sandbox.names[2], "192.168.60.5"));
    assert!(ping(&sandbox.names[2], "192.168.61.5"));
    let postrouting = ns(
        &sandbox.names[1],
        &["iptables", "-t", "nat", "-S", "POSTROUTING"],
    );
    let rules = String::from_utf8_lossy(&postrouting.stdout);
    assert!(rules
        .lines()
        .any(|r| r.contains("192.168.60.0/24") && r.contains("--to-source 192.168.60.1")));
    assert!(rules
        .lines()
        .any(|r| r.contains("192.168.61.0/24") && r.contains("--to-source 192.168.61.1")));
    // Delete only one SNAT rule. Another rule remains, so a boolean/count check would miss it.
    let plan = gateway_plan.unwrap();
    let mut delete = plan.nat_rules[1].iptables_args("192.168.61.1".parse().unwrap());
    delete[0] = "-D".into();
    let mut argv = vec!["iptables", "-t", "nat"];
    argv.extend(delete.iter().map(String::as_str));
    net(&sandbox.names[1], &argv);
    let state_dir = sandbox.dir.join("agent");
    let config = meshlet_config::AgentConfig {
        server_url: "http://127.0.0.1:1".into(),
        state_dir: state_dir.to_string_lossy().into_owned(),
        device_token: Some(tokens[0].clone()),
        bootstrap_token: None,
        device_name: None,
        tray: meshlet_config::TrayConfig::OFF,
        dataplane: meshlet_config::DataplaneConfig {
            enabled: true,
            hub_endpoint: Some("172.31.1.1:51820".into()),
            ..Default::default()
        },
    };
    let mut agent = meshlet_agent::agent::Agent::with_backend(
        config,
        Some(keys[0].clone()),
        SystemBackend::new()
            .with_netns(sandbox.names[1].clone())
            .with_sudo(),
    );
    meshlet_agent::reconcile::AgentState::from_plan(&plan)
        .save(agent.state_path())
        .unwrap();
    assert_eq!(
        agent.reconcile(&plan).unwrap().reason,
        meshlet_agent::reconcile::Reason::KernelDrift
    );
    assert!(ping(&sandbox.names[2], "192.168.61.5"));
    net(
        &sandbox.names[1],
        &["sysctl", "-w", "net.ipv4.ip_forward=0"],
    );
    assert_eq!(
        agent.reconcile(&plan).unwrap().reason,
        meshlet_agent::reconcile::Reason::KernelDrift
    );
    assert!(ping(&sandbox.names[2], "192.168.60.5"));
    // Direct dual_route preserves the source and requires an explicit LAN return route.
    let (status, _) = request(
        &app,
        "DELETE",
        &format!("/api/v1/networks/{}/routes/{}", networks[0], route_ids[0]),
        Value::Null,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let dual = admin(&app, &cookie, &format!("/api/v1/networks/{}/routes", networks[0]), json!({"gateway_device_id":device_ids[0],"destination_cidr":"192.168.60.0/24","route_mode":"direct","return_path_mode":"dual_route"})).await;
    route_ids[0] = dual["id"].as_str().unwrap().to_owned();
    apply(&app, &cookie, &networks[0]).await;
    let (_, body) = request(
        &app,
        "GET",
        "/api/v1/agent/device/desired",
        Value::Null,
        None,
        Some(&tokens[0]),
    )
    .await;
    let dual_plan: DevicePlan = serde_json::from_value(body).unwrap();
    agent.reconcile(&dual_plan).unwrap();
    let (_, body) = request(
        &app,
        "GET",
        "/api/v1/agent/device/desired",
        Value::Null,
        None,
        Some(&tokens[1]),
    )
    .await;
    let mut dual_client: DevicePlan = serde_json::from_value(body).unwrap();
    dual_client.tunnel.peers[0].endpoint = Some("172.31.2.1:51820".into());
    let mut backend = SystemBackend::new()
        .with_netns(sandbox.names[2].clone())
        .with_sudo();
    backend
        .apply_device_plan_sync(&dual_client, Some(keys[1].clone()), None)
        .unwrap();
    assert!(!ping(&sandbox.names[2], "192.168.60.5"));
    net(
        &sandbox.names[5],
        &["ip", "route", "add", "10.240.0.0/24", "via", "192.168.60.1"],
    );
    assert!(reconnects(&sandbox.names[2], "192.168.60.5"));
    // Switch to a DNAT-only gateway. No SNAT rule or inferred SNAT address is needed.
    for id in &route_ids {
        let (status, _) = request(
            &app,
            "DELETE",
            &format!("/api/v1/networks/{}/routes/{id}", networks[0]),
            Value::Null,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
    let route = admin(&app, &cookie, &format!("/api/v1/networks/{}/routes", networks[0]), json!({"gateway_device_id":device_ids[0],"destination_cidr":"192.168.61.0/24","route_mode":"alias","return_path_mode":"dual_route"})).await;
    admin(&app, &cookie, &format!("/api/v1/networks/{}/aliases", networks[0]), json!({"lan_route_id":route["id"],"alias_cidr":"10.243.61.0/24","translation_mode":"dnat_only"})).await;
    apply(&app, &cookie, &networks[0]).await;
    let (_, body) = request(
        &app,
        "GET",
        "/api/v1/agent/device/desired",
        Value::Null,
        None,
        Some(&tokens[0]),
    )
    .await;
    let only_dnat: DevicePlan = serde_json::from_value(body).unwrap();
    assert_eq!(only_dnat.nat_rules.len(), 1);
    agent.reconcile(&only_dnat).unwrap();
    let (_, body) = request(
        &app,
        "GET",
        "/api/v1/agent/device/desired",
        Value::Null,
        None,
        Some(&tokens[1]),
    )
    .await;
    let mut client: DevicePlan = serde_json::from_value(body).unwrap();
    client.tunnel.peers[0].endpoint = Some("172.31.2.1:51820".into());
    let mut backend = SystemBackend::new()
        .with_netns(sandbox.names[2].clone())
        .with_sudo();
    backend
        .apply_device_plan_sync(&client, Some(keys[1].clone()), None)
        .unwrap();
    assert!(
        !ping(&sandbox.names[2], "10.243.61.5"),
        "source-preserving mode needs a LAN return route"
    );
    net(
        &sandbox.names[6],
        &["ip", "route", "add", "10.240.0.0/24", "via", "192.168.61.1"],
    );
    assert!(reconnects(&sandbox.names[2], "10.243.61.5"));
    assert!(ping(&sandbox.names[3], "10.242.0.3"));
    // Revoking A's gateway removes its peer and credentials without disturbing B.
    admin(
        &app,
        &cookie,
        &format!(
            "/api/v1/networks/{}/devices/{}/revoke",
            networks[0], device_ids[0]
        ),
        json!({}),
    )
    .await;
    assert_eq!(
        apply(&app, &cookie, &networks[0]).await["apply_status"],
        "applied"
    );
    assert!(!ping(&sandbox.names[2], "10.240.0.2"));
    assert!(ping(&sandbox.names[3], "10.242.0.3"));
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/v1/agent/device/desired",
            Value::Null,
            None,
            Some(&tokens[0])
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    factory(&shared.lock().unwrap(), &networks[0])
        .reconcile()
        .unwrap();
    assert!(!ping(&sandbox.names[2], "10.240.0.2"));
    // First-ever application failure has no previous plan: clear C alone and
    // persist removal of its failed desired resources, including across restart.
    let c = admin(
        &app,
        &cookie,
        "/api/v1/networks",
        json!({"name":"first-failure","overlay_cidr":"10.244.0.0/24"}),
    )
    .await;
    let c = c["id"].as_str().unwrap();
    let invite = admin(
        &app,
        &cookie,
        &format!("/api/v1/networks/{c}/invites"),
        json!({"max_uses":1}),
    )
    .await;
    let (_, public) = meshlet_network::keys::generate_keypair().unwrap();
    let (status, device) = request(&app, "POST", "/api/v1/enroll", json!({"invite_token":invite["token"],"device_name":"c","public_key":public,"platform":"linux"}), None, None).await;
    assert_eq!(status, StatusCode::CREATED);
    net(
        &sandbox.names[0],
        &["ip", "route", "add", "192.168.100.0/24", "dev", "lo"],
    );
    let route = admin(&app, &cookie, &format!("/api/v1/networks/{c}/routes"), json!({"gateway_device_id":device["device_id"],"destination_cidr":"192.168.100.0/24","return_path_mode":"dual_route"})).await;
    assert_eq!(apply(&app, &cookie, c).await["apply_status"], "failed");
    let rolled = admin(
        &app,
        &cookie,
        &format!(
            "/api/v1/networks/{c}/config-revisions/{}/rollback",
            route["revision_id"]
        ),
        json!({}),
    )
    .await;
    assert_eq!(rolled["apply_status"], "rolled_back", "{rolled}");
    assert!(!ns(&sandbox.names[0], &["ip", "link", "show", "mlt3"])
        .status
        .success());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM lan_routes WHERE network_id=?")
        .bind(c)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    assert!(ping(&sandbox.names[3], "10.242.0.3"));
}

async fn desired_plan(app: &Router, token: &str) -> DevicePlan {
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

fn forwarding_agent(
    sandbox: &Sandbox,
    index: usize,
    token: &str,
    private_key: &str,
) -> meshlet_agent::agent::Agent {
    let config = meshlet_config::AgentConfig {
        server_url: "http://127.0.0.1:1".into(),
        state_dir: sandbox
            .dir
            .join(format!("forward-agent-{index}"))
            .to_string_lossy()
            .into_owned(),
        device_token: Some(token.into()),
        bootstrap_token: None,
        device_name: None,
        tray: meshlet_config::TrayConfig::OFF,
        dataplane: meshlet_config::DataplaneConfig {
            enabled: true,
            hub_endpoint: Some(format!("172.31.{index}.1:51820")),
            ..Default::default()
        },
    };
    meshlet_agent::agent::Agent::with_backend(
        config,
        Some(private_key.into()),
        SystemBackend::new()
            .with_netns(sandbox.names[index].clone())
            .with_sudo(),
    )
}

/// Real TCP/UDP round trips assert both payload and translated reply/source IP.
fn host_echo(sandbox: &Sandbox, lan: usize, alias: &str, source: &str, udp: bool) {
    use std::io::BufRead;
    use std::process::Stdio;
    struct Echo(std::process::Child);
    impl Drop for Echo {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let server = r#"
import socket, sys
udp = sys.argv[1] == 'udp'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.settimeout(10)
s.bind(('0.0.0.0', 23456))
if not udp: s.listen(1)
print('ready', flush=True)
if udp:
    body, peer = s.recvfrom(256)
    s.sendto(body + b' seen=' + peer[0].encode(), peer)
else:
    c, peer = s.accept()
    c.settimeout(10)
    body = c.recv(256)
    c.sendall(body + b' seen=' + peer[0].encode())
    c.close()
"#;
    let protocol = if udp { "udp" } else { "tcp" };
    let mut child = Echo(
        Command::new("sudo")
            .args([
                "-n",
                "ip",
                "netns",
                "exec",
                &sandbox.names[5 + lan],
                "python3",
                "-u",
                "-c",
                server,
                protocol,
            ])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut ready = String::new();
    std::io::BufReader::new(child.0.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready.trim(), "ready");
    let client = r#"
import socket, sys
udp = sys.argv[1] == 'udp'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
s.settimeout(5)
s.connect((sys.argv[2], 23456))
s.send(b'roundtrip')
if udp:
    body, peer = s.recvfrom(256)
else:
    body, peer = s.recv(256), s.getpeername()
assert peer[0] == sys.argv[2], peer
assert body == b'roundtrip seen=' + sys.argv[3].encode(), body
print(body.decode())
"#;
    net(
        &sandbox.names[2],
        &["python3", "-c", client, protocol, alias, source],
    );
    assert!(child.0.wait().unwrap().success());
}

#[tokio::test(flavor = "multi_thread")]
async fn host_forward_agent_roundtrip_sources_and_cleanup() {
    let Some(sandbox) = setup() else {
        return;
    };
    let (private, _) = meshlet_network::keys::generate_keypair().unwrap();
    let path = sandbox.dir.join("forward-hub.key");
    std::fs::write(&path, private).unwrap();
    let cfg = meshlet_config::DataPlaneConfig {
        enabled: true,
        interface: "wg0".into(),
        listen_port: Some(51820),
        private_key_file: Some(path.to_string_lossy().into_owned()),
    };
    let hub_ns = sandbox.names[0].clone();
    let factory =
        meshlet_server::revision::hub_backend_factory_with(cfg.clone(), Some(1380), move || {
            SystemBackend::new().with_netns(hub_ns.clone()).with_sudo()
        });
    let pool = meshlet_server::store::connect("sqlite::memory:")
        .await
        .unwrap();
    let state = Arc::new(
        meshlet_server::auth::AppState::new(
            Default::default(),
            meshlet_server::auth::AuthStore::new(pool.clone()),
            meshlet_server::agent::AgentTokenStore::new(pool.clone()),
            meshlet_server::api_token::ApiTokenStore::new(pool),
            false,
        )
        .with_dataplane(cfg)
        .with_tunnel_mtu(Some(1380))
        .with_apply_backend(factory),
    );
    let app = meshlet_server::router(state);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email":"forward@test.local","password":"forwarding-password-123"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let network = admin(
        &app,
        &cookie,
        "/api/v1/networks",
        json!({"name":"host-forward", "overlay_cidr":"10.240.0.0/24"}),
    )
    .await;
    let network = network["id"].as_str().unwrap();
    let invite = admin(
        &app,
        &cookie,
        &format!("/api/v1/networks/{network}/invites"),
        json!({"max_uses":2}),
    )
    .await;
    let mut tokens = Vec::new();
    let mut keys = Vec::new();
    let mut devices = Vec::new();
    for i in 0..2 {
        let (private, public) = meshlet_network::keys::generate_keypair().unwrap();
        let (status, device) = request(&app, "POST", "/api/v1/enroll", json!({"invite_token":invite["token"],"device_name":format!("forward-{i}"),"public_key":public,"platform":"linux"}), None, None).await;
        assert_eq!(status, StatusCode::CREATED, "{device}");
        keys.push(private);
        tokens.push(device["agent_token"].as_str().unwrap().to_owned());
        devices.push(device["device_id"].as_str().unwrap().to_owned());
    }
    let uri = format!("/api/v1/networks/{network}/host-forwards");
    let mut gateway = forwarding_agent(&sandbox, 1, &tokens[0], &keys[0]);
    let mut client = forwarding_agent(&sandbox, 2, &tokens[1], &keys[1]);
    let mut forwards = Vec::new();
    for lan in [60, 61] {
        forwards.push(admin(&app, &cookie, &uri, json!({"gateway_device_id":devices[0],"target_ipv4":format!("192.168.{lan}.5"),"alias_ipv4":format!("10.243.{lan}.5")})).await);
    }
    assert_eq!(
        apply(&app, &cookie, network).await["apply_status"],
        "applied"
    );
    let plan = desired_plan(&app, &tokens[0]).await;
    gateway.reconcile(&plan).unwrap();
    client
        .reconcile(&desired_plan(&app, &tokens[1]).await)
        .unwrap();
    assert!(
        reconnects(&sandbox.names[2], "10.243.60.5"),
        "client did not reach 10.243.60.5"
    );
    for (lan, alias, source) in [
        (0, "10.243.60.5", "192.168.60.1"),
        (1, "10.243.61.5", "192.168.61.1"),
    ] {
        for udp in [false, true] {
            host_echo(&sandbox, lan, alias, source, udp);
        }
    }
    assert_eq!(
        gateway.reconcile(&plan).unwrap().reason,
        meshlet_agent::reconcile::Reason::UpToDate
    );
    // Change the kernel's preferred source. Reconciliation must replace, rather
    // than append behind, the stale SNAT rule of this exact mapping owner.
    let route = ns(
        &sandbox.names[1],
        &["ip", "-4", "route", "get", "192.168.60.5"],
    );
    let text = String::from_utf8_lossy(&route.stdout);
    let fields: Vec<_> = text.split_whitespace().collect();
    let dev = fields.windows(2).find(|p| p[0] == "dev").unwrap()[1];
    net(
        &sandbox.names[1],
        &["ip", "addr", "add", "192.168.60.9/24", "dev", dev],
    );
    net(
        &sandbox.names[1],
        &[
            "ip",
            "route",
            "add",
            "192.168.60.5/32",
            "dev",
            dev,
            "src",
            "192.168.60.9",
        ],
    );
    assert_eq!(
        gateway.reconcile(&plan).unwrap().reason,
        meshlet_agent::reconcile::Reason::KernelDrift
    );
    host_echo(&sandbox, 0, "10.243.60.5", "192.168.60.9", true);
    host_echo(&sandbox, 1, "10.243.61.5", "192.168.61.1", true);
    let rules = ns(
        &sandbox.names[1],
        &["iptables", "-t", "nat", "-S", "POSTROUTING"],
    );
    let rules = String::from_utf8_lossy(&rules.stdout);
    assert!(!rules.contains("--to-source 192.168.60.1"));
    assert_eq!(rules.matches("--to-source 192.168.60.9").count(), 1);
    assert_eq!(
        gateway.reconcile(&plan).unwrap().reason,
        meshlet_agent::reconcile::Reason::UpToDate
    );
    // No route: report failure and keep the last successful ledger. No partial
    // NETMAP/SNAT unit may be created for the unreachable /32.
    let unreachable = admin(&app, &cookie, &uri, json!({"gateway_device_id":devices[0],"target_ipv4":"192.168.90.5","alias_ipv4":"10.243.90.5"})).await;
    let applied = apply_revision(
        &app,
        &cookie,
        network,
        unreachable["revision_id"].as_u64().unwrap(),
    )
    .await;
    assert_eq!(applied["apply_status"], "applied", "{applied}");
    let ledger = std::fs::read(gateway.state_path()).unwrap();
    let error = gateway
        .reconcile(&desired_plan(&app, &tokens[0]).await)
        .unwrap_err();
    assert!(
        error.contains("route") || error.contains("egress"),
        "{error}"
    );
    assert_eq!(std::fs::read(gateway.state_path()).unwrap(), ledger);
    let rules = ns(
        &sandbox.names[1],
        &["iptables", "-t", "nat", "-S", "PREROUTING"],
    );
    assert!(!String::from_utf8_lossy(&rules.stdout).contains("10.243.90.5/32"));
    let (status, _) = request(
        &app,
        "DELETE",
        &format!("{uri}/{}", unreachable["id"].as_str().unwrap()),
        Value::Null,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // DNAT-only does not require an SNAT source, even without LAN egress.
    let only_dnat = admin(&app, &cookie, &uri, json!({"gateway_device_id":devices[0],"target_ipv4":"192.168.90.5","alias_ipv4":"10.243.90.5","translation_mode":"dnat_only"})).await;
    assert_eq!(
        apply(&app, &cookie, network).await["apply_status"],
        "applied"
    );
    gateway
        .reconcile(&desired_plan(&app, &tokens[0]).await)
        .unwrap();
    let (status, _) = request(
        &app,
        "DELETE",
        &format!("{uri}/{}", only_dnat["id"].as_str().unwrap()),
        Value::Null,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // Replace home with source-preserving DNAT; prove its explicit return route.
    let owner = format!("meshlet alias {}", forwards[0]["id"].as_str().unwrap());
    let (status, _) = request(
        &app,
        "DELETE",
        &format!("{uri}/{}", forwards[0]["id"].as_str().unwrap()),
        Value::Null,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let preserved = admin(&app, &cookie, &uri, json!({"gateway_device_id":devices[0],"target_ipv4":"192.168.60.5","alias_ipv4":"10.243.60.5","translation_mode":"dnat_only"})).await;
    assert_eq!(
        apply(&app, &cookie, network).await["apply_status"],
        "applied"
    );
    gateway
        .reconcile(&desired_plan(&app, &tokens[0]).await)
        .unwrap();
    client
        .reconcile(&desired_plan(&app, &tokens[1]).await)
        .unwrap();
    assert!(!ping(&sandbox.names[2], "10.243.60.5"));
    net(
        &sandbox.names[5],
        &["ip", "route", "add", "10.240.0.0/24", "via", "192.168.60.1"],
    );
    assert!(ping(&sandbox.names[2], "10.243.60.5"));
    for udp in [false, true] {
        host_echo(&sandbox, 0, "10.243.60.5", "10.240.0.3", udp);
    }
    let (status, _) = request(
        &app,
        "DELETE",
        &format!("{uri}/{}", preserved["id"].as_str().unwrap()),
        Value::Null,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        apply(&app, &cookie, network).await["apply_status"],
        "applied"
    );
    gateway
        .reconcile(&desired_plan(&app, &tokens[0]).await)
        .unwrap();
    client
        .reconcile(&desired_plan(&app, &tokens[1]).await)
        .unwrap();
    assert!(!ping(&sandbox.names[2], "10.243.60.5"));
    host_echo(&sandbox, 1, "10.243.61.5", "192.168.61.1", true);
    for chain in ["PREROUTING", "POSTROUTING"] {
        let rules = ns(&sandbox.names[1], &["iptables", "-t", "nat", "-S", chain]);
        let rules = String::from_utf8_lossy(&rules.stdout);
        assert!(!rules.contains(&owner));
        assert!(!rules.contains(&format!(
            "meshlet alias {}",
            preserved["id"].as_str().unwrap()
        )));
        assert!(!rules.contains("10.243.90.5/32"));
    }
}
