//! Host forwarding agent scenarios and real TCP/UDP round-trip evidence.
#![cfg(target_os = "linux")]
use super::boot::*;
use super::single_instance_support::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use meshlet_network::SystemBackend;
use serde_json::{json, Value};
use std::{process::Command, sync::Arc};
use tower::ServiceExt;

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
        upgrade: meshlet_config::AgentConfig::default().upgrade,
        dataplane: meshlet_config::DataplaneConfig {
            enabled: true,
            hub_endpoint: Some(format!("172.31.{index}.1:51820")),
            ..Default::default()
        },
        ssh_config_sync: meshlet_config::SshConfigSyncConfig::OFF,
        mcp: meshlet_config::McpConfig::OFF,
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
