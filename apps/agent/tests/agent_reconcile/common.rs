//! Shared agent reconciliation fixtures and real-device topology helpers.

#![cfg(target_os = "linux")]
#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use meshlet_agent::Agent;
use meshlet_config::{AgentConfig, DataplaneConfig, DirectConnectConfig};
use meshlet_domain::{AliasMapping, AliasMappingId, LanRouteId, NetworkId, TranslationMode};
use meshlet_network::linux::LinuxNetworkBackend;
use meshlet_network::{DevicePlan, PeerConfig, RouteConfig, TunnelConfig};

pub(crate) const PREFIX: &str = "mlg";
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(40);

/// This process's object tag (`mlg<pid><suffix>`): kernel object names are global, so leftovers
/// from a crash or another concurrently running test must not fail this run by name collision. Interface names are capped at 15
/// characters, and `mlg` + pid (≤7) + suffix (1) still fits; **the suffix distinguishes tests** — cases
/// running in parallel inside one test process share a pid, and without a suffix they collide (bridge: File exists).
pub(crate) fn tag(suffix: &str) -> String {
    format!("{PREFIX}{}{suffix}", std::process::id())
}

// ---------------------------------------------------------------- process helpers

pub(crate) fn sudo(args: &[&str]) -> Output {
    Command::new("sudo")
        .arg("-n")
        .args(args)
        .output()
        .expect("spawn sudo")
}

pub(crate) fn sudo_ok(args: &[&str]) -> bool {
    sudo(args).status.success()
}

pub(crate) fn netns_exec(ns: &str, args: &[&str]) -> Output {
    let mut full = vec!["ip", "netns", "exec", ns];
    full.extend_from_slice(args);
    sudo(&full)
}

pub(crate) fn require_ok(out: &Output, what: &str) {
    if !out.status.success() {
        panic!(
            "{what} failed (rc={:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

pub(crate) fn count_prefix_lines(text: &str, prefix: &str) -> usize {
    text.lines().filter(|l| l.starts_with(prefix)).count()
}

// ---------------------------------------------------------------- prerequisites

pub(crate) fn prerequisites() -> Option<()> {
    if !sudo_ok(&["true"]) {
        assert!(
            std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
            "required dataplane prerequisite failed"
        );
        eprintln!("SKIP: passwordless sudo (sudo -n) unavailable");
        return None;
    }
    match Command::new("wg").arg("--version").output() {
        Ok(o) if o.status.success() => {}
        _ => {
            assert!(
                std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
                "required dataplane prerequisite failed"
            );
            eprintln!("SKIP: wireguard-tools (wg) not installed");
            return None;
        }
    }
    if !sudo_ok(&["modprobe", "wireguard"]) && !Path::new("/sys/module/wireguard").exists() {
        assert!(
            std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
            "required dataplane prerequisite failed"
        );
        eprintln!("SKIP: wireguard kernel module unavailable");
        return None;
    }
    Some(())
}

/// Clear away historical leftovers: only objects under this prefix whose **pid-suffix process no longer exists** get removed.
///
/// Objects owned by a concurrently running test (another cargo test / a manual re-run) carry a live
/// pid and must be skipped — otherwise the "cleanup" would delete someone else's topology and cause
/// inexplicable failures in the parallel run. Leftovers without a numeric suffix (older prefix scheme) are removed anyway.
pub(crate) fn preflight_cleanup() {
    let text = String::from_utf8_lossy(&sudo(&["ip", "netns", "list"]).stdout).to_string();
    for line in text.lines() {
        if let Some(name) = line.split_whitespace().next() {
            if name.starts_with(PREFIX) && !owner_alive(name) {
                let _ = sudo(&["ip", "netns", "del", name]);
            }
        }
    }
    let links = String::from_utf8_lossy(&sudo(&["ip", "-br", "link"]).stdout).to_string();
    for line in links.lines() {
        if let Some(name) = line.split_whitespace().next() {
            if name.starts_with(PREFIX) && !owner_alive(name) {
                let _ = sudo(&["ip", "link", "del", name]);
            }
        }
    }
}

/// Whether the process named by the object's pid suffix is still alive (alive = another test is using it, do not delete).
pub(crate) fn owner_alive(name: &str) -> bool {
    let tail = &name[PREFIX.len()..];
    let pid: String = tail.chars().take_while(char::is_ascii_digit).collect();
    if pid.is_empty() {
        return false;
    }
    Path::new("/proc").join(pid).exists()
}

// ---------------------------------------------------------------- keys

pub(crate) fn wg_genkey() -> Option<String> {
    let out = Command::new("wg").arg("genkey").output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub(crate) fn wg_pubkey(private: &str) -> Option<String> {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new("wg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .ok()?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(private.as_bytes())
        .ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

// ---------------------------------------------------------------- topology

pub(crate) struct Node {
    pub(crate) netns: String,
    pub(crate) veth_host: String,
    pub(crate) veth_ns: String,
    pub(crate) underlay: String,
    pub(crate) overlay: String,
    pub(crate) public_key: String,
    pub(crate) private_key: String,
}

pub(crate) struct Guard {
    netns: Vec<String>,
    veth: Vec<String>,
    pub(crate) bridge: Option<String>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        for ns in &self.netns {
            let _ = sudo(&["ip", "netns", "del", ns]);
        }
        for link in &self.veth {
            let _ = sudo(&["ip", "link", "del", link]);
        }
        if let Some(bridge) = &self.bridge {
            let _ = sudo(&["ip", "link", "del", bridge]);
        }
    }
}

pub(crate) struct Topology {
    #[allow(dead_code)] // the field is only ever used by Drop for cleanup
    pub(crate) guard: Guard,
    pub(crate) hub: Node,
    pub(crate) a: Node,
    pub(crate) b: Node,
    pub(crate) gw: Node,
    #[allow(dead_code)]
    pub(crate) lan: String,
}

impl Topology {
    pub(crate) fn setup(suffix: &str) -> Option<Topology> {
        prerequisites()?;
        preflight_cleanup();

        let mut guard = Guard {
            netns: Vec::new(),
            veth: Vec::new(),
            bridge: None,
        };

        let mut keys = Vec::new();
        for _ in 0..4 {
            let private = match wg_genkey() {
                Some(k) => k,
                None => {
                    assert!(
                        std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
                        "required dataplane prerequisite failed"
                    );
                    eprintln!("SKIP: key generation failed");
                    return None;
                }
            };
            let public = match wg_pubkey(&private) {
                Some(k) => k,
                None => {
                    assert!(
                        std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
                        "required dataplane prerequisite failed"
                    );
                    eprintln!("SKIP: key derivation failed");
                    return None;
                }
            };
            keys.push((private, public));
        }

        let defs = [
            ("H", "10.98.0.10", "10.240.0.1"),
            ("A", "10.98.0.20", "10.240.0.2"),
            ("B", "10.98.0.30", "10.240.0.3"),
            ("G", "10.98.0.40", "10.240.0.4"),
        ];
        let tag = tag(suffix);
        let mut nodes = Vec::new();
        for ((name, underlay, overlay), (private, public)) in defs.iter().zip(keys.iter()) {
            nodes.push(Node {
                netns: format!("{tag}{name}"),
                veth_host: format!("{tag}{name}0"),
                veth_ns: format!("{tag}{name}1"),
                underlay: underlay.to_string(),
                overlay: overlay.to_string(),
                public_key: public.clone(),
                private_key: private.clone(),
            });
        }

        let bridge = format!("{tag}br0");
        guard.bridge = Some(bridge.clone());
        require_ok(
            &sudo(&["ip", "link", "add", &bridge, "type", "bridge"]),
            "create bridge",
        );
        require_ok(&sudo(&["ip", "link", "set", &bridge, "up"]), "bridge up");

        for n in &nodes {
            guard.netns.push(n.netns.clone());
            guard.veth.push(n.veth_host.clone());
            require_ok(&sudo(&["ip", "netns", "add", &n.netns]), "netns add");
            require_ok(
                &sudo(&[
                    "ip",
                    "link",
                    "add",
                    &n.veth_host,
                    "type",
                    "veth",
                    "peer",
                    "name",
                    &n.veth_ns,
                ]),
                "veth add",
            );
            require_ok(
                &sudo(&["ip", "link", "set", &n.veth_ns, "netns", &n.netns]),
                "veth into netns",
            );
            require_ok(
                &sudo(&["ip", "link", "set", &n.veth_host, "master", &bridge]),
                "veth onto bridge",
            );
            require_ok(
                &netns_exec(
                    &n.netns,
                    &[
                        "ip",
                        "addr",
                        "add",
                        &format!("{}/24", n.underlay),
                        "dev",
                        &n.veth_ns,
                    ],
                ),
                "underlay addr",
            );
            require_ok(
                &sudo(&["ip", "link", "set", &n.veth_host, "up"]),
                "veth host up",
            );
            require_ok(
                &netns_exec(&n.netns, &["ip", "link", "set", &n.veth_ns, "up"]),
                "veth ns up",
            );
            require_ok(
                &netns_exec(&n.netns, &["ip", "link", "set", "lo", "up"]),
                "lo up",
            );
            for dev in [&n.veth_host, &n.veth_ns] {
                let _ = sudo(&[
                    "ethtool", "-K", dev, "gro", "off", "gso", "off", "tso", "off", "rx", "off",
                    "tx", "off", "sg", "off",
                ]);
            }
        }

        // Gateway LAN segment (a second interface on G plus the LAN hosts' netns).
        let lan = format!("{tag}L");
        let (lan0, lan1) = (format!("{tag}X0"), format!("{tag}X1"));
        guard.netns.push(lan.clone());
        guard.veth.push(lan0.clone());
        require_ok(&sudo(&["ip", "netns", "add", &lan]), "lan netns add");
        require_ok(
            &sudo(&[
                "ip", "link", "add", &lan0, "type", "veth", "peer", "name", &lan1,
            ]),
            "lan veth add",
        );
        let gw_netns = nodes[3].netns.clone();
        require_ok(
            &sudo(&["ip", "link", "set", &lan0, "netns", &gw_netns]),
            "lan0 -> G",
        );
        require_ok(
            &sudo(&["ip", "link", "set", &lan1, "netns", &lan]),
            "lan1 -> L",
        );
        require_ok(
            &netns_exec(
                &gw_netns,
                &["ip", "addr", "add", "192.168.1.1/24", "dev", &lan0],
            ),
            "gateway lan addr",
        );
        require_ok(
            &netns_exec(&lan, &["ip", "addr", "add", "192.168.1.5/24", "dev", &lan1]),
            "lan host addr",
        );
        require_ok(
            &netns_exec(&gw_netns, &["ip", "link", "set", &lan0, "up"]),
            "lan0 up",
        );
        require_ok(
            &netns_exec(&lan, &["ip", "link", "set", &lan1, "up"]),
            "lan1 up",
        );
        require_ok(
            &netns_exec(&lan, &["ip", "link", "set", "lo", "up"]),
            "lan lo up",
        );
        for dev in [&lan0, &lan1] {
            let _ = sudo(&[
                "ethtool", "-K", dev, "gro", "off", "gso", "off", "tso", "off", "rx", "off", "tx",
                "off", "sg", "off",
            ]);
        }

        let [hub, a, b, gw] = nodes.try_into().ok()?;
        Some(Topology {
            guard,
            hub,
            a,
            b,
            gw,
            lan,
        })
    }

    pub(crate) fn wait_handshake(&self, ns: &str) -> bool {
        let start = Instant::now();
        while start.elapsed() < HANDSHAKE_TIMEOUT {
            let out = netns_exec(ns, &["wg", "show", "wg0"]);
            if String::from_utf8_lossy(&out.stdout).contains("latest handshake") {
                return true;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        false
    }

    pub(crate) fn ping(&self, from: &str, to: &str) -> bool {
        netns_exec(from, &["ping", "-c", "3", "-W", "2", to])
            .status
            .success()
    }

    /// A "should be reachable" probe: right after a handshake is established the first packet may be
    /// lost (key exchange in flight), so retry within the deadline; only staying unreachable the whole time counts as failure.
    pub(crate) fn ping_within(&self, from: &str, to: &str, within: Duration) -> bool {
        let start = Instant::now();
        loop {
            if self.ping(from, to) {
                return true;
            }
            if start.elapsed() >= within {
                return false;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    pub(crate) fn nat_rules(&self, ns: &str, chain: &str) -> String {
        String::from_utf8_lossy(&netns_exec(ns, &["iptables", "-t", "nat", "-S", chain]).stdout)
            .to_string()
    }
}

// ---------------------------------------------------------------- plan builders

/// The hub-side plan (isomorphic to the server adapter layer's `hub_plan`): peers = all devices, AllowedIPs
/// = the virtual IP /32 plus the Alias prefixes forwarded through that device. The private key is **not** in the
/// plan (ADR-010); the caller injects it from `[dataplane] private_key_file` — the same discipline as the agent path.
pub(crate) fn hub_plan(topo: &Topology) -> DevicePlan {
    DevicePlan {
        desired_revision: 0,
        hub_port: None,
        tunnel: TunnelConfig {
            name: "wg0".into(),
            address: topo.hub.overlay.parse().unwrap(),
            address_prefix: 24,
            listen_port: Some(16180),
            peers: ["a", "b", "gw"]
                .iter()
                .map(|key| peer_for(topo, key))
                .collect(),
            // Explicit MTU (not the default 1420): makes "the plan value really landed in the kernel" assertable (#51(1)).
            mtu: Some(1380),
            private_key: None,
        },
        routes: vec![
            // Both the Alias routes (virtual prefixes) and the Direct routes (real LAN segments) are forwarded
            // via the gateway device's virtual IP — §9.4 "the VPS only forwards by prefix".
            RouteConfig {
                destination: "10.241.1.0/24".parse().unwrap(),
                interface: "wg0".into(),
                gateway: Some(topo.gw.overlay.parse().unwrap()),
            },
            RouteConfig {
                destination: "192.168.1.0/24".parse().unwrap(),
                interface: "wg0".into(),
                gateway: Some(topo.gw.overlay.parse().unwrap()),
            },
        ],
        nat_rules: Vec::new(),
        hub_address: Some(topo.hub.overlay.parse().unwrap()),
        publish: None,
        ssh_config: None,
        desired_config_hash: "hub-hash".into(),
    }
}

pub(crate) fn peer_for(topo: &Topology, key: &str) -> PeerConfig {
    let node = match key {
        "a" => &topo.a,
        "b" => &topo.b,
        _ => &topo.gw,
    };
    let mut allowed_ips = vec![format!("{}/32", node.overlay).parse().unwrap()];
    if key == "gw" {
        // The hub must be configured to encrypt for every prefix forwarded through this device, or forwarded packets cannot reach the gateway.
        allowed_ips.push("10.241.1.0/24".parse().unwrap());
        allowed_ips.push("192.168.1.0/24".parse().unwrap());
    }
    PeerConfig {
        public_key: node.public_key.clone(),
        allowed_ips,
        endpoint: None,
        persistent_keepalive_secs: None,
    }
}

/// The client device plan (isomorphic to the server's `build_device_plan`): the tunnel plus routes to the
/// other gateways' LANs; `private_key` is always `None` (ADR-010: injected locally by the agent).
pub(crate) fn leaf_plan(
    node: &Node,
    hub: &Node,
    allowed_ips: &[&str],
    routes: &[(&str, &str)],
    nat_rules: Vec<meshlet_network::nat::NatRule>,
    hash: &str,
) -> DevicePlan {
    DevicePlan {
        desired_revision: 0,
        hub_port: None,
        tunnel: TunnelConfig {
            name: "wg0".into(),
            address: node.overlay.parse().unwrap(),
            address_prefix: 24,
            listen_port: None,
            peers: vec![PeerConfig {
                public_key: hub.public_key.clone(),
                allowed_ips: allowed_ips.iter().map(|s| s.parse().unwrap()).collect(),
                endpoint: Some(format!("{}:16180", hub.underlay)),
                persistent_keepalive_secs: Some(2),
            }],
            mtu: None,
            private_key: None,
        },
        routes: routes
            .iter()
            .map(|(dst, gw)| RouteConfig {
                destination: dst.parse().unwrap(),
                interface: "wg0".into(),
                gateway: Some(gw.parse().unwrap()),
            })
            .collect(),
        nat_rules,
        hub_address: Some(hub.overlay.parse().unwrap()),
        publish: None,
        ssh_config: None,
        desired_config_hash: hash.into(),
    }
}

pub(crate) fn alias_mapping() -> AliasMapping {
    let mut alias = AliasMapping::new(
        AliasMappingId("al-1".into()),
        NetworkId("net-1".into()),
        LanRouteId("rt-1".into()),
        "10.241.1.0/24".parse().unwrap(),
        "192.168.1.0/24".parse().unwrap(),
        TranslationMode::DnatSnat,
    )
    .unwrap();
    alias.status = meshlet_domain::DesiredStateStatus::Applied;
    alias
}

pub(crate) const ALIAS_OWNER: &str = "meshlet alias al-1";

// ---------------------------------------------------------------- agent assembly

/// Run an agent instance inside a netns (the backend is injected into the netns; the private key is injected locally per ADR-010).
pub(crate) fn agent_in(node: &Node, state_dir: &str) -> Agent {
    let config = AgentConfig {
        server_url: "http://127.0.0.1:1".into(),
        state_dir: state_dir.into(),
        device_token: Some("test-token".into()),
        bootstrap_token: None,
        device_name: None,
        tray: meshlet_config::TrayConfig::OFF,
        upgrade: meshlet_config::UpgradeConfig::default(),
        dataplane: DataplaneConfig {
            enabled: true,
            ..DataplaneConfig::default()
        },
        ssh_config_sync: meshlet_config::SshConfigSyncConfig::OFF,
        mcp: meshlet_config::McpConfig::OFF,
    };
    let backend = LinuxNetworkBackend::new()
        .with_netns(&node.netns)
        .with_sudo()
        .with_interface("wg0");
    Agent::with_backend(config, Some(node.private_key.clone()), backend)
}

pub(crate) fn temp_state_dir(name: &str) -> String {
    let dir = std::env::temp_dir().join(format!("meshlet-agent-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    dir.to_string_lossy().to_string()
}

/// An agent with direct-connect config (§12): `direct_connect.enabled` plus a fixed `listen_port` —
/// reconcile binds the wg interface to that port, which is what direct peers send packets to.
pub(crate) fn agent_in_direct(
    node: &Node,
    state_dir: &str,
    listen_port: u16,
    server_url: &str,
    token: &str,
) -> Agent {
    let config = AgentConfig {
        server_url: server_url.into(),
        state_dir: state_dir.into(),
        device_token: Some(token.into()),
        bootstrap_token: None,
        device_name: None,
        tray: meshlet_config::TrayConfig::OFF,
        upgrade: meshlet_config::UpgradeConfig::default(),
        dataplane: DataplaneConfig {
            enabled: true,
            direct_connect: DirectConnectConfig {
                enabled: true,
                listen_port,
            },
            ..DataplaneConfig::default()
        },
        mcp: meshlet_config::McpConfig::OFF,
        ssh_config_sync: meshlet_config::SshConfigSyncConfig::OFF,
    };
    let backend = LinuxNetworkBackend::new()
        .with_netns(&node.netns)
        .with_sudo()
        .with_interface("wg0");
    Agent::with_backend(config, Some(node.private_key.clone()), backend)
}

/// A minimal agent API mock (std-only): dispatches the `GET .../peers/endpoints` JSON response by Bearer
/// credential (the candidate list as seen by the server). The response body is hot-swappable (withdraw candidates to force a fallback).
/// The connection-level semantics (connection: close) are compatible with ureq; one request per connection.
/// The endpoint mock's hot-swappable response pool: `(server-side candidate list, mutable remaining responses)`.
pub(crate) type EndpointResponses = Arc<Mutex<Vec<(String, String)>>>;

pub(crate) fn spawn_endpoint_server(
    responses: Vec<(String, String)>,
) -> (String, EndpointResponses) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let addr = listener.local_addr().unwrap();
    let shared = Arc::new(Mutex::new(responses));
    let map = Arc::clone(&shared);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let n = std::io::Read::read(&mut stream, &mut chunk).unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&buf).to_string();
            let token = text
                .split("\r\n")
                .find_map(|line| {
                    let (k, v) = line.split_once(':')?;
                    k.trim()
                        .eq_ignore_ascii_case("authorization")
                        .then(|| v.trim().to_string())
                })
                .unwrap_or_default();
            let token = token
                .strip_prefix("Bearer ")
                .unwrap_or_default()
                .to_string();
            let body = map
                .lock()
                .unwrap()
                .iter()
                .find(|(t, _)| *t == token)
                .map(|(_, body)| body.clone())
                .unwrap_or_else(|| "[]".to_string());
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            std::io::Write::write_all(&mut stream, resp.as_bytes()).ok();
        }
    });
    (format!("http://{addr}"), shared)
}

/// The per-device candidate list as seen by the server (the `GET .../peers/endpoints` response body).
pub(crate) fn endpoints_body(public_key: &str, vip: &str, lan_ip: &str, port: u16) -> String {
    serde_json::json!([{
        "device_id": "dev-peer",
        "public_key": public_key,
        "virtual_ipv4": vip,
        "endpoints": [{ "ip": lan_ip, "port": port, "kind": "lan" }],
    }])
    .to_string()
}

// ---------------------------------------------------------------- tests
