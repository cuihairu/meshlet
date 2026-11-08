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

/// 本进程的对象标签（`mlg<pid><suffix>`）：内核对象名是全局的，崩溃残留或
/// 并行跑的另一份测试都不该让本轮撞名失败。接口名限长 15 字符，`mlg` +
/// pid(≤7) + suffix(1) 仍在限内；**suffix 按测试区分**——同一测试进程里并行
/// 跑的多个用例共享 pid，没有 suffix 会撞名（bridge File exists）。
pub(crate) fn tag(suffix: &str) -> String {
    format!("{PREFIX}{}{suffix}", std::process::id())
}

// ---------------------------------------------------------------- 进程辅助

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

// ---------------------------------------------------------------- 前置条件

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

/// 清掉历史残留：只删本前缀下、**其 pid 后缀进程已不存在**的对象。
///
/// 正在跑的并行测试（另一份 cargo test / 手工重跑）对象带活着的 pid，必须跳过
/// ——否则「清场」会把别人的拓扑删掉，让并行跑出现莫名其妙的失败。没有数字后缀
/// 的历史残留（旧前缀方案留下的）照删。
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

/// 对象名的 pid 后缀进程是否还活着（活着=别的测试正在用，别删）。
pub(crate) fn owner_alive(name: &str) -> bool {
    let tail = &name[PREFIX.len()..];
    let pid: String = tail.chars().take_while(char::is_ascii_digit).collect();
    if pid.is_empty() {
        return false;
    }
    Path::new("/proc").join(pid).exists()
}

// ---------------------------------------------------------------- 密钥

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

// ---------------------------------------------------------------- 拓扑

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
    #[allow(dead_code)] // 字段只经 Drop 清理
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

        // 网关 LAN 段（G 另一个接口 + LAN 主机 netns）。
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

    /// 「应当可达」的探测：握手刚建立时首包可能丢失（key exchange 在途），
    /// 因此在时限内重试；时限内一直不通才算失败。
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

// ---------------------------------------------------------------- 计划构造

/// hub 侧计划（与 server 适配层 `hub_plan` 同构）：peer = 全部设备，AllowedIPs
/// = 虚拟 IP /32 + 经该设备转发的 Alias 前缀。私钥**不**在计划里（ADR-010），
/// 由调用方从 `[dataplane] private_key_file` 注入——与 agent 路径同一纪律。
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
            // 显式 MTU（非默认 1420）：让「计划值真的落到内核」可断言（#51①）。
            mtu: Some(1380),
            private_key: None,
        },
        routes: vec![
            // Alias 路由（虚拟前缀）与 Direct 路由（真实 LAN 网段）都经网关
            // 设备虚拟 IP 转发——§9.4「VPS 只按前缀转发」。
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
        // hub 必须为「经该设备转发的每个前缀」加密下发，否则转发包到不了网关。
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

/// 客户端设备计划（与 server `build_device_plan` 同构）：隧道 + 他人网关的
/// 路由；`private_key` 恒为 `None`（ADR-010：agent 本地注入）。
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

// ---------------------------------------------------------------- agent 装配

/// 在 netns 内跑一个 agent 实例（后端注入 netns；私钥按 ADR-010 本地注入）。
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

/// 带直连配置的 agent（§12）：`direct_connect.enabled` + 固定 `listen_port`——
/// reconcile 会把 wg 接口绑到该端口，直连对端才能按它发包。
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
        ssh_config_sync: meshlet_config::SshConfigSyncConfig::OFF,
    };
    let backend = LinuxNetworkBackend::new()
        .with_netns(&node.netns)
        .with_sudo()
        .with_interface("wg0");
    Agent::with_backend(config, Some(node.private_key.clone()), backend)
}

/// 极简 agent API mock（std-only）：按 Bearer 凭证分发 `GET .../peers/endpoints`
/// 的 JSON 应答（服务端视角的候选列表）。应答体可热切换（撤候选 → 回退）。
/// 连接级语义（connection: close）与 ureq 兼容；每连接一个请求。
/// 端点 mock 的可热切换应答池：`(服务端候选列表, 可变的剩余应答)`。
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

/// 服务端视角的单设备候选列表（`GET .../peers/endpoints` 应答体）。
pub(crate) fn endpoints_body(public_key: &str, vip: &str, lan_ip: &str, port: u16) -> String {
    serde_json::json!([{
        "device_id": "dev-peer",
        "public_key": public_key,
        "virtual_ipv4": vip,
        "endpoints": [{ "ip": lan_ip, "port": port, "kind": "lan" }],
    }])
    .to_string()
}

// ---------------------------------------------------------------- 测试
