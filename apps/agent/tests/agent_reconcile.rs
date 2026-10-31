//! Agent 数据面的真机集成测试（[ADR-007](../../docs/decisions/adr-007-linux-network-backend.md)、
//! [存档 §7.2/§9.4/§10.1](../../docs/review/chatgpt-2026-10-13.md)）。
//!
//! 复用 `meshlet-network/tests/backend_wiring.rs` 的拓扑基建（网桥 star +
//! veth 两端关 offload + endpoint 指 netns 侧地址），验证的是**agent 侧**
//! 的两条验收路径：
//!
//! 1. **计划应用（§16.4 → ADR-007）**：agent 只拿结构化
//!    [`DevicePlan`]（服务端 `GET /api/v1/agent/device/desired` 的形状）就
//!    能把隧道/路由/NAT 装到内核——A 与 B 经 hub 双向互通，网关经 Alias NAT
//!    打通真实 LAN；
//! 2. **启动对账 / 重启重放（TODO #32）**：账本记着「已应用」但主机重启后
//!    隧道接口消失（`ip link del wg0`），agent 再次对账必须判定漂移并重放，
//!    数据面随之恢复；无变更时不重放（幂等，§10.1）；
//! 3. **映射删除即整单元清理（§12.6）**：计划里 Alias 消失后 agent 按所有权
//!    注释移除对应 NAT 规则，预埋的非 Meshlet 规则原样保留。
//!
//! 前置条件与 SKIP 纪律同 `backend_wiring.rs`：免密 sudo、`wg`、wireguard
//! 内核模块；缺任一项打印 `SKIP:` 正常返回，CI 无 root 仍全绿。
//!
//! 对象名 `mlg` + **本进程 pid**（与其它 netns 测试区分：`mlt` 系列的前缀清理
//! 不能命中本文件的对象；再带 pid 是因为对象名是内核全局的——上一次跑崩留下的
//! 残留、或另一份测试进程并行跑，都不该让本轮以 `File exists` 失败）。清场时
//! 按 `mlg` 前缀扫历史残留，但**跳过 pid 进程仍存活的对象**（并行跑不清别人的
//! 拓扑），本轮对象按自己的 pid 断言。

#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use meshlet_agent::{Agent, Reason};
use meshlet_config::{AgentConfig, DataplaneConfig, DirectConnectConfig};
use meshlet_domain::{AliasMapping, AliasMappingId, LanRouteId, NetworkId, TranslationMode};
use meshlet_network::linux::LinuxNetworkBackend;
use meshlet_network::nat::alias_nat_rules;
use meshlet_network::{DevicePlan, PeerConfig, RouteConfig, TunnelConfig};

const PREFIX: &str = "mlg";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(40);

/// 本进程的对象标签（`mlg<pid><suffix>`）：内核对象名是全局的，崩溃残留或
/// 并行跑的另一份测试都不该让本轮撞名失败。接口名限长 15 字符，`mlg` +
/// pid(≤7) + suffix(1) 仍在限内；**suffix 按测试区分**——同一测试进程里并行
/// 跑的多个用例共享 pid，没有 suffix 会撞名（bridge File exists）。
fn tag(suffix: &str) -> String {
    format!("{PREFIX}{}{suffix}", std::process::id())
}

// ---------------------------------------------------------------- 进程辅助

fn sudo(args: &[&str]) -> Output {
    Command::new("sudo")
        .arg("-n")
        .args(args)
        .output()
        .expect("spawn sudo")
}

fn sudo_ok(args: &[&str]) -> bool {
    sudo(args).status.success()
}

fn netns_exec(ns: &str, args: &[&str]) -> Output {
    let mut full = vec!["ip", "netns", "exec", ns];
    full.extend_from_slice(args);
    sudo(&full)
}

fn require_ok(out: &Output, what: &str) {
    if !out.status.success() {
        panic!(
            "{what} failed (rc={:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn count_prefix_lines(text: &str, prefix: &str) -> usize {
    text.lines().filter(|l| l.starts_with(prefix)).count()
}

// ---------------------------------------------------------------- 前置条件

fn prerequisites() -> Option<()> {
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
fn preflight_cleanup() {
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
fn owner_alive(name: &str) -> bool {
    let tail = &name[PREFIX.len()..];
    let pid: String = tail.chars().take_while(char::is_ascii_digit).collect();
    if pid.is_empty() {
        return false;
    }
    Path::new("/proc").join(pid).exists()
}

// ---------------------------------------------------------------- 密钥

fn wg_genkey() -> Option<String> {
    let out = Command::new("wg").arg("genkey").output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn wg_pubkey(private: &str) -> Option<String> {
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

struct Node {
    netns: String,
    veth_host: String,
    veth_ns: String,
    underlay: String,
    overlay: String,
    public_key: String,
    private_key: String,
}

struct Guard {
    netns: Vec<String>,
    veth: Vec<String>,
    bridge: Option<String>,
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

struct Topology {
    #[allow(dead_code)] // 字段只经 Drop 清理
    guard: Guard,
    hub: Node,
    a: Node,
    b: Node,
    gw: Node,
    #[allow(dead_code)]
    lan: String,
}

impl Topology {
    fn setup(suffix: &str) -> Option<Topology> {
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

    fn wait_handshake(&self, ns: &str) -> bool {
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

    fn ping(&self, from: &str, to: &str) -> bool {
        netns_exec(from, &["ping", "-c", "3", "-W", "2", to])
            .status
            .success()
    }

    /// 「应当可达」的探测：握手刚建立时首包可能丢失（key exchange 在途），
    /// 因此在时限内重试；时限内一直不通才算失败。
    fn ping_within(&self, from: &str, to: &str, within: Duration) -> bool {
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

    fn nat_rules(&self, ns: &str, chain: &str) -> String {
        String::from_utf8_lossy(&netns_exec(ns, &["iptables", "-t", "nat", "-S", chain]).stdout)
            .to_string()
    }
}

// ---------------------------------------------------------------- 计划构造

/// hub 侧计划（与 server 适配层 `hub_plan` 同构）：peer = 全部设备，AllowedIPs
/// = 虚拟 IP /32 + 经该设备转发的 Alias 前缀。私钥**不**在计划里（ADR-010），
/// 由调用方从 `[dataplane] private_key_file` 注入——与 agent 路径同一纪律。
fn hub_plan(topo: &Topology) -> DevicePlan {
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
        desired_config_hash: "hub-hash".into(),
    }
}

fn peer_for(topo: &Topology, key: &str) -> PeerConfig {
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
fn leaf_plan(
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
        desired_config_hash: hash.into(),
    }
}

fn alias_mapping() -> AliasMapping {
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

const ALIAS_OWNER: &str = "meshlet alias al-1";

// ---------------------------------------------------------------- agent 装配

/// 在 netns 内跑一个 agent 实例（后端注入 netns；私钥按 ADR-010 本地注入）。
fn agent_in(node: &Node, state_dir: &str) -> Agent {
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
    };
    let backend = LinuxNetworkBackend::new()
        .with_netns(&node.netns)
        .with_sudo()
        .with_interface("wg0");
    Agent::with_backend(config, Some(node.private_key.clone()), backend)
}

fn temp_state_dir(name: &str) -> String {
    let dir = std::env::temp_dir().join(format!("meshlet-agent-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    dir.to_string_lossy().to_string()
}

/// 带直连配置的 agent（§12）：`direct_connect.enabled` + 固定 `listen_port`——
/// reconcile 会把 wg 接口绑到该端口，直连对端才能按它发包。
fn agent_in_direct(
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
type EndpointResponses = Arc<Mutex<Vec<(String, String)>>>;

fn spawn_endpoint_server(responses: Vec<(String, String)>) -> (String, EndpointResponses) {
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
fn endpoints_body(public_key: &str, vip: &str, lan_ip: &str, port: u16) -> String {
    serde_json::json!([{
        "device_id": "dev-peer",
        "public_key": public_key,
        "virtual_ipv4": vip,
        "endpoints": [{ "ip": lan_ip, "port": port, "kind": "lan" }],
    }])
    .to_string()
}

// ---------------------------------------------------------------- 测试

#[test]
fn agent_applies_the_plan_and_replays_after_a_reboot() {
    let topo = match Topology::setup("r") {
        Some(t) => t,
        None => return, // 已打印 SKIP:
    };

    // ---- hub 侧先行（server 数据面，与 agent 无关） ------------------------
    let mut hub_backend = LinuxNetworkBackend::new()
        .with_netns(&topo.hub.netns)
        .with_sudo()
        .with_interface("wg0");
    hub_backend
        .apply_device_plan_sync(
            &hub_plan(&topo),
            Some(topo.hub.private_key.clone()),
            None,
            &BTreeSet::new(),
        )
        .expect("hub applies its own plan");
    // 内核级 MTU 断言（#51①）：计划里的 MTU 真的落在了接口上。
    assert_eq!(
        hub_backend.inspect_sync().expect("hub snapshot").tunnel_mtu,
        Some(1380),
        "hub tunnel MTU must match the plan in the kernel"
    );

    // ---- 1. agent 应用设备计划（隧道 + 他人网关的前缀路由） ----------------
    // 客户端计划的路由 = 他人网关发布的 LAN/Alias 前缀经该网关虚拟 IP，
    // AllowedIPs 恰好覆盖同一批前缀 + Overlay（与 server `build_device_plan`
    // 同构，§7.2）。二者必须一致：目的前缀不在 AllowedIPs 里时 WireGuard
    // 不发包（路由装了也不通），所以「AllowedIPs 与目标路由一致」是可测约束。
    let a_dir = temp_state_dir("state-a");
    let mut a_agent = agent_in(&topo.a, &a_dir);
    let a_plan = leaf_plan(
        &topo.a,
        &topo.hub,
        &["10.240.0.0/16", "192.168.1.0/24", "10.241.1.0/24"],
        &[
            ("10.241.1.0/24", &topo.gw.overlay),
            ("192.168.1.0/24", &topo.gw.overlay),
        ],
        Vec::new(),
        "hash-a1",
    );

    // 首装：无账本 → 必须应用（NoLocalLedger）。
    let decision = a_agent.reconcile(&a_plan).expect("agent applies plan");
    assert!(decision.needs_apply);
    assert_eq!(decision.reason, Reason::NoLocalLedger);
    assert!(a_agent.state_path().exists(), "ledger written after apply");

    // B 侧同样应用（另一个 agent 实例）。
    let b_dir = temp_state_dir("state-b");
    let mut b_agent = agent_in(&topo.b, &b_dir);
    let b_plan = leaf_plan(
        &topo.b,
        &topo.hub,
        &["10.240.0.0/16", "192.168.1.0/24", "10.241.1.0/24"],
        &[
            ("10.241.1.0/24", &topo.gw.overlay),
            ("192.168.1.0/24", &topo.gw.overlay),
        ],
        Vec::new(),
        "hash-b1",
    );
    b_agent.reconcile(&b_plan).expect("agent B applies plan");

    for (label, ns) in [("A", &topo.a.netns), ("B", &topo.b.netns)] {
        assert!(
            topo.wait_handshake(ns),
            "{label} handshake did not complete"
        );
    }
    assert!(
        topo.ping_within(&topo.a.netns, &topo.b.overlay, HANDSHAKE_TIMEOUT),
        "A -> B via hub"
    );
    assert!(
        topo.ping_within(&topo.b.netns, &topo.a.overlay, HANDSHAKE_TIMEOUT),
        "B -> A via hub"
    );

    // 无变更时不重放（§10.1 有变更才重放）。
    let decision = a_agent.reconcile(&a_plan).expect("second reconcile");
    assert!(!decision.needs_apply, "unchanged plan must not be replayed");
    assert_eq!(decision.reason, Reason::UpToDate);

    // ---- 2. 服务端新修订 → 重放 -------------------------------------------
    let a_plan_v2 = leaf_plan(
        &topo.a,
        &topo.hub,
        &[
            "10.240.0.0/16",
            "192.168.1.0/24",
            "192.168.2.0/24",
            "10.241.1.0/24",
        ],
        &[
            ("10.241.1.0/24", &topo.gw.overlay),
            ("192.168.1.0/24", &topo.gw.overlay),
            ("192.168.2.0/24", &topo.gw.overlay),
        ],
        Vec::new(),
        "hash-a2",
    );
    let decision = a_agent.reconcile(&a_plan_v2).expect("replay new revision");
    assert!(decision.needs_apply);
    assert_eq!(decision.reason, Reason::DesiredConfigChanged);
    assert!(
        topo.ping_within(&topo.a.netns, &topo.b.overlay, HANDSHAKE_TIMEOUT),
        "data path survives replay"
    );

    // ---- 3. 主机重启：账本说已应用，内核接口没了 → 判定漂移并重放（#32）----
    require_ok(
        &netns_exec(&topo.a.netns, &["ip", "link", "del", "wg0"]),
        "simulate host reboot losing the tunnel",
    );
    assert!(
        !topo.ping(&topo.a.netns, &topo.b.overlay),
        "tunnel is gone after the simulated reboot"
    );
    // 账本仍记着 hash-a2 —— 这正是「重启后账本记 applied」的现场。
    let decision = a_agent.reconcile(&a_plan_v2).expect("replay after reboot");
    assert!(decision.needs_apply, "lost tunnel must be replayed");
    assert_eq!(decision.reason, Reason::KernelDrift);
    assert!(
        topo.wait_handshake(&topo.a.netns),
        "A handshake after replay"
    );
    assert!(
        topo.ping_within(&topo.a.netns, &topo.b.overlay, HANDSHAKE_TIMEOUT),
        "A -> B recovered after replay"
    );

    // 重放后再次对账：无漂移 → 不重放。
    assert!(!a_agent.reconcile(&a_plan_v2).unwrap().needs_apply);

    // ---- 3.5 MTU：计划值落到内核；内核读数不符 → 判漂移并纠回（#51）-------
    let a_backend = LinuxNetworkBackend::new()
        .with_netns(&topo.a.netns)
        .with_sudo()
        .with_interface("wg0");
    let mut mtu_plan = a_plan_v2.clone();
    mtu_plan.tunnel.mtu = Some(1380);
    // MTU 是计划的一部分：服务端哈希覆盖整份计划，MTU 变化即新修订。
    mtu_plan.desired_config_hash = "hash-a3".into();
    let decision = a_agent.reconcile(&mtu_plan).expect("apply mtu plan");
    assert!(decision.needs_apply);
    assert_eq!(decision.reason, Reason::DesiredConfigChanged);
    assert_eq!(
        a_backend.inspect_sync().expect("A snapshot").tunnel_mtu,
        Some(1380),
        "planned MTU must land in the kernel"
    );

    // 内核读数被改走（手工改动 / 半途失败）→ 对账判漂移，重放纠回。
    require_ok(
        &netns_exec(&topo.a.netns, &["ip", "link", "set", "wg0", "mtu", "1420"]),
        "sabotage tunnel mtu",
    );
    let decision = a_agent
        .reconcile(&mtu_plan)
        .expect("reconcile after mtu sabotage");
    assert!(decision.needs_apply, "mtu mismatch must be replayed");
    assert_eq!(decision.reason, Reason::KernelDrift);
    assert_eq!(
        a_backend.inspect_sync().expect("A snapshot").tunnel_mtu,
        Some(1380),
        "replay restores the planned MTU"
    );

    // 设备侧实测证据（#51②）：内核读数 + 大包探测（`ping -M do`，载荷 =
    // 计划 MTU − 28）随心跳回传——探测目标 = hub overlay 地址，走真实隧道。
    let evidence = a_agent.collect_evidence(Some(&mtu_plan));
    assert_eq!(evidence.tunnel_mtu, Some(1380), "kernel reading reported");
    assert_eq!(
        evidence.mtu_probe_payload,
        Some(1352),
        "large-packet probe must pass at planned MTU - 28 via the tunnel"
    );

    // ---- 4. 网关侧：Alias NAT 随计划下发，映射删除即整单元清理（§12.6）----
    let gw_dir = temp_state_dir("state-gw");
    let mut gw_agent = agent_in(&topo.gw, &gw_dir);
    let gw_plan = leaf_plan(
        &topo.gw,
        &topo.hub,
        &["10.240.0.0/16"],
        &[],
        alias_nat_rules(&alias_mapping()),
        "hash-gw1",
    );
    gw_agent
        .reconcile(&gw_plan)
        .expect("gateway applies nat rules");
    assert!(topo.wait_handshake(&topo.gw.netns), "G handshake");
    // 网关证据（#57②）：心跳回传的 NAT 读数反映内核实际（有规则 → true）。
    let gw_evidence = gw_agent.collect_evidence(Some(&gw_plan));
    assert_eq!(
        gw_evidence.nat_rules_present,
        Some(true),
        "gateway must report its meshlet NAT rules as present"
    );
    // Direct 模式（非 Alias）路由：计划里的 `192.168.1.0/24 via 网关` 让远端
    // 真实 LAN 直接可达（§8.1 验收「发布 CIDR 后远端可访问」）。
    assert!(
        topo.ping_within(&topo.a.netns, "192.168.1.5", HANDSHAKE_TIMEOUT),
        "A -> remote LAN via the gateway (direct route from the plan)"
    );
    // Alias 路径：计划里的 Alias 前缀 + 网关侧 DNAT/SNAT 规则打通同一网段。
    assert!(
        topo.ping_within(&topo.a.netns, "10.241.1.5", HANDSHAKE_TIMEOUT),
        "A -> alias prefix reaches the real LAN behind G"
    );

    // 预埋一条非 Meshlet 规则（用户视角的外来规则）。
    require_ok(
        &netns_exec(
            &topo.gw.netns,
            &[
                "iptables",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-d",
                "203.0.113.0/24",
                "-j",
                "ACCEPT",
                "-m",
                "comment",
                "--comment",
                "user rule",
            ],
        ),
        "plant foreign nat rule",
    );

    // 映射被删除（新修订，NAT 规则清空）→ agent 按所有权注释精确清理。
    let gw_plan_v2 = leaf_plan(
        &topo.gw,
        &topo.hub,
        &["10.240.0.0/16"],
        &[],
        Vec::new(),
        "hash-gw2",
    );
    let decision = gw_agent.reconcile(&gw_plan_v2).expect("gateway drops nat");
    assert!(decision.needs_apply);
    assert_eq!(decision.reason, Reason::DesiredConfigChanged);
    let prerouting = topo.nat_rules(&topo.gw.netns, "PREROUTING");
    assert!(
        !prerouting.contains(ALIAS_OWNER),
        "meshlet alias rules must be gone:\n{prerouting}"
    );
    assert!(
        prerouting.contains("user rule"),
        "foreign rule must survive:\n{prerouting}"
    );
    assert!(
        !topo.ping(&topo.a.netns, "10.241.1.5"),
        "alias path must fail after the mapping is deleted"
    );
    assert!(
        topo.ping_within(&topo.a.netns, &topo.b.overlay, HANDSHAKE_TIMEOUT),
        "overlay must stay unaffected by the mapping removal"
    );
    // 清理后的证据如实翻转（#57②）：内核实际没有 Meshlet NAT 规则 → false。
    let gw_evidence = gw_agent.collect_evidence(Some(&gw_plan_v2));
    assert_eq!(
        gw_evidence.nat_rules_present,
        Some(false),
        "evidence must report the kernel after the ownership cleanup"
    );

    // ---- 4.5 身份级漂移端到端（M2）：Reason 归因 + 非 meshlet 资源永不动 ----
    // (a) 隧道上多出一个外来 peer（身份不在计划里）→ KernelDrift 并清掉。
    let stranger_private = wg_genkey().expect("generate a stranger key");
    let stranger_public = wg_pubkey(&stranger_private).expect("derive the stranger key");
    require_ok(
        &netns_exec(
            &topo.a.netns,
            &[
                "wg",
                "set",
                "wg0",
                "peer",
                &stranger_public,
                "allowed-ips",
                "10.244.0.0/24",
            ],
        ),
        "plant a foreign peer on A's tunnel",
    );
    let decision = a_agent
        .reconcile(&mtu_plan)
        .expect("reconcile after peer injection");
    assert!(decision.needs_apply, "an extra peer is kernel drift");
    assert_eq!(decision.reason, Reason::KernelDrift);
    let peers = a_backend
        .inspect_sync()
        .expect("A snapshot after repair")
        .peers;
    assert!(
        !peers.iter().any(|p| p.public_key == stranger_public),
        "the foreign peer must be removed: {peers:?}"
    );
    assert_eq!(
        peers
            .iter()
            .map(|p| p.public_key.clone())
            .collect::<Vec<_>>(),
        vec![topo.hub.public_key.clone()],
        "A's planned peer must survive the repair"
    );
    assert!(
        topo.ping_within(&topo.a.netns, &topo.b.overlay, HANDSHAKE_TIMEOUT),
        "data path must survive the peer repair"
    );

    // (b) 隧道接口上一条未打 Meshlet 标记的路由 → 不算漂移（UpToDate），
    // 且该路由原样保留：非本 meshlet 资源永不动。
    require_ok(
        &netns_exec(
            &topo.a.netns,
            &["ip", "route", "add", "10.245.0.0/24", "dev", "wg0"],
        ),
        "plant an unmarked route on A's tunnel",
    );
    let decision = a_agent
        .reconcile(&mtu_plan)
        .expect("reconcile with a foreign route");
    assert!(
        !decision.needs_apply,
        "a foreign route is not drift: {:?}",
        decision.reason
    );
    let shown = String::from_utf8_lossy(
        &netns_exec(
            &topo.a.netns,
            &["ip", "route", "show", "exact", "10.245.0.0/24"],
        )
        .stdout,
    )
    .to_string();
    assert!(
        shown.contains("wg0"),
        "the foreign route must survive untouched: {shown}"
    );

    // (c) 网关上一条 Meshlet 所有权注释、但不在计划里的 NAT 规则（多余自有
    // 对象）→ KernelDrift 并按指纹清理；外来规则保留。
    gw_agent
        .reconcile(&gw_plan)
        .expect("gateway re-applies nat plan");
    require_ok(
        &netns_exec(
            &topo.gw.netns,
            &[
                "iptables",
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-d",
                "203.0.113.0/24",
                "-j",
                "SNAT",
                "--to-source",
                "192.168.1.1",
                "-m",
                "comment",
                "--comment",
                ALIAS_OWNER,
            ],
        ),
        "plant an extra meshlet-owned nat rule",
    );
    let decision = gw_agent
        .reconcile(&gw_plan)
        .expect("reconcile after nat injection");
    assert!(decision.needs_apply, "an extra meshlet-owned rule is drift");
    assert_eq!(decision.reason, Reason::KernelDrift);
    let postrouting = topo.nat_rules(&topo.gw.netns, "POSTROUTING");
    assert!(
        !postrouting.contains("203.0.113.0/24"),
        "the extra meshlet-owned rule must be removed:\n{postrouting}"
    );
    assert!(
        postrouting.contains(ALIAS_OWNER),
        "the planned snat rule must survive:\n{postrouting}"
    );
    let prerouting = topo.nat_rules(&topo.gw.netns, "PREROUTING");
    assert!(
        prerouting.contains("user rule"),
        "the foreign rule must survive the fingerprint cleanup:\n{prerouting}"
    );
    assert!(
        !a_agent.reconcile(&mtu_plan).unwrap().needs_apply,
        "no drift left on A"
    );

    // teardown 并断言「跑完不留垃圾」（按本进程标签计，历史残留由
    // `preflight_cleanup` 负责）。
    drop(topo);
    let tag = tag("r");
    let netns_text = String::from_utf8_lossy(&sudo(&["ip", "netns", "list"]).stdout).to_string();
    let links_text = String::from_utf8_lossy(&sudo(&["ip", "-br", "link"]).stdout).to_string();
    assert_eq!(
        count_prefix_lines(&netns_text, &tag),
        0,
        "leftover netns after teardown:\n{netns_text}"
    );
    assert_eq!(
        count_prefix_lines(&links_text, &tag),
        0,
        "leftover links after teardown:\n{links_text}"
    );
    for dir in [a_dir, b_dir, gw_dir] {
        std::fs::remove_dir_all(dir).ok();
    }
}

/// §12 直连建立/回退的真机验收：走**完整真实流程**——mock agent API 下发候选
/// → `reconcile_direct`（拉候选 → 域层状态机 → `wg set`）建立同网段直连 →
/// hub 入口关闭仍通（证明走的是直连，/32 长前缀优先）→ 服务端撤候选 →
/// 状态机回退并移除直连 → 经 hub 恢复。对账全程不得把直连对端当漂移清掉；
/// 外来 peer 注入仍必须按漂移清除。
#[test]
fn agent_direct_connect_establishes_and_falls_back_to_hub() {
    let topo = match Topology::setup("d") {
        Some(t) => t,
        None => return, // 已打印 SKIP:
    };
    let port: u16 = 51820;

    // ---- mock agent API：A 看到候选 B，B 看到候选 A（各自 LAN endpoint）----
    let (server_url, responses) = spawn_endpoint_server(vec![
        (
            "tok-a".into(),
            endpoints_body(&topo.b.public_key, &topo.b.overlay, &topo.b.underlay, port),
        ),
        (
            "tok-b".into(),
            endpoints_body(&topo.a.public_key, &topo.a.overlay, &topo.a.underlay, port),
        ),
    ]);

    // ---- hub 侧先行（server 数据面） --------------------------------------
    let mut hub_backend = LinuxNetworkBackend::new()
        .with_netns(&topo.hub.netns)
        .with_sudo()
        .with_interface("wg0");
    hub_backend
        .apply_device_plan_sync(
            &hub_plan(&topo),
            Some(topo.hub.private_key.clone()),
            None,
            &BTreeSet::new(),
        )
        .expect("hub applies its own plan");

    // ---- A、B 各起一个带直连配置的 agent：reconcile 把 wg0 绑到直连端口 ----
    let a_dir = temp_state_dir("direct-a");
    let b_dir = temp_state_dir("direct-b");
    let mut a_agent = agent_in_direct(&topo.a, &a_dir, port, &server_url, "tok-a");
    let mut b_agent = agent_in_direct(&topo.b, &b_dir, port, &server_url, "tok-b");
    let a_plan = leaf_plan(
        &topo.a,
        &topo.hub,
        &["10.240.0.0/16"],
        &[],
        Vec::new(),
        "hash-a-d",
    );
    let b_plan = leaf_plan(
        &topo.b,
        &topo.hub,
        &["10.240.0.0/16"],
        &[],
        Vec::new(),
        "hash-b-d",
    );
    a_agent.reconcile(&a_plan).expect("A applies hub plan");
    b_agent.reconcile(&b_plan).expect("B applies hub plan");
    assert!(topo.wait_handshake(&topo.a.netns), "A hub handshake");
    assert!(topo.wait_handshake(&topo.b.netns), "B hub handshake");
    assert!(
        topo.ping_within(&topo.a.netns, &topo.b.overlay, HANDSHAKE_TIMEOUT),
        "A -> B via hub"
    );
    // ---- 真实直连探测一轮（拉候选 → SameLan 决策 → wg set 下发）----------
    a_agent.reconcile_direct(&a_plan);
    b_agent.reconcile_direct(&b_plan);

    // 直连握手建立（keepalive 15s 触发；域层健康窗口 35s 判健康）。
    let a_backend = LinuxNetworkBackend::new()
        .with_netns(&topo.a.netns)
        .with_sudo()
        .with_interface("wg0");
    let established = {
        let start = Instant::now();
        loop {
            let ages = a_backend.handshake_ages_sync().expect("A handshake ages");
            if ages.get(&topo.b.public_key).is_some_and(|age| *age <= 35) {
                break true;
            }
            if start.elapsed() >= HANDSHAKE_TIMEOUT {
                break false;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    };
    assert!(established, "direct handshake A <-> B did not establish");

    // ---- §12.3 状态上报：等一个「到期」探测周期（30s 节流真实生效，keepalive
    // 15s 持续刷新握手 → 到期周期读到健康 → 状态机转 Direct）。届时链路状态
    // 导出「direct」并携带探测时的握手年龄快照（供 hub/控制台展示）。------
    let reported_direct = {
        let start = Instant::now();
        loop {
            a_agent.reconcile_direct(&a_plan);
            let statuses = a_agent.direct_link_statuses();
            if statuses.first().is_some_and(|s| s.link_state == "direct") {
                break Some(statuses);
            }
            if start.elapsed() >= Duration::from_secs(50) {
                break None;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    };
    let statuses = reported_direct.expect("state machine promotes to Direct within a due probe");
    assert_eq!(statuses.len(), 1, "one direct link reported: {statuses:?}");
    assert_eq!(statuses[0].public_key, topo.b.public_key, "{statuses:?}");
    assert!(
        statuses[0]
            .last_handshake_age_secs
            .is_some_and(|age| age <= 35),
        "healthy handshake age snapshotted: {statuses:?}"
    );

    // ---- 关 hub 入口：A/B 的 hub peer endpoint 指到死地址。此后 A→B 仍通
    // 必然是直连 peer（/32 长前缀优先）承载，而非 hub。-------------------
    for node in [&topo.a, &topo.b] {
        require_ok(
            &netns_exec(
                &node.netns,
                &[
                    "wg",
                    "set",
                    "wg0",
                    "peer",
                    &topo.hub.public_key,
                    "endpoint",
                    "10.98.0.99:16180",
                ],
            ),
            "kill hub endpoint",
        );
    }
    assert!(
        topo.ping_within(&topo.a.netns, &topo.b.overlay, HANDSHAKE_TIMEOUT),
        "A -> B via direct with hub down"
    );
    assert!(
        topo.ping_within(&topo.b.netns, &topo.a.overlay, HANDSHAKE_TIMEOUT),
        "B -> A via direct with hub down"
    );

    // ---- 直连对端不得被对账当漂移清掉：reconcile 后仍在、且不重放 -------
    let decision = a_agent
        .reconcile(&a_plan)
        .expect("A reconcile with a direct peer");
    assert!(
        !decision.needs_apply,
        "a direct peer must not force a replay: {:?}",
        decision.reason
    );
    assert!(
        a_backend
            .handshake_ages_sync()
            .unwrap()
            .contains_key(&topo.b.public_key),
        "direct peer survived reconcile"
    );

    // ---- 服务端撤候选（B 下线）→ 下一探测周期状态机回退并移除直连 -------
    responses
        .lock()
        .unwrap()
        .iter_mut()
        .for_each(|(_, body)| *body = "[]".into());
    let demoted = {
        let start = Instant::now();
        loop {
            // 30s 节流内新周期不触发，直接再驱动一轮（测试不受节流约束语义）。
            a_agent.reconcile_direct(&a_plan);
            b_agent.reconcile_direct(&b_plan);
            if !a_backend
                .handshake_ages_sync()
                .unwrap()
                .contains_key(&topo.b.public_key)
            {
                break true;
            }
            if start.elapsed() >= Duration::from_secs(60) {
                break false;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    };
    assert!(demoted, "direct peer must be demoted after the revoke");

    // ---- §12.3 状态上报随回退清空：不再上报该对端（UI 默认按中继呈现）----
    assert!(
        a_agent.direct_link_statuses().is_empty(),
        "no direct link reported after fallback"
    );

    // ---- 恢复 hub 入口 → 经 hub 恢复 -------------------------------------
    for node in [&topo.a, &topo.b] {
        require_ok(
            &netns_exec(
                &node.netns,
                &[
                    "wg",
                    "set",
                    "wg0",
                    "peer",
                    &topo.hub.public_key,
                    "endpoint",
                    &format!("{}:16180", topo.hub.underlay),
                ],
            ),
            "restore hub endpoint",
        );
    }
    assert!(
        topo.ping_within(&topo.a.netns, &topo.b.overlay, HANDSHAKE_TIMEOUT),
        "A -> B via hub after fallback"
    );
    assert!(
        topo.ping_within(&topo.b.netns, &topo.a.overlay, HANDSHAKE_TIMEOUT),
        "B -> A via hub after fallback"
    );

    // ---- 回退后对账不再持有直连保留集，也不重放（缺失的直连对端不算漂移）
    let decision = a_agent
        .reconcile(&a_plan)
        .expect("A reconcile after fallback");
    assert!(
        !decision.needs_apply,
        "no replay after fallback: {:?}",
        decision.reason
    );

    drop(topo);
    for dir in [a_dir, b_dir] {
        std::fs::remove_dir_all(dir).ok();
    }
}
