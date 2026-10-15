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

use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use meshlet_agent::{Agent, Reason};
use meshlet_config::{AgentConfig, DataplaneConfig};
use meshlet_domain::{AliasMapping, AliasMappingId, LanRouteId, NetworkId, TranslationMode};
use meshlet_network::linux::LinuxNetworkBackend;
use meshlet_network::nat::alias_nat_rules;
use meshlet_network::{DevicePlan, PeerConfig, RouteConfig, TunnelConfig};

const PREFIX: &str = "mlg";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(40);

/// 本进程的对象标签（`mlg<pid>`）：内核对象名是全局的，崩溃残留或并行跑的
/// 另一份测试都不该让本轮撞名失败。接口名限长 15 字符，`mlg` + pid(≤7) + 3
/// 字符仍在限内。
fn tag() -> String {
    format!("{PREFIX}{}", std::process::id())
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
        eprintln!("SKIP: passwordless sudo (sudo -n) unavailable");
        return None;
    }
    match Command::new("wg").arg("--version").output() {
        Ok(o) if o.status.success() => {}
        _ => {
            eprintln!("SKIP: wireguard-tools (wg) not installed");
            return None;
        }
    }
    if !sudo_ok(&["modprobe", "wireguard"]) && !Path::new("/sys/module/wireguard").exists() {
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
    fn setup() -> Option<Topology> {
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
                    eprintln!("SKIP: key generation failed");
                    return None;
                }
            };
            let public = match wg_pubkey(&private) {
                Some(k) => k,
                None => {
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
        let tag = tag();
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
        tunnel: TunnelConfig {
            name: "wg0".into(),
            address: topo.hub.overlay.parse().unwrap(),
            address_prefix: 24,
            listen_port: Some(16180),
            peers: ["a", "b", "gw"]
                .iter()
                .map(|key| peer_for(topo, key))
                .collect(),
            mtu: None,
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

// ---------------------------------------------------------------- 测试

#[test]
fn agent_applies_the_plan_and_replays_after_a_reboot() {
    let topo = match Topology::setup() {
        Some(t) => t,
        None => return, // 已打印 SKIP:
    };

    // ---- hub 侧先行（server 数据面，与 agent 无关） ------------------------
    LinuxNetworkBackend::new()
        .with_netns(&topo.hub.netns)
        .with_sudo()
        .with_interface("wg0")
        .apply_device_plan_sync(&hub_plan(&topo), Some(topo.hub.private_key.clone()), None)
        .expect("hub applies its own plan");

    // ---- 1. agent 应用设备计划（隧道 + 他人网关的前缀路由） ----------------
    // 客户端计划的路由 = 他人网关发布的 LAN/Alias 前缀经该网关虚拟 IP，
    // AllowedIPs 恰好覆盖同一批前缀 + Overlay（与 server `build_device_plan`
    // 同构，§7.2）。二者必须一致：目的前缀不在 AllowedIPs 里时 WireGuard
    // 不发包（路由装了也不通），所以「AllowedIPs 与目标路由一致」是可测约束。
    let a_dir = temp_state_dir("state-a");
    let a_agent = agent_in(&topo.a, &a_dir);
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
    let b_agent = agent_in(&topo.b, &b_dir);
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

    // ---- 4. 网关侧：Alias NAT 随计划下发，映射删除即整单元清理（§12.6）----
    let gw_dir = temp_state_dir("state-gw");
    let gw_agent = agent_in(&topo.gw, &gw_dir);
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

    // teardown 并断言「跑完不留垃圾」（按本进程标签计，历史残留由
    // `preflight_cleanup` 负责）。
    drop(topo);
    let tag = tag();
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
