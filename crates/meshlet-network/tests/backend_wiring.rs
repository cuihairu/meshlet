//! Linux `NetworkBackend` 实装的真机集成测试（[ADR-007](../../docs/decisions/adr-007-linux-network-backend.md)）。
//!
//! 与 `wg_forwarding.rs` / `alias_nat.rs` 的区别：**全部内核操作走
//! `LinuxNetworkBackend`**（netns + sudo 测试钩子），不再用裸 `wg` / `ip`
//! 命令配置数据面——控制面 apply 路径与内核之间是同一套代码。裸命令只用于
//! 搭 underlay（网桥/veth/netns 本身，非后端职责）与「外部视角」探针。
//!
//! 验收（TODO 数据面接线条目）：
//!
//! 1. **A → B 互通**：hub 侧 `apply_tunnel` + 客户端 `apply_tunnel` 全程经
//!    后端下发，A/B 经 hub 转发双向可达；
//! 2. **Alias 路径**：hub `apply_routes`（Alias 前缀经网关虚拟 IP）+ 网关
//!    `apply_nat`（nat.rs 计划层渲染 NETMAP/SNAT）后，客户端经 Alias 打到
//!    网关后真实 LAN；
//! 3. **幂等**：同一 tunnel/NAT 配置重复应用结果一致（§10.3）；
//! 4. **删 Alias 同步清理 NAT 且不触碰非 Meshlet 规则**：`remove_nat` 按
//!    所有权注释精确移除，预埋的用户规则原样保留（§12.6、ADR-007）；
//! 5. **Overlay 源保留（§7.4）**：网关 NAT 规则在场时，B 上的 UDP echo
//!    观测到 A→B 的源地址仍是 A 的原始 Overlay 地址（无差别 SNAT 不存在）；
//! 6. **撤销即失效**：hub 重应用去掉 B 的 peer 集，B 的 peer 条目消失、
//!    A→B 立即不通，其余 peer 与 Alias 通路不受影响（§11.5）；
//! 7. **回滚只删 Meshlet 自有对象**：hub `rollback` 后 peer/隧道路由清空，
//!    接口与系统 ip_forward 保留（§10.3）。
//!
//! 前置条件与 SKIP 纪律同 `wg_forwarding.rs` / `alias_nat.rs`：免密 sudo、
//! `wg`、`wireguard` 内核模块、`python3`（§7.4 源观测的 UDP echo）；缺任一
//! 项打印 `SKIP:` 正常返回，CI 无 root 仍全绿。
//!
//! 拓扑坑位（与既有测试一致）：underlay 网桥 star、veth 两端关 offload、
//! endpoint 指 netns 侧地址、private-key 与 peer 分两次 `wg set`（后端已
//! 固化该纪律，见 `src/linux.rs` 头注）。

#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use meshlet_domain::{AliasMapping, AliasMappingId, LanRouteId, NetworkId, TranslationMode};
use meshlet_network::linux::LinuxNetworkBackend;
use meshlet_network::{PeerConfig, RouteConfig, TunnelConfig};

/// 对象名前缀（与其它 netns 测试区分）。
const PREFIX: &str = "mltb";
/// 握手等待上限。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(25);

/// §7.4 源观测脚本：B 上一收即退的 UDP echo（10s 无包亦自退，不留孤儿进程），
/// 应答体为收包源地址。占位符 @BIND@ 换成 B 的 Overlay 地址。
const ECHO_SERVER_PY: &str = r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("@BIND@", 15900))
s.settimeout(10)
try:
    _, addr = s.recvfrom(2048)
    s.sendto(("src=" + addr[0]).encode(), addr)
except Exception:
    pass
"#;

/// echo 客户端：打一次 @PEER@，打印应答体。占位符 @PEER@ 换成 B 的 Overlay 地址。
const ECHO_CLIENT_PY: &str = r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(b"hi", ("@PEER@", 15900))
print(s.recvfrom(2048)[0].decode().strip())
"#;

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

/// 拓扑搭建阶段的命令失败直接 panic（环境对了而命令失败就是真 bug）。
fn require_ok(out: &Output, what: &str) {
    if !out.status.success() {
        panic!(
            "{what} failed (rc={:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn count_prefix_lines(text: &str) -> usize {
    text.lines().filter(|l| l.starts_with(PREFIX)).count()
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
    match Command::new("python3").arg("--version").output() {
        Ok(o) if o.status.success() => {}
        _ => {
            assert!(
                std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
                "required dataplane prerequisite failed"
            );
            eprintln!("SKIP: python3 not installed (udp echo probe)");
            return None;
        }
    }
    Some(())
}

fn preflight_cleanup() {
    let out = sudo(&["ip", "netns", "list"]);
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(name) = line.split_whitespace().next() {
            if name.starts_with(PREFIX) {
                let _ = sudo(&["ip", "netns", "del", name]);
            }
        }
    }
    let out = sudo(&["ip", "-br", "link"]);
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(name) = line.split_whitespace().next() {
            if name.starts_with(PREFIX) {
                let _ = sudo(&["ip", "link", "del", name]);
            }
        }
    }
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

impl Node {
    fn backend(&self) -> LinuxNetworkBackend {
        LinuxNetworkBackend::new()
            .with_netns(&self.netns)
            .with_sudo()
            .with_interface("wg0")
    }
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
    /// LAN 主机 netns（网关后面的 192.168.1.5）。
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

        // --- 密钥（每节点独立）
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

        // --- 节点身份（H/A/B/G 挂网桥；G 另带 LAN 段）
        let defs = [
            ("H", "10.99.0.10", "10.240.0.1"),
            ("A", "10.99.0.20", "10.240.0.2"),
            ("B", "10.99.0.30", "10.240.0.3"),
            ("G", "10.99.0.40", "10.240.0.4"),
        ];
        let mut nodes = Vec::new();
        for ((name, underlay, overlay), (private, public)) in defs.iter().zip(keys.iter()) {
            nodes.push(Node {
                netns: format!("{PREFIX}{name}"),
                veth_host: format!("{PREFIX}{name}0"),
                veth_ns: format!("{PREFIX}{name}1"),
                underlay: underlay.to_string(),
                overlay: overlay.to_string(),
                public_key: public.clone(),
                private_key: private.clone(),
            });
        }

        // --- 网桥 + netns + veth + 关 offload（wg_forwarding.rs 同款坑位处理）
        let bridge = format!("{PREFIX}br0");
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
            // GRO/GSO/TSO 会让 wg-over-veth 握手静默失败；两端都要关。
            for dev in [&n.veth_host, &n.veth_ns] {
                let _ = sudo(&[
                    "ethtool", "-K", dev, "gro", "off", "gso", "off", "tso", "off", "rx", "off",
                    "tx", "off", "sg", "off",
                ]);
            }
        }

        // --- 网关 LAN 段（G 的另一个接口 + LAN 主机 netns）
        let lan = format!("{PREFIX}L");
        let (lan0, lan1) = (format!("{PREFIX}X0"), format!("{PREFIX}X1"));
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

    fn wg_show(&self, ns: &str) -> String {
        String::from_utf8_lossy(&netns_exec(ns, &["wg", "show", "wg0"]).stdout).to_string()
    }

    fn nat_rules(&self, ns: &str, chain: &str) -> String {
        String::from_utf8_lossy(&netns_exec(ns, &["iptables", "-t", "nat", "-S", chain]).stdout)
            .to_string()
    }

    /// §7.4 源保留观测：B 起一次性 UDP echo（应答体=收包源地址），A 发一次。
    /// 返回应答体（`Some("src=<源地址>")`），用于断言 A→B 的源未被改写。
    fn overlay_source_seen_by_b(&self) -> Option<String> {
        let server = ECHO_SERVER_PY.replace("@BIND@", &self.b.overlay);
        let mut child = Command::new("sudo")
            .arg("-n")
            .args([
                "ip",
                "netns",
                "exec",
                &self.b.netns,
                "python3",
                "-c",
                &server,
            ])
            .stdout(Stdio::null())
            .spawn()
            .ok()?;
        std::thread::sleep(Duration::from_millis(700)); // echo 服务就绪
        let client = ECHO_CLIENT_PY.replace("@PEER@", &self.b.overlay);
        let mut answer = None;
        for _ in 0..3 {
            let out = netns_exec(&self.a.netns, &["python3", "-c", &client]);
            if out.status.success() {
                answer = Some(String::from_utf8_lossy(&out.stdout).trim().to_string());
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        let _ = child.wait();
        answer
    }
}

// ---------------------------------------------------------------- 配置构造

/// hub 侧隧道配置（与 server 适配层 `hub_plan` 同构：peer allowed-ips =
/// 虚拟 IP /32 + 经该设备转发的 Alias 前缀）。
fn hub_tunnel(hub: &Node, a: &Node, b: &Node, gw: &Node, with_b: bool) -> TunnelConfig {
    let mut peers = vec![
        PeerConfig {
            public_key: a.public_key.clone(),
            allowed_ips: vec!["10.240.0.2/32".parse().unwrap()],
            endpoint: None,
            persistent_keepalive_secs: None,
        },
        PeerConfig {
            public_key: gw.public_key.clone(),
            allowed_ips: vec![
                "10.240.0.4/32".parse().unwrap(),
                "10.241.1.0/24".parse().unwrap(),
            ],
            endpoint: None,
            persistent_keepalive_secs: None,
        },
    ];
    if with_b {
        peers.insert(
            1,
            PeerConfig {
                public_key: b.public_key.clone(),
                allowed_ips: vec!["10.240.0.3/32".parse().unwrap()],
                endpoint: None,
                persistent_keepalive_secs: None,
            },
        );
    }
    TunnelConfig {
        name: "wg0".into(),
        address: hub.overlay.parse().unwrap(),
        address_prefix: 24,
        listen_port: Some(16190),
        peers,
        mtu: None,
        private_key: Some(hub.private_key.clone()),
    }
}

/// hub 的 Alias 转发路由（server 适配层 `hub_plan` 对 Alias 路由的产物）。
fn hub_routes() -> Vec<RouteConfig> {
    vec![RouteConfig {
        destination: "10.241.1.0/24".parse().unwrap(),
        interface: "wg0".into(),
        gateway: Some("10.240.0.4".parse().unwrap()),
    }]
}

/// 客户端/网关侧隧道配置（peer = hub，endpoint 指网桥上 hub 的 netns 地址）。
fn leaf_tunnel(node: &Node, hub: &Node, allowed_ips: &[&str]) -> TunnelConfig {
    TunnelConfig {
        name: "wg0".into(),
        address: node.overlay.parse().unwrap(),
        address_prefix: 24,
        listen_port: None,
        peers: vec![PeerConfig {
            public_key: hub.public_key.clone(),
            allowed_ips: allowed_ips.iter().map(|s| s.parse().unwrap()).collect(),
            endpoint: Some(format!("{}:16190", hub.underlay)),
            persistent_keepalive_secs: Some(2),
        }],
        mtu: None,
        private_key: Some(node.private_key.clone()),
    }
}

/// dnat_snat 模式的 Alias 映射（§9.4–§9.5，与 alias_nat.rs 同一形状）。
fn alias_mapping() -> AliasMapping {
    AliasMapping::new(
        AliasMappingId("al-1".into()),
        NetworkId("net-1".into()),
        LanRouteId("rt-1".into()),
        "10.241.1.0/24".parse().unwrap(),
        "192.168.1.0/24".parse().unwrap(),
        TranslationMode::DnatSnat,
    )
    .unwrap()
}

const ALIAS_OWNER: &str = "meshlet alias al-1";

#[test]
fn backend_driven_tunnel_routes_and_nat() {
    let topo = match Topology::setup() {
        Some(t) => t,
        None => return, // 已打印 SKIP:
    };

    // ---- 全部数据面配置经 LinuxNetworkBackend 下发 ------------------------
    let hub_backend = topo.hub.backend();
    let a_backend = topo.a.backend();
    let b_backend = topo.b.backend();
    let gw_backend = topo.gw.backend();

    // hub：tunnel（peer A/B/G）+ Alias 前缀转发路由。
    hub_backend
        .apply_tunnel_sync(&hub_tunnel(&topo.hub, &topo.a, &topo.b, &topo.gw, true))
        .expect("hub apply_tunnel");
    hub_backend
        .apply_routes_sync(&hub_routes())
        .expect("hub apply_routes");

    // 客户端 A/B：tunnel + Alias 段进隧道的路由。
    for (node, backend) in [(&topo.a, &a_backend), (&topo.b, &b_backend)] {
        backend
            .apply_tunnel_sync(&leaf_tunnel(
                node,
                &topo.hub,
                &["10.240.0.0/16", "10.241.0.0/16"],
            ))
            .unwrap_or_else(|e| panic!("{} apply_tunnel: {e}", node.netns));
        backend
            .apply_routes_sync(&[RouteConfig {
                destination: "10.241.0.0/16".parse().unwrap(),
                interface: "wg0".into(),
                gateway: None,
            }])
            .unwrap_or_else(|e| panic!("{} apply_routes: {e}", node.netns));
    }

    // 网关 G：tunnel + 回程路由 + Alias NAT（计划层渲染执行）。
    gw_backend
        .apply_tunnel_sync(&leaf_tunnel(
            &topo.gw,
            &topo.hub,
            &["10.240.0.0/16", "10.241.0.0/16"],
        ))
        .expect("gw apply_tunnel");
    gw_backend
        .apply_routes_sync(&[RouteConfig {
            destination: "10.241.0.0/16".parse().unwrap(),
            interface: "wg0".into(),
            gateway: None,
        }])
        .expect("gw apply_routes");
    let alias = alias_mapping();
    let rules = meshlet_network::nat::alias_nat_rules(&alias);
    gw_backend
        .apply_nat_sync(&rules, "192.168.1.1".parse().unwrap())
        .expect("gw apply_nat");

    // ---- 1. 握手完成 + inspect 快照 ---------------------------------------
    for ns in [&topo.a.netns, &topo.b.netns, &topo.gw.netns] {
        assert!(
            topo.wait_handshake(ns),
            "handshake did not complete in {ns}"
        );
    }
    let snap = hub_backend.inspect_sync().expect("hub inspect");
    assert!(snap.tunnel_exists);
    assert_eq!(snap.peer_count, 3, "hub peers: A + B + G");
    assert_eq!(snap.forwarding_enabled, Some(true));
    assert!(
        snap.installed_routes
            .contains(&"10.241.1.0/24".parse().unwrap()),
        "hub must route the alias prefix: {:?}",
        snap.installed_routes
    );
    assert!(!snap.nat_rules_present, "hub carries no NAT rules");

    // 网关 G 的快照：规则在场 + 受控 SNAT 读数在场（dnat_snat 模式，
    // §8.2「内核实测所采用模式」的证据源）。
    let gw_snap = gw_backend.inspect_sync().expect("gw inspect");
    assert!(gw_snap.nat_rules_present, "gw carries meshlet NAT rules");
    assert!(
        gw_snap.nat_snat_rules_present,
        "dnat_snat mode: controlled SNAT rule kernel-verified"
    );

    // ---- 2. A -> B 经 hub 转发可达（双向） --------------------------------
    assert!(topo.ping(&topo.a.netns, &topo.b.overlay), "A -> B via hub");
    assert!(topo.ping(&topo.b.netns, &topo.a.overlay), "B -> A via hub");

    // ---- 3. Alias 路径：A 经 hub + G + NAT 打到 G 后真实 LAN --------------
    assert!(
        topo.ping(&topo.a.netns, "10.241.1.5"),
        "A -> alias 10.241.1.5 (real LAN 192.168.1.5 behind G)"
    );

    // ---- 4. 幂等：同一配置重复应用结果一致（§10.3） ------------------------
    hub_backend
        .apply_tunnel_sync(&hub_tunnel(&topo.hub, &topo.a, &topo.b, &topo.gw, true))
        .expect("hub apply_tunnel (re-apply)");
    gw_backend
        .apply_nat_sync(&rules, "192.168.1.1".parse().unwrap())
        .expect("gw apply_nat (re-apply)");
    assert!(
        topo.ping(&topo.a.netns, &topo.b.overlay),
        "A -> B after re-apply"
    );
    assert!(
        topo.ping(&topo.a.netns, "10.241.1.5"),
        "alias after re-apply"
    );

    // ---- 5. Overlay 源保留（§7.4）：NAT 在场，A→B 源仍是原始地址 ----------
    // G 的 NAT 规则此刻在场——若存在无差别 SNAT，B 看到的源就会被改写。
    let expected_source = format!("src={}", topo.a.overlay);
    let observed = topo.overlay_source_seen_by_b();
    assert_eq!(
        observed.as_deref(),
        Some(expected_source.as_str()),
        "overlay A->B must keep the original source address (7.4)"
    );

    // ---- 6. remove_nat 只删 Meshlet 规则，不触碰用户规则（§12.6） ----------
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
    gw_backend
        .remove_nat_sync(ALIAS_OWNER)
        .expect("gw remove_nat");
    let prerouting = topo.nat_rules(&topo.gw.netns, "PREROUTING");
    assert!(
        !prerouting.contains(ALIAS_OWNER),
        "meshlet alias rules must be gone:\n{prerouting}"
    );
    assert!(
        prerouting.contains("user rule"),
        "foreign rule must survive remove_nat:\n{prerouting}"
    );
    assert!(
        !topo.ping(&topo.a.netns, "10.241.1.5"),
        "alias path must fail after remove_nat"
    );
    assert!(
        topo.ping(&topo.a.netns, &topo.b.overlay),
        "overlay must be unaffected by remove_nat"
    );

    // ---- 7. 撤销即失效：hub 重应用去掉 B，其余 peer 不受影响（§11.5） -------
    hub_backend
        .apply_tunnel_sync(&hub_tunnel(&topo.hub, &topo.a, &topo.b, &topo.gw, false))
        .expect("hub apply_tunnel without B");
    let hub_peers = topo.wg_show(&topo.hub.netns);
    assert!(
        !hub_peers.contains(&topo.b.public_key),
        "revoked B must vanish from hub peers:\n{hub_peers}"
    );
    assert!(
        hub_peers.contains(&topo.a.public_key),
        "A must survive B's revoke:\n{hub_peers}"
    );
    assert!(
        !topo.ping(&topo.a.netns, &topo.b.overlay),
        "A -> B must fail after B revoked"
    );
    // Alias 通路（A→G）不受 B 撤销影响（G 的 NAT 尚未恢复）。
    assert!(
        hub_peers.contains(&topo.gw.public_key),
        "G must survive B's revoke:\n{hub_peers}"
    );

    // ---- 8. 回滚只删 Meshlet 自有对象（§10.3） -----------------------------
    hub_backend.rollback_sync().expect("hub rollback");
    let snap = hub_backend
        .inspect_sync()
        .expect("hub inspect after rollback");
    assert_eq!(snap.peer_count, 0, "rollback removes all peers");
    assert!(
        snap.installed_routes.is_empty(),
        "rollback removes tunnel routes: {:?}",
        snap.installed_routes
    );
    assert!(snap.tunnel_exists, "rollback keeps the interface");
    assert_eq!(
        snap.forwarding_enabled,
        Some(true),
        "ip_forward is system state"
    );
    assert!(
        !topo.ping(&topo.b.netns, &topo.a.overlay),
        "data path must be down after rollback"
    );

    // ---- 9. 模式判读（§8.2、ADR-005）：inspect 快照按链区分返回路径模式
    // ——`dnat_only` 只有 PREROUTING（无 SNAT 读数），`dnat_snat` 追加
    // POSTROUTING；证据通道据此内核实测所采用模式，不靠路由记录的字段值
    // 冒充生效状态。同文件只有一个 netns 前缀（并发测试互踩），故并入本
    // 测试末尾而非独立用例。
    gw_backend
        .remove_nat_sync(ALIAS_OWNER)
        .expect("gw remove_nat before mode switch");
    let dnat_only = AliasMapping::new(
        AliasMappingId("al-2".into()),
        NetworkId("net-1".into()),
        LanRouteId("rt-1".into()),
        "10.241.1.0/24".parse().unwrap(),
        "192.168.1.0/24".parse().unwrap(),
        TranslationMode::DnatOnly,
    )
    .unwrap();
    gw_backend
        .apply_nat_sync(
            &meshlet_network::nat::alias_nat_rules(&dnat_only),
            "192.168.1.1".parse().unwrap(),
        )
        .expect("gw apply_nat dnat_only");
    let snap = gw_backend.inspect_sync().expect("gw inspect dnat_only");
    assert!(snap.nat_rules_present, "dnat rules present in kernel");
    assert!(
        !snap.nat_snat_rules_present,
        "dnat_only: no meshlet SNAT rule in kernel (original sources preserved)"
    );
    gw_backend
        .remove_nat_sync("meshlet alias al-2")
        .expect("gw remove_nat dnat_only");
    gw_backend
        .apply_nat_sync(
            &meshlet_network::nat::alias_nat_rules(&alias_mapping()),
            "192.168.1.1".parse().unwrap(),
        )
        .expect("gw apply_nat dnat_snat");
    let snap = gw_backend.inspect_sync().expect("gw inspect dnat_snat");
    assert!(snap.nat_rules_present);
    assert!(
        snap.nat_snat_rules_present,
        "dnat_snat: controlled SNAT rule kernel-verified"
    );

    // ---- 10. 已存在本地路由的冲突检测（§18.3）：`ip route replace` 不得静默
    // 接管非 Meshlet 的路由——冲突时显式拒绝并点名冲突对象，外部路由原样保留；
    // 而经受管接口的既有路由是 Meshlet 自有对象（上次 apply 留下的），幂等
    // 重放与计划变更照常改写。同文件只有一个 netns 前缀，故并入本测试末尾。
    let foreign = "10.244.0.0/24";
    require_ok(
        &netns_exec(
            &topo.hub.netns,
            &["ip", "route", "add", foreign, "dev", &topo.hub.veth_ns],
        ),
        "seed foreign route",
    );
    let conflicted = hub_backend.apply_routes_sync(&[RouteConfig {
        destination: foreign.parse().unwrap(),
        interface: "wg0".into(),
        gateway: Some("10.240.0.4".parse().unwrap()),
    }]);
    match conflicted {
        Err(meshlet_network::NetworkError::ApplyRejected(message)) => {
            assert!(
                message.contains(foreign) && message.contains("already exists"),
                "conflict must name the destination: {message}"
            );
        }
        other => panic!("foreign route must be rejected, got {other:?}"),
    }
    let shown = String::from_utf8_lossy(
        &netns_exec(&topo.hub.netns, &["ip", "route", "show", "exact", foreign]).stdout,
    )
    .to_string();
    assert!(
        shown.contains(&topo.hub.veth_ns),
        "foreign route must be left untouched: {shown}"
    );
    assert!(
        !shown.contains("wg0"),
        "foreign route must not be retargeted onto the tunnel: {shown}"
    );
    // 既有经 wg0 的路由是 Meshlet 自己的：再 apply 一次照常成功（幂等不被
    // 冲突检测误伤）。
    hub_backend
        .apply_routes_sync(&hub_routes())
        .expect("hub apply_routes idempotent");

    // teardown 并断言「跑完不留垃圾」。
    drop(topo);
    let netns_left = sudo(&["ip", "netns", "list"]);
    let links_left = sudo(&["ip", "-br", "link"]);
    let netns_text = String::from_utf8_lossy(&netns_left.stdout).to_string();
    let links_text = String::from_utf8_lossy(&links_left.stdout).to_string();
    assert_eq!(
        count_prefix_lines(&netns_text),
        0,
        "leftover netns after teardown:\n{netns_text}"
    );
    assert_eq!(
        count_prefix_lines(&links_text),
        0,
        "leftover links after teardown:\n{links_text}"
    );
}
