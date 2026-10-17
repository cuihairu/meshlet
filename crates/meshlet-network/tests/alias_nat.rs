//! Alias DNAT/SNAT 原型的真实网络集成测试（[存档 §9.2–§9.5](../../../docs/review/chatgpt-2026-10-13.md)、
//! [ADR-006](../../../docs/decisions/adr-006-alias-prefix-nat.md)）。
//!
//! 六个网络命名空间搭出「VPS hub + 两个站点网关 + 两个**同前缀**真实 LAN +
//! Overlay 客户端」的拓扑——两个站点的真实 LAN 都是 `192.168.1.0/24`（地址
//! 重叠），只能靠 Alias 前缀区分：
//!
//! - **site1**：Alias `10.241.1.0/24` → gw1，`dnat_snat` 模式（默认兼容，
//!   受控 SNAT 返回路径，§9.5 模式 B）；
//! - **site2**：Alias `10.241.2.0/24` → gw2，`dnat_only` 模式（保留源地址，
//!   要求 LAN 有指向网关的返回路由，§9.5 模式 A）。
//!
//! NAT 规则用 `iptables NETMAP`/`SNAT` 下发，与 [NatRule::iptables_args]
//! 的渲染同形（计划与执行同一形状，不漂移）。
//!
//! 验收四项：
//!
//! 1. **双 192.168.1.0/24 经不同 Alias 互通**：客户端 ping `10.241.1.5` 与
//!    `10.241.2.5` 都通（真实子网完全重叠，Alias 前缀是唯一区分）；
//! 2. **站内身份不串线**：UDP echo 应答体携带站点名——alias1 的应答来自
//!    `site1`，alias2 来自 `site2`（重叠子网确实落到了两个不同站点）；
//! 3. **受控 SNAT 可观测（site1）**：LAN 主机看到的源地址是网关自身 LAN
//!    地址 `192.168.1.1`（§9.5 明示的限制），应答源地址被 conntrack 逆变换
//!    回 Alias 地址 `10.241.1.5`；
//! 4. **源地址保留可观测（site2）**：LAN 主机看到客户端的真实 Overlay 源
//!    `10.240.0.3`（§9.5 模式 A），应答源为 `10.241.2.5`。
//!
//! 拓扑要点（全部实测踩明）：
//!
//! - 先 `ip netns add` 再把 veth 端搬进 netns——顺序颠倒命令静默失败，LAN
//!   端地址没配上，表现为网关侧 ARP 不通（`Destination Host Unreachable`
//!   且来源是逆变换后的 Alias 地址）；
//! - VPS hub 只按前缀转发：`ip route add 10.241.1.0/24 via <gw1 wg addr>
//!   dev wg0`，hub 自己不做任何 NAT（§9.4）；
//! - 客户端要有 `10.241.0.0/16 dev wg0` 路由（`wg set` 不会自动加路由）；
//! - 转换发生在**目标 LAN 网关**（gw1/gw2 上 NETMAP），不是 hub 上；
//! - NETMAP 是 conntrack 化的：应答方向的逆变换（真实地址 → Alias 地址）
//!   不需要额外规则。
//!
//! 前置条件与跳过纪律同 [wg_forwarding]；清理走 `Drop` + 末尾断言无残留。

#![cfg(target_os = "linux")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// 本测试创建的所有对象共用的名称前缀。
const PREFIX: &str = "mlta";
/// 客户端路由经由 hub 的 Overlay 网段。
const OVERLAY_CIDR: &str = "10.240.0.0/16";
/// 两个站点共享的 Alias 超网（客户端侧路由）。
const ALIAS_CIDR: &str = "10.241.0.0/16";
/// 两个站点**完全重叠**的真实 LAN 前缀。
const REAL_LAN: &str = "192.168.1.0/24";
/// LAN 主机地址（两个站点同名）。
const LAN_HOST: &str = "192.168.1.5";
/// 网关在真实 LAN 内的地址（受控 SNAT 的 SNAT 目标）。
const LAN_GW: &str = "192.168.1.1";
/// 握手等待上限。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(25);

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

fn netns_bash(ns: &str, script: &str) -> Output {
    netns_exec(ns, &["bash", "-c", script])
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

fn count_prefix_lines(text: &str) -> usize {
    text.lines().filter(|l| l.starts_with(PREFIX)).count()
}

/// 前置条件（同 [wg_forwarding]：免密 sudo + wg + 内核模块；本测试另需
/// python3 跑 UDP echo 与 iptables NETMAP 支持）。
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
            eprintln!("SKIP: python3 not installed");
            return None;
        }
    }
    Some(())
}

/// 幂等清场（崩溃恢复）。
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

// ---------------------------------------------------------------- 拓扑

/// Overlay 侧节点（挂在网桥上，有 wg0）。
struct Node {
    netns: String,
    underlay: String,
    overlay: String,
    port: u16,
    public_key: String,
    private_key: String,
}

impl Node {
    fn netns_exec(&self, args: &[&str]) -> Output {
        netns_exec(&self.netns, args)
    }
    fn netns_bash(&self, script: &str) -> Output {
        netns_bash(&self.netns, script)
    }
}

/// 追踪已建对象，setup 中途 panic 也能清干净。
struct Guard {
    netns: Vec<String>,
    veth: Vec<String>,
    bridge: Option<String>,
    scripts_dir: Option<PathBuf>,
}

impl Guard {
    fn new() -> Self {
        Guard {
            netns: Vec::new(),
            veth: Vec::new(),
            bridge: None,
            scripts_dir: None,
        }
    }
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
        if let Some(dir) = &self.scripts_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

struct Topology {
    #[allow(dead_code)]
    guard: Guard,
    hub: Node,
    gw1: Node,
    gw2: Node,
    client: Node,
    keys_dir: PathBuf,
}

/// 桥上节点（netns + veth + underlay 地址 + 关 offload）。
fn bridge_node(guard: &mut Guard, bridge: &str, name: &str, underlay: &str) -> (String, String) {
    let netns = format!("{PREFIX}{name}");
    let veth_host = format!("{PREFIX}{name}0");
    let veth_ns = format!("{PREFIX}{name}1");
    guard.netns.push(netns.clone());
    guard.veth.push(veth_host.clone());
    require_ok(&sudo(&["ip", "netns", "add", &netns]), "netns add");
    require_ok(
        &sudo(&[
            "ip", "link", "add", &veth_host, "type", "veth", "peer", "name", &veth_ns,
        ]),
        "veth add",
    );
    require_ok(
        &sudo(&["ip", "link", "set", &veth_ns, "netns", &netns]),
        "veth into netns",
    );
    require_ok(
        &sudo(&["ip", "link", "set", &veth_host, "master", bridge]),
        "veth onto bridge",
    );
    require_ok(
        &netns_exec(
            &netns,
            &[
                "ip",
                "addr",
                "add",
                &format!("{underlay}/24"),
                "dev",
                &veth_ns,
            ],
        ),
        "underlay addr",
    );
    require_ok(
        &sudo(&["ip", "link", "set", &veth_host, "up"]),
        "veth host up",
    );
    require_ok(
        &netns_exec(&netns, &["ip", "link", "set", &veth_ns, "up"]),
        "veth ns up",
    );
    require_ok(
        &netns_exec(&netns, &["ip", "link", "set", "lo", "up"]),
        "lo up",
    );
    // GRO/GSO/TSO 会让 wg-over-veth 握手静默失败；两端都要关。
    let offload = [
        "gro", "off", "gso", "off", "tso", "off", "rx", "off", "tx", "off", "sg", "off",
    ];
    let mut host_offload = vec!["ethtool", "-K", &veth_host];
    host_offload.extend_from_slice(&offload);
    let mut ns_offload = vec!["ethtool", "-K", &veth_ns];
    ns_offload.extend_from_slice(&offload);
    let _ = sudo(&host_offload);
    let _ = netns_exec(&netns, &ns_offload);
    (netns, veth_ns)
}

/// 网关身后的 LAN 段：veth 一端进网关、一端进 LAN 主机 netns。
/// `lan_veth` 命名用站点字母（X/Y）避免与桥上 veth 冲突。
fn lan_segment(guard: &mut Guard, gw_netns: &str, letter: &str, gw_addr: &str, host_addr: &str) {
    let lan_netns = format!("{PREFIX}L{letter}");
    let veth_gw = format!("{PREFIX}{letter}0");
    let veth_host = format!("{PREFIX}{letter}1");
    guard.netns.push(lan_netns.clone());
    guard.veth.push(veth_gw.clone());
    require_ok(&sudo(&["ip", "netns", "add", &lan_netns]), "lan netns add");
    require_ok(
        &sudo(&[
            "ip", "link", "add", &veth_gw, "type", "veth", "peer", "name", &veth_host,
        ]),
        "lan veth add",
    );
    require_ok(
        &sudo(&["ip", "link", "set", &veth_gw, "netns", gw_netns]),
        "lan veth into gw",
    );
    require_ok(
        &sudo(&["ip", "link", "set", &veth_host, "netns", &lan_netns]),
        "lan veth into host",
    );
    require_ok(
        &netns_exec(
            gw_netns,
            &[
                "ip",
                "addr",
                "add",
                &format!("{gw_addr}/24"),
                "dev",
                &veth_gw,
            ],
        ),
        "gw lan addr",
    );
    require_ok(
        &netns_exec(
            &lan_netns,
            &[
                "ip",
                "addr",
                "add",
                &format!("{host_addr}/24"),
                "dev",
                &veth_host,
            ],
        ),
        "lan host addr",
    );
    require_ok(
        &netns_exec(gw_netns, &["ip", "link", "set", &veth_gw, "up"]),
        "gw lan up",
    );
    require_ok(
        &netns_exec(&lan_netns, &["ip", "link", "set", &veth_host, "up"]),
        "lan host up",
    );
    require_ok(
        &netns_exec(gw_netns, &["ip", "link", "set", "lo", "up"]),
        "gw lo up",
    );
    require_ok(
        &netns_exec(&lan_netns, &["ip", "link", "set", "lo", "up"]),
        "lan lo up",
    );
    // LAN 主机把网关当默认路由（§9.5 模式 A 的返回路径）。
    require_ok(
        &netns_exec(
            &lan_netns,
            &["ip", "route", "add", "default", "via", gw_addr],
        ),
        "lan default route",
    );
}

/// wg0 + 地址 +（可选）ip_forward；private-key 与 peer 分两次 `wg set`。
fn wg_iface(node: &Node, forward: bool) {
    let fwd = if forward {
        " && sysctl -w net.ipv4.ip_forward=1"
    } else {
        ""
    };
    let script = format!(
        "ip link add wg0 type wireguard && ip address add {}/24 dev wg0 && ip link set wg0 up{fwd}",
        node.overlay
    );
    require_ok(&node.netns_bash(&script), "wg interface");
    let script = format!(
        "wg set wg0 listen-port {} private-key <(echo {})",
        node.port, node.private_key
    );
    require_ok(&node.netns_bash(&script), "private key");
}

impl Topology {
    fn setup() -> Option<Topology> {
        prerequisites()?;
        preflight_cleanup();

        let keys_dir = std::env::temp_dir().join(format!(
            "{PREFIX}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()?
                .as_nanos(),
        ));
        if std::fs::create_dir_all(&keys_dir).is_err() {
            return None;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&keys_dir, std::fs::Permissions::from_mode(0o700));
        }
        let mut guard = Guard::new();
        guard.scripts_dir = Some(keys_dir.clone());

        // --- 密钥
        let mut keys = Vec::new();
        for name in ["H", "G1", "G2", "CL"] {
            let private = match wg_genkey() {
                Ok(k) => k,
                Err(e) => {
                    assert!(
                        std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
                        "required dataplane prerequisite failed"
                    );
                    eprintln!("SKIP: key generation failed: {e}");
                    return None;
                }
            };
            let public = match wg_pubkey(&private) {
                Ok(k) => k,
                Err(e) => {
                    assert!(
                        std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
                        "required dataplane prerequisite failed"
                    );
                    eprintln!("SKIP: key derivation failed: {e}");
                    return None;
                }
            };
            keys.push((name, private, public));
        }

        // --- underlay 网桥 + 桥上节点
        let bridge = format!("{PREFIX}br0");
        guard.bridge = Some(bridge.clone());
        require_ok(
            &sudo(&["ip", "link", "add", &bridge, "type", "bridge"]),
            "create bridge",
        );
        require_ok(&sudo(&["ip", "link", "set", &bridge, "up"]), "bridge up");

        let mk = |guard: &mut Guard, name: &str, underlay: &str, overlay: &str, port: u16| {
            let (netns, _) = bridge_node(guard, &bridge, name, underlay);
            let private = keys
                .iter()
                .find(|(n, _, _)| *n == name)
                .expect("key")
                .1
                .clone();
            let public = keys
                .iter()
                .find(|(n, _, _)| *n == name)
                .expect("key")
                .2
                .clone();
            Node {
                netns,
                underlay: underlay.to_string(),
                overlay: overlay.to_string(),
                port,
                public_key: public,
                private_key: private,
            }
        };
        let hub = mk(&mut guard, "H", "10.99.0.10", "10.240.0.1", 16180);
        let gw1 = mk(&mut guard, "G1", "10.99.0.20", "10.240.0.2", 16181);
        let gw2 = mk(&mut guard, "G2", "10.99.0.30", "10.240.0.4", 16182);
        let client = mk(&mut guard, "CL", "10.99.0.40", "10.240.0.3", 16183);

        // --- 网关身后的 LAN 段（两个站点真实前缀完全重叠）
        lan_segment(&mut guard, &gw1.netns, "X", LAN_GW, LAN_HOST);
        lan_segment(&mut guard, &gw2.netns, "Y", LAN_GW, LAN_HOST);

        // --- wg 接口（hub/网关开转发）
        wg_iface(&hub, true);
        wg_iface(&gw1, true);
        wg_iface(&gw2, true);
        wg_iface(&client, false);

        // --- hub peers：每个网关携带自己的 Alias 前缀（VPS 只按前缀转发）
        require_ok(
            &hub.netns_bash(&format!(
                "wg set wg0 peer {} allowed-ips 10.240.0.2/32,10.241.1.0/24",
                gw1.public_key
            )),
            "hub peer gw1",
        );
        require_ok(
            &hub.netns_bash(&format!(
                "wg set wg0 peer {} allowed-ips 10.240.0.4/32,10.241.2.0/24",
                gw2.public_key
            )),
            "hub peer gw2",
        );
        require_ok(
            &hub.netns_bash(&format!(
                "wg set wg0 peer {} allowed-ips 10.240.0.3/32",
                client.public_key
            )),
            "hub peer client",
        );
        // --- 网关/客户端 peers（都指向 hub，覆盖 Overlay + Alias 空间）
        for n in [&gw1, &gw2] {
            require_ok(
                &n.netns_bash(&format!(
                    "wg set wg0 peer {} allowed-ips {OVERLAY_CIDR},{ALIAS_CIDR} endpoint {}:{} persistent-keepalive 2",
                    hub.public_key, hub.underlay, hub.port
                )),
                "gateway peer",
            );
        }
        require_ok(
            &client.netns_bash(&format!(
                "wg set wg0 peer {} allowed-ips {OVERLAY_CIDR},{ALIAS_CIDR} endpoint {}:{} persistent-keepalive 2",
                hub.public_key, hub.underlay, hub.port
            )),
            "client peer",
        );

        // --- hub：Alias 前缀路由到对应站点网关（§9.4：VPS 不做 NAT）
        require_ok(
            &hub.netns_exec(&[
                "ip",
                "route",
                "add",
                "10.241.1.0/24",
                "via",
                &gw1.overlay,
                "dev",
                "wg0",
            ]),
            "hub alias1 route",
        );
        require_ok(
            &hub.netns_exec(&[
                "ip",
                "route",
                "add",
                "10.241.2.0/24",
                "via",
                &gw2.overlay,
                "dev",
                "wg0",
            ]),
            "hub alias2 route",
        );
        // --- 客户端：Alias 空间进隧道（wg set 不会自动加路由）
        require_ok(
            &client.netns_exec(&["ip", "route", "add", ALIAS_CIDR, "dev", "wg0"]),
            "client alias route",
        );

        // --- 网关 NAT 规则（与 NatRule::iptables_args 渲染同形）
        // site1（dnat_snat）：DNAT 恒有 + 受控 SNAT（§9.5 模式 B）
        require_ok(
            &gw1.netns_exec(&[
                "iptables",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-d",
                "10.241.1.0/24",
                "-j",
                "NETMAP",
                "--to",
                REAL_LAN,
            ]),
            "gw1 netmap",
        );
        require_ok(
            &gw1.netns_exec(&[
                "iptables",
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-d",
                REAL_LAN,
                "-j",
                "SNAT",
                "--to-source",
                LAN_GW,
            ]),
            "gw1 controlled snat",
        );
        // site2（dnat_only）：只有 DNAT，保留原始源地址（§9.5 模式 A）
        require_ok(
            &gw2.netns_exec(&[
                "iptables",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-d",
                "10.241.2.0/24",
                "-j",
                "NETMAP",
                "--to",
                REAL_LAN,
            ]),
            "gw2 netmap",
        );

        // --- echo/send 脚本
        let echo_py = keys_dir.join("echo.py");
        std::fs::write(&echo_py, ECHO_PY).expect("write echo.py");
        let send_py = keys_dir.join("send.py");
        std::fs::write(&send_py, SEND_PY).expect("write send.py");

        Some(Topology {
            guard,
            hub,
            gw1,
            gw2,
            client,
            keys_dir,
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

    /// 在 `site`（L1/L2 netns）起一次性 UDP echo 服务，客户端打 `alias`。
    /// 返回应答体（形如 `site1 seen=192.168.1.1`）与应答源地址。
    fn udp_echo(
        &self,
        site_netns: &str,
        site_name: &str,
        port: u16,
        alias: &str,
    ) -> (String, String) {
        let echo_py = self.keys_dir.join("echo.py");
        let send_py = self.keys_dir.join("send.py");
        let mut server = Command::new("sudo")
            .arg("-n")
            .args(["ip", "netns", "exec", site_netns, "python3"])
            .arg(&echo_py)
            .arg(port.to_string())
            .arg(site_name)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn echo server");
        // 客户端带重试：echo 服务起来之前发出的包会被丢弃，重发即可。
        let out = netns_exec(
            &self.client.netns,
            &[
                "python3",
                &send_py.to_string_lossy(),
                alias,
                &port.to_string(),
            ],
        );
        let client_line = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let _ = server.wait();
        if !out.status.success() {
            return (client_line, String::new());
        }
        // send.py 输出形如 `reply_from=<ip> body=<...>`。
        let mut reply_from = String::new();
        for part in client_line.split_whitespace() {
            if let Some(v) = part.strip_prefix("reply_from=") {
                reply_from = v.to_string();
            }
        }
        let body = client_line
            .split_once("body=")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default();
        (body, reply_from)
    }

    fn dump_all(&self) {
        for n in [&self.hub, &self.gw1, &self.gw2, &self.client] {
            eprintln!("--- wg show wg0 in {} ---", n.netns);
            let out = n.netns_exec(&["wg", "show", "wg0"]);
            eprintln!("{}", String::from_utf8_lossy(&out.stdout));
        }
    }
}

/// 一次性 UDP echo 服务：收到一个包、回 `site seen=<src>`、退出。
const ECHO_PY: &str = "\
import socket, sys
port, site = int(sys.argv[1]), sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', port))
s.settimeout(15)
data, addr = s.recvfrom(2048)
s.sendto(f'{site} seen={addr[0]}'.encode(), addr)
";

/// UDP 发送端：带重试（等 echo 服务起）、打印应答源与应答体。
const SEND_PY: &str = "\
import socket, sys, time
target, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1.5)
for i in range(12):
    try:
        s.sendto(b'probe', (target, port))
        data, addr = s.recvfrom(2048)
        print(f'reply_from={addr[0]} body={data.decode()}')
        sys.exit(0)
    except socket.timeout:
        pass
print('no_reply')
sys.exit(1)
";

fn wg_genkey() -> std::io::Result<String> {
    let out = Command::new("wg").arg("genkey").output()?;
    if !out.status.success() {
        return Err(std::io::Error::other("wg genkey failed"));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn wg_pubkey(private: &str) -> std::io::Result<String> {
    let mut child = Command::new("wg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(private.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(std::io::Error::other("wg pubkey failed"));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[test]
fn alias_nat_forwarding() {
    let topo = match Topology::setup() {
        Some(t) => t,
        None => return, // 已打印 SKIP:
    };

    for ns in [&topo.gw1.netns, &topo.gw2.netns, &topo.client.netns] {
        if !topo.wait_handshake(ns) {
            topo.dump_all();
            panic!("wireguard handshake did not complete within {HANDSHAKE_TIMEOUT:?}");
        }
    }

    // 1. 双 192.168.1.0/24 经不同 Alias 互通（真实前缀完全重叠）。
    assert!(
        topo.ping(&topo.client.netns, LAN_HOST_ALIAS1),
        "alias 10.241.1.0/24 must reach site1's 192.168.1.5"
    );
    assert!(
        topo.ping(&topo.client.netns, LAN_HOST_ALIAS2),
        "alias 10.241.2.0/24 must reach site2's 192.168.1.5"
    );

    // 2+3. site1（dnat_snat）：站点身份正确 + LAN 看到网关 LAN 地址（受控
    // SNAT，§9.5 模式 B）+ 应答源被逆变换回 Alias 地址。
    let (body, reply_from) = topo.udp_echo("mltaLX", "site1", 45701, LAN_HOST_ALIAS1);
    assert_eq!(
        reply_from, LAN_HOST_ALIAS1,
        "echo reply must come from the alias address"
    );
    assert!(
        body.starts_with("site1 "),
        "alias1 traffic must land on site1, got: {body}"
    );
    assert_eq!(
        body, "site1 seen=192.168.1.1",
        "dnat_snat mode: LAN host must see the gateway's own LAN address (controlled SNAT)"
    );

    // 2+4. site2（dnat_only）：站点身份正确 + LAN 看到真实 Overlay 源地址
    // （§9.5 模式 A，源保留）+ 应答源为 Alias 地址。
    let (body, reply_from) = topo.udp_echo("mltaLY", "site2", 45702, LAN_HOST_ALIAS2);
    assert_eq!(
        reply_from, LAN_HOST_ALIAS2,
        "echo reply must come from the alias address"
    );
    assert!(
        body.starts_with("site2 "),
        "alias2 traffic must land on site2, got: {body}"
    );
    assert_eq!(
        body, "site2 seen=10.240.0.3",
        "dnat_only mode: LAN host must see the client's real overlay source (preserved)"
    );

    // teardown 并断言无残留。
    let keys_dir = topo.keys_dir.clone();
    drop(topo);
    let netns_left = sudo(&["ip", "netns", "list"]);
    let links_left = sudo(&["ip", "-br", "link"]);
    let netns_text = String::from_utf8_lossy(&netns_left.stdout);
    let links_text = String::from_utf8_lossy(&links_left.stdout);
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
    assert!(!keys_dir.exists(), "keys dir {keys_dir:?} not removed");
}

const LAN_HOST_ALIAS1: &str = "10.241.1.5";
const LAN_HOST_ALIAS2: &str = "10.241.2.5";
