//! WireGuard 中心转发原型的真实网络集成测试（[存档 §7.3](../../../docs/review/chatgpt-2026-10-13.md)）。
//!
//! 在四个网络命名空间里搭出 hub-and-spoke 拓扑（hub + 客户端 A + 客户端 B +
//! 未授权 C），用 `ip netns exec` 驱动真实 WireGuard 数据面，证明四项转发
//! 保证：
//!
//! 1. **A → B 可达**：经 hub 转发，双向都通；
//! 2. **B → A 可达**；
//! 3. **未授权第三节点不可达**：C 不在 hub 的 peer 列表里，C 打不到 A/B，
//!    hub 上也没有 C 的 peer 条目；
//! 4. **撤销 peer 立即失效**：hub 上 `wg set wg0 peer <A> remove` 之后，
//!    A→B 与 B→A 立刻不通，且 hub 的 peer 列表里 A 已消失。
//!
//! 拓扑要点（踩过的坑，全部在拓扑里体现）：
//!
//! - **underlay 用网桥（L2 star）**：四个 netns 的 veth 都挂到同一网桥。
//!   若把网桥换成「宿主 4 个 veth 共用一个 /24 + 宿主转发」，宿主有四个接口
//!   落在同一子网，路由歧义，握手包到不了 hub 的 netns；
//! - **veth 两端都关 offload**（`ethtool -K ... gro/gso/tso/rx/tx/sg off`）：
//!   默认 GRO/GSO/TSO 会让 wg 握手静默失败（tx 有字节、rx=0）；
//! - **peer endpoint 指向 hub 的 netns 侧 veth 地址**（网桥上的 10.99.0.10），
//!   不是宿主侧地址——否则包送到宿主自己的 UDP 栈，那里没有 wg0；
//! - **hub 的 `ip_forward` 必须在 hub 的 netns 里单独开**（每个 netns 有自己
//!   的 `net.ipv4.ip_forward`，宿主的值不继承）；
//! - **`wg set` 而非 `wg setconf`**：本环境 `setconf` 读配置文件报
//!   `fopen: Permission denied`（rc=1），`wg set` 正常；
//! - **private-key 与 peer 分两次 `wg set`**：合在一条命令里 peer 会被静默丢掉；
//! - **每个节点独立密钥对**：peer 公钥与自身公钥相同时 `wg set peer` 静默忽略。
//!
//! 前置条件：免密 sudo、`wg`（wireguard-tools）、`wireguard` 内核模块。
//! 缺任一项时打印 `SKIP:` 并正常返回——`cargo test --workspace` 在没有特权
//! 的 CI runner 上仍是全绿。
//!
//! 清理：`Topology` 的 `Drop` 删掉所有 netns、veth、网桥与临时密钥目录；
//! 测试最后再断言一次「跑完不留垃圾」。

#![cfg(target_os = "linux")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// 本测试创建的所有对象（netns / veth / 网桥）共用的名称前缀。
///
/// 各 netns 测试的前缀必须**互不为前缀**：`preflight_cleanup` 按
/// `starts_with` 批量清理，"mlt" 会连带删掉 "mlta"/"mltb"/"mltd" 的对象，
/// `cargo test --workspace` 并行跑时互相清场（对象跑到一半被删掉）。
const PREFIX: &str = "mltw";
/// 客户端路由经由 hub 的 Overlay 网段。
const OVERLAY_CIDR: &str = "10.240.0.0/16";
/// 握手等待上限。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(25);

// ---------------------------------------------------------------- 进程辅助

/// 以 root（`sudo -n`，无密码提示）执行命令。
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

/// 在 netns 内执行命令。
fn netns_exec(ns: &str, args: &[&str]) -> Output {
    let mut full = vec!["ip", "netns", "exec", ns];
    full.extend_from_slice(args);
    sudo(&full)
}

/// 在 netns 内执行一段 bash。用 bash（而非 sh）是因为 `wg set` 的
/// `private-key <(echo ...)` 需要进程替换。
fn netns_bash(ns: &str, script: &str) -> Output {
    netns_exec(ns, &["bash", "-c", script])
}

/// 建拓扑阶段：任何命令失败都 panic 并带上 stderr——环境对了而命令失败就是
/// 真 bug，不该静默。
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

/// 缺任一前置条件就返回 `None`（并打印 `SKIP:`），让 CI 无特权环境保持全绿。
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
    // 已加载则 modprobe 可能报错，所以两个条件取「或」。
    if !sudo_ok(&["modprobe", "wireguard"]) && !Path::new("/sys/module/wireguard").exists() {
        eprintln!("SKIP: wireguard kernel module unavailable");
        return None;
    }
    Some(())
}

/// 幂等清场：删掉上一次（崩溃的）运行留下的 mlt* 对象与临时密钥目录。
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
    let _ = std::fs::remove_dir_all(format!("/tmp/{PREFIX}-keys"));
}

// ---------------------------------------------------------------- 密钥

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

// ---------------------------------------------------------------- 拓扑

/// 一个节点（hub 或客户端）的配置与身份。
struct Node {
    netns: String,
    veth_host: String,
    veth_ns: String,
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
    fn wg_show(&self) -> String {
        let out = self.netns_exec(&["wg", "show", "wg0"]);
        String::from_utf8_lossy(&out.stdout).to_string()
    }
}

/// 从 netns / veth / 网桥 / 密钥目录中追踪已建对象，保证无论 setup 走到哪
/// 一步 panic 都能清干净。
struct Guard {
    netns: Vec<String>,
    veth: Vec<String>,
    bridge: Option<String>,
    keys_dir: Option<PathBuf>,
}

impl Guard {
    fn new() -> Self {
        Guard {
            netns: Vec::new(),
            veth: Vec::new(),
            bridge: None,
            keys_dir: None,
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
        if let Some(dir) = &self.keys_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

struct Topology {
    #[allow(dead_code)]
    guard: Guard,
    nodes: Vec<Node>,
    keys_dir: PathBuf,
}

impl Topology {
    /// 建拓扑。前置条件不满足返回 `None`（已打印 `SKIP:`）。
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
        guard.keys_dir = Some(keys_dir.clone());

        // --- 密钥（每个节点独立密钥对）
        let mut nodes = Vec::new();
        for (name, underlay, overlay, port) in [
            ("H", "10.99.0.10", "10.240.0.1", 15180),
            ("A", "10.99.0.20", "10.240.0.2", 15181),
            ("B", "10.99.0.30", "10.240.0.3", 15182),
            ("C", "10.99.0.40", "10.240.0.4", 15183),
        ] {
            let private = match wg_genkey() {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("SKIP: key generation failed: {e}");
                    return None;
                }
            };
            let public = match wg_pubkey(&private) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("SKIP: key derivation failed: {e}");
                    return None;
                }
            };
            nodes.push(Node {
                netns: format!("{PREFIX}{name}"),
                veth_host: format!("{PREFIX}{name}0"),
                veth_ns: format!("{PREFIX}{name}1"),
                underlay: underlay.to_string(),
                overlay: overlay.to_string(),
                port,
                public_key: public,
                private_key: private,
            });
        }
        let hub = &nodes[0];

        // --- underlay：网桥 star
        let bridge = format!("{PREFIX}br0");
        guard.bridge = Some(bridge.clone());
        require_ok(
            &sudo(&["ip", "link", "add", &bridge, "type", "bridge"]),
            "create bridge",
        );
        require_ok(&sudo(&["ip", "link", "set", &bridge, "up"]), "bridge up");

        // --- netns + veth + underlay 地址 + 关 offload
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
                &n.netns_exec(&[
                    "ip",
                    "addr",
                    "add",
                    &format!("{}/24", n.underlay),
                    "dev",
                    &n.veth_ns,
                ]),
                "underlay addr",
            );
            require_ok(
                &sudo(&["ip", "link", "set", &n.veth_host, "up"]),
                "veth host up",
            );
            require_ok(
                &n.netns_exec(&["ip", "link", "set", &n.veth_ns, "up"]),
                "veth ns up",
            );
            require_ok(&n.netns_exec(&["ip", "link", "set", "lo", "up"]), "lo up");
            // GRO/GSO/TSO 会让 wg-over-veth 握手静默失败；两端都要关。
            let offload = [
                "gro", "off", "gso", "off", "tso", "off", "rx", "off", "tx", "off", "sg", "off",
            ];
            let mut host_offload = vec!["ethtool", "-K", &n.veth_host];
            host_offload.extend_from_slice(&offload);
            let mut ns_offload = vec!["ethtool", "-K", &n.veth_ns];
            ns_offload.extend_from_slice(&offload);
            let _ = sudo(&host_offload);
            let _ = n.netns_exec(&ns_offload);
        }

        // --- wg 接口 + 地址
        for n in &nodes {
            let script = format!(
                "ip link add wg0 type wireguard && ip address add {}/24 dev wg0 && ip link set wg0 up",
                n.overlay
            );
            require_ok(&n.netns_bash(&script), "wg interface");
        }
        // 每个 netns 有自己的 net.ipv4.ip_forward，宿主的值不继承。
        require_ok(
            &hub.netns_exec(&["sysctl", "-w", "net.ipv4.ip_forward=1"]),
            "hub ip_forward",
        );

        // --- hub 的 wg 配置：private-key 先设，peer 分条设置
        let script = format!(
            "wg set wg0 listen-port {} private-key <(echo {})",
            hub.port, hub.private_key
        );
        require_ok(&hub.netns_bash(&script), "hub private key");
        for peer in &nodes[1..3] {
            // 只有 A 和 B——C 是未授权节点，hub 上没有它的 peer 条目。
            let script = format!(
                "wg set wg0 peer {} allowed-ips {}/32",
                peer.public_key, peer.overlay
            );
            require_ok(&hub.netns_bash(&script), "hub peer");
        }

        // --- 客户端的 wg 配置
        for n in &nodes[1..] {
            let script = format!(
                "wg set wg0 listen-port {} private-key <(echo {})",
                n.port, n.private_key
            );
            require_ok(&n.netns_bash(&script), "client private key");
            let script = format!(
                "wg set wg0 peer {} allowed-ips {OVERLAY_CIDR} endpoint {}:{} persistent-keepalive 2",
                hub.public_key, hub.underlay, hub.port
            );
            require_ok(&n.netns_bash(&script), "client peer");
        }

        Some(Topology {
            guard,
            nodes,
            keys_dir,
        })
    }

    /// 等某个节点看到「latest handshake」；超时返回 false。
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

    fn hub_peers(&self) -> String {
        self.nodes[0].wg_show()
    }

    /// 握手失败时把四个节点的 `wg show wg0` 全打出来，便于定位。
    fn dump_all(&self) {
        for n in &self.nodes {
            eprintln!("--- wg show wg0 in {} ---", n.netns);
            eprintln!("{}", n.wg_show());
        }
    }
}

#[test]
fn wg_hub_forwarding() {
    let topo = match Topology::setup() {
        Some(t) => t,
        None => return, // 已打印 SKIP:
    };

    let [hub, a, b, c] = topo.nodes.as_slice() else {
        panic!("expected 4 nodes, got {}", topo.nodes.len());
    };

    for node in [a, b] {
        if !topo.wait_handshake(&node.netns) {
            topo.dump_all();
            panic!("wireguard handshake did not complete within {HANDSHAKE_TIMEOUT:?}");
        }
    }

    // 1. A -> B 经 hub 转发可达。
    assert!(
        topo.ping(&a.netns, &b.overlay),
        "A -> B must reach through the hub"
    );
    // 2. B -> A 反向也通。
    assert!(
        topo.ping(&b.netns, &a.overlay),
        "B -> A must reach through the hub"
    );

    // 3. 未授权第三节点不可达，且 hub 上无其 peer 条目。
    assert!(
        !topo.ping(&c.netns, &a.overlay),
        "unauthorized C must not reach A"
    );
    assert!(
        !topo.ping(&c.netns, &b.overlay),
        "unauthorized C must not reach B"
    );
    let hub_peers = topo.hub_peers();
    assert!(
        !hub_peers.contains(&c.public_key),
        "hub must not have a peer entry for unauthorized C:\n{hub_peers}"
    );
    // C 在场不影响已授权节点的连通性。
    assert!(
        topo.ping(&a.netns, &b.overlay),
        "A -> B must still work while unauthorized C is present"
    );

    // 4. 撤销 A：hub 上移除 peer 后立刻失效。
    require_ok(
        &hub.netns_bash(&format!("wg set wg0 peer {} remove", a.public_key)),
        "revoke peer A",
    );
    assert!(
        !topo.ping(&a.netns, &b.overlay),
        "A -> B must fail after A is revoked on the hub"
    );
    assert!(
        !topo.ping(&b.netns, &a.overlay),
        "B -> A must fail after A is revoked on the hub"
    );
    let hub_peers = topo.hub_peers();
    assert!(
        !hub_peers.contains(&a.public_key),
        "hub must not list revoked peer A:\n{hub_peers}"
    );

    // teardown 并断言「跑完不留垃圾」。
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
