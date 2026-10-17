//! server → agent → 内核全链路集成测试：**双重叠 LAN 经控制面发布、经 agent
//! 交付、各自可达**（[ADR-006](../../docs/decisions/adr-006-alias-prefix-nat.md)
//! 旗舰场景的单条端到端证据，TODO #57①）。
//!
//! 此前该验收只有拆分证据：`alias_nat.rs`（后端执行层，双站点但无控制面）与
//! `agent_reconcile.rs`（agent 交付层，单站点且计划手工构造）。本测试把两半
//! 接成一条链：真实 axum 服务（真实 socket，netns 内可达）+ 真实 enroll/路由/
//! Alias/修订 apply + 四个 agent `tick()`（真实 HTTP 拉计划 → 对账 → 应用）
//! + 真实内核转发。
//!
//! 拓扑（6 netns，underlay `10.99.0.0/24` 桥接；host 桥地址 `10.99.0.250`
//! 承载服务端 HTTP；前缀 `mls`+pid，与 `mltw`/`mlta`/`mltb`/`mlg` 互不为前缀）：
//!
//! ```text
//!           ┌── HUB (server 数据面 wg0 = 10.240.0.1，underlay .10，listen 51830)
//!  bridge ──┼── G1  (网关 10.240.0.2，underlay .20) ── LAN1 192.168.1.0/24 (L1 = .5)
//!           ├── G2  (网关 10.240.0.3，underlay .30) ── LAN2 192.168.1.0/24 (L2 = .5)
//!           ├── A   (客户端 10.240.0.4，underlay .40)        ↑ 两个真实前缀完全重叠
//!           ├── H2  (net-B hub mlt2 = 10.242.0.1，underlay .50，listen 51830)
//!           └── B   (net-B 客户端，underlay .60)             ↑ overlay 完全不相交
//! ```
//!
//! 断言对应验收：
//! 1. **双重叠 LAN 各自可达**——A 分别经 `10.241.1.0/24`（→G1→L1）与
//!    `10.241.2.0/24`（→G2→L2）ping 0 丢，UDP echo 应答体携带站点名
//!    （`site1`/`site2`，重叠子网确实落到两个不同站点，不串线）；
//! 2. **hub 只按前缀转发、不做 NAT（§9.4）**——服务端 hub 计划里 Alias 前缀
//!    才进 hub 路由/AllowedIPs，真实前缀不进（重叠时两个 peer 的 AllowedIPs
//!    保持互斥，cryptkey 路由无歧义）；
//! 3. **证据回传闭环（§7.5/§12.4）**——设备视图里网关上报
//!    `nat_rules_present = true`、`nat_snat_rules_present = true`（内核实测
//!    受控 SNAT 在场，§8.2 模式判读）、客户端上报 MTU 大包探测 `1392`；
//! 4. **跨网络隔离（§18.2.12）**——net-B 是同一部署（同一 DB、同管理面）下
//!    的另一个 Network，`10.242.0.0/16` 与 net-A 完全不相交。B 与 net-B hub
//!    真实握手可达（排除「B 没起来」），但 A ping 不到 B；两侧期望计划的
//!    peer AllowedIPs 只含本网络 overlay，双方内核路由表里都没有对端网络的
//!    路由（TODO #68）。

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use meshlet_config::DataPlaneConfig;
use meshlet_network::linux::LinuxNetworkBackend;
use serde_json::{json, Value};

const PREFIX: &str = "mls";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(40);
const SERVER_BRIDGE_IP: &str = "10.99.0.250"; // host 侧桥地址：承载 HTTP
const HUB_UNDERLAY_IP: &str = "10.99.0.10"; // hub wg endpoint（agent hub_endpoint）
const HUB_LISTEN_PORT: u16 = 51830;
const OVERLAY: &str = "10.240.0.0/16";
// 第二个网络（跨网络隔离验收，§18.2.12）：overlay 与 net-A 完全不相交，
// 由第二个服务端实例接管 hub 数据面（同库同管理面，独立 hub 密钥与 netns）。
const OVERLAY_B: &str = "10.242.0.0/16";
const HUB_B_UNDERLAY_IP: &str = "10.99.0.50";
// net-B 的 hub overlay 地址 = 池内首个可用地址（IPAM 保留给 hub，ADR-004）。
const HUB_B_VIP: &str = "10.242.0.1";

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
            eprintln!("SKIP: python3 not installed");
            return None;
        }
    }
    Some(())
}

/// 清掉本前缀下历史残留（pid 后缀进程已死才删；并行测试的对象不动）。
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
    let out = Command::new("wg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write as _;
            c.stdin.as_mut().unwrap().write_all(private.as_bytes())?;
            c.wait_with_output()
        })
        .ok()?;
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
        for v in &self.veth {
            let _ = sudo(&["ip", "link", "del", v]);
        }
        if let Some(b) = &self.bridge {
            let _ = sudo(&["ip", "link", "del", b]);
        }
        for n in &self.netns {
            let _ = sudo(&["ip", "netns", "del", n]);
        }
    }
}

struct Topology {
    guard: Guard,
    hub: Node,
    g1: Node,
    g2: Node,
    a: Node,
    hub2: Node,
    b: Node,
    lan1: String,
    lan2: String,
}

fn offload_off(dev: &str) {
    let _ = sudo(&[
        "ethtool", "-K", dev, "gro", "off", "gso", "off", "tso", "off", "rx", "off", "tx", "off",
        "sg", "off",
    ]);
}

impl Topology {
    fn setup() -> Option<Topology> {
        prerequisites()?;
        preflight_cleanup();

        let mut keys = Vec::new();
        for _ in 0..6 {
            let private = match wg_genkey() {
                Some(k) => k,
                None => {
                    assert!(
                        std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
                        "required dataplane prerequisite failed"
                    );
                    eprintln!("SKIP: wg genkey failed");
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
                    eprintln!("SKIP: wg pubkey failed");
                    return None;
                }
            };
            keys.push((private, public));
        }

        let mut guard = Guard {
            netns: Vec::new(),
            veth: Vec::new(),
            bridge: None,
        };

        // HUB / G1 / G2 / A（net-A）+ H2 / B（net-B）：underlay 全在
        // 10.99.0.0/24 桥上，overlay 互不相交。
        let defs = [
            ("H", "10.99.0.10"),
            ("1", "10.99.0.20"),
            ("2", "10.99.0.30"),
            ("A", "10.99.0.40"),
            ("H2", "10.99.0.50"),
            ("B", "10.99.0.60"),
        ];
        let tag = tag();
        let mut nodes = Vec::new();
        for ((name, underlay), (private, public)) in defs.iter().zip(keys.iter()) {
            nodes.push(Node {
                netns: format!("{tag}{name}"),
                veth_host: format!("{tag}{name}0"),
                veth_ns: format!("{tag}{name}1"),
                underlay: underlay.to_string(),
                public_key: public.clone(),
                private_key: private.clone(),
            });
        }

        let bridge = format!("{tag}br0");
        guard.bridge = Some(bridge.clone());
        require_ok(
            &sudo(&["ip", "link", "add", &bridge, "type", "bridge"]),
            "bridge",
        );
        require_ok(&sudo(&["ip", "link", "set", &bridge, "up"]), "bridge up");
        // host 侧桥地址：服务端 HTTP 绑这里，netns 内 agent 经真实 socket 到达。
        require_ok(
            &sudo(&[
                "ip",
                "addr",
                "add",
                &format!("{SERVER_BRIDGE_IP}/24"),
                "dev",
                &bridge,
            ]),
            "bridge addr",
        );

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
            offload_off(&n.veth_host);
            offload_off(&n.veth_ns);
        }

        // 两个**真实前缀完全重叠**的站点 LAN（ADR-006 旗舰场景的前提）。
        let [hub, g1, g2, a, hub2, b] = nodes.try_into().ok()?;
        let (lan1, lan2) = (format!("{tag}L1"), format!("{tag}L2"));
        for (lan_netns, gw, suffix) in [(lan1.clone(), &g1, "1"), (lan2.clone(), &g2, "2")] {
            let (host_end, lan_end) = (format!("{tag}X{suffix}0"), format!("{tag}X{suffix}1"));
            guard.netns.push(lan_netns.clone());
            guard.veth.push(host_end.clone());
            require_ok(&sudo(&["ip", "netns", "add", &lan_netns]), "lan netns add");
            require_ok(
                &sudo(&[
                    "ip", "link", "add", &host_end, "type", "veth", "peer", "name", &lan_end,
                ]),
                "lan veth add",
            );
            require_ok(
                &sudo(&["ip", "link", "set", &host_end, "netns", &gw.netns]),
                "lan end -> gateway",
            );
            require_ok(
                &sudo(&["ip", "link", "set", &lan_end, "netns", &lan_netns]),
                "lan end -> lan host",
            );
            require_ok(
                &netns_exec(
                    &gw.netns,
                    &["ip", "addr", "add", "192.168.1.1/24", "dev", &host_end],
                ),
                "gateway lan addr",
            );
            require_ok(
                &netns_exec(
                    &lan_netns,
                    &["ip", "addr", "add", "192.168.1.5/24", "dev", &lan_end],
                ),
                "lan host addr",
            );
            require_ok(
                &netns_exec(&gw.netns, &["ip", "link", "set", &host_end, "up"]),
                "gw lan up",
            );
            require_ok(
                &netns_exec(&lan_netns, &["ip", "link", "set", &lan_end, "up"]),
                "lan host up",
            );
            require_ok(
                &netns_exec(&lan_netns, &["ip", "link", "set", "lo", "up"]),
                "lan lo up",
            );
            offload_off(&host_end);
            offload_off(&lan_end);
        }

        Some(Topology {
            guard,
            hub,
            g1,
            g2,
            a,
            hub2,
            b,
            lan1,
            lan2,
        })
    }

    fn wait_handshake(&self, ns: &str) -> bool {
        let start = Instant::now();
        while start.elapsed() < HANDSHAKE_TIMEOUT {
            let interface = if ns == self.hub2.netns { "mlt2" } else { "wg0" };
            let out = netns_exec(ns, &["wg", "show", interface]);
            if String::from_utf8_lossy(&out.stdout).contains("latest handshake") {
                return true;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        false
    }

    fn ping_within(&self, from: &str, to: &str, within: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < within {
            if netns_exec(from, &["ping", "-c", "3", "-W", "2", to])
                .status
                .success()
            {
                return true;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        false
    }
}

// ---------------------------------------------------------------- 服务端

/// 起一个真实 axum 服务（host 桥地址上的 ephemeral 端口），hub 数据面经注入
/// 的后端构造跑进 HUB netns。返回 base URL。
fn start_server(db: PathBuf, hub_key: PathBuf, hub_netns: String) -> String {
    let cfg = DataPlaneConfig {
        enabled: true,
        interface: "wg0".into(),
        listen_port: Some(HUB_LISTEN_PORT),
        private_key_file: Some(hub_key.to_string_lossy().to_string()),
    };
    let factory =
        meshlet_server::revision::hub_backend_factory_with(cfg.clone(), None, move || {
            LinuxNetworkBackend::new()
                .with_netns(&hub_netns)
                .with_sudo()
        });
    let listener = std::net::TcpListener::bind((SERVER_BRIDGE_IP, 0)).expect("bind bridge ip");
    listener
        .set_nonblocking(true)
        .expect("listener nonblocking for tokio");
    let port = listener.local_addr().unwrap().port();
    let db_url = format!("sqlite:{}", db.to_string_lossy());
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("server runtime");
        rt.block_on(async move {
            let pool = meshlet_server::store::connect(&db_url)
                .await
                .expect("store connect");
            // 走真实启动路径（§17.3）：从 DB 重建期望状态。两个服务端实例
            // 共库时，后启动的那个据此看到先启动的那个写入的网络与设备。
            let boot =
                meshlet_server::persist::load(&pool, meshlet_domain::PresenceThresholds::default())
                    .await
                    .expect("boot load");
            let state = Arc::new(
                meshlet_server::auth::AppState::new(
                    Arc::new(std::sync::Mutex::new(boot.mesh)),
                    meshlet_server::auth::AuthStore::new(pool.clone()),
                    meshlet_server::agent::AgentTokenStore::new(pool.clone()),
                    meshlet_server::api_token::ApiTokenStore::new(pool),
                    false,
                )
                .with_dataplane(cfg)
                .with_apply_backend(factory),
            );
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            axum::serve(listener, meshlet_server::router(state))
                .await
                .unwrap();
        });
    });
    format!("http://{SERVER_BRIDGE_IP}:{port}")
}

/// 等服务端开始应答（线程起来有一个窗口；任何 HTTP 状态都算「已应答」）。
fn wait_server_up(base: &str) {
    let start = Instant::now();
    loop {
        match ureq::get(&format!("{base}/api/v1/networks")).call() {
            Ok(_) | Err(ureq::Error::Status(_, _)) => return,
            Err(_) => {}
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "server did not come up"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// 管理 API 的 HTTP 调用（会话 Cookie + CSRF 头，§13.2）。
fn http_json(
    method: &str,
    url: &str,
    cookie: Option<&str>,
    bearer: Option<&str>,
    body: Option<Value>,
) -> (u16, Value) {
    let req = ureq::request(method, url)
        .set("content-type", "application/json")
        .set("x-requested-with", "XMLHttpRequest");
    let req = match cookie {
        Some(c) => req.set("cookie", c),
        None => req,
    };
    let req = match bearer {
        Some(b) => req.set("authorization", &format!("Bearer {b}")),
        None => req,
    };
    let res = match body {
        Some(v) => req.send_string(&v.to_string()),
        None => req.call(),
    };
    let (code, text) = match res {
        Ok(resp) => (resp.status(), resp.into_string().unwrap_or_default()),
        Err(ureq::Error::Status(code, resp)) => (code, resp.into_string().unwrap_or_default()),
        Err(e) => panic!("http {method} {url}: {e}"),
    };
    let value = serde_json::from_str(&text).unwrap_or(Value::Null);
    (code, value)
}

fn admin(base: &str, cookie: &str, method: &str, path: &str, body: Option<Value>) -> Value {
    let (code, value) = http_json(method, &format!("{base}{path}"), Some(cookie), None, body);
    assert!(
        (200..300).contains(&code),
        "{method} {path} -> {code}: {value}"
    );
    value
}

// ---------------------------------------------------------------- echo

/// UDP echo 服务端：应答 `{site} seen={客户端看到的源}`（alias_nat.rs 同款）。
const ECHO_PY: &str = "\
import socket, sys
port, site = int(sys.argv[1]), sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', port))
s.settimeout(15)
data, addr = s.recvfrom(2048)
s.sendto(f'{site} seen={addr[0]}'.encode(), addr)
";

/// UDP 发送端：带重试（等 echo 服务起），打印应答源与应答体。
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

/// 客户端 A 打 `alias`，站点 netns 起一次性 echo；返回应答体。
fn udp_echo(
    topo: &Topology,
    script_dir: &Path,
    lan_netns: &str,
    site: &str,
    alias: &str,
    port: u16,
) -> String {
    let echo_py = script_dir.join("echo.py");
    let send_py = script_dir.join("send.py");
    let mut server = Command::new("sudo")
        .arg("-n")
        .args(["ip", "netns", "exec", lan_netns, "python3"])
        .arg(&echo_py)
        .arg(port.to_string())
        .arg(site)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn echo server");
    let out = netns_exec(
        &topo.a.netns,
        &[
            "python3",
            &send_py.to_string_lossy(),
            alias,
            &port.to_string(),
        ],
    );
    let _ = server.wait();
    assert!(
        out.status.success(),
        "udp echo to {alias}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

// ---------------------------------------------------------------- 测试

#[test]
fn dual_same_prefix_lans_published_via_the_control_plane_reach_their_sites() {
    let topo = match Topology::setup() {
        Some(t) => t,
        None => return, // 已打印 SKIP:
    };
    // 清场对象已登记（Guard 持有 bridge / veth / netns 名单）。
    assert!(topo.guard.bridge.is_some(), "bridge recorded for cleanup");

    // ---- 服务端（真实 socket + hub 数据面进 HUB netns） -------------------
    let dir = std::env::temp_dir().join(format!("meshlet-dual-site-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let hub_key_path = dir.join("hub.key");
    std::fs::write(
        &hub_key_path,
        format!("{}\n", wg_genkey().expect("hub key")),
    )
    .unwrap();
    let echo_py = dir.join("echo.py");
    std::fs::write(&echo_py, ECHO_PY).unwrap();
    let send_py = dir.join("send.py");
    std::fs::write(&send_py, SEND_PY).unwrap();

    let base = start_server(
        dir.join("db.sqlite3"),
        hub_key_path.clone(),
        topo.hub.netns.clone(),
    );
    wait_server_up(&base);

    // bootstrap 首管理员（拿会话 Cookie）。
    let res = ureq::post(&format!("{base}/api/v1/auth/bootstrap"))
        .set("content-type", "application/json")
        .send_string(
            &json!({"email": "admin@e2e.local", "password": "e2e-password-123"}).to_string(),
        );
    let cookie = match res {
        Ok(resp) => resp
            .all("set-cookie")
            .iter()
            .find_map(|v| v.split(';').next().map(|s| s.to_string()))
            .expect("session cookie"),
        Err(ureq::Error::Status(409, _)) => login_cookie(&base),
        Err(e) => panic!("bootstrap: {e}"),
    };

    // 建网 + 邀请 + 三台设备（真实 wg 公钥）。
    let net = admin(
        &base,
        &cookie,
        "POST",
        "/api/v1/networks",
        Some(json!({
            "name": "dual",
            "overlay_cidr": OVERLAY,
        })),
    );
    let network_id = net["id"].as_str().unwrap().to_string();
    let invite = admin(
        &base,
        &cookie,
        "POST",
        &format!("/api/v1/networks/{network_id}/invites"),
        Some(json!({"max_uses": 3})),
    );
    let invite_token = invite["token"].as_str().unwrap().to_string();

    let mut tokens = Vec::new();
    for (name, node) in [("gw1", &topo.g1), ("gw2", &topo.g2), ("laptop-a", &topo.a)] {
        let (code, device) = http_json(
            "POST",
            &format!("{base}/api/v1/enroll"),
            None,
            None,
            Some(json!({
                "invite_token": invite_token,
                "device_name": name,
                "public_key": node.public_key,
                "platform": "linux",
            })),
        );
        assert_eq!(code, 201, "enroll {name}: {device}");
        tokens.push((
            device["device_id"].as_str().unwrap().to_string(),
            device["agent_token"].as_str().unwrap().to_string(),
        ));
    }
    let (g1_id, g1_token) = tokens[0].clone();
    let (g2_id, g2_token) = tokens[1].clone();
    let (_a_id, a_token) = tokens[2].clone();

    // ---- 网络 B（overlay 与 A 完全不相交，跨网络隔离验收 §18.2.12）--------
    // net-B 是**另一个 hub**：本模型里 hub 数据面归服务端管理（设备计划里 hub
    // 是唯一 peer，hub 私钥只在服务端 `private_key_file`，ADR-010），所以
    // net-B 的 hub 由第二个服务端实例接管（见下）。hub 自身**不作为设备
    // 入网**——hub 的 overlay 地址由 IPAM 预留（`hub_plan` 取 `hub_address`），
    // 与 net-A 的 hub 同一形态。
    let net_b = admin(
        &base,
        &cookie,
        "POST",
        "/api/v1/networks",
        Some(json!({"name": "dual-b", "overlay_cidr": OVERLAY_B})),
    );
    let network_b_id = net_b["id"].as_str().unwrap().to_string();
    let invite_b = admin(
        &base,
        &cookie,
        "POST",
        &format!("/api/v1/networks/{network_b_id}/invites"),
        Some(json!({"max_uses": 1})),
    );
    let invite_token_b = invite_b["token"].as_str().unwrap().to_string();

    let (code, device_b) = http_json(
        "POST",
        &format!("{base}/api/v1/enroll"),
        None,
        None,
        Some(json!({
            "invite_token": invite_token_b,
            "device_name": "laptop-b",
            "public_key": topo.b.public_key,
            "platform": "linux",
        })),
    );
    assert_eq!(code, 201, "enroll net-b laptop-b: {device_b}");
    let b_token = device_b["agent_token"].as_str().unwrap().to_string();
    let b_vip = device_b["virtual_ipv4"].as_str().unwrap().to_string();

    // ---- net-B 的 hub 数据面：第二个服务端实例 ----------------------------
    // 与 net-A 同库、同管理面（一个部署管两个网络），但 hub 后端注入 H2
    // netns、hub 私钥独立（`private_key_file` 指向 H2 的真实密钥）。启动走
    // 真实 boot 路径 `persist::load`，所以它能看到先前经 `base` 写入的
    // net-B 设备（§17.3）。
    let hub_b_key_path = dir.join("hub-b.key");
    std::fs::write(&hub_b_key_path, format!("{}\n", topo.hub2.private_key)).unwrap();
    let base_b = start_server(
        dir.join("db.sqlite3"),
        hub_b_key_path,
        topo.hub2.netns.clone(),
    );
    wait_server_up(&base_b);

    // net-B uses the network-specific mlt2 interface and base port + 1, even
    // though this historical topology still places it in its own namespace.
    let revisions_b = admin(
        &base_b,
        &cookie,
        "GET",
        &format!("/api/v1/networks/{network_b_id}/config-revisions"),
        None,
    );
    let latest_b = revisions_b.as_array().unwrap().last().unwrap()["revision"]
        .as_u64()
        .unwrap();
    let applied_b = admin(
        &base_b,
        &cookie,
        "POST",
        &format!("/api/v1/networks/{network_b_id}/config-revisions/{latest_b}/apply"),
        Some(json!({})),
    );
    assert_eq!(
        applied_b["apply_status"], "applied",
        "hub-b apply: {applied_b}"
    );

    // 控制面发布：两条 **alias 模式** 路由，真实前缀完全重叠（ADR-006 例外）。
    let routes_uri = format!("/api/v1/networks/{network_id}/routes");
    let aliases_uri = format!("/api/v1/networks/{network_id}/aliases");
    let mut route_ids = Vec::new();
    for (name, gateway, alias_cidr) in [
        ("gw1", g1_id.as_str(), "10.241.1.0/24"),
        ("gw2", g2_id.as_str(), "10.241.2.0/24"),
    ] {
        let (code, route) = http_json(
            "POST",
            &format!("{base}{routes_uri}"),
            Some(&cookie),
            None,
            Some(json!({
                "gateway_device_id": gateway,
                "destination_cidr": "192.168.1.0/24",
                "return_path_mode": "controlled_snat",
                "route_mode": "alias",
            })),
        );
        assert_eq!(code, 201, "route for {name}: {route}");
        let route_id = route["id"].as_str().unwrap().to_string();
        let (code, alias) = http_json(
            "POST",
            &format!("{base}{aliases_uri}"),
            Some(&cookie),
            None,
            Some(json!({
                "lan_route_id": route_id,
                "alias_cidr": alias_cidr,
                "translation_mode": "dnat_snat",
            })),
        );
        assert_eq!(code, 201, "alias for {name}: {alias}");
        route_ids.push(route_id);
    }
    assert_ne!(route_ids[0], route_ids[1], "each site keeps its own route");

    // apply 最新修订：hub 侧计划经注入后端真实下发到 HUB netns。
    let revisions = admin(
        &base,
        &cookie,
        "GET",
        &format!("/api/v1/networks/{network_id}/config-revisions"),
        None,
    );
    let latest = revisions.as_array().unwrap().last().unwrap()["revision"]
        .as_u64()
        .unwrap();
    let applied = admin(
        &base,
        &cookie,
        "POST",
        &format!("/api/v1/networks/{network_id}/config-revisions/{latest}/apply"),
        Some(json!({})),
    );
    assert_eq!(applied["apply_status"], "applied", "hub apply: {applied}");

    // ---- 四个 agent：真实 HTTP 拉计划 → 对账 → 应用 → 心跳 ----------------
    let hub_endpoint = format!("{HUB_UNDERLAY_IP}:{HUB_LISTEN_PORT}");
    for (node, token, name) in [
        (&topo.g1, g1_token.as_str(), "g1"),
        (&topo.g2, g2_token.as_str(), "g2"),
        (&topo.a, a_token.as_str(), "a"),
    ] {
        tick_agent(&dir, &base, name, node, token, Some(&hub_endpoint));
    }
    // net-B 的客户端：必须向 `base_b` 拉计划——计划里唯一 peer 的公钥取自
    // 服务端实例自身的 `private_key_file`（`hub_public_key`），`base` 的密钥
    // 文件指向 net-A 的 hub，用它下发 net-B 计划会让客户端握不上 hand。
    // hub 入口另指 net-B 的 hub underlay 地址。
    let hub_b_endpoint = format!("{HUB_B_UNDERLAY_IP}:{HUB_LISTEN_PORT}");
    tick_agent(
        &dir,
        &base_b,
        "laptop-b",
        &topo.b,
        b_token.as_str(),
        Some(&hub_b_endpoint),
    );

    // ---- 握手（两网络各自成链）-------------------------------------------
    for ns in [
        &topo.g1.netns,
        &topo.g2.netns,
        &topo.a.netns,
        &topo.hub2.netns,
        &topo.b.netns,
    ] {
        assert!(
            topo.wait_handshake(ns),
            "handshake did not complete in {ns}"
        );
    }

    // ---- 验收①：双重叠 LAN 各自可达（ping + 站点名不串线） ---------------
    assert!(
        topo.ping_within(&topo.a.netns, "10.241.1.5", HANDSHAKE_TIMEOUT),
        "A -> site1 via alias 10.241.1.5"
    );
    assert!(
        topo.ping_within(&topo.a.netns, "10.241.2.5", HANDSHAKE_TIMEOUT),
        "A -> site2 via alias 10.241.2.5"
    );

    let reply1 = udp_echo(&topo, &dir, &topo.lan1, "site1", "10.241.1.5", 7701);
    assert!(
        reply1.contains("site1"),
        "alias1 must land at site1 (overlap must not cross-wire): {reply1}"
    );
    let reply2 = udp_echo(&topo, &dir, &topo.lan2, "site2", "10.241.2.5", 7702);
    assert!(
        reply2.contains("site2"),
        "alias2 must land at site2: {reply2}"
    );
    // dnat_snat（§9.5 模式 B）：LAN 主机看到的源是网关自身 LAN 地址。
    assert!(
        reply1.contains("seen=192.168.1.1"),
        "controlled snat rewrites the source to the gateway lan addr: {reply1}"
    );
    assert!(
        reply2.contains("seen=192.168.1.1"),
        "site2 gateway lan addr expected: {reply2}"
    );

    // ---- 验收③：证据回传闭环（设备视图读到内核实测） ---------------------
    // 手工再跑一轮心跳（此刻握手已建立，探测才会成功）。
    for (node, token, name) in [
        (&topo.g1, g1_token.as_str(), "g1"),
        (&topo.g2, g2_token.as_str(), "g2"),
        (&topo.a, a_token.as_str(), "a"),
    ] {
        tick_agent(&dir, &base, name, node, token, Some(&hub_endpoint));
    }

    let devices = admin(
        &base,
        &cookie,
        "GET",
        &format!("/api/v1/networks/{network_id}/devices"),
        None,
    );
    let devices = devices.as_array().unwrap();
    let evidence_of = |name: &str| {
        devices
            .iter()
            .find(|d| d["name"] == name)
            .unwrap_or_else(|| panic!("device {name} in view: {devices:?}"))["dataplane_evidence"]
            .clone()
    };
    for name in ["gw1", "gw2"] {
        let ev = evidence_of(name);
        assert_eq!(
            ev["nat_rules_present"], true,
            "gateway {name} must report its meshlet nat rules: {ev}"
        );
        assert_eq!(
            ev["nat_snat_rules_present"], true,
            "gateway {name} runs dnat_snat: controlled snat rule kernel-verified: {ev}"
        );
    }
    let ev = evidence_of("laptop-a");
    assert_eq!(
        ev["mtu_probe_payload"], 1392,
        "client must report the large-packet probe (1420 default mtu - 28): {ev}"
    );
    assert_eq!(ev["tunnel_mtu"], 1420, "kernel mtu reading: {ev}");

    // ---- 验收④：跨网络隔离（§18.2.12）------------------------------------
    // net-B 自身是活的（B ↔ net-B hub 可达），所以 A → B 的失败只能归因于
    // 隔离，而不是 B 没起来。
    assert!(
        topo.ping_within(&topo.b.netns, HUB_B_VIP, HANDSHAKE_TIMEOUT),
        "net-b must be alive: laptop-b -> net-b hub"
    );
    assert!(
        !topo.ping_within(&topo.a.netns, &b_vip, Duration::from_secs(10)),
        "net-a device must not reach net-b device (isolation)"
    );
    // 结构性根因：期望计划里 peer AllowedIPs 只含本网络 overlay——A 的计划
    // 不含 10.242、B 的计划不含 10.240，隧道里根本没有对端网络的路由。
    let plan_of = |base: &str, token: &str| -> Value {
        let (code, v) = http_json(
            "GET",
            &format!("{base}/api/v1/agent/device/desired"),
            None,
            Some(token),
            None,
        );
        assert!(code < 300, "desired plan fetch -> {code}: {v}");
        v
    };
    let a_plan = plan_of(&base, &a_token);
    let b_plan = plan_of(&base_b, &b_token);
    // 正向锚点：计划确实带本网络 overlay，否则「不含对端网络」是空断言。
    assert!(
        a_plan.to_string().contains("10.240.0.0/16"),
        "net-a plan carries its own overlay: {a_plan}"
    );
    assert!(
        b_plan.to_string().contains("10.242.0.0/16"),
        "net-b plan carries its own overlay: {b_plan}"
    );
    assert!(
        !a_plan.to_string().contains("10.242"),
        "net-a plan must not carry net-b's overlay: {a_plan}"
    );
    assert!(
        !b_plan.to_string().contains("10.240"),
        "net-b plan must not carry net-a's overlay: {b_plan}"
    );
    // 内核路由表同样没有对端网络的路由（双保险，不只在计划层）。
    let routes_in = |ns: &str| -> String {
        let out = netns_exec(ns, &["ip", "route"]);
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    assert!(
        routes_in(&topo.a.netns).contains("10.240.0.0/16"),
        "net-a kernel route carries its own overlay: {}",
        routes_in(&topo.a.netns)
    );
    assert!(
        routes_in(&topo.b.netns).contains("10.242.0.0/16"),
        "net-b kernel route carries its own overlay: {}",
        routes_in(&topo.b.netns)
    );
    assert!(
        !routes_in(&topo.a.netns).contains("10.242"),
        "net-a kernel routes must not reach net-b: {}",
        routes_in(&topo.a.netns)
    );
    assert!(
        !routes_in(&topo.b.netns).contains("10.240"),
        "net-b kernel routes must not reach net-a: {}",
        routes_in(&topo.b.netns)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// 构造一个真实 socket 连服务端、netns 内下数据的 agent 并跑一轮 tick
/// （拉计划 → 对账 → 应用 → 心跳）。`hub_endpoint` 为客户端侧 hub 端点
/// 兜底（服务端计划不带端点）；hub 设备自身为 `None`。
fn tick_agent(
    dir: &std::path::Path,
    base: &str,
    name: &str,
    node: &Node,
    token: &str,
    hub_endpoint: Option<&str>,
) {
    let config = meshlet_config::AgentConfig {
        server_url: base.to_string(),
        state_dir: dir
            .join(format!("agent-{name}"))
            .to_string_lossy()
            .to_string(),
        device_token: Some(token.to_string()),
        bootstrap_token: None,
        device_name: None,
        tray: meshlet_config::TrayConfig::OFF,
        dataplane: meshlet_config::DataplaneConfig {
            enabled: true,
            hub_endpoint: hub_endpoint.map(str::to_string),
            ..meshlet_config::DataplaneConfig::default()
        },
    };
    let backend = LinuxNetworkBackend::new()
        .with_netns(&node.netns)
        .with_sudo()
        .with_interface("wg0");
    let agent = meshlet_agent::Agent::with_backend(config, Some(node.private_key.clone()), backend);
    agent
        .tick()
        .unwrap_or_else(|e| panic!("agent {name} tick: {e}"));
}

/// 登录拿会话 Cookie（bootstrap 409 后的兜底路径）。
fn login_cookie(base: &str) -> String {
    let res = ureq::post(&format!("{base}/api/v1/auth/login"))
        .set("content-type", "application/json")
        .send_string(
            &json!({"email": "admin@e2e.local", "password": "e2e-password-123"}).to_string(),
        )
        .expect("login");
    res.all("set-cookie")
        .iter()
        .find_map(|v| v.split(';').next().map(|s| s.to_string()))
        .expect("login cookie")
}
