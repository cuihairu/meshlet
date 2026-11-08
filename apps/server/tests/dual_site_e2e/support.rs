//! Shared process, topology, server, and packet helpers for cross-site e2e tests.
//!
//! ```text
//!           ┌── HUB (server 数据面 wg0 = 10.240.0.1，underlay .10，listen 51830)
//!  bridge ──┼── G1  (网关 10.240.0.2，underlay .20) ── LAN1 192.168.1.0/24 (L1 = .5)
//!           ├── G2  (网关 10.240.0.3，underlay .30) ── LAN2 192.168.1.0/24 (L2 = .5)
//!           ├── A   (客户端 10.240.0.4，underlay .40) ── LOCAL 192.168.1.0/24 (L0 = .5)
//!           ├── H2  (net-B hub mlt2 = 10.242.0.1，underlay .50，listen 51830)
//!           └── B   (net-B 客户端，underlay .60)             ↑ overlay 完全不相交
//! ```
//!
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use meshlet_config::DataPlaneConfig;
use meshlet_network::linux::LinuxNetworkBackend;
use serde_json::{json, Value};

pub(crate) const PREFIX: &str = "mls";
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(40);
pub(crate) const SERVER_BRIDGE_IP: &str = "10.99.0.250"; // host 侧桥地址：承载 HTTP
pub(crate) const HUB_UNDERLAY_IP: &str = "10.99.0.10"; // hub wg endpoint（agent hub_endpoint）
pub(crate) const HUB_LISTEN_PORT: u16 = 51830;
pub(crate) const OVERLAY: &str = "10.240.0.0/16";
// 第二个网络（跨网络隔离验收，§18.2.12）：overlay 与 net-A 完全不相交，
// 由第二个服务端实例接管 hub 数据面（同库同管理面，独立 hub 密钥与 netns）。
pub(crate) const OVERLAY_B: &str = "10.242.0.0/16";
pub(crate) const HUB_B_UNDERLAY_IP: &str = "10.99.0.50";
// net-B 的 hub overlay 地址 = 池内首个可用地址（IPAM 保留给 hub，ADR-004）。
pub(crate) const HUB_B_VIP: &str = "10.242.0.1";

pub(crate) fn tag() -> String {
    format!("{PREFIX}{}", std::process::id())
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
    match Command::new("tcpdump").arg("--version").output() {
        Ok(o) if o.status.success() => {}
        _ => {
            assert!(
                std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
                "required dataplane prerequisite failed"
            );
            eprintln!("SKIP: tcpdump not installed");
            return None;
        }
    }
    Some(())
}

/// 清掉本前缀下历史残留（pid 后缀进程已死才删；并行测试的对象不动）。
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

pub(crate) fn owner_alive(name: &str) -> bool {
    let tail = &name[PREFIX.len()..];
    let pid: String = tail.chars().take_while(char::is_ascii_digit).collect();
    if pid.is_empty() {
        return false;
    }
    Path::new("/proc").join(pid).exists()
}

pub(crate) fn kernel_routes(ns: &str) -> String {
    let out = netns_exec(ns, &["ip", "route"]);
    require_ok(&out, "ip route");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

pub(crate) fn iptables_save(ns: &str) -> String {
    let out = netns_exec(ns, &["iptables-save"]);
    require_ok(&out, "iptables-save");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

pub(crate) fn policy_rules(ns: &str) -> String {
    let out = netns_exec(ns, &["ip", "rule"]);
    require_ok(&out, "ip rule");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

pub(crate) fn managed_iptables(ns: &str) -> Vec<String> {
    iptables_save(ns)
        .lines()
        .filter(|line| line.starts_with("-A "))
        .map(str::to_string)
        .collect()
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

pub(crate) struct Node {
    pub(crate) netns: String,
    pub(crate) veth_host: String,
    pub(crate) veth_ns: String,
    pub(crate) underlay: String,
    pub(crate) public_key: String,
    pub(crate) private_key: String,
}

pub(crate) struct Guard {
    pub(crate) netns: Vec<String>,
    pub(crate) veth: Vec<String>,
    pub(crate) bridge: Option<String>,
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

pub(crate) struct Topology {
    pub(crate) guard: Guard,
    pub(crate) hub: Node,
    pub(crate) g1: Node,
    pub(crate) g2: Node,
    pub(crate) a: Node,
    pub(crate) hub2: Node,
    pub(crate) b: Node,
    pub(crate) lan1: String,
    pub(crate) lan2: String,
    pub(crate) local_lan: String,
}

pub(crate) fn offload_off(dev: &str) {
    let _ = sudo(&[
        "ethtool", "-K", dev, "gro", "off", "gso", "off", "tso", "off", "rx", "off", "tx", "off",
        "sg", "off",
    ]);
}

impl Topology {
    pub(crate) fn setup() -> Option<Topology> {
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

        let (local_host_end, local_lan_end) = (format!("{tag}XA0"), format!("{tag}XA1"));
        let local_lan = format!("{tag}L0");
        guard.netns.push(local_lan.clone());
        guard.veth.push(local_host_end.clone());
        require_ok(
            &sudo(&["ip", "netns", "add", &local_lan]),
            "client lan netns add",
        );
        require_ok(
            &sudo(&[
                "ip",
                "link",
                "add",
                &local_host_end,
                "type",
                "veth",
                "peer",
                "name",
                &local_lan_end,
            ]),
            "client lan veth add",
        );
        require_ok(
            &sudo(&["ip", "link", "set", &local_host_end, "netns", &a.netns]),
            "client lan end -> client",
        );
        require_ok(
            &sudo(&["ip", "link", "set", &local_lan_end, "netns", &local_lan]),
            "client lan host end -> lan",
        );
        require_ok(
            &netns_exec(
                &a.netns,
                &[
                    "ip",
                    "addr",
                    "add",
                    "192.168.1.1/24",
                    "dev",
                    &local_host_end,
                ],
            ),
            "client lan addr",
        );
        require_ok(
            &netns_exec(
                &local_lan,
                &["ip", "addr", "add", "192.168.1.5/24", "dev", &local_lan_end],
            ),
            "client lan host addr",
        );
        require_ok(
            &netns_exec(&a.netns, &["ip", "link", "set", &local_host_end, "up"]),
            "client lan up",
        );
        require_ok(
            &netns_exec(&local_lan, &["ip", "link", "set", &local_lan_end, "up"]),
            "client lan host up",
        );
        require_ok(
            &netns_exec(&local_lan, &["ip", "link", "set", "lo", "up"]),
            "client lan lo up",
        );
        offload_off(&local_host_end);
        offload_off(&local_lan_end);

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
            local_lan,
        })
    }

    pub(crate) fn wait_handshake(&self, ns: &str) -> bool {
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

    pub(crate) fn ping_within(&self, from: &str, to: &str, within: Duration) -> bool {
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

pub(crate) fn start_stoppable_server(
    db: PathBuf,
    hub_key: PathBuf,
    hub_netns: String,
) -> (String, ServerHandle) {
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
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let thread = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("server runtime");
        rt.block_on(async move {
            let pool = meshlet_server::store::connect(&db_url)
                .await
                .expect("store connect");
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
            // §12：heartbeat 观测直连源地址（与 main.rs 的 serve 装配一致）。
            let result = axum::serve(
                listener,
                meshlet_server::router(state)
                    .into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
            if let Err(error) = result {
                eprintln!("test server stopped: {error}");
            }
        });
    });
    (
        format!("http://{SERVER_BRIDGE_IP}:{port}"),
        ServerHandle {
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        },
    )
}

pub(crate) struct ServerHandle {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl ServerHandle {
    pub(crate) fn stop(mut self) {
        if let Some(sender) = self.shutdown.take() {
            let _ = sender.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().expect("join server");
        }
    }
}

/// 等服务端开始应答（线程起来有一个窗口；任何 HTTP 状态都算「已应答」）。
pub(crate) fn wait_server_up(base: &str) {
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
pub(crate) fn http_json(
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

pub(crate) fn admin(
    base: &str,
    cookie: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Value {
    let (code, value) = http_json(method, &format!("{base}{path}"), Some(cookie), None, body);
    assert!(
        (200..300).contains(&code),
        "{method} {path} -> {code}: {value}"
    );
    value
}

// ---------------------------------------------------------------- echo

/// UDP echo 服务端：应答 `{site} seen={客户端看到的源}`（alias_nat.rs 同款）。
pub(crate) const ECHO_PY: &str = "\
import socket, sys
port, site = int(sys.argv[1]), sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', port))
s.settimeout(15)
data, addr = s.recvfrom(2048)
s.sendto(f'{site} seen={addr[0]}'.encode(), addr)
";

/// TCP echo server: replies `{site} seen={source}` and logs the 5-tuple.
pub(crate) const TCP_ECHO_PY: &str = r#"
import socket, sys
from pathlib import Path
port, site, ready_path = int(sys.argv[1]), sys.argv[2], sys.argv[3]
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0', port))
s.listen(5)
Path(ready_path).touch()
s.settimeout(15)
conn, peer = s.accept()
data = conn.recv(2048)
local = conn.getsockname()
print(f'{site} seen={peer[0]} tuple={peer[0]}:{peer[1]}->{local[0]}:{local[1]} tcp')
conn.sendall(f'{site} seen={peer[0]} tuple={peer[0]}:{peer[1]}->{local[0]}:{local[1]} tcp'.encode())
conn.close()
"#;

/// TCP client: sends a marker, returns the site identity and observed tuple.
pub(crate) const TCP_SEND_PY: &str = r#"
import socket, sys
target, port = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((target, port), timeout=3)
s.settimeout(3)
s.sendall(b'tcp-probe')
print(s.recv(2048).decode())
s.close()
"#;

/// UDP 发送端：带重试（等 echo 服务起），打印应答源与应答体。
pub(crate) const SEND_PY: &str = "\
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
pub(crate) fn udp_echo(
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

pub(crate) fn local_udp_echo(
    topo: &Topology,
    script_dir: &Path,
    target: &str,
    port: u16,
) -> String {
    let echo_py = script_dir.join("echo.py");
    let send_py = script_dir.join("send.py");
    let mut server = Command::new("sudo")
        .arg("-n")
        .args(["ip", "netns", "exec", &topo.local_lan, "python3"])
        .arg(&echo_py)
        .arg(port.to_string())
        .arg("local")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn local echo server");
    let out = netns_exec(
        &topo.a.netns,
        &[
            "python3",
            &send_py.to_string_lossy(),
            target,
            &port.to_string(),
        ],
    );
    let _ = server.wait();
    assert!(
        out.status.success(),
        "local udp echo to {target}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

pub(crate) fn tcp_echo(
    topo: &Topology,
    script_dir: &Path,
    source_ns: &str,
    target: &str,
    site: &str,
    port: u16,
) -> String {
    let echo_py = script_dir.join("tcp-echo.py");
    let send_py = script_dir.join("tcp-send.py");
    let ready_path = script_dir.join(format!("tcp-{port}.ready"));
    let _ = std::fs::remove_file(&ready_path);
    let server_ns = if site == "local" {
        &topo.local_lan
    } else {
        source_ns
    };
    let server = Command::new("sudo")
        .arg("-n")
        .args(["ip", "netns", "exec", server_ns, "python3"])
        .arg(&echo_py)
        .arg(port.to_string())
        .arg(site)
        .arg(&ready_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tcp echo server");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !ready_path.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "tcp echo server did not become ready on port {port}"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let out = netns_exec(
        &topo.a.netns,
        &[
            "python3",
            &send_py.to_string_lossy(),
            target,
            &port.to_string(),
        ],
    );
    let server_output = server.wait_with_output().expect("tcp echo server output");
    assert!(
        out.status.success() && server_output.status.success(),
        "tcp echo to {target}: client={} server={} client_error={} server_error={}",
        out.status,
        server_output.status,
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&server_output.stderr),
    );
    let reply = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let server_tuple = String::from_utf8_lossy(&server_output.stdout)
        .trim()
        .to_string();
    assert!(
        reply.contains(site),
        "tcp reply must identify {site}: {reply}"
    );
    assert!(
        reply == server_tuple,
        "client and server must record the same TCP tuple: reply={reply}, server={server_tuple}"
    );
    reply
}

pub(crate) fn capture_packet(
    topo: &Topology,
    script_dir: &Path,
    netns: &str,
    interface: &str,
    filter: &str,
    target: &str,
    port: u16,
) -> String {
    let capture = script_dir.join("capture.out");
    let _ = std::fs::remove_file(&capture);
    let server_ns = if target.starts_with("10.241.1.") {
        &topo.lan1
    } else if target.starts_with("10.241.2.") {
        &topo.lan2
    } else {
        &topo.local_lan
    };
    let echo_py = script_dir.join("tcp-echo.py");
    let ready_path = script_dir.join(format!("tcp-{port}.ready"));
    let _ = std::fs::remove_file(&ready_path);
    let mut server = Command::new("sudo")
        .arg("-n")
        .args(["ip", "netns", "exec", server_ns, "python3"])
        .arg(&echo_py)
        .arg(port.to_string())
        .arg("capture")
        .arg(&ready_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn capture echo server");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !ready_path.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "capture tcp echo server did not become ready on port {port}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut tcpdump = Command::new("sudo")
        .arg("-n")
        .args([
            "ip", "netns", "exec", netns, "tcpdump", "-l", "-c", "1", "-i", interface, filter,
        ])
        .stdout(Stdio::from(
            std::fs::File::create(&capture).expect("create capture output"),
        ))
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn tcpdump");
    std::thread::sleep(Duration::from_millis(250));
    let send_py = script_dir.join("tcp-send.py");
    let probe = netns_exec(
        netns,
        &[
            "python3",
            &send_py.to_string_lossy(),
            target,
            &port.to_string(),
        ],
    );
    let status = tcpdump.wait().expect("wait tcpdump");
    let probe_status = probe.status;
    let _ = server.wait();
    let output = std::fs::read_to_string(&capture).unwrap_or_default();
    assert!(probe_status.success(), "tcp probe for capture failed");
    assert!(status.success(), "tcpdump exited unsuccessfully");
    assert!(
        output.contains(target) && output.contains(&port.to_string()),
        "capture did not contain the requested TCP 5-tuple: {output}"
    );
    output
}

/// 构造一个真实 socket 连服务端、netns 内下数据的 agent 并跑一轮 tick
/// （拉计划 → 对账 → 应用 → 心跳）。`hub_endpoint` 为客户端侧 hub 端点
/// 兜底（服务端计划不带端点）；hub 设备自身为 `None`。
pub(crate) fn tick_agent(
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
        upgrade: meshlet_config::AgentConfig::default().upgrade,
        dataplane: meshlet_config::DataplaneConfig {
            enabled: true,
            hub_endpoint: hub_endpoint.map(str::to_string),
            direct_connect: meshlet_config::DirectConnectConfig {
                enabled: false,
                ..meshlet_config::DirectConnectConfig::default()
            },
            ..meshlet_config::DataplaneConfig::default()
        },
        ssh_config_sync: meshlet_config::SshConfigSyncConfig::OFF,
        mcp: meshlet_config::McpConfig::default(),
    };
    let backend = LinuxNetworkBackend::new()
        .with_netns(&node.netns)
        .with_sudo()
        .with_interface("wg0");
    let mut agent =
        meshlet_agent::Agent::with_backend(config, Some(node.private_key.clone()), backend);
    agent
        .tick()
        .unwrap_or_else(|e| panic!("agent {name} tick: {e}"));
}

/// 登录拿会话 Cookie（bootstrap 409 后的兜底路径）。
pub(crate) fn login_cookie(base: &str) -> String {
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
