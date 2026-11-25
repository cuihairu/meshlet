//! Real-network integration tests for the WireGuard central-forwarding prototype
//! ([archive §7.3](../../../docs/review/chatgpt-2026-10-13.md)).
//!
//! Builds a hub-and-spoke topology in four network namespaces (hub + client A + client B +
//! unauthorized C) and drives the real WireGuard dataplane with `ip netns exec`, proving four
//! forwarding guarantees:
//!
//! 1. **A -> B is reachable**: forwarded through the hub, working in both directions;
//! 2. **B -> A is reachable**;
//! 3. **The unauthorized third node is not reachable**: C is not in the hub's peer list, C cannot
//!    reach A/B, and the hub carries no peer entry for C;
//! 4. **Revoking a peer takes effect immediately**: after `wg set wg0 peer <A> remove` on the hub,
//!    A->B and B->A stop working right away and A is gone from the hub's peer list.
//!
//! Topology essentials (pitfalls that were actually stepped on, all reflected in the topology):
//!
//! - **The underlay uses a bridge (an L2 star)**: the veth of all four netns hang off the same
//!   bridge. Swap the bridge for "the host holding 4 veth on one shared /24 + host forwarding" and
//!   the host ends up with four interfaces on the same subnet: routes become ambiguous and the
//!   handshake packets never reach the hub's netns;
//! - **Offload is disabled on both ends of every veth** (`ethtool -K ... gro/gso/tso/rx/tx/sg off`):
//!   the default GRO/GSO/TSO makes the wg handshake fail silently (bytes go out on tx, rx = 0);
//! - **Peer endpoints point at the hub's netns-side veth address** (10.99.0.10 on the bridge), not
//!   the host-side address -- otherwise the packets land in the host's own UDP stack, where no wg0 exists;
//! - **The hub's `ip_forward` must be turned on inside the hub's netns specifically** (each netns has
//!   its own `net.ipv4.ip_forward`; the host's value is not inherited);
//! - **`wg set`, not `wg setconf`**: in this environment `setconf` fails reading the config file with
//!   `fopen: Permission denied` (rc=1), while `wg set` works;
//! - **private-key and peers go in two separate `wg set` calls**: combining them into one command
//!   silently drops the peer;
//! - **Every node gets its own key pair**: when a peer's public key equals the interface's own,
//!   `wg set peer` is silently ignored.
//!
//! Prerequisites: passwordless sudo, `wg` (wireguard-tools), and the `wireguard` kernel module.
//! When any of them is missing, print `SKIP:` and return normally -- `cargo test --workspace` stays
//! green on CI runners without privileges.
//!
//! Cleanup: `Topology`'s `Drop` removes all netns, veth, the bridge and the temp key directory; the
//! test finally asserts once more that "nothing is left behind after the run".

#![cfg(target_os = "linux")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The name prefix shared by every object (netns / veth / bridge) this test creates.
///
/// The prefixes of the netns tests must **never be prefixes of one another**: `preflight_cleanup`
/// clears objects in bulk by `starts_with`, so "mlt" would also wipe the objects of
/// "mlta"/"mltb"/"mltd" -- when `cargo test --workspace` runs them in parallel they would clear each
/// other's stage (objects deleted mid-test).
const PREFIX: &str = "mltw";
/// The overlay range that client routes traverse via the hub.
const OVERLAY_CIDR: &str = "10.240.0.0/16";
/// Upper bound for waiting on the handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(25);

// ---------------------------------------------------------------- process helpers

/// Run a command as root (`sudo -n`, no password prompt).
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

/// Run a command inside a netns.
fn netns_exec(ns: &str, args: &[&str]) -> Output {
    let mut full = vec!["ip", "netns", "exec", ns];
    full.extend_from_slice(args);
    sudo(&full)
}

/// Run a bash snippet inside a netns. bash (not sh) because `wg set`'s
/// `private-key <(echo ...)` needs process substitution.
fn netns_bash(ns: &str, script: &str) -> Output {
    netns_exec(ns, &["bash", "-c", script])
}

/// Topology-building phase: any failing command panics with the stderr attached -- with the
/// environment right, a failing command is a real bug and must not be swallowed.
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

// ---------------------------------------------------------------- prerequisites

/// Return `None` (after printing `SKIP:`) when any prerequisite is missing, keeping CI's
/// unprivileged environments green.
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
    // When already loaded, modprobe may error out -- hence the OR of the two conditions.
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

/// Idempotent pre-cleanup: delete the mlt* objects and temp key directories left by a previous
/// (crashed) run.
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

// ---------------------------------------------------------------- keys

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

// ---------------------------------------------------------------- topology

/// One node's (hub or client) configuration and identity.
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

/// Tracks the objects built so far (netns / veth / bridge / key directory), guaranteeing that a
/// panic at any step of setup can still clean everything up.
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
    /// Build the topology. Returns `None` when a prerequisite is not met (`SKIP:` already printed).
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

        // --- Keys (an independent key pair per node)
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

        // --- Underlay: a bridge star
        let bridge = format!("{PREFIX}br0");
        guard.bridge = Some(bridge.clone());
        require_ok(
            &sudo(&["ip", "link", "add", &bridge, "type", "bridge"]),
            "create bridge",
        );
        require_ok(&sudo(&["ip", "link", "set", &bridge, "up"]), "bridge up");

        // --- netns + veth + underlay addresses + turning off offload
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
            // GRO/GSO/TSO make a wg-over-veth handshake fail silently; turn them off on both ends.
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

        // --- wg interfaces + addresses
        for n in &nodes {
            let script = format!(
                "ip link add wg0 type wireguard && ip address add {}/24 dev wg0 && ip link set wg0 up",
                n.overlay
            );
            require_ok(&n.netns_bash(&script), "wg interface");
        }
        // Every netns has its own net.ipv4.ip_forward; the host's value is not inherited.
        require_ok(
            &hub.netns_exec(&["sysctl", "-w", "net.ipv4.ip_forward=1"]),
            "hub ip_forward",
        );

        // --- The hub's wg config: set the private key first, then each peer in its own statement
        let script = format!(
            "wg set wg0 listen-port {} private-key <(echo {})",
            hub.port, hub.private_key
        );
        require_ok(&hub.netns_bash(&script), "hub private key");
        for peer in &nodes[1..3] {
            // Only A and B -- C is an unauthorized node, and the hub carries no peer entry for it.
            let script = format!(
                "wg set wg0 peer {} allowed-ips {}/32",
                peer.public_key, peer.overlay
            );
            require_ok(&hub.netns_bash(&script), "hub peer");
        }

        // --- The clients' wg config
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

    /// Wait until some node reports a "latest handshake"; return false on timeout.
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

    /// When the handshake fails, dump `wg show wg0` for all four nodes to help locate the problem.
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
        None => return, // Already printed SKIP:
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

    // 1. A -> B is reachable forwarded through the hub.
    assert!(
        topo.ping(&a.netns, &b.overlay),
        "A -> B must reach through the hub"
    );
    // 2. B -> A works in the other direction as well.
    assert!(
        topo.ping(&b.netns, &a.overlay),
        "B -> A must reach through the hub"
    );

    // 3. The unauthorized third node is unreachable, and the hub holds no peer entry for it.
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
    // C being present does not affect connectivity between the authorized nodes.
    assert!(
        topo.ping(&a.netns, &b.overlay),
        "A -> B must still work while unauthorized C is present"
    );

    // 4. Revoke A: removing the peer on the hub takes effect immediately.
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

    // Teardown and assert that "nothing is left behind after the run".
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
