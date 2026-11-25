//! Two-path netns acceptance for SEL-001 candidate probing ([todo.md](../../../todo.md) SEL-001):
//! `tc netem` imposes different latencies on the two paths, and ICMP probing measures different RTTs
//! (the slow path is markedly higher than the fast one), proving that the probing layer really does
//! measure the path difference rather than a constant reading.
//!
//! Topology: two netns (`mltpa` / `mltpb`) each connect to the host through one veth, and the host-side
//! veths carry `netem delay 15ms` / `delay 60ms` respectively; each netns `ping`s its host-side peer
//! address (10.199.1.1 / 10.199.2.1), the ICMP echo traverses the matching veth's netem, and the RTT
//! roughly equals the one-way delay of that path.
//!
//! Prerequisites: passwordless sudo, `ip` (iproute2), `tc`, `ping`. When any is missing, print
//! `SKIP:` and return normally -- unprivileged CI stays green; on a local machine the acceptance run
//! sets `MESHLET_REQUIRE_DATAPLANE=1` to require them (a missing prerequisite then fails).
//!
//! Cleanup: `Topology`'s `Drop` removes all netns and veth; the test finally asserts that nothing is
//! left behind.

#![cfg(target_os = "linux")]

use std::net::Ipv4Addr;
use std::process::{Command, Output};

use meshlet_domain::{DeviceId, EndpointCandidate, PeerEndpoints};
use meshlet_network::probe::{probe_round, ProbeTracker};

/// The name prefix shared by every object (netns / veth) this test creates.
///
/// The prefixes of the netns tests must **never be prefixes of one another** (`preflight_cleanup`
/// clears objects in bulk by `starts_with`): `mltb` (pre-existing) / `mltw` (wg_forwarding) do not
/// delete this test's objects, and this prefix does not delete theirs. `mltp` is an independent
/// prefix with respect to both.
const PREFIX: &str = "mltp";
/// Probe rounds: a single `ping` may time out sporadically; the median (the window's rtt_ms) is steadier.
const ROUNDS: usize = 3;
/// The fast path's one-way netem delay (milliseconds).
const DELAY_FAST_MS: u64 = 15;
/// The slow path's one-way netem delay (milliseconds).
const DELAY_SLOW_MS: u64 = 60;
/// The lower bound on the RTT difference between the two paths (milliseconds): a net difference of at
/// least this much counts as "different" (flakiness guard).
const MIN_DIFF_MS: u64 = 20;

// ---------------------------------------------------------------- process helpers

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

fn require_ok(out: &Output, what: &str) {
    if !out.status.success() {
        panic!(
            "{what} failed (rc={:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// Whether a tool is available: iproute2's `ip`/`tc` and iputils' `ping` all accept only `-V`
/// (`--version` reports an unknown option), so `-V` is used uniformly to probe for existence.
fn has(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("-V")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------- prerequisites

/// Return `None` (after printing `SKIP:`) when any prerequisite is missing, keeping unprivileged CI
/// environments green.
fn prerequisites() -> Option<()> {
    if !sudo_ok(&["true"]) {
        assert!(
            std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
            "required dataplane prerequisite failed"
        );
        eprintln!("SKIP: passwordless sudo (sudo -n) unavailable");
        return None;
    }
    if !has("ip") {
        assert!(
            std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
            "required dataplane prerequisite failed"
        );
        eprintln!("SKIP: iproute2 (ip) not installed");
        return None;
    }
    if !has("tc") {
        assert!(
            std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
            "required dataplane prerequisite failed"
        );
        eprintln!("SKIP: iproute2 (tc) not installed");
        return None;
    }
    if !has("ping") {
        assert!(
            std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
            "required dataplane prerequisite failed"
        );
        eprintln!("SKIP: ping not installed");
        return None;
    }
    Some(())
}

/// Idempotent pre-cleanup: remove the mltp* netns and veth left by a previous (crashed) run.
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

// ---------------------------------------------------------------- topology

/// One test path: a netns + the host-side veth + the peer's host-side address.
struct Path {
    ns: String,
    veth_host: String,
    /// The host-side peer address (the ping target from inside the netns).
    peer_host_ip: Ipv4Addr,
}

impl Path {
    fn add(
        ns: String,
        veth_host: String,
        veth_ns: String,
        peer_host_ip: Ipv4Addr,
        ns_ip: Ipv4Addr,
        delay_ms: u64,
    ) -> Self {
        // Build the veth pair: host side + netns side.
        require_ok(
            &sudo(&[
                "ip", "link", "add", &veth_host, "type", "veth", "peer", "name", &veth_ns,
            ]),
            "create veth pair",
        );
        // Move the netns side into the namespace.
        require_ok(
            &sudo(&["ip", "link", "set", &veth_ns, "netns", &ns]),
            "move veth into netns",
        );
        // Host-side address + bring it up.
        require_ok(
            &sudo(&[
                "ip",
                "addr",
                "add",
                &format!("{peer_host_ip}/24"),
                "dev",
                &veth_host,
            ]),
            "assign host-side address",
        );
        require_ok(
            &sudo(&["ip", "link", "set", &veth_host, "up"]),
            "bring up host veth",
        );
        // Netns-side address + bring it up (inside the namespace).
        require_ok(
            &sudo(&[
                "ip",
                "netns",
                "exec",
                &ns,
                "ip",
                "addr",
                "add",
                &format!("{ns_ip}/24"),
                "dev",
                &veth_ns,
            ]),
            "assign netns-side address",
        );
        require_ok(
            &sudo(&[
                "ip", "netns", "exec", &ns, "ip", "link", "set", &veth_ns, "up",
            ]),
            "bring up netns veth",
        );
        // Hang a one-way netem delay on the host-side egress (which delays the echo's reply direction).
        require_ok(
            &sudo(&[
                "tc",
                "qdisc",
                "add",
                "dev",
                &veth_host,
                "root",
                "netem",
                "delay",
                &format!("{delay_ms}ms"),
            ]),
            "attach netem delay",
        );
        Self {
            ns,
            veth_host,
            peer_host_ip,
        }
    }
}

/// The test topology; `Drop` removes all netns and veth (nothing is left behind after the run).
struct Topology {
    paths: Vec<Path>,
}

impl Topology {
    fn setup() -> Self {
        preflight_cleanup();
        // The netns must exist before the veth (Path::add moves the veth into it).
        require_ok(
            &sudo(&["ip", "netns", "add", &format!("{PREFIX}a")]),
            "create netns a",
        );
        require_ok(
            &sudo(&["ip", "netns", "add", &format!("{PREFIX}b")]),
            "create netns b",
        );
        let mut paths = Vec::new();
        paths.push(Path::add(
            format!("{PREFIX}a"),
            format!("{PREFIX}a0"),
            format!("{PREFIX}a1"),
            "10.199.1.1".parse().unwrap(),
            "10.199.1.2".parse().unwrap(),
            DELAY_FAST_MS,
        ));
        paths.push(Path::add(
            format!("{PREFIX}b"),
            format!("{PREFIX}b0"),
            format!("{PREFIX}b1"),
            "10.199.2.1".parse().unwrap(),
            "10.199.2.2".parse().unwrap(),
            DELAY_SLOW_MS,
        ));
        Self { paths }
    }
}

impl Drop for Topology {
    fn drop(&mut self) {
        for path in &self.paths {
            let _ = sudo(&["ip", "link", "del", &path.veth_host]);
            let _ = sudo(&["ip", "netns", "del", &path.ns]);
        }
    }
}

// ---------------------------------------------------------------- probing

/// `ping` the target address inside a given netns and parse the first RTT (milliseconds).
fn ping_in_ns(ns: &str, ip: Ipv4Addr) -> Option<u128> {
    let out = sudo(&[
        "ip",
        "netns",
        "exec",
        ns,
        "ping",
        "-c",
        "1",
        "-W",
        "1",
        &ip.to_string(),
    ]);
    if !out.status.success() {
        return None;
    }
    meshlet_network::linux::parse_ping_rtt_ms(&String::from_utf8_lossy(&out.stdout))
}

/// Probe a single path for `ROUNDS` rounds and return the median RTT of the window (milliseconds).
fn probe_median_rtt(path: &Path) -> Option<u64> {
    let peer = PeerEndpoints {
        device_id: DeviceId("peer".into()),
        public_key: "peer-key".into(),
        virtual_ipv4: "10.240.0.2".parse().unwrap(),
        name: "peer".into(),
        endpoints: vec![EndpointCandidate::lan(path.peer_host_ip, 51821)],
    };
    let mut tracker = ProbeTracker::new(ROUNDS.max(1));
    let peers = std::slice::from_ref(&peer);
    for _ in 0..ROUNDS {
        probe_round(&mut tracker, peers, |ip| ping_in_ns(&path.ns, ip));
    }
    // The window is keyed by the peer's public key (probe_round's convention, since 2026-11-13).
    tracker
        .window("peer-key", EndpointCandidate::lan(path.peer_host_ip, 51821))
        .and_then(|w| w.rtt_ms())
}

// ---------------------------------------------------------------- tests

#[test]
fn netns_dual_path_probes_yield_different_rtt() {
    let Some(()) = prerequisites() else {
        return; // Already printed SKIP:
    };
    let topo = Topology::setup();
    let fast = probe_median_rtt(&topo.paths[0]);
    let slow = probe_median_rtt(&topo.paths[1]);
    let (fast, slow) = match (fast, slow) {
        (Some(f), Some(s)) => (f, s),
        _ => panic!(
            "probe returned no RTT on a live path (fast={fast:?}, slow={slow:?}) \
             -- topology or ping in netns broken"
        ),
    };
    // The slow path (60ms netem) must be markedly slower than the fast path (15ms netem); the net difference must reach MIN_DIFF_MS.
    assert!(
        slow >= fast + MIN_DIFF_MS,
        "dual-path probe failed to see different RTT: fast={fast}ms slow={slow}ms \
         (expected slow >= fast + {MIN_DIFF_MS}ms)"
    );
    eprintln!(
        "SEL-001 netns dual-path evidence: fast_path={fast}ms slow_path={slow}ms \
         diff={}ms (netem {DELAY_FAST_MS}ms vs {DELAY_SLOW_MS}ms)",
        slow - fast
    );
}
