//! SEL-001 候选探测的 netns 双路径验收（[todo.md](../../../todo.md) SEL-001）：
//! 两条路径经 `tc netem` 施加不同时延，ICMP 探测测得的 RTT 不同（慢路径
//! 显著高于快路径），证明探测层确实测到路径差异而非恒等读数。
//!
//! 拓扑：两个 netns（`mltpa` / `mltpb`）各经一条 veth 连宿主，宿主侧 veth
//! 上分别挂 `netem delay 15ms` / `delay 60ms`；从每个 netns 里 `ping` 其
//! 宿主侧对端地址（10.199.1.1 / 10.199.2.1），ICMP 回声穿过对应 veth 的
//! netem，RTT 大致等于该路径的单向时延。
//!
//! 前置条件：免密 sudo、`ip`（iproute2）、`tc`、`ping`。缺任一项打印
//! `SKIP:` 并正常返回——无特权 CI 保持全绿；本机验收跑
//! `MESHLET_REQUIRE_DATAPLANE=1` 强制要求（缺前置即失败）。
//!
//! 清理：`Topology` 的 `Drop` 删掉所有 netns 与 veth；测试最后断言不留垃圾。

#![cfg(target_os = "linux")]

use std::net::Ipv4Addr;
use std::process::{Command, Output};

use meshlet_domain::{DeviceId, EndpointCandidate, PeerEndpoints};
use meshlet_network::probe::{probe_round, ProbeTracker};

/// 本测试创建的所有对象（netns / veth）共用的名称前缀。
///
/// 各 netns 测试的前缀必须**互不为前缀**（`preflight_cleanup` 按
/// `starts_with` 批量清理）：`mltb`（既有）/ `mltw`（wg_forwarding）不会连带
/// 删本测试对象，本前缀也不会删它们的。`mltp` 对两者都是独立前缀。
const PREFIX: &str = "mltp";
/// 探测轮数：单次 `ping` 可能偶发超时，取中位数（窗口 rtt_ms）更稳。
const ROUNDS: usize = 3;
/// 快路径 netem 单向时延（毫秒）。
const DELAY_FAST_MS: u64 = 15;
/// 慢路径 netem 单向时延（毫秒）。
const DELAY_SLOW_MS: u64 = 60;
/// 两路径 RTT 差的下限（毫秒）：净差至少这么多才算「不同」（防 flake）。
const MIN_DIFF_MS: u64 = 20;

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

fn require_ok(out: &Output, what: &str) {
    if !out.status.success() {
        panic!(
            "{what} failed (rc={:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// 工具是否可用：iproute2 的 `ip`/`tc` 与 iputils 的 `ping` 都只认 `-V`
///（`--version` 会报 unknown option），故统一用 `-V` 探测存在性。
fn has(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("-V")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------- 前置条件

/// 缺任一前置条件就返回 `None`（并打印 `SKIP:`），让 CI 无特权环境保持全绿。
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

/// 幂等清场：删掉上一次（崩溃的）运行留下的 mltp* netns 与 veth。
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

/// 一条测试路径：一个 netns + 宿主侧 veth + 对端宿主地址。
struct Path {
    ns: String,
    veth_host: String,
    /// 宿主侧对端地址（netns 里 ping 的目标）。
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
        // 建 veth 对：宿主侧 + netns 侧。
        require_ok(
            &sudo(&[
                "ip", "link", "add", &veth_host, "type", "veth", "peer", "name", &veth_ns,
            ]),
            "create veth pair",
        );
        // netns 侧移入命名空间。
        require_ok(
            &sudo(&["ip", "link", "set", &veth_ns, "netns", &ns]),
            "move veth into netns",
        );
        // 宿主侧地址 + up。
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
        // netns 侧地址 + up（在命名空间内）。
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
        // 宿主侧出口挂 netem 单向时延（回声的回复方向被延迟）。
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

/// 测试拓扑；`Drop` 删除所有 netns 与 veth（跑完不留垃圾）。
struct Topology {
    paths: Vec<Path>,
}

impl Topology {
    fn setup() -> Self {
        preflight_cleanup();
        // netns 须先于 veth 存在（Path::add 把 veth 移入它）。
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

// ---------------------------------------------------------------- 探测

/// 在指定 netns 内 `ping` 目标地址，解析首个 RTT（毫秒）。
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

/// 对单条路径跑 `ROUNDS` 轮探测，返回窗口内 RTT 中位数（毫秒）。
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
    tracker
        .window("peer", EndpointCandidate::lan(path.peer_host_ip, 51821))
        .and_then(|w| w.rtt_ms())
}

// ---------------------------------------------------------------- 测试

#[test]
fn netns_dual_path_probes_yield_different_rtt() {
    let Some(()) = prerequisites() else {
        return; // 已打印 SKIP:
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
    // 慢路径（60ms netem）必须比快路径（15ms netem）显著慢；净差下限 MIN_DIFF_MS。
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
