//! Real-netns ownership recovery coverage.

#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::{Command, Output};

use meshlet_agent::{Agent, AgentState};
use meshlet_config::{AgentConfig, DataplaneConfig, TrayConfig};
use meshlet_domain::Ipv4Cidr;
use meshlet_network::linux::LinuxNetworkBackend;
use meshlet_network::nat::{NatAction, NatChain, NatRule};
use meshlet_network::{DevicePlan, RouteConfig, TunnelConfig};

fn sudo(args: &[&str]) -> Output {
    Command::new("sudo")
        .arg("-n")
        .args(args)
        .output()
        .expect("spawn sudo")
}

fn netns(ns: &str, args: &[&str]) -> Output {
    let mut full = vec!["ip", "netns", "exec", ns];
    full.extend_from_slice(args);
    sudo(&full)
}

fn required(output: &Output, what: &str) {
    assert!(
        output.status.success(),
        "{what} failed (rc={:?}): {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn prerequisites() -> bool {
    if !Command::new("wg")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
    {
        assert!(
            std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
            "required dataplane prerequisite failed"
        );
        eprintln!("SKIP: wireguard-tools (wg) not installed");
        return false;
    }
    if !sudo(&["true"]).status.success() {
        assert!(
            std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
            "required dataplane prerequisite failed"
        );
        eprintln!("SKIP: passwordless sudo (sudo -n) unavailable");
        return false;
    }
    if !sudo(&["ip", "netns", "list"]).status.success() {
        assert!(
            std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
            "required dataplane prerequisite failed"
        );
        eprintln!("SKIP: ip netns unavailable");
        return false;
    }
    true
}

struct Namespace(String);

impl Namespace {
    fn new(suffix: &str) -> Self {
        let name = format!("mlr{}{suffix}", std::process::id());
        required(&sudo(&["ip", "netns", "add", &name]), "netns add");
        Self(name)
    }

    fn run(&self, args: &[&str], what: &str) {
        required(&netns(&self.0, args), what);
    }

    fn output(&self, args: &[&str]) -> String {
        let output = netns(&self.0, args);
        required(&output, "read kernel state");
        String::from_utf8_lossy(&output.stdout).to_string()
    }
}

impl Drop for Namespace {
    fn drop(&mut self) {
        let _ = sudo(&["ip", "netns", "del", &self.0]);
    }
}

struct Case {
    ns: Namespace,
    state_dir: String,
    old_owner: &'static str,
    owned_route: &'static str,
    foreign_route: &'static str,
}

impl Case {
    fn new(suffix: &str) -> Self {
        let ns = Namespace::new(suffix);
        ns.run(&["ip", "link", "add", "wg0", "type", "wireguard"], "add wg");
        ns.run(&["ip", "link", "set", "wg0", "up"], "up wg");
        let state_dir = std::env::temp_dir()
            .join(format!(
                "meshlet-ledger-recovery-{}-{suffix}",
                std::process::id()
            ))
            .to_string_lossy()
            .to_string();
        let _ = std::fs::remove_dir_all(&state_dir);
        Self {
            ns,
            state_dir,
            old_owner: "meshlet alias al-gone",
            owned_route: "10.241.1.0/24",
            foreign_route: "198.51.100.0/24",
        }
    }

    fn plant_stale_objects(&self) {
        self.ns.run(
            &[
                "ip",
                "route",
                "add",
                self.owned_route,
                "dev",
                "wg0",
                "proto",
                "198",
            ],
            "plant owned route",
        );
        self.ns.run(
            &["ip", "route", "add", self.foreign_route, "dev", "wg0"],
            "plant foreign route",
        );
        self.ns.run(
            &[
                "iptables",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-d",
                self.owned_route,
                "-j",
                "ACCEPT",
                "-m",
                "comment",
                "--comment",
                self.old_owner,
            ],
            "plant owned NAT",
        );
        self.ns.run(
            &[
                "iptables",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-d",
                "203.0.113.1/32",
                "-j",
                "ACCEPT",
                "-m",
                "comment",
                "--comment",
                "corporate rule",
            ],
            "plant foreign NAT",
        );
    }

    fn backend(&self) -> LinuxNetworkBackend {
        LinuxNetworkBackend::new()
            .with_netns(&self.ns.0)
            .with_sudo()
            .with_interface("wg0")
    }

    fn agent(&self) -> Agent {
        let config = AgentConfig {
            server_url: "http://127.0.0.1:1".into(),
            state_dir: self.state_dir.clone(),
            device_token: Some("test-token".into()),
            bootstrap_token: None,
            device_name: None,
            tray: TrayConfig::OFF,
            dataplane: DataplaneConfig {
                enabled: true,
                ..DataplaneConfig::default()
            },
            upgrade: meshlet_config::UpgradeConfig::default(),
        };
        Agent::with_backend(config, None, self.backend())
    }

    fn assert_recovery(&self) {
        let routes = self.ns.output(&["ip", "-4", "route", "show", "dev", "wg0"]);
        assert!(
            !routes.contains(self.owned_route),
            "owned route survived:\n{routes}"
        );
        assert!(
            routes.contains(self.foreign_route),
            "foreign route deleted:\n{routes}"
        );
        let nat = self
            .ns
            .output(&["iptables", "-t", "nat", "-S", "PREROUTING"]);
        assert!(!nat.contains(self.old_owner), "owned NAT survived:\n{nat}");
        assert!(
            nat.contains("corporate rule"),
            "foreign NAT deleted:\n{nat}"
        );
    }
}

impl Case {
    /// Ledger path, mirroring [`meshlet_agent::reconcile::state_path`].
    fn ledger(&self) -> std::path::PathBuf {
        Path::new(&self.state_dir).join("applied.json")
    }

    fn routes(&self) -> String {
        self.ns.output(&["ip", "-4", "route", "show", "dev", "wg0"])
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.state_dir);
    }
}

fn plan(hash: &str, routes: Vec<RouteConfig>) -> DevicePlan {
    DevicePlan {
        desired_revision: 1,
        hub_port: None,
        tunnel: TunnelConfig {
            name: "wg0".into(),
            address: "10.240.0.9".parse().unwrap(),
            address_prefix: 24,
            listen_port: None,
            peers: Vec::new(),
            mtu: None,
            private_key: None,
        },
        routes,
        nat_rules: Vec::new(),
        hub_address: None,
        publish: None,
        desired_config_hash: hash.into(),
    }
}

fn old_owner_rule() -> NatRule {
    NatRule {
        source_cidr: None,
        incoming_interface: None,
        chain: NatChain::Prerouting,
        match_dest: "10.241.1.0/24".parse().unwrap(),
        action: NatAction::NetMap {
            to: "192.168.1.0/24".parse().unwrap(),
        },
        owner: "meshlet alias al-gone".into(),
    }
}

#[test]
fn missing_ledger_cleans_kernel_owned_objects_and_keeps_foreign() {
    if !prerequisites() {
        return;
    }
    let case = Case::new("missing");
    case.plant_stale_objects();
    let inventory = case.backend().meshlet_nat_owners_sync().expect("inventory");
    assert_eq!(inventory, vec!["meshlet alias al-gone"]);
    let decision = case
        .agent()
        .reconcile(&plan("empty", Vec::new()))
        .expect("missing ledger recovery");
    assert_eq!(decision.reason, meshlet_agent::Reason::NoLocalLedger);
    case.assert_recovery();
    assert!(Path::new(&case.state_dir).join("applied.json").exists());
}

#[test]
fn corrupt_ledger_cleans_kernel_owned_objects_and_keeps_foreign() {
    if !prerequisites() {
        return;
    }
    let case = Case::new("corrupt");
    case.plant_stale_objects();
    std::fs::create_dir_all(&case.state_dir).unwrap();
    std::fs::write(Path::new(&case.state_dir).join("applied.json"), "{broken").unwrap();
    case.agent()
        .reconcile(&plan("empty", Vec::new()))
        .expect("corrupt ledger recovery");
    case.assert_recovery();
}

#[test]
fn deleted_mapping_replays_after_restart() {
    if !prerequisites() {
        return;
    }
    let case = Case::new("restart");
    case.plant_stale_objects();
    let mut old = plan(
        "old",
        vec![RouteConfig {
            destination: "10.241.1.0/24".parse().unwrap(),
            interface: "wg0".into(),
            gateway: None,
        }],
    );
    old.nat_rules.push(old_owner_rule());
    AgentState::from_plan(&old)
        .save(&Path::new(&case.state_dir).join("applied.json"))
        .unwrap();
    let decision = case
        .agent()
        .reconcile(&plan("empty", Vec::new()))
        .expect("restart recovery");
    assert_eq!(decision.reason, meshlet_agent::Reason::DesiredConfigChanged);
    case.assert_recovery();
}

#[test]
fn partial_failure_still_removes_old_entries_and_keeps_foreign() {
    if !prerequisites() {
        return;
    }
    let case = Case::new("partial");
    case.plant_stale_objects();
    case.ns.run(
        &["ip", "route", "add", "blackhole", "10.199.0.0/24"],
        "plant route conflict",
    );
    let desired = plan(
        "new",
        vec![RouteConfig {
            destination: "10.199.0.0/24".parse::<Ipv4Cidr>().unwrap(),
            interface: "wg0".into(),
            gateway: None,
        }],
    );
    let error = case
        .agent()
        .reconcile(&desired)
        .expect_err("conflicting desired route must fail");
    assert!(error.contains("already exists on another path"), "{error}");
    case.assert_recovery();
    assert!(!Path::new(&case.state_dir).join("applied.json").exists());
}

fn route_to(destination: &str) -> RouteConfig {
    RouteConfig {
        destination: destination.parse().unwrap(),
        interface: "wg0".into(),
        gateway: None,
    }
}

/// M3 场景 2「Agent 重启不信账本单独判断」的锋利形态：账本完好、哈希与期望
/// 一致（重启后读到的正是「上次成功应用」的记录），但内核不是账本描述的状态。
/// 判定必须来自内核观测——账本说“已应用”不能替内核作证。
#[test]
fn a_matching_ledger_does_not_shield_kernel_drift() {
    if !prerequisites() {
        return;
    }
    let case = Case::new("stale-ledger");
    let desired = plan("rev-7", vec![route_to("10.241.1.0/24")]);

    // 先由真实 apply 把内核带到与计划一致的状态并留下账本——对照组：账本与
    // 内核都一致时，tick 必须安静。这证明下面检出的漂移只能来自内核。
    case.agent().reconcile(&desired).expect("first install");
    let control = case.agent().reconcile(&desired).expect("control tick");
    assert_eq!(control.reason, meshlet_agent::Reason::UpToDate);

    // 有人把受管路由整条换成另一条同标记路由：条数仍是 1，身份变了。数量检查
    // 会漏过这种替换，只有身份比对能抓到。
    case.ns.run(
        &["ip", "route", "del", "10.241.1.0/24"],
        "remove the desired route",
    );
    case.ns.run(
        &[
            "ip",
            "route",
            "add",
            "10.241.9.0/24",
            "dev",
            "wg0",
            "proto",
            "198",
        ],
        "swap in a different owned route",
    );
    case.ns.run(
        &["ip", "route", "add", "198.51.100.0/24", "dev", "wg0"],
        "plant foreign route",
    );
    let decision = case.agent().reconcile(&desired).expect("drift repair tick");
    assert_eq!(
        decision.reason,
        meshlet_agent::Reason::KernelDrift,
        "the ledger must not stand in for the kernel"
    );
    let routes = case.routes();
    assert!(
        routes.contains("10.241.1.0/24"),
        "desired route must be reinstalled:\n{routes}"
    );
    assert!(
        !routes.contains("10.241.9.0/24"),
        "the meshlet-owned swap-in must be removed:\n{routes}"
    );
    assert!(
        routes.contains("198.51.100.0/24"),
        "the foreign route must survive:\n{routes}"
    );
    let steady = case.agent().reconcile(&desired).expect("steady-state tick");
    assert_eq!(steady.reason, meshlet_agent::Reason::UpToDate);
}

/// M3 场景 3「改路由时进程被杀」：计划 A 已应用并记账，向计划 B 的切换中途
/// 被杀——内核停在半途状态。下一轮 tick 必须从内核实际状态收敛到 B，既不
/// 留下 A 的残余，也不动外部路由；账本最终描述 B。
#[test]
fn a_half_applied_route_change_from_a_killed_apply_converges() {
    if !prerequisites() {
        return;
    }
    // 路由切换的三个被杀断点，每个都种下真实的半途内核状态：
    // - after-add：加了新、旧还没删 → {old, new} 同时在场；
    // - between：删了旧、新还没加 → 两者都不在场；
    // - before-write：一条都没动 → {old}。
    for (suffix, has_old, has_new) in [
        ("killed-after-add", true, true),
        ("killed-between-remove-and-add", false, false),
        ("killed-before-any-write", true, false),
    ] {
        let case = Case::new(suffix);
        let old = plan("rev-a", vec![route_to("10.241.1.0/24")]);
        let new = plan("rev-b", vec![route_to("10.241.2.0/24")]);
        // 计划 A 真实应用并记账，之后才按断点制造半途状态。
        case.agent().reconcile(&old).expect("apply plan A");
        case.ns.run(
            &["ip", "route", "add", "198.51.100.0/24", "dev", "wg0"],
            "plant foreign route",
        );
        if !has_old {
            case.ns.run(
                &["ip", "route", "del", "10.241.1.0/24"],
                "old route removed by the killed apply",
            );
        }
        if has_new {
            case.ns.run(
                &[
                    "ip",
                    "route",
                    "add",
                    "10.241.2.0/24",
                    "dev",
                    "wg0",
                    "proto",
                    "198",
                ],
                "half-applied new route",
            );
        }

        let decision = case.agent().reconcile(&new).expect("converge tick");
        assert_ne!(
            decision.reason,
            meshlet_agent::Reason::UpToDate,
            "{suffix}: the half-applied state must not read as up to date"
        );
        let routes = case.routes();
        assert!(
            routes.contains("10.241.2.0/24"),
            "{suffix}: the new route must be installed:\n{routes}"
        );
        assert!(
            !routes.contains("10.241.1.0/24"),
            "{suffix}: the old route must not survive the crash:\n{routes}"
        );
        assert!(
            routes.contains("198.51.100.0/24"),
            "{suffix}: the foreign route must survive:\n{routes}"
        );
        let saved = std::fs::read_to_string(case.ledger()).unwrap();
        assert!(
            saved.contains("rev-b"),
            "{suffix}: the ledger must describe the new plan"
        );

        // 收敛之后稳态：再 tick 不动作。
        let decision = case.agent().reconcile(&new).expect("steady-state tick");
        assert_eq!(
            decision.reason,
            meshlet_agent::Reason::UpToDate,
            "{suffix}: after convergence the tick must be quiet"
        );
    }
}
