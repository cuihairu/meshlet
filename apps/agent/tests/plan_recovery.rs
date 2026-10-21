#![cfg(target_os = "linux")]

use std::net::Ipv4Addr;

use meshlet_agent::Agent;
use meshlet_config::{AgentConfig, DataplaneConfig, TrayConfig};

use meshlet_network::linux::LinuxNetworkBackend;
use meshlet_network::nat::{NatAction, NatChain, NatRule};
use meshlet_network::{DevicePlan, PeerConfig, RouteConfig, TunnelConfig};

fn prerequisites() -> bool {
    if !std::process::Command::new("wg")
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

fn sudo(args: &[&str]) -> std::process::Output {
    std::process::Command::new("sudo")
        .args(["-n"])
        .args(args)
        .output()
        .expect("run sudo")
}

fn netns(name: &str, args: &[&str]) -> std::process::Output {
    let mut command = std::process::Command::new("sudo");
    command.args(["-n", "ip", "netns", "exec", name]);
    command.args(args);
    command.output().expect("run netns command")
}

struct Namespace(String);

impl Namespace {
    fn new(suffix: &str) -> Self {
        let name = format!("mpr{}{suffix}", std::process::id());
        let output = sudo(&["ip", "netns", "add", &name]);
        assert!(
            output.status.success(),
            "netns add failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Self(name)
    }

    fn required(&self, args: &[&str], what: &'static str) {
        let output = netns(&self.0, args);
        assert!(
            output.status.success(),
            "{what} failed (rc={:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn text(&self, args: &[&str]) -> String {
        let output = netns(&self.0, args);
        assert!(
            output.status.success(),
            "read kernel state failed (rc={:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
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
    private_key: String,
}

impl Case {
    fn new(suffix: &str) -> Self {
        let private_key = wg_genkey().expect("generate WireGuard key");
        let ns = Namespace::new(suffix);
        ns.required(&["ip", "link", "set", "lo", "up"], "up loopback");
        ns.required(
            &["ip", "link", "add", "lan0", "type", "dummy"],
            "add LAN egress",
        );
        ns.required(
            &["ip", "addr", "add", "192.168.60.1/24", "dev", "lan0"],
            "add LAN address",
        );
        ns.required(&["ip", "link", "set", "lan0", "up"], "up LAN egress");
        ns.required(&["ip", "link", "add", "wg0", "type", "wireguard"], "add wg");
        ns.required(&["ip", "link", "set", "wg0", "up"], "up wg");
        ns.required(
            &["ip", "route", "add", "198.51.100.0/24", "dev", "wg0"],
            "add foreign route",
        );
        ns.required(
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
            "add foreign NAT",
        );
        let state_dir = std::env::temp_dir()
            .join(format!(
                "meshlet-plan-recovery-{}-{suffix}",
                std::process::id()
            ))
            .to_string_lossy()
            .to_string();
        let _ = std::fs::remove_dir_all(&state_dir);
        Self {
            ns,
            state_dir,
            private_key,
        }
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
        Agent::with_backend(config, Some(self.private_key.clone()), self.backend())
    }

    fn assert_last_good(&self) {
        assert!(self
            .ns
            .text(&["ip", "-4", "addr", "show", "dev", "wg0"])
            .contains("10.240.0.9/24"));
        assert!(self
            .ns
            .text(&["ip", "route", "show", "dev", "wg0", "proto", "198"])
            .contains("10.241.1.0/24"));
        let nat = self.ns.text(&["iptables", "-t", "nat", "-S", "PREROUTING"]);
        assert!(nat.contains("-d 10.241.1.0/24"));
        assert!(nat.contains("corporate rule"));
    }
}

fn wg_genkey() -> Option<String> {
    let output = std::process::Command::new("wg")
        .arg("genkey")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

impl Drop for Case {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.state_dir);
    }
}

fn plan(
    hash: &str,
    address: Ipv4Addr,
    routes: Vec<RouteConfig>,
    nat_rules: Vec<NatRule>,
) -> DevicePlan {
    DevicePlan {
        desired_revision: 1,
        hub_port: None,
        tunnel: TunnelConfig {
            name: "wg0".into(),
            address,
            address_prefix: 24,
            listen_port: None,
            peers: Vec::new(),
            mtu: None,
            private_key: None,
        },
        routes,
        nat_rules,
        hub_address: None,
        desired_config_hash: hash.into(),
    }
}

fn route(destination: &str) -> RouteConfig {
    RouteConfig {
        destination: destination.parse().unwrap(),
        interface: "wg0".into(),
        gateway: None,
    }
}

fn nat_rule(destination: &str, owner: &'static str) -> NatRule {
    NatRule {
        source_cidr: None,
        incoming_interface: None,
        chain: NatChain::Prerouting,
        match_dest: destination.parse().unwrap(),
        action: NatAction::NetMap {
            to: "192.168.1.0/24".parse().unwrap(),
        },
        owner: owner.to_string(),
    }
}

fn snat_rule(destination: &str, owner: &'static str) -> NatRule {
    NatRule {
        source_cidr: None,
        incoming_interface: None,
        chain: NatChain::Postrouting,
        match_dest: destination.parse().unwrap(),
        action: NatAction::SnatToGatewayLan,
        owner: owner.to_string(),
    }
}

#[test]
fn tunnel_failure_recovers_last_good_plan_and_keeps_receipt_failed() {
    if !prerequisites() {
        return;
    }
    let case = Case::new("tunnel");
    let good = plan(
        "good",
        "10.240.0.9".parse().unwrap(),
        vec![route("10.241.1.0/24")],
        vec![nat_rule("10.241.1.0/24", "meshlet alias al-good")],
    );
    case.agent().reconcile(&good).expect("establish last good");
    case.assert_last_good();

    case.ns
        .required(&["ip", "link", "del", "wg0"], "remove tunnel");
    let mut desired = plan(
        "tunnel-fail",
        "10.240.0.9".parse().unwrap(),
        Vec::new(),
        Vec::new(),
    );
    desired.tunnel.peers.push(PeerConfig {
        public_key: "invalid-public-key".into(),
        allowed_ips: vec!["10.199.0.0/24".parse().unwrap()],
        endpoint: None,
        persistent_keepalive_secs: None,
    });
    let error = case
        .agent()
        .reconcile(&desired)
        .expect_err("tunnel failure must be visible");
    assert!(error.contains("apply the desired plan"), "{error}");
    case.assert_last_good();
    let state = std::fs::read_to_string(std::path::Path::new(&case.state_dir).join("applied.json"))
        .unwrap();
    assert!(state.contains("\"desired_config_hash\": \"good\""));
}

#[test]
fn route_failure_recovers_last_good_plan_and_keeps_foreign_objects() {
    if !prerequisites() {
        return;
    }
    let case = Case::new("route");
    let good = plan(
        "good",
        "10.240.0.9".parse().unwrap(),
        vec![route("10.241.1.0/24")],
        vec![nat_rule("10.241.1.0/24", "meshlet alias al-good")],
    );
    case.agent().reconcile(&good).expect("establish last good");
    case.assert_last_good();

    case.ns.required(
        &["ip", "route", "replace", "blackhole", "10.199.0.0/24"],
        "plant route conflict",
    );
    let desired = plan(
        "route-fail",
        "10.240.0.9".parse().unwrap(),
        vec![route("10.199.0.0/24")],
        Vec::new(),
    );
    let error = case
        .agent()
        .reconcile(&desired)
        .expect_err("route failure must be visible");
    assert!(error.contains("already exists on another path"), "{error}");
    case.assert_last_good();
}

#[test]
fn nat_failure_recovers_last_good_plan_and_retries_converge() {
    if !prerequisites() {
        return;
    }
    let case = Case::new("nat");
    let good = plan(
        "good",
        "10.240.0.9".parse().unwrap(),
        vec![route("10.241.1.0/24")],
        vec![nat_rule("10.241.1.0/24", "meshlet alias al-good")],
    );
    case.agent().reconcile(&good).expect("establish last good");
    case.assert_last_good();

    let desired = plan(
        "nat-fail",
        "10.240.0.9".parse().unwrap(),
        vec![route("10.241.1.0/24")],
        vec![snat_rule("10.199.0.0/24", "meshlet alias al-new")],
    );
    case.ns.required(
        &[
            "ip",
            "route",
            "add",
            "10.199.0.0/24",
            "via",
            "192.168.60.2",
            "dev",
            "lan0",
        ],
        "add LAN egress route",
    );
    case.ns.required(
        &["ip", "route", "replace", "blackhole", "10.199.0.0/24"],
        "force NAT source failure",
    );
    let error = case
        .agent()
        .reconcile(&desired)
        .expect_err("NAT failure must be visible");
    assert!(
        error.contains("no usable LAN egress/source")
            || error.contains("ip -4 route get 10.199.0.0 exited 2"),
        "{error}"
    );
    case.assert_last_good();

    case.ns.required(
        &[
            "ip",
            "route",
            "replace",
            "10.199.0.0/24",
            "via",
            "192.168.60.2",
            "dev",
            "lan0",
        ],
        "restore LAN egress route",
    );
    let retry = plan(
        "retry",
        "10.240.0.9".parse().unwrap(),
        vec![route("10.241.1.0/24")],
        vec![snat_rule("10.199.0.0/24", "meshlet alias al-new")],
    );
    case.agent().reconcile(&retry).expect("retry converges");
    let routes = case
        .ns
        .text(&["ip", "route", "show", "dev", "wg0", "proto", "198"]);
    assert!(routes.contains("10.241.1.0/24"));
    let nat = case
        .ns
        .text(&["iptables", "-t", "nat", "-S", "POSTROUTING"]);
    assert!(nat.contains("meshlet alias al-new"));
    assert!(!nat.contains("meshlet alias al-good"));
}
