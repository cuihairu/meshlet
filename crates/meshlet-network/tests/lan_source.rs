//! Actual route-selected SNAT sources: host targets, multiple and routed LANs.
#![cfg(target_os = "linux")]
use meshlet_network::SystemBackend;
use std::process::Command;

struct Namespace(String);
impl Namespace {
    fn run(&self, args: &[&str]) {
        let out = Command::new("sudo")
            .args(["-n", "ip", "netns", "exec", &self.0])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
impl Drop for Namespace {
    fn drop(&mut self) {
        let _ = Command::new("sudo")
            .args(["-n", "ip", "netns", "del", &self.0])
            .status();
    }
}

#[test]
fn host_and_routed_lans_use_the_actual_egress_source() {
    let name = format!("mlsrc{}", std::process::id());
    let out = Command::new("sudo")
        .args(["-n", "ip", "netns", "add", &name])
        .output()
        .unwrap();
    if !out.status.success() {
        assert!(
            std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
            "netns required: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        eprintln!("SKIP: netns unavailable");
        return;
    }
    let ns = Namespace(name.clone());
    ns.run(&["ip", "link", "set", "lo", "up"]);
    for (dev, addr) in [
        ("lan0", "192.168.60.1/24"),
        ("lan1", "192.168.61.1/24"),
        ("wg0", "10.240.0.2/24"),
    ] {
        ns.run(&["ip", "link", "add", dev, "type", "dummy"]);
        ns.run(&["ip", "addr", "add", addr, "dev", dev]);
        ns.run(&["ip", "link", "set", dev, "up"]);
    }
    let backend = SystemBackend::new().with_netns(name).with_sudo();
    for (target, source) in [
        ("192.168.60.5/32", "192.168.60.1"),
        ("192.168.61.5/32", "192.168.61.1"),
    ] {
        assert_eq!(
            backend
                .lan_source_for(target.parse().unwrap())
                .unwrap()
                .to_string(),
            source
        );
    }
    ns.run(&[
        "ip",
        "route",
        "add",
        "192.168.70.0/24",
        "via",
        "192.168.60.2",
        "dev",
        "lan0",
    ]);
    assert_eq!(
        backend
            .lan_source_for("192.168.70.5/32".parse().unwrap())
            .unwrap()
            .to_string(),
        "192.168.60.1"
    );
    ns.run(&["ip", "addr", "add", "192.168.60.9/24", "dev", "lan0"]);
    ns.run(&[
        "ip",
        "route",
        "add",
        "192.168.60.5/32",
        "dev",
        "lan0",
        "src",
        "192.168.60.9",
    ]);
    assert_eq!(
        backend
            .lan_source_for("192.168.60.5/32".parse().unwrap())
            .unwrap()
            .to_string(),
        "192.168.60.9"
    );
    for target in ["192.168.90.5/32", "10.240.0.3/32", "192.168.60.1/32"] {
        assert!(
            backend.lan_source_for(target.parse().unwrap()).is_err(),
            "{target}"
        );
    }
    ns.run(&["ip", "route", "add", "blackhole", "192.168.99.0/24"]);
    assert!(backend
        .lan_source_for("192.168.99.5/32".parse().unwrap())
        .is_err());
}
