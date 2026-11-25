//! AGENT-FW-1 real-machine acceptance (Windows, in the CI `windows-latest` administrator state):
//! the netsh / PowerShell commands produced by the planning layer run the full loop on a **real
//! Windows firewall** and are idempotent -- todo.md originally ruled that "the direct ping acceptance
//! needs a real Windows machine", and this file uses CI's real Windows machine to add the real-machine
//! evidence layer for "command shapes + idempotent re-runs" (the end-to-end ping is still judged by
//! real-machine acceptance). On non-Windows targets the whole file is empty and Linux CI simply skips it.

#![cfg(windows)]

use meshlet_network::windows_firewall::{
    exec::run_mesh_firewall_command, firewall_rule_present, mesh_icmp_rule,
    net_category_is_private, rule_output_has_satisfied_icmp_rule, IcmpRuleState,
    MeshFirewallCommand,
};
use meshlet_network::{ApplyResult, NetworkError};

/// Run a command and take the merged output (netsh's output is encoded in the active code page; the
/// test assertions rely only on ASCII keywords and the "rule is present" semantics, not on
/// localized wording).
fn run(program: &str, args: &[String]) -> (i32, String) {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .expect("spawn netsh/powershell");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    (output.status.code().unwrap_or(-1), text)
}

/// `netsh advfirewall firewall show rule name=<name>` (the same shape as the planning layer's prefix).
fn show_rule(name: &str) -> (i32, String) {
    run(
        "netsh",
        &[
            "advfirewall".to_string(),
            "firewall".to_string(),
            "show".to_string(),
            "rule".to_string(),
            format!("name={name}"),
        ],
    )
}

/// `netsh advfirewall firewall delete rule name=<name>` (shaped the same as
/// [`meshlet_network::windows_firewall::FirewallRuleCommand::Delete`]; built inline here to avoid
/// adding an export just for the cleanup path).
fn delete_rule(name: &str) -> (i32, String) {
    run(
        "netsh",
        &[
            "advfirewall".to_string(),
            "firewall".to_string(),
            "delete".to_string(),
            "rule".to_string(),
            format!("name={name}"),
        ],
    )
}

/// The real-machine full loop: add -> show reads it back as present -> rerun the apply probe (the rule
/// already exists -> an empty, idempotent plan) -> delete -> show reads it back as absent. This is the
/// shape validation, on a real firewall, of the "probe + idempotent catch-up" path the agent walks on
/// every apply round; the rule uses the production name `Meshlet-ICMPv4-In` with
/// `localip=127.0.0.1` (the test machine's loopback, never touching real subnets), and the test cleans up at the end.
#[test]
fn icmp_rule_add_show_delete_roundtrip_is_idempotent_on_a_real_firewall() {
    let rule = mesh_icmp_rule("127.0.0.1".parse().unwrap());
    let name = rule.name.clone();
    // Starting cleanup: delete any leftover rule first (idempotent: succeeding even when absent).
    delete_rule(&name);

    // add (the real execution path of the agent's apply).
    let applied =
        run_mesh_firewall_command(&MeshFirewallCommand::AddIcmpRule { rule: rule.clone() })
            .expect("add Meshlet-ICMPv4-In");
    assert_eq!(applied, ApplyResult::ok());

    // Read back with show: the rule really exists (netsh has no query semantics; show + a presence verdict come from the same source).
    let (_, shown) = show_rule(&name);
    assert!(
        firewall_rule_present(&shown),
        "rule must be present after add; netsh said: {shown:?}"
    );

    // Idempotent rerun: the probe is already satisfied -> an empty plan (the agent never re-adds). The state
    // is derived from the real show output with the same predicates as the planning layer (present +
    // enabled + localip matching).
    let device_addr = "127.0.0.1".parse().unwrap();
    let icmp_state = if firewall_rule_present(&shown) {
        if rule_output_has_satisfied_icmp_rule(&shown, device_addr) {
            IcmpRuleState::Satisfied
        } else {
            IcmpRuleState::Stale
        }
    } else {
        IcmpRuleState::Absent
    };
    let plan = meshlet_network::windows_firewall::mesh_reachability_commands(
        "meshlet",
        device_addr,
        true,
        icmp_state,
    )
    .unwrap();
    assert!(
        plan.is_empty(),
        "satisfied probes must produce an empty (idempotent) plan"
    );

    // delete -> show reads it back as absent (real-machine evidence for the revocation path).
    delete_rule(&name);
    let (_, gone) = show_rule(&name);
    assert!(
        !firewall_rule_present(&gone),
        "rule must be absent after delete; netsh said: {gone:?}"
    );
}

/// Real-machine category: `Set-NetConnectionProfile -NetworkCategory Private` runs twice on a real
/// interface (an idempotent, re-runnable set) and reads back as Private. The interface comes from
/// `Get-NetConnectionProfile` (guaranteeing a connection profile exists; the CI runner's Ethernet
/// interface). A runner's interface alias often contains spaces (`Ethernet 1`), which fails the
/// planning layer's injection-defense charset -- so it is renamed inline to a legal alias (one-shot;
/// the runner is a disposable machine).
#[test]
fn network_category_private_set_is_idempotent_on_a_real_interface() {
    // Find an interface with a connection profile (both the runner's physical and virtual NICs have one).
    let (_, profiles) = run(
        "powershell",
        &[
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-Command".to_string(),
            "(Get-NetConnectionProfile | Select-Object -First 1).InterfaceAlias".to_string(),
        ],
    );
    let interface = profiles.lines().map(str::trim).find(|l| !l.is_empty());
    let Some(interface) = interface else {
        panic!("no interface with a connection profile on this machine: {profiles:?}");
    };

    // The alias fails the planning layer's injection-defense charset (e.g. it has spaces) -> rename it to a legal name.
    let charset_ok = !interface.is_empty()
        && interface
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'.');
    let interface = if charset_ok {
        interface.to_string()
    } else {
        let (_, rename_out) = run(
            "powershell",
            &[
                "-NoProfile".to_string(),
                "-NonInteractive".to_string(),
                "-Command".to_string(),
                format!("Rename-NetAdapter -Name '{interface}' -NewName 'meshletci'"),
            ],
        );
        eprintln!("rename adapter output: {rename_out}");
        "meshletci".to_string()
    };

    // The interface name enters a PowerShell single-quoted string -- the same injection defense as production (validated by the planning layer).
    let set = MeshFirewallCommand::set_network_category_private(&interface)
        .expect("planned interface name must pass injection validation");
    // Set it twice in a row: the second is the idempotent rerun (setting again while already Private still succeeds).
    run_mesh_firewall_command(&set).expect("first set");
    run_mesh_firewall_command(&set).expect("idempotent re-set");

    // Read the category back (the same command the agent's probe uses).
    let (_, profile) = run(
        "powershell",
        &[
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-Command".to_string(),
            format!("Get-NetConnectionProfile -InterfaceAlias '{interface}'"),
        ],
    );
    assert!(
        net_category_is_private(&profile),
        "category must read Private after set; profile: {profile:?}"
    );
}

/// A compile-time pin: privilege-class failures still map to `InsufficientPrivileges` on a real machine
/// (the real-message path of a non-administrator running netsh add; the CI runner is an administrator,
/// so this asserts against the real `access is denied` text with the planning layer's classifier,
/// keeping the execution layer's classification aligned with real-machine wording).
#[test]
fn firewall_failure_classification_maps_denied_to_privileges() {
    let set = MeshFirewallCommand::set_network_category_private("meshlet-ci").unwrap();
    let error = meshlet_network::windows_firewall::classify_netsh_firewall_failure(
        1,
        "Access is denied.",
        set.operation(),
        "meshlet-ci",
    )
    .unwrap_err();
    assert!(matches!(error, NetworkError::InsufficientPrivileges(_)));
}
