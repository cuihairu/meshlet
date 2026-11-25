//! Real-machine integration tests for the Windows uninstall chain (evidence for ADR-008 TODO #52):
//! the full loop on a real sc.exe / netsh -- service create -> stop (1062 idempotent when never
//! started) -> delete -> re-delete (1060 idempotent) -- and firewall add -> delete -> re-delete
//! (idempotent on localized "not found" wording), closing with a re-entry into an empty-state
//! CleanupPlan to verify that "cleaning down to an empty state does not count as a failure" (§10.3).
//!
//! Real-machine evidence (2026-10-26, a Chinese Windows Server, CP936 output decoded through
//! `windows_console`):
//! - `sc stop` on a service that never started -> exit 1062 "[SC] ControlService failed 1062: The
//!   service has not been started." (the quoted wording is the Chinese localization; the target state
//!   of a Stop is "stopped", so not running = already achieved);
//! - `sc delete` on a nonexistent service -> exit 1060 "The specified service is not installed.";
//! - `netsh firewall delete rule` with no match -> "There are no rules matching the specified
//!   standard."
//!
//! Test hygiene: the service/rule names use the dedicated `__meshlet_probe_*` prefix (machine-global
//! objects are never scanned or touched); the service's binPath points at the system's built-in
//! cmd.exe and is never started; a RouteGuard-style Drop provides the fallback cleanup, and repeated
//! deletions after a failed assertion are idempotent and harmless.

#![cfg(target_os = "windows")]

use meshlet_network::windows_cleanup::{exec::run_cleanup_command, CleanupPlan};
use meshlet_network::windows_firewall::{
    exec::run_firewall_command, FirewallAction, FirewallDirection, FirewallProfile,
    FirewallProtocol, FirewallRule, FirewallRuleCommand,
};
use meshlet_network::windows_service::{
    exec::run_service_command, ServiceCommand, ServiceStartMode,
};

/// The probe service name: a dedicated prefix, never touching the machine's global services.
const PROBE_SERVICE: &str = "__meshlet_probe_svc";
/// The probe firewall rule name: a dedicated prefix.
const PROBE_RULE: &str = "__meshlet_probe_rule";

fn delete_probe_service() -> ServiceCommand {
    ServiceCommand::Delete {
        name: PROBE_SERVICE.into(),
    }
}

fn delete_probe_rule() -> FirewallRuleCommand {
    FirewallRuleCommand::Delete {
        name: PROBE_RULE.into(),
    }
}

/// The fallback on failure: Drop makes a best-effort deletion of the two probe targets (deleting
/// something already absent is idempotent, and repeated cleanup is harmless).
struct ProbeGuard;

impl Drop for ProbeGuard {
    fn drop(&mut self) {
        let _ = run_service_command(&delete_probe_service());
        let _ = run_firewall_command(&delete_probe_rule());
    }
}

fn probe_rule() -> FirewallRule {
    FirewallRule {
        name: PROBE_RULE.into(),
        direction: FirewallDirection::Inbound,
        action: FirewallAction::Allow,
        protocol: FirewallProtocol::Udp,
        local_port: "51820".into(),
        remote_port: "any".into(),
        profiles: Some(vec![FirewallProfile::Public]),
        description: Some("meshlet probe".into()),
        local_ip: None,
    }
}

/// The uninstall re-entry backbone: from any half-state (already deleted / never started / the rule
/// missing) every step succeeds idempotently.
#[test]
fn uninstall_chain_is_reentrant_from_partial_states() {
    // 0) Empty-state warm-up: deleting a service/rule that does not exist must succeed idempotently
    //    (the very same path the Drop fallback cleanup walks).
    run_service_command(&delete_probe_service())
        .expect("delete of absent service must be idempotent");
    run_firewall_command(&delete_probe_rule()).expect("delete of absent rule must be idempotent");

    let _guard = ProbeGuard;

    // 1) create (disabled, never started): the entry point of the uninstall chain.
    let create = ServiceCommand::Create {
        name: PROBE_SERVICE.into(),
        bin_path: r"C:\Windows\System32\cmd.exe".into(),
        start_mode: ServiceStartMode::Disabled,
    };
    let result = run_service_command(&create).expect("sc create probe service");
    assert!(result.applied);

    // 2) stop a service that never started: real-machine 1062 "The service has not been started" -> an
    //    idempotent success (the target state of a Stop is "stopped").
    let result = run_service_command(&ServiceCommand::Stop {
        name: PROBE_SERVICE.into(),
    })
    .expect("stop of never-started service must be idempotent success");
    assert!(result.applied);

    // 3) delete -> 4) re-delete: the real-machine 1060 localized wording -> an idempotent success.
    let result = run_service_command(&delete_probe_service()).expect("sc delete probe service");
    assert!(result.applied);
    let result = run_service_command(&delete_probe_service())
        .expect("re-delete of absent service must be idempotent success");
    assert!(result.applied);

    // 5) Firewall add -> delete -> re-delete: the localized "missing" wording, once decoded by
    //    windows_console, hits the idempotence verdict.
    let result = run_firewall_command(&FirewallRuleCommand::Add { rule: probe_rule() })
        .expect("netsh add probe rule");
    assert!(result.applied);
    let result = run_firewall_command(&delete_probe_rule()).expect("netsh delete probe rule");
    assert!(result.applied);
    let result = run_firewall_command(&delete_probe_rule())
        .expect("re-delete of absent rule must be idempotent success");
    assert!(result.applied);

    // 6) Re-entry into an empty-state CleanupPlan: every step in the plan (service stop/delete, route
    //    delete, firewall delete) already has its target missing, and all of them must succeed
    //    idempotently -- uninstalling can re-enter from any half-state down to the empty state.
    let plan = CleanupPlan {
        service_name: PROBE_SERVICE.into(),
        route_interface: "Loopback Pseudo-Interface 1".into(),
        route_prefixes: vec!["192.0.2.0/24".parse().unwrap()],
        firewall_rule_names: vec![PROBE_RULE.into()],
        temp_files: Vec::new(),
        key_material_files: Vec::new(),
    };
    for command in plan.commands() {
        let result = run_cleanup_command(&command).unwrap_or_else(|error| {
            panic!(
                "cleanup step `{}` must be idempotent from empty state: {error}",
                command.operation()
            )
        });
        assert!(result.applied);
    }
}
