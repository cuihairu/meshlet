//! Parsing and default-value tests for `AgentConfig` (the server-side ones are
//! inlined in server.rs).

use super::*;

#[test]
fn agent_config_validates_url_scheme() {
    let c = AgentConfig::from_toml("server_url = \"https://vps.example.com\"").unwrap();
    assert_eq!(c.server_url, "https://vps.example.com");

    let err = AgentConfig::from_toml("server_url = \"ftp://vps.example.com\"").unwrap_err();
    assert!(matches!(err, ConfigError::InvalidServerUrl(_)));

    // Defaults are usable.
    let d = AgentConfig::from_toml("").unwrap();
    assert_eq!(d, AgentConfig::default());
}

#[test]
fn agent_tray_integrations_default_off_and_parse_independently() {
    assert!(!AgentConfig::default().tray.notifications);
    assert!(!AgentConfig::default().tray.status_notifier_item);
    assert_eq!(
        AgentConfig::from_toml("").unwrap().tray,
        TrayConfig::default()
    );

    let config = AgentConfig::from_toml("[tray]\nnotifications = true\n").unwrap();
    assert!(config.tray.notifications);
    assert!(!config.tray.status_notifier_item);

    let config = AgentConfig::from_toml("[tray]\nstatus_notifier_item = true\n").unwrap();
    assert!(!config.tray.notifications);
    assert!(config.tray.status_notifier_item);
}

#[test]
fn agent_dataplane_defaults_off_and_parses_explicit_section() {
    // All off by default: the agent does not touch the kernel (§10.3 wiring is
    // a deterministically visible failure before it exists).
    let d = AgentConfig::default();
    assert!(!d.dataplane.enabled);
    assert_eq!(d.dataplane.interface, "wg0");
    assert_eq!(d.dataplane.private_key_file, None);
    assert_eq!(d.dataplane.hub_endpoint, None);
    assert_eq!(d.dataplane.poll_interval_secs, 30);

    let c = AgentConfig::from_toml(
        r#"
server_url = "https://vps.example.com"
device_token = "tok-abc"

[dataplane]
enabled = true
interface = "mesh0"
private_key_file = "/etc/meshlet/device.key"
hub_endpoint = "vps.example.com:51820"
poll_interval_secs = 10
"#,
    )
    .unwrap();
    assert_eq!(c.device_token.as_deref(), Some("tok-abc"));
    assert!(c.dataplane.enabled);
    assert_eq!(c.dataplane.interface, "mesh0");
    assert_eq!(
        c.dataplane.private_key_file.as_deref(),
        Some("/etc/meshlet/device.key")
    );
    assert_eq!(
        c.dataplane.hub_endpoint.as_deref(),
        Some("vps.example.com:51820")
    );
    assert_eq!(c.dataplane.poll_interval_secs, 10);

    let c = AgentConfig::from_toml("[upgrade]\nenabled = true\ncheck_interval_secs = 300").unwrap();
    assert!(c.upgrade.enabled);
    assert_eq!(c.upgrade.check_interval_secs, 300);

    let d = AgentConfig::from_toml("").unwrap();
    assert!(!d.upgrade.enabled);
    assert_eq!(d.upgrade.check_interval_secs, 86_400);

    // Only `enabled` set: the rest keep their defaults.
    let c = AgentConfig::from_toml("[dataplane]\nenabled = true").unwrap();
    assert!(c.dataplane.enabled);
    assert_eq!(c.dataplane.interface, "wg0");
    assert_eq!(c.dataplane.poll_interval_secs, 30);
}

#[test]
fn dataplane_hub_endpoints_splits_comma_and_dedups() {
    // Absent / empty -> empty table (the "no fallback" semantics are kept).
    assert_eq!(
        AgentConfig::default().dataplane.hub_endpoints(),
        Vec::<String>::new()
    );
    let d = AgentConfig::from_toml("[dataplane]\nenabled = true").unwrap();
    assert_eq!(d.dataplane.hub_endpoints(), Vec::<String>::new());

    // Single endpoint (the legacy spelling): one-element table, so the
    // failover decision degenerates to always picking that entry.
    let d = AgentConfig::from_toml(
        "[dataplane]\nenabled = true\nhub_endpoint = \"vps.example.com:51820\"",
    )
    .unwrap();
    assert_eq!(
        d.dataplane.hub_endpoints(),
        vec!["vps.example.com:51820".to_string()]
    );

    // Multiple endpoints (failover batch): comma separated, each item trimmed,
    // empty segments dropped, deduplicated, order preserved.
    let d = AgentConfig::from_toml(
        "[dataplane]\nenabled = true\nhub_endpoint = \" a:51820 , b:51821 , a:51820 , , c:51822 \"",
    )
    .unwrap();
    assert_eq!(
        d.dataplane.hub_endpoints(),
        vec![
            "a:51820".to_string(),
            "b:51821".to_string(),
            "c:51822".to_string()
        ]
    );

    // The raw field stays a verbatim single string (contract compatibility;
    // readers do not change because of multiple endpoints).
    let d =
        AgentConfig::from_toml("[dataplane]\nenabled = true\nhub_endpoint = \"a:51820,b:51821\"")
            .unwrap();
    assert_eq!(d.dataplane.hub_endpoint.as_deref(), Some("a:51820,b:51821"));
}

#[test]
fn agent_dataplane_tunnel_backend_defaults_service_and_parses() {
    // The default is `service` (unchanged behaviour); this picks the Windows
    // dataplane backend.
    assert_eq!(
        AgentConfig::default().dataplane.tunnel_backend,
        TunnelBackend::Service
    );
    assert_eq!(
        AgentConfig::from_toml("").unwrap().dataplane.tunnel_backend,
        TunnelBackend::Service
    );

    let c = AgentConfig::from_toml("[dataplane]\ntunnel_backend = \"nt\"").unwrap();
    assert_eq!(c.dataplane.tunnel_backend, TunnelBackend::Nt);

    let c = AgentConfig::from_toml("[dataplane]\ntunnel_backend = \"service\"").unwrap();
    assert_eq!(c.dataplane.tunnel_backend, TunnelBackend::Service);

    // An unknown value fails closed (never silently fall back to `service` on
    // a typo).
    let err = AgentConfig::from_toml("[dataplane]\ntunnel_backend = \"wireguard\"").unwrap_err();
    assert!(matches!(err, ConfigError::InvalidDataPlane(_)));
}

#[test]
fn agent_dataplane_tunnel_backend_mac_boringtun_round_trips() {
    // ③-C pin: "mac-boringtun" parses to MacBoringtun, and as_str -> parse are
    // inverse operations (round-trip); walk all three variants.
    let c = AgentConfig::from_toml("[dataplane]\ntunnel_backend = \"mac-boringtun\"").unwrap();
    assert_eq!(c.dataplane.tunnel_backend, TunnelBackend::MacBoringtun);

    for (variant, text) in [
        (TunnelBackend::Service, "service"),
        (TunnelBackend::Nt, "nt"),
        (TunnelBackend::MacBoringtun, "mac-boringtun"),
    ] {
        assert_eq!(variant.as_str(), text);
        let parsed = AgentConfig::from_toml(&format!("[dataplane]\ntunnel_backend = \"{text}\""))
            .unwrap()
            .dataplane
            .tunnel_backend;
        assert_eq!(parsed, variant, "round-trip {text}");
    }

    // Near-miss spelling fails closed (`mac_boringtun` with an underscore is
    // not a legal string).
    let err =
        AgentConfig::from_toml("[dataplane]\ntunnel_backend = \"mac_boringtun\"").unwrap_err();
    assert!(matches!(err, ConfigError::InvalidDataPlane(_)));
}

#[test]
fn agent_dataplane_rejects_empty_interface_and_zero_poll() {
    let err = AgentConfig::from_toml(
        r#"
[dataplane]
enabled = true
interface = "  "
"#,
    )
    .unwrap_err();
    assert!(matches!(err, ConfigError::InvalidDataPlane(_)));

    let err = AgentConfig::from_toml("[dataplane]\npoll_interval_secs = 0").unwrap_err();
    assert!(matches!(err, ConfigError::InvalidDataPlane(_)));

    let err = AgentConfig::from_toml("[upgrade]\ncheck_interval_secs = 0").unwrap_err();
    assert!(matches!(err, ConfigError::InvalidUpgrade(_)));
}

#[test]
fn agent_direct_connect_defaults_on_and_parses_section() {
    // §12 P2P: a direct connection is the core goal; after batch ④ firewall
    // integration landed and the walk-through passed on two real machines, the
    // default flipped on. It is turned off only by an explicit
    // [dataplane.direct_connect] enabled = false.
    // The listen port defaults to 51820.
    let d = AgentConfig::default().dataplane.direct_connect;
    assert!(d.enabled);
    assert_eq!(d.listen_port, 51820);
    // Without a [dataplane] section it is likewise on by default.
    assert!(
        AgentConfig::from_toml("")
            .unwrap()
            .dataplane
            .direct_connect
            .enabled
    );

    let c = AgentConfig::from_toml(
        r#"
[dataplane.direct_connect]
enabled = false
listen_port = 20000
"#,
    )
    .unwrap();
    assert!(!c.dataplane.direct_connect.enabled);
    assert_eq!(c.dataplane.direct_connect.listen_port, 20000);
}

#[test]
fn agent_direct_connect_rejects_zero_port_and_unknown_key() {
    let err = AgentConfig::from_toml("[dataplane.direct_connect]\nlisten_port = 0").unwrap_err();
    assert!(matches!(err, ConfigError::InvalidDataPlane(_)));

    let err = AgentConfig::from_toml("[dataplane.direct_connect]\nbogus = 1").unwrap_err();
    assert!(matches!(err, ConfigError::Parse(_)));
}

#[test]
fn ssh_config_sync_defaults_off_and_requires_explicit_opt_in() {
    // Safety rule: writing the user's ~/.ssh is a sensitive surface, so it is
    // off everywhere by default -- nothing is written unless explicitly enabled.
    let d = AgentConfig::default().ssh_config_sync;
    assert!(!d.enabled);
    assert!(!d.manage_include);

    let none = AgentConfig::from_toml("").unwrap().ssh_config_sync;
    assert_eq!(none, SshConfigSyncConfig::OFF);

    let on = AgentConfig::from_toml(
        r#"
[ssh_config_sync]
enabled = true
manage_include = true
"#,
    )
    .unwrap()
    .ssh_config_sync;
    assert!(on.enabled);
    assert!(on.manage_include);

    // `manage_include` can be enabled on its own (it then only takes care of
    // the Include lines).
    let partial = AgentConfig::from_toml("[ssh_config_sync]\nenabled = true")
        .unwrap()
        .ssh_config_sync;
    assert!(partial.enabled);
    assert!(!partial.manage_include);

    let err = AgentConfig::from_toml("[ssh_config_sync]\nbogus = 1").unwrap_err();
    assert!(matches!(err, ConfigError::Parse(_)));
}

#[test]
fn ssh_config_sync_target_homes_parses_and_defaults_to_empty() {
    // Default / empty array = the legacy single-home semantics (only the home of
    // the account running the agent is written).
    let none = AgentConfig::from_toml("").unwrap().ssh_config_sync;
    assert!(none.target_homes.is_empty());
    let empty = AgentConfig::from_toml("[ssh_config_sync]\ntarget_homes = []")
        .unwrap()
        .ssh_config_sync;
    assert!(empty.target_homes.is_empty());

    let homes = AgentConfig::from_toml(
        r#"
[ssh_config_sync]
enabled = true
target_homes = ["/home/cui", "  ", "/root"]
"#,
    )
    .unwrap()
    .ssh_config_sync;
    assert_eq!(
        homes.target_homes,
        vec![
            std::path::PathBuf::from("/home/cui"),
            std::path::PathBuf::from("/root")
        ]
    );
}

#[test]
fn mcp_defaults_off_and_requires_explicit_opt_in() {
    // Safety rule: the listening surface is off by default -- nothing listens
    // unless explicitly enabled (2026-11-08).
    let d = AgentConfig::default().mcp;
    assert!(!d.enabled);
    assert_eq!(d.port, 0);

    let none = AgentConfig::from_toml("").unwrap().mcp;
    assert_eq!(none, McpConfig::default());

    let on = AgentConfig::from_toml("[mcp]\nenabled = true\nport = 8765\n")
        .unwrap()
        .mcp;
    assert!(on.enabled);
    assert_eq!(on.port, 8765);

    // Only `enabled` set: the port defaults to 0 (random, handed over via
    // mcp.json).
    let rand = AgentConfig::from_toml("[mcp]\nenabled = true").unwrap().mcp;
    assert!(rand.enabled);
    assert_eq!(rand.port, 0);

    let err = AgentConfig::from_toml("[mcp]\nbogus = 1").unwrap_err();
    assert!(matches!(err, ConfigError::Parse(_)));
}

#[test]
fn agent_probe_defaults_on_5s_and_parses_section() {
    // SEL-001: on by default -- direct_connect is on by default (98c75fe) and
    // the probe is its safety net (SEL-003's degrade-and-return-to-hub only
    // consumes a probe window; probe off = a degraded direct path pinned to a
    // black hole for good, the 2026-11-13 imac<->work5 incident on real
    // hardware). Interval 5s (task spec), window 20.
    let d = AgentConfig::default().dataplane.probe;
    assert!(d.enabled);
    assert_eq!(d.interval_secs, 5);
    assert_eq!(d.window, 20);
    // SEL-002 hysteresis defaults: 3 consecutive samples, 30% margin.
    assert_eq!(d.switch_required, 3);
    assert_eq!(d.switch_margin, 0.30);
    // SEL-003 recovery gate default: switch back only after 3 healthy rounds.
    assert_eq!(d.recovery_required, 3);
    // SEL-003 latency-degradation threshold default: a window RTT median of
    // >=800ms counts as degraded (blind band below the 1000ms probe timeout;
    // on real hardware 2026-11-13 a 1715ms probe_ok pinned the direct path).
    assert_eq!(d.degrade_rtt_ms, 800);
    // SEL-003 packet-loss spike threshold default: 20% (narrowed on 2026-11-17
    // from 50% -- a 49%-loss path passed as "healthy" under the old threshold;
    // measured ping showed a degraded path flipping between three states).
    assert_eq!(d.loss_spike, 0.20);
    // Scheme 1 defaults: switch cooldown interval×required×2 = 30s (within the
    // 60s cap), young-window exemption floor 4.
    assert_eq!(d.switch_cooldown_secs, 30);
    assert_eq!(d.degrade_min_samples, 4);
    // Without a [dataplane] section the defaults apply too.
    let d = AgentConfig::from_toml("").unwrap().dataplane.probe;
    assert!(d.enabled);
    assert_eq!(d.interval_secs, 5);
    assert_eq!(d.switch_required, 3);
    assert_eq!(d.switch_margin, 0.30);
    assert_eq!(d.recovery_required, 3);
    assert_eq!(d.degrade_rtt_ms, 800);
    assert_eq!(d.loss_spike, 0.20);
    assert_eq!(d.switch_cooldown_secs, 30);
    assert_eq!(d.degrade_min_samples, 4);

    let c = AgentConfig::from_toml(
        r#"
[dataplane.probe]
enabled = true
interval_secs = 2
window = 8
switch_required = 5
switch_margin_percent = 40
recovery_required = 4
degrade_rtt_ms = 500
loss_spike_percent = 30
"#,
    )
    .unwrap();
    assert!(c.dataplane.probe.enabled);
    assert_eq!(c.dataplane.probe.interval_secs, 2);
    assert_eq!(c.dataplane.probe.window, 8);
    assert_eq!(c.dataplane.probe.switch_required, 5);
    assert_eq!(c.dataplane.probe.switch_margin, 0.40);
    assert_eq!(c.dataplane.probe.recovery_required, 4);
    assert_eq!(c.dataplane.probe.degrade_rtt_ms, 500);
    assert_eq!(c.dataplane.probe.loss_spike, 0.30);
    // Cooldown default = interval×required×2 = 2×5×2 = 20 (not clamped, still
    // under the 60 cap).
    assert_eq!(c.dataplane.probe.switch_cooldown_secs, 20);
    assert_eq!(c.dataplane.probe.degrade_min_samples, 4);

    // An explicit cooldown / young-window exemption parses as usual; the
    // cooldown default is clamped to 60 when it exceeds the cap.
    let c = AgentConfig::from_toml(
        r#"
[dataplane.probe]
interval_secs = 60
switch_required = 10
switch_cooldown_secs = 45
degrade_min_samples = 6
"#,
    )
    .unwrap();
    assert_eq!(c.dataplane.probe.switch_cooldown_secs, 45);
    assert_eq!(c.dataplane.probe.degrade_min_samples, 6);
    let c = AgentConfig::from_toml(
        r#"
[dataplane.probe]
interval_secs = 60
switch_required = 10
"#,
    )
    .unwrap();
    assert_eq!(c.dataplane.probe.switch_cooldown_secs, 60, "clamped to cap");
}

#[test]
fn agent_probe_rejects_zero_interval_and_window() {
    let err = AgentConfig::from_toml("[dataplane.probe]\ninterval_secs = 0").unwrap_err();
    assert!(matches!(err, ConfigError::InvalidDataPlane(_)));

    let err = AgentConfig::from_toml("[dataplane.probe]\nwindow = 0").unwrap_err();
    assert!(matches!(err, ConfigError::InvalidDataPlane(_)));

    let err = AgentConfig::from_toml("[dataplane.probe]\nswitch_required = 0").unwrap_err();
    assert!(matches!(err, ConfigError::InvalidDataPlane(_)));

    let err = AgentConfig::from_toml("[dataplane.probe]\nswitch_margin_percent = 101").unwrap_err();
    assert!(matches!(err, ConfigError::InvalidDataPlane(_)));

    let err = AgentConfig::from_toml("[dataplane.probe]\nrecovery_required = 0").unwrap_err();
    assert!(matches!(err, ConfigError::InvalidDataPlane(_)));

    let err = AgentConfig::from_toml("[dataplane.probe]\ndegrade_rtt_ms = 0").unwrap_err();
    assert!(matches!(err, ConfigError::InvalidDataPlane(_)));

    let err = AgentConfig::from_toml("[dataplane.probe]\nloss_spike_percent = 101").unwrap_err();
    assert!(matches!(err, ConfigError::InvalidDataPlane(_)));

    // Scheme 1: cooldown cap is 60s (a longer one delays real failover); the
    // young-window exemption is >=1 and <= window.
    let err = AgentConfig::from_toml("[dataplane.probe]\nswitch_cooldown_secs = 61").unwrap_err();
    assert!(matches!(err, ConfigError::InvalidDataPlane(_)));

    let err = AgentConfig::from_toml("[dataplane.probe]\ndegrade_min_samples = 0").unwrap_err();
    assert!(matches!(err, ConfigError::InvalidDataPlane(_)));

    let err = AgentConfig::from_toml("[dataplane.probe]\nwindow = 8\ndegrade_min_samples = 9")
        .unwrap_err();
    assert!(matches!(err, ConfigError::InvalidDataPlane(_)));

    let err = AgentConfig::from_toml("[dataplane.probe]\nbogus = 1").unwrap_err();
    assert!(matches!(err, ConfigError::Parse(_)));
}

#[test]
fn agent_backoff_defaults_and_parses_explicit_section() {
    // FLIP-002 defaults: 30s base / 15min cap / cleared after 3 consecutive
    // healthy rounds (per the task spec; confirmations matches the SEL-003
    // RecoveryGate value).
    let d = AgentConfig::from_toml("[dataplane]\nenabled = true").unwrap();
    assert_eq!(d.dataplane.backoff.backoff_base_ms, 30_000);
    assert_eq!(d.dataplane.backoff.backoff_cap_ms, 900_000);
    assert_eq!(d.dataplane.backoff.recovery_confirmations, 3);

    let c = AgentConfig::from_toml(
        r#"
[dataplane]
[dataplane.backoff]
backoff_base_ms = 60_000
backoff_cap_ms = 600_000
recovery_confirmations = 5
"#,
    )
    .unwrap();
    assert_eq!(c.dataplane.backoff.backoff_base_ms, 60_000);
    assert_eq!(c.dataplane.backoff.backoff_cap_ms, 600_000);
    assert_eq!(c.dataplane.backoff.recovery_confirmations, 5);

    // Giving just one value: the rest keep their defaults.
    let c = AgentConfig::from_toml("[dataplane]\n[dataplane.backoff]\nbackoff_base_ms = 45_000")
        .unwrap();
    assert_eq!(c.dataplane.backoff.backoff_base_ms, 45_000);
    assert_eq!(c.dataplane.backoff.backoff_cap_ms, 900_000);
    assert_eq!(c.dataplane.backoff.recovery_confirmations, 3);
}

#[test]
fn agent_backoff_rejects_zero_base_and_cap_below_base() {
    let err = AgentConfig::from_toml("[dataplane]\n[dataplane.backoff]\nbackoff_base_ms = 0")
        .unwrap_err();
    assert!(matches!(err, ConfigError::InvalidDataPlane(_)));

    let err = AgentConfig::from_toml(
        "[dataplane]\n[dataplane.backoff]\nbackoff_base_ms = 600_000\nbackoff_cap_ms = 30_000",
    )
    .unwrap_err();
    assert!(matches!(err, ConfigError::InvalidDataPlane(_)));

    let err =
        AgentConfig::from_toml("[dataplane]\n[dataplane.backoff]\nrecovery_confirmations = 0")
            .unwrap_err();
    assert!(matches!(err, ConfigError::InvalidDataPlane(_)));
}
