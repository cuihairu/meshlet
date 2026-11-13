//! `AgentConfig` 解析与默认值测试（server 侧测试内联在 server.rs）。

use super::*;

#[test]
fn agent_config_validates_url_scheme() {
    let c = AgentConfig::from_toml("server_url = \"https://vps.example.com\"").unwrap();
    assert_eq!(c.server_url, "https://vps.example.com");

    let err = AgentConfig::from_toml("server_url = \"ftp://vps.example.com\"").unwrap_err();
    assert!(matches!(err, ConfigError::InvalidServerUrl(_)));

    // 默认值可用。
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
    // 默认全关：agent 不碰内核（§10.3 接线前确定性失败可见）。
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

    // 只开 enabled：其余默认。
    let c = AgentConfig::from_toml("[dataplane]\nenabled = true").unwrap();
    assert!(c.dataplane.enabled);
    assert_eq!(c.dataplane.interface, "wg0");
    assert_eq!(c.dataplane.poll_interval_secs, 30);
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
    // §12 P2P：直连是核心目标，批次④防火墙联动已落地、双真机走查通过后
    // 默认改开。显式 [dataplane.direct_connect] enabled = false 才关闭。
    // 监听端口默认 51820。
    let d = AgentConfig::default().dataplane.direct_connect;
    assert!(d.enabled);
    assert_eq!(d.listen_port, 51820);
    // 缺 [dataplane] 段同样默认开启。
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
    // 安全铁律：写用户 ~/.ssh 属敏感面，默认全关——不显式开启不落盘。
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

    // manage_include 可以单独开（此时只多管 Include 行）。
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
    // 缺省/空数组 = 单 home 旧语义（只写运行账号自己的 home）。
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
    // 安全铁律：监听面默认关——不显式开启不监听（2026-11-08）。
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

    // 只开 enabled：端口默认 0（随机，写 mcp.json 交接）。
    let rand = AgentConfig::from_toml("[mcp]\nenabled = true").unwrap().mcp;
    assert!(rand.enabled);
    assert_eq!(rand.port, 0);

    let err = AgentConfig::from_toml("[mcp]\nbogus = 1").unwrap_err();
    assert!(matches!(err, ConfigError::Parse(_)));
}

#[test]
fn agent_probe_defaults_on_5s_and_parses_section() {
    // SEL-001：默认开——direct_connect 默认开（98c75fe），探测是它的安全网
    // （SEL-003 劣化回中继只吃探测窗口；探测关 = 劣化直连无限钉死黑洞，
    // 真机 2026-11-13 imac↔work5 事故）。周期 5s（任务书），窗口 20。
    let d = AgentConfig::default().dataplane.probe;
    assert!(d.enabled);
    assert_eq!(d.interval_secs, 5);
    assert_eq!(d.window, 20);
    // SEL-002 迟滞默认：连续 3 采样、裕量 30%。
    assert_eq!(d.switch_required, 3);
    assert_eq!(d.switch_margin, 0.30);
    // SEL-003 恢复门默认：连续 3 轮健康才切回。
    assert_eq!(d.recovery_required, 3);
    // SEL-003 时延劣化阈值默认：窗口 RTT 中位数 ≥800ms 判劣化（探测超时
    // 1000ms 之前盲带，真机 2026-11-13 1715ms probe_ok 钉直连）。
    assert_eq!(d.degrade_rtt_ms, 800);
    // 缺 [dataplane] 段同样取默认。
    let d = AgentConfig::from_toml("").unwrap().dataplane.probe;
    assert!(d.enabled);
    assert_eq!(d.interval_secs, 5);
    assert_eq!(d.switch_required, 3);
    assert_eq!(d.switch_margin, 0.30);
    assert_eq!(d.recovery_required, 3);
    assert_eq!(d.degrade_rtt_ms, 800);

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

    let err = AgentConfig::from_toml("[dataplane.probe]\nbogus = 1").unwrap_err();
    assert!(matches!(err, ConfigError::Parse(_)));
}
