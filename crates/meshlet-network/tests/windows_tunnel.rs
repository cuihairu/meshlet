//! Windows 隧道计划层 + 执行层可运行面的集成测试（[ADR-008]）。
//!
//! 与 [windows_netsh](windows_netsh)、[windows_cleanup_e2e](windows_cleanup_e2e)
//! 同一文件级 `#![cfg]` 纪律：仅 Windows 编译执行，CI windows-latest job 的
//! `cargo test --workspace` 真跑本文件，Linux job 不受影响。
//!
//! **不触发真实隧道安装**（CI hosted runner 未装 WireGuardNT 驱动，也无
//! 意在此创建内核隧道）：本文件只覆盖无需驱动、无需提权的执行面——conf
//! 写入回读（字节一致、覆盖重写 = 幂等 re-apply）与 exec 入口签名锁定。
//!
//! **仍未覆盖（如实留缺口，R-05 保持未勾）**：WireGuardNT 驱动安装后的
//! 隧道全生命周期（install → start → stop → uninstall）、提权执行层真机
//! 报文、开机恢复重启验证，以及据此做出的 [crate::SystemBackend] 接线决策；
//! 见 ADR-008 复审条件。wireguard.exe 命令形状在计划层单测锁定（Windows
//! canonical argv），真实二进制的透传语义待上述真机验收闭环。

#![cfg(target_os = "windows")]

use meshlet_domain::Ipv4Cidr;
use meshlet_network::windows_tunnel::{
    conf_file_name,
    exec::{run_wireguard_command, write_tunnel_conf},
    render_wireguard_conf, WireGuardCommand,
};
use meshlet_network::{ApplyResult, NetworkError, PeerConfig, TunnelConfig};
use std::path::{Path, PathBuf};

/// 隧道探针名：专用前缀，绝不触碰机器全局服务/隧道对象。
const PROBE_TUNNEL: &str = "__meshlet_probe_tunnel";

fn probe_tunnel_config() -> TunnelConfig {
    TunnelConfig {
        name: PROBE_TUNNEL.into(),
        address: "10.240.0.7".parse().unwrap(),
        address_prefix: 32,
        listen_port: Some(51820),
        peers: vec![PeerConfig {
            public_key: "PROBE-PUBLIC-KEY-BASE64==".into(),
            allowed_ips: vec!["10.240.0.1/32".parse::<Ipv4Cidr>().unwrap()],
            endpoint: Some("198.51.100.10:51820".into()),
            persistent_keepalive_secs: Some(25),
        }],
        mtu: None,
        private_key: Some("PROBE-PRIVATE-KEY-BASE64==".into()),
    }
}

fn probe_conf_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "meshlet-tunnel-int-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// exec 入口签名锁定：只接收计划命令与可执行覆盖、返回计划层结果；测试不
/// 启动 wireguard.exe、不触碰真实隧道。
#[test]
fn exec_entrypoint_takes_planned_command_and_returns_planned_result() {
    fn assert_signature(
        _run: fn(&WireGuardCommand, Option<&Path>) -> Result<ApplyResult, NetworkError>,
    ) {
    }
    assert_signature(run_wireguard_command);
}

/// conf 写入回读：字节一致（私钥 base64 不被转码破坏），覆盖重写 = 幂等
/// re-apply。
#[test]
fn conf_write_round_trips_and_overwrite_is_idempotent() {
    let path = probe_conf_path();
    let conf = render_wireguard_conf(&probe_tunnel_config());
    write_tunnel_conf(&path, &conf).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), conf);

    let mut rotated = probe_tunnel_config();
    rotated.private_key = Some("ROTATED-PROBE-KEY-BASE64==".into());
    let rotated_conf = render_wireguard_conf(&rotated);
    write_tunnel_conf(&path, &rotated_conf).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), rotated_conf);
    assert!(rotated_conf.contains("ROTATED-PROBE-KEY-BASE64=="));

    let _ = std::fs::remove_file(&path);
}

/// 计划层渲染经 exec 写盘闭环：文件即渲染文本，隧道名/密钥行原样保留。
#[test]
fn plan_renders_through_write_path_unchanged() {
    let path = probe_conf_path();
    let config = probe_tunnel_config();
    let conf = render_wireguard_conf(&config);
    write_tunnel_conf(&path, &conf).unwrap();
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(on_disk.contains(&format!("Name = {PROBE_TUNNEL}\n")));
    assert!(on_disk.contains("PrivateKey = PROBE-PRIVATE-KEY-BASE64==\n"));
    assert!(on_disk.contains("AllowedIPs = 10.240.0.1/32\n"));
    assert_eq!(on_disk, conf);
    assert_eq!(conf_file_name(PROBE_TUNNEL), "__meshlet_probe_tunnel.conf");

    let _ = std::fs::remove_file(&path);
}
