//! AGENT-FW-1 真机验收（Windows，CI `windows-latest` 管理员态）：
//! 计划层产出的 netsh / PowerShell 命令在**真实 Windows 防火墙**上全链路
//! 跑通且幂等——todo.md 原判定「真机 ping 直接通验收需 Windows 真机」，本
//! 文件用 CI 的真实 Windows 机器补上「命令形状 + 幂等重跑」的真机证据层
//! （端到端 ping 仍以真机验收为准）。非 Windows 目标整个文件为空，Linux CI
//! 直接跳过。

#![cfg(windows)]

use meshlet_network::windows_firewall::{
    exec::run_mesh_firewall_command, firewall_rule_present, mesh_icmp_rule,
    net_category_is_private, rule_output_has_satisfied_icmp_rule, IcmpRuleState,
    MeshFirewallCommand,
};
use meshlet_network::{ApplyResult, NetworkError};

/// 跑一条命令并取合并输出（netsh 输出按活动代码页编码；测试断言只用
/// ASCII 关键词与「规则存在」语义，不依赖本地化文案）。
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

/// `netsh advfirewall firewall show rule name=<name>`（计划层同一前缀形状）。
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

/// `netsh advfirewall firewall delete rule name=<name>`（与
/// [`meshlet_network::windows_firewall::FirewallRuleCommand::Delete`] 同形状，
/// 测试内就地构造避免为清理路径引入额外导出）。
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

/// 真机全链路：add → show 读回在 → 重跑 apply 探测（规则已在 → 幂等空计划）
/// → delete → show 读回不在。这就是 agent 每轮 apply 走的「探测 + 幂等补齐」
/// 路径在真实防火墙上的形状验证；规则用生产名 `Meshlet-ICMPv4-In`，
/// `localip=127.0.0.1`（测试机回环，不碰真实网段），测试末尾清理。
#[test]
fn icmp_rule_add_show_delete_roundtrip_is_idempotent_on_a_real_firewall() {
    let rule = mesh_icmp_rule("127.0.0.1".parse().unwrap());
    let name = rule.name.clone();
    // 起点清理：残留规则先删（幂等：不存在也成功）。
    delete_rule(&name);

    // add（agent apply 的真实执行路径）。
    let applied =
        run_mesh_firewall_command(&MeshFirewallCommand::AddIcmpRule { rule: rule.clone() })
            .expect("add Meshlet-ICMPv4-In");
    assert_eq!(applied, ApplyResult::ok());

    // show 读回：规则确实存在（netsh 无 query 语义，show + 存在性判定同源）。
    let (_, shown) = show_rule(&name);
    assert!(
        firewall_rule_present(&shown),
        "rule must be present after add; netsh said: {shown:?}"
    );

    // 幂等重跑：探测已满足 → 计划为空（agent 不会重复 add）。状态从真实
    // show 输出按计划层同款谓词推导（在场 + 已启用 + localip 匹配）。
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

    // delete → show 读回不在（撤销路径真机取证）。
    delete_rule(&name);
    let (_, gone) = show_rule(&name);
    assert!(
        !firewall_rule_present(&gone),
        "rule must be absent after delete; netsh said: {gone:?}"
    );
}

/// 真机档位：`Set-NetConnectionProfile -NetworkCategory Private` 在真实
/// 接口上执行两次（幂等可重跑）后读回确为 Private。接口取自
/// `Get-NetConnectionProfile`（保证存在连接档位；CI runner 的以太网接口）。
/// runner 的接口别名常含空格（`Ethernet 1`），不满足计划层的注入防线字符
/// 集——就地重命名为合法别名（一次性，runner 是可丢弃机器）。
#[test]
fn network_category_private_set_is_idempotent_on_a_real_interface() {
    // 找一个有连接档位的接口（runner 的物理/虚拟网卡都有）。
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

    // 别名不满足计划层注入防线字符集（如含空格）→ 重命名为合法名。
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

    // 接口名进 PowerShell 单引号字符串——与生产同一注入防线（计划层校验）。
    let set = MeshFirewallCommand::set_network_category_private(&interface)
        .expect("planned interface name must pass injection validation");
    // 连设两次：第二次是幂等重跑（已是 Private 再设仍成功）。
    run_mesh_firewall_command(&set).expect("first set");
    run_mesh_firewall_command(&set).expect("idempotent re-set");

    // 读回档位（agent 的探测同款命令）。
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

/// 编译期锁定：权限类失败在真机上仍归 `InsufficientPrivileges`（非管理员
/// 跑 netsh add 的真实报文路径；CI runner 为管理员态，此处用计划层分类器
/// 对真实 `access is denied` 文本断言，保证执行层分类与真机文案对齐）。
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
