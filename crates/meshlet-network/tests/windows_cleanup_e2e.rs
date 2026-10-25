//! Windows 卸载链真机集成测试（ADR-008 TODO #52 取证）：在真实 sc.exe /
//! netsh 上走服务 create → stop（从未启动 1062 幂等）→ delete → re-delete
//! （1060 幂等）与防火墙 add → delete → re-delete（本地化缺失文案幂等）
//! 全程，最后以空态 CleanupPlan 重入验证「清理清到空态不算失败」（§10.3）。
//!
//! 真机取证（2026-10-26，中文 Windows Server，CP936 输出经
//! `windows_console` 解码）：
//! - `sc stop` 从未启动的服务 → exit 1062「[SC] ControlService 失败 1062:
//!   服务尚未启动。」——Stop 的目标状态是「已停止」，未运行 = 已达成；
//! - `sc delete` 不存在的服务 → exit 1060「指定的服务未安装。」；
//! - `netsh firewall delete rule` 无匹配 →「没有与指定标准相匹配的规则。」。
//!
//! 测试卫生：服务/规则名用 `__meshlet_probe_*` 专用前缀（绝不扫描或触碰
//! 机器全局对象）；服务 binPath 指向系统内置 cmd.exe 且从不 start；
//! RouteGuard 式 Drop 兜底清理，断言失败时重复删除均幂等无害。

#![cfg(target_os = "windows")]

use meshlet_network::windows_cleanup::{exec::run_cleanup_command, CleanupPlan};
use meshlet_network::windows_firewall::{
    exec::run_firewall_command, FirewallAction, FirewallDirection, FirewallProfile,
    FirewallProtocol, FirewallRule, FirewallRuleCommand,
};
use meshlet_network::windows_service::{
    exec::run_service_command, ServiceCommand, ServiceStartMode,
};

/// 服务探针名：专用前缀，绝不触碰机器全局服务。
const PROBE_SERVICE: &str = "__meshlet_probe_svc";
/// 防火墙探针规则名：专用前缀。
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

/// 失败兜底：Drop 时尽力删除两个探针目标（删除已不存在者幂等，重复清理
/// 无害）。
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
    }
}

/// 卸载重入主干：任意半状态（已删/从未启动/规则缺失）下每一步都幂等成功。
#[test]
fn uninstall_chain_is_reentrant_from_partial_states() {
    // 0) 空态预热：直接删除不存在的服务/规则必须幂等成功（Drop 兜底清理
    //    走的同一条路径）。
    run_service_command(&delete_probe_service()).expect("delete of absent service must be idempotent");
    run_firewall_command(&delete_probe_rule()).expect("delete of absent rule must be idempotent");

    let _guard = ProbeGuard;

    // 1) create（disabled，从不 start）：卸载链的入口。
    let create = ServiceCommand::Create {
        name: PROBE_SERVICE.into(),
        bin_path: r"C:\Windows\System32\cmd.exe".into(),
        start_mode: ServiceStartMode::Disabled,
    };
    let result = run_service_command(&create).expect("sc create probe service");
    assert!(result.applied);

    // 2) stop 从未启动的服务：真机 1062「服务尚未启动。」→ 幂等成功
    //    （Stop 的目标状态是「已停止」）。
    let result = run_service_command(&ServiceCommand::Stop {
        name: PROBE_SERVICE.into(),
    })
    .expect("stop of never-started service must be idempotent success");
    assert!(result.applied);

    // 3) delete → 4) re-delete：真机 1060 本地化文案 → 幂等成功。
    let result = run_service_command(&delete_probe_service()).expect("sc delete probe service");
    assert!(result.applied);
    let result = run_service_command(&delete_probe_service())
        .expect("re-delete of absent service must be idempotent success");
    assert!(result.applied);

    // 5) 防火墙 add → delete → re-delete：本地化缺失文案经 windows_console
    //    解码后命中幂等判定。
    let result = run_firewall_command(&FirewallRuleCommand::Add {
        rule: probe_rule(),
    })
    .expect("netsh add probe rule");
    assert!(result.applied);
    let result = run_firewall_command(&delete_probe_rule()).expect("netsh delete probe rule");
    assert!(result.applied);
    let result = run_firewall_command(&delete_probe_rule())
        .expect("re-delete of absent rule must be idempotent success");
    assert!(result.applied);

    // 6) 空态 CleanupPlan 重入：计划里的每一步（服务 stop/delete、路由
    //    delete、防火墙 delete）目标都已缺失，全部必须幂等成功——
    //    卸载可从任意半状态重入到空态。
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
