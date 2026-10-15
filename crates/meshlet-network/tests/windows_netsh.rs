//! Windows 路由计划层的**真机**集成测试（[ADR-008](../../docs/decisions/adr-008-windows-network-backend.md)、
//! TODO #52）：在真实 netsh 上走 add → show 读回 → delete → 幂等 re-delete
//! 全程，并断言失败文本分类吃的是 Windows 真实报文而非fixture。
//!
//! 与 `backend_wiring.rs` 的纪律对称：被测路径走 `windows_routes::exec`
//! （计划层构造参数 + 计划层分类输出），裸 netsh 只作「外部视角」探针
//! （`show route` 读回、re-delete 的原始报文取证）。
//!
//! 平台与执行环境：
//! - 仅 Windows 编译执行（文件级 `#![cfg]`，Linux 上本二进制为空、
//!   CI linux job 不受影响）；CI windows-latest job 的
//!   `cargo test --workspace` 真跑本文件；
//! - 前提：提权 shell（hosted runner 默认满足）+ en-US 输出（runner 默认）。
//!
//! 测试网络卫生：前缀取 RFC 5737 文档保留段（`192.0.2.0/24`，绝不承载真实
//! 流量）；接口用恒在的回环接口；`store=active` 不跨重启持久；失败路径经
//! `RouteGuard`（Drop 删前缀）清理，re-delete 本身幂等，重复清理无害。
//!
//! **仍未覆盖（如实留缺口，TODO #52 保持未勾）**：权限拒绝路径的真实
//! elevation 报文——hosted runner 全程提权，`requires elevation` /
//! `access is denied` 无法自然产生；该映射由 `src/windows_routes.rs` 单测
//! 以 Windows canonical 文案固定。

#![cfg(target_os = "windows")]

use std::process::Command;

use meshlet_network::windows_routes::exec::run_route_command;
use meshlet_network::windows_routes::{
    route_already_absent, route_prefixes_on_interface, NetshRouteCommand,
};
use meshlet_network::{NetworkError, RouteConfig};

/// RFC 5737 TEST-NET-1：文档保留段，路由表里本不该出现，用后即删。
const TEST_PREFIX: &str = "192.0.2.0/24";
/// Windows 恒在的回环接口（多词名，顺带覆盖计划层引号渲染路径）。
const TEST_INTERFACE: &str = "Loopback Pseudo-Interface 1";
/// 不存在的接口名：真实 netsh 失败报文的取证探针。
const MISSING_INTERFACE: &str = "meshlet-no-such-if-01";

fn test_route(interface: &str) -> RouteConfig {
    RouteConfig {
        destination: TEST_PREFIX.parse().unwrap(),
        interface: interface.into(),
        gateway: None,
    }
}

fn delete_command() -> NetshRouteCommand {
    NetshRouteCommand::Delete {
        destination: TEST_PREFIX.parse().unwrap(),
        interface: TEST_INTERFACE.into(),
        gateway: None,
    }
}

/// 裸 netsh 探针（不经被测代码）：合并 stdout+stderr，返回 (exit, text)。
fn netsh_raw(args: &[String]) -> (i32, String) {
    let output = Command::new("netsh")
        .args(args)
        .output()
        .expect("spawn netsh");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.code().unwrap_or(-1), text)
}

/// 只保留含测试前缀/接口的行（CI 日志取证用，别刷全表）。
fn relevant_lines(table: &str) -> String {
    table
        .lines()
        .filter(|l| l.contains(TEST_PREFIX) || l.contains(TEST_INTERFACE))
        .collect::<Vec<_>>()
        .join("\n")
}

/// 失败也要清理：Drop 时尽力删除测试前缀（删除已不存在的路由按幂等成功
/// 处理，panic 与正常路径重复清理均无害）。
struct RouteGuard(NetshRouteCommand);

impl Drop for RouteGuard {
    fn drop(&mut self) {
        let _ = run_route_command(&self.0);
    }
}

/// 验收主干：add → `show route` 读回（计划层解析器 vs 真实表输出）→
/// delete → 前缀消失 → re-delete 的**真实报文**命中幂等判定 → exec 幂等
/// 成功契约。
#[test]
fn add_show_readback_delete_and_idempotent_redelete() {
    let add = NetshRouteCommand::Add {
        route: test_route(TEST_INTERFACE),
    };
    let delete = delete_command();

    // 1) add：提权 runner 上必须成功（若报 InsufficientPrivileges，说明
    //    runner 上下文变了——错误详情自带 netsh 原文）。
    let result =
        run_route_command(&add).expect("netsh add route must succeed on the elevated CI runner");
    assert!(result.applied);

    // 守卫从路由存在的那一刻起兜底：后续任一断言失败也清理。
    let _guard = RouteGuard(delete.clone());

    // 2) show route 读回：route_prefixes_on_interface 解析真实表输出，
    //    测试前缀落在回环接口上。
    let (_, table) = netsh_raw(&[
        "interface".into(),
        "ipv4".into(),
        "show".into(),
        "route".into(),
    ]);
    eprintln!(
        "netsh show route (relevant lines):\n{}",
        relevant_lines(&table)
    );
    let prefixes = route_prefixes_on_interface(&table, TEST_INTERFACE);
    assert!(
        prefixes.iter().any(|p| p.to_string() == TEST_PREFIX),
        "added route must read back on `{TEST_INTERFACE}`; parsed: {prefixes:?}"
    );

    // 3) delete → applied；4) show：前缀从该接口消失。
    let result = run_route_command(&delete).expect("netsh delete route");
    assert!(result.applied);
    let (_, table_after) = netsh_raw(&[
        "interface".into(),
        "ipv4".into(),
        "show".into(),
        "route".into(),
    ]);
    let prefixes_after = route_prefixes_on_interface(&table_after, TEST_INTERFACE);
    assert!(
        !prefixes_after.iter().any(|p| p.to_string() == TEST_PREFIX),
        "deleted route must be gone; parsed: {prefixes_after:?}"
    );

    // 5) re-delete 的真实报文取证：Windows 对删除不存在路由的原文必须
    //    命中 route_already_absent（报文改版这里会红，宁可红不假绿）。
    let (code, text) = netsh_raw(&[
        "interface".into(),
        "ipv4".into(),
        "delete".into(),
        "route".into(),
        format!("prefix={TEST_PREFIX}"),
        format!("interface={TEST_INTERFACE}"),
        "store=active".into(),
    ]);
    eprintln!("re-delete exit={code} raw output: {text}");
    assert!(
        route_already_absent(&text),
        "real Windows absence text must classify as idempotent delete: {text}"
    );

    // 6) exec 三态契约：对已不存在的路由再删 = Ok（失败可清理，§10.3）。
    let result = run_route_command(&delete)
        .expect("re-delete of an absent route must be idempotent success");
    assert!(result.applied);
}

/// 真实 netsh 失败文本的分类取证：对不存在的接口 add route →
/// fail closed 为 `ApplyRejected`，携带原文与接口名；**不得**误判成权限类
/// （真实报文没有权限字样——这是对宽匹配不误报的反向断言）。
#[test]
fn add_route_to_missing_interface_fails_closed_with_real_text() {
    let add = NetshRouteCommand::Add {
        route: test_route(MISSING_INTERFACE),
    };
    match run_route_command(&add) {
        Err(NetworkError::ApplyRejected(detail)) => {
            assert!(detail.contains(MISSING_INTERFACE), "{detail}");
            assert!(
                !detail.contains("(no output)"),
                "real netsh error text must be carried: {detail}"
            );
        }
        Err(NetworkError::InsufficientPrivileges(detail)) => {
            panic!("runner is elevated; a privilege denial here is unexpected: {detail}")
        }
        other => panic!("add on a missing interface must fail closed, got {other:?}"),
    }
}
