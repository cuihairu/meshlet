//! Windows 路由计划层（[ADR-008](../../../docs/decisions/adr-008-windows-network-backend.md)）。
//!
//! 本模块是**纯规划**（与 [nat](../../../crates/meshlet-network/src/nat.rs) 模块同一
//! 模式）：netsh 路由命令的参数构造、`show route` 输出解析与失败文本分类，
//! 不执行任何命令——计划层函数在任意平台编译并单测（本仓 CI 的 Linux 侧
//! 即可跑绿）。
//!
//! 执行层是 [exec] 子模块，`#[cfg(windows)]` 下只调本模块的计划函数；
//! **未在 Windows 上实测**（本仓无 Windows 运行时，随 TODO #52 的环境走查
//! 补齐）。实测前 Windows 不接为 [crate::SystemBackend]——非 Linux 平台仍
//! 是 [unsupported](../../../crates/meshlet-network/src/unsupported.rs) 的显式
//! 占位，绝不假装有数据面（§10.3、§12.2）。
//!
//! ADR-008 的取舍在本模块落成三件事：
//!
//! - **受控命令**：只构造 `netsh interface ipv4 add/delete route` 的命名
//!   参数形式（`prefix=` / `interface=` / `nexthop=` / `store=active`），
//!   不拼接自由文本；接口名含空格时值整体加引号（WireGuard 隧道名允许
//!   空格，而 netsh 命名参数必须是单个词元）；
//! - **权限不足提示明确**：`requires elevation` / `access is denied` 文案
//!   归入 [`NetworkError::InsufficientPrivileges`]，消息点名操作与接口；
//! - **失败可清理**：删除目标不存在的路由（`element not found` 等）按
//!   幂等成功处理；未知失败文本 fail closed 为
//!   [`NetworkError::ApplyRejected`] 并携带 netsh 原始行。
//!
//! `store=active`（非持久）与 agent 对账模型一致：路由不跨重启残留，漂移
//! 由 agent 重放纠回（重启重放语义见 ADR-009）。

use std::net::Ipv4Addr;

use meshlet_domain::Ipv4Cidr;

use crate::{NetworkError, RouteConfig};

/// 一条受控 netsh 路由命令（计划态；执行见 [exec]）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetshRouteCommand {
    /// 添加一条路由（`gateway = None` 为 on-link 路由，无 `nexthop=`）。
    Add { route: RouteConfig },
    /// 删除一条路由；目标不存在按幂等成功处理（失败可清理）。
    Delete {
        destination: Ipv4Cidr,
        interface: String,
        gateway: Option<Ipv4Addr>,
    },
}

impl NetshRouteCommand {
    /// netsh 参数（含 `interface ipv4 add/delete route` 前缀；单测与执行层
    /// 共用同一构造，计划与执行不漂移——与
    /// [nat::NatRule::iptables_args](../../../crates/meshlet-network/src/nat.rs)
    /// 同一纪律）。
    pub fn args(&self) -> Vec<String> {
        let mut args = vec!["interface".into(), "ipv4".into()];
        let (verb, destination, interface, gateway) = match self {
            NetshRouteCommand::Add { route } => {
                ("add", route.destination, &route.interface, route.gateway)
            }
            NetshRouteCommand::Delete {
                destination,
                interface,
                gateway,
            } => ("delete", *destination, interface, *gateway),
        };
        args.push(verb.into());
        args.push("route".into());
        args.push(format!("prefix={destination}"));
        args.push(named_value("interface", interface));
        if let Some(gateway) = gateway {
            args.push(format!("nexthop={gateway}"));
        }
        // store=active：路由不跨重启持久（agent 对账重放纠回，ADR-009）。
        args.push("store=active".into());
        args
    }

    /// 操作名（错误消息点名用）。
    pub fn operation(&self) -> &'static str {
        match self {
            NetshRouteCommand::Add { .. } => "route add",
            NetshRouteCommand::Delete { .. } => "route delete",
        }
    }

    /// 受管接口名（错误消息点名用）。
    pub fn interface(&self) -> &str {
        match self {
            NetshRouteCommand::Add { route } => &route.interface,
            NetshRouteCommand::Delete { interface, .. } => interface,
        }
    }

    pub fn is_delete(&self) -> bool {
        matches!(self, NetshRouteCommand::Delete { .. })
    }
}

/// `key=value` 形式的 netsh 命名参数；值含空白时整体加引号
/// （`interface="Meshlet Office"`——netsh 的命名参数是单个词元）。
fn named_value(key: &str, value: &str) -> String {
    if value.split_whitespace().count() > 1 {
        format!("{key}=\"{value}\"")
    } else {
        format!("{key}={value}")
    }
}

/// 修改一条路由 = **删除重建**（与控制面路由同习语：无 PATCH，修改 = 删除
/// 重建）。netsh 没有 `set route`；语义上等价于先删旧前缀再建新前缀，
/// 两步各是一次受控调用。
pub fn replace_route_commands(old: &RouteConfig, new: &RouteConfig) -> Vec<NetshRouteCommand> {
    vec![
        NetshRouteCommand::Delete {
            destination: old.destination,
            interface: old.interface.clone(),
            gateway: old.gateway,
        },
        NetshRouteCommand::Add { route: new.clone() },
    ]
}

/// 把 netsh 的退出码与输出分类为后端错误（纯函数，任意平台单测）。
///
/// 权限类文案**刻意宽匹配**（不区分大小写的子串）：Windows 各版本对
/// ERROR_ELEVATION_REQUIRED（740）与 ERROR_ACCESS_DENIED（5）的文案不完全
/// 一致，宁可把模糊的权限失败归入「权限不足」（提示明确），也绝不把
/// 权限问题误报成别的原因。其余失败 fail closed 为
/// [`NetworkError::ApplyRejected`]（未知 ≠ 成功，§8.3）。
pub fn classify_netsh_route_failure(
    exit_code: i32,
    output: &str,
    operation: &str,
    interface: &str,
) -> NetworkError {
    let lowered = output.to_lowercase();
    if lowered.contains("requires elevation") || lowered.contains("access is denied") {
        return NetworkError::InsufficientPrivileges(format!(
            "netsh {operation} on interface `{interface}` requires administrator \
             privileges (run from an elevated shell); netsh said: {}",
            first_nonempty_line(output)
        ));
    }
    NetworkError::ApplyRejected(format!(
        "netsh {operation} on interface `{interface}` failed (exit {exit_code}): {}",
        first_nonempty_line(output)
    ))
}

/// netsh 删除报「目标不存在」= 幂等成功（清理路径清到空态不算失败，
/// §10.3 失败可清理）。同样按子串宽匹配，覆盖各版本文案差异。
pub fn route_already_absent(output: &str) -> bool {
    let lowered = output.to_lowercase();
    lowered.contains("element not found") || lowered.contains("cannot find")
}

/// 输出的首个非空行（错误消息携带 netsh 原文，便于诊断）。
fn first_nonempty_line(output: &str) -> &str {
    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("(no output)")
}

/// 解析 `netsh interface ipv4 show route` 的表格式输出，取**落在指定接口**
/// 上的 IPv4 前缀（对账用：Windows 侧 `installed_routes` 的读数来源）。
///
/// 判定按行进行：行内唯一可解析为 [Ipv4Cidr] 的词元是前缀列；行尾词元
/// 序列等于接口名词元序列（接口名可含空格，如 `Loopback Pseudo-Interface 1`）。
/// IPv6 行（`::/0` 等）解析失败自然跳过；表头/分隔行无 CIDR 词元自然跳过。
pub fn route_prefixes_on_interface(output: &str, interface: &str) -> Vec<Ipv4Cidr> {
    let name: Vec<&str> = interface.split_whitespace().collect();
    output
        .lines()
        .filter_map(|line| {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let prefix = tokens.iter().find_map(|t| t.parse::<Ipv4Cidr>().ok())?;
            let trailing = tokens.len().saturating_sub(name.len());
            (tokens.get(trailing..)? == name.as_slice()).then_some(prefix)
        })
        .collect()
}

/// 执行层（`#[cfg(windows)]`）：只负责把计划函数构造的参数交给 netsh、
/// 把输出交回计划层分类，没有其他逻辑。
///
/// **未在 Windows 上实测**（本仓无 Windows 运行时）。TODO #52 的环境走查
/// 之前 Windows 不接为 [crate::SystemBackend]——非 Linux 平台保持
/// [unsupported](../../../crates/meshlet-network/src/unsupported.rs) 的显式
/// 占位，不假装有数据面。
#[cfg(target_os = "windows")]
pub mod exec {
    use super::{classify_netsh_route_failure, route_already_absent, NetshRouteCommand};
    use crate::{ApplyResult, NetworkError};

    /// 执行一条受控 netsh 路由命令：成功/幂等成功/分类失败三态。
    pub fn run_route_command(command: &NetshRouteCommand) -> Result<ApplyResult, NetworkError> {
        let output = std::process::Command::new("netsh")
            .args(command.args())
            .output()
            .map_err(|error| NetworkError::Io(format!("spawn netsh: {error}")))?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        if output.status.success() {
            return Ok(ApplyResult::ok());
        }
        // 删除目标已不存在 = 幂等成功（清理路径清到空态不算失败）。
        if command.is_delete() && route_already_absent(&text) {
            return Ok(ApplyResult::ok());
        }
        Err(classify_netsh_route_failure(
            output.status.code().unwrap_or(-1),
            &text,
            command.operation(),
            command.interface(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(interface: &str, gateway: Option<Ipv4Addr>) -> RouteConfig {
        RouteConfig {
            destination: "10.241.1.0/24".parse().unwrap(),
            interface: interface.into(),
            gateway,
        }
    }

    /// 命名参数形式 + store=active；带网关的路由含 nexthop=。
    #[test]
    fn add_route_renders_named_netsh_form_with_gateway() {
        let command = NetshRouteCommand::Add {
            route: route("meshlet", Some("10.240.0.4".parse().unwrap())),
        };
        assert_eq!(
            command.args(),
            vec![
                "interface",
                "ipv4",
                "add",
                "route",
                "prefix=10.241.1.0/24",
                "interface=meshlet",
                "nexthop=10.240.0.4",
                "store=active",
            ]
        );
    }

    /// on-link 路由（无网关）不产生 nexthop= 词元。
    #[test]
    fn add_route_without_gateway_is_on_link() {
        let command = NetshRouteCommand::Add {
            route: route("meshlet", None),
        };
        let args = command.args();
        assert_eq!(
            args[..4],
            [
                "interface".to_string(),
                "ipv4".into(),
                "add".into(),
                "route".into()
            ]
        );
        assert!(!args.iter().any(|a| a.starts_with("nexthop=")));
        assert_eq!(args.last().unwrap(), "store=active");
    }

    /// 删除与添加共用同一命名参数形式（动词不同）。
    #[test]
    fn delete_route_renders_named_netsh_form() {
        let command = NetshRouteCommand::Delete {
            destination: "10.241.1.0/24".parse().unwrap(),
            interface: "meshlet".into(),
            gateway: Some("10.240.0.4".parse().unwrap()),
        };
        assert_eq!(
            command.args(),
            vec![
                "interface",
                "ipv4",
                "delete",
                "route",
                "prefix=10.241.1.0/24",
                "interface=meshlet",
                "nexthop=10.240.0.4",
                "store=active",
            ]
        );
        assert_eq!(command.operation(), "route delete");
        assert!(command.is_delete());
    }

    /// 接口名含空格（WireGuard 隧道名允许）时值整体加引号——netsh 命名
    /// 参数必须是单个词元。
    #[test]
    fn interface_names_with_spaces_are_quoted() {
        let command = NetshRouteCommand::Add {
            route: route("Meshlet Office", None),
        };
        assert!(command
            .args()
            .contains(&"interface=\"Meshlet Office\"".to_string()));
        let plain = NetshRouteCommand::Add {
            route: route("meshlet", None),
        };
        assert!(plain.args().contains(&"interface=meshlet".to_string()));
    }

    /// 修改 = 删除重建，顺序固定（先删旧前缀再建新前缀）。
    #[test]
    fn replace_is_delete_then_add_in_order() {
        let old = route("meshlet", Some("10.240.0.4".parse().unwrap()));
        let new = RouteConfig {
            destination: "10.242.1.0/24".parse().unwrap(),
            interface: "meshlet".into(),
            gateway: Some("10.240.0.5".parse().unwrap()),
        };
        assert_eq!(
            replace_route_commands(&old, &new),
            vec![
                NetshRouteCommand::Delete {
                    destination: old.destination,
                    interface: old.interface.clone(),
                    gateway: old.gateway,
                },
                NetshRouteCommand::Add { route: new.clone() },
            ]
        );
    }

    /// 「权限不足提示明确」：elevation 文案 → InsufficientPrivileges，
    /// 消息点名操作与接口，并带 netsh 原文（管理员提示可执行）。
    #[test]
    fn elevation_failure_maps_to_insufficient_privileges_naming_operation_and_interface() {
        let error = classify_netsh_route_failure(
            1,
            "The requested operation requires elevation.",
            "route add",
            "meshlet",
        );
        match error {
            NetworkError::InsufficientPrivileges(detail) => {
                assert!(detail.contains("route add"), "{detail}");
                assert!(detail.contains("meshlet"), "{detail}");
                assert!(detail.contains("administrator"), "{detail}");
                assert!(detail.contains("requires elevation"), "{detail}");
            }
            other => panic!("elevation must map to InsufficientPrivileges, got {other:?}"),
        }
    }

    /// access denied 与 elevation 同归权限类（不区分大小写的子串宽匹配）。
    #[test]
    fn access_denied_also_maps_to_insufficient_privileges() {
        let error = classify_netsh_route_failure(1, "Access is denied.", "route delete", "meshlet");
        assert!(matches!(error, NetworkError::InsufficientPrivileges(_)));
    }

    /// 未知失败文本 fail closed 为 ApplyRejected：携带操作、接口、退出码与
    /// netsh 原始行（未知 ≠ 成功，§8.3）。
    #[test]
    fn unknown_failure_fails_closed_as_rejection_with_raw_line() {
        let error = classify_netsh_route_failure(
            1,
            "\r\nThe parameter is incorrect.\r\n",
            "route add",
            "meshlet",
        );
        match error {
            NetworkError::ApplyRejected(detail) => {
                assert!(detail.contains("route add"), "{detail}");
                assert!(detail.contains("meshlet"), "{detail}");
                assert!(detail.contains("exit 1"), "{detail}");
                assert!(detail.contains("The parameter is incorrect."), "{detail}");
            }
            other => panic!("unknown text must fail closed, got {other:?}"),
        }
    }

    /// 「失败可清理」：删除目标不存在按幂等成功处理——各版本文案宽匹配。
    #[test]
    fn absent_route_output_counts_as_idempotent_delete() {
        assert!(route_already_absent("Element not found."));
        assert!(route_already_absent(
            "The system cannot find the file specified."
        ));
        assert!(!route_already_absent("Ok."));
        assert!(!route_already_absent(""));
    }

    /// `show route` 表输出按接口过滤前缀：表头/分隔行与 IPv6 行自然跳过，
    /// 接口名可含空格（行尾词元序列匹配）。
    #[test]
    fn show_route_output_scopes_prefixes_to_the_interface() {
        let output = "\
Publish  Type      Met   Prefix                    Idx  Gateway/Interface Name
-------  --------  ----  ------------------------  ---  ------------------------
No       System    256   127.0.0.0/8                1   Loopback Pseudo-Interface 1
No       System    0     ::/0                      17  meshlet
No       Manual    0     10.241.1.0/24             17  10.240.0.4 meshlet
No       Manual    0     10.242.1.0/24             12  10.240.0.9 Meshlet Office
";
        assert_eq!(
            route_prefixes_on_interface(output, "meshlet"),
            vec![
                "10.241.1.0/24".parse::<Ipv4Cidr>().unwrap(),
                // ::/0 解析不出 IPv4 CIDR，自然跳过。
            ]
        );
        assert_eq!(
            route_prefixes_on_interface(output, "Meshlet Office"),
            vec!["10.242.1.0/24".parse::<Ipv4Cidr>().unwrap()]
        );
        assert!(route_prefixes_on_interface(output, "unknown-if").is_empty());
    }
}
