//! Windows 防火墙计划层（[ADR-008](../../../docs/decisions/adr-008-windows-network-backend.md)）。
//!
//! 本模块包含**纯规划**与 `#[cfg(windows)]` 执行层：`netsh advfirewall
//! firewall add/delete rule` 的参数构造、失败文本分类与受控执行。计划层
//! 函数在任意平台编译并单测（本仓 CI 的 Linux 侧即可跑绿）；执行层**未在
//! Windows 上实测**，实测前 Windows 仍保持 [crate::unsupported] 的显式
//! 占位，不接 [crate::SystemBackend]。
//!
//! 与 [windows_routes](../../../crates/meshlet-network/src/windows_routes.rs)
//! 同一纪律：
//!
//! - **受控命令**：只构造 `name=` / `dir=` / `action=` / `protocol=` /
//!   `localport=` / `remoteport=` / `profile=` 等命名参数；`key=value` 对
//!   保持单个 argv 词元，含空格的规则名（如 `Meshlet WireGuard`）不拆词，
//!   也**不内嵌引号**（netsh 引号语义见 [windows_routes] 的实测注记）；
//! - **确定性**：Add 的字段顺序固定；profile 多值固定为
//!   `domain,private,public`，重复值去重，未显式提供时用 `any`；
//! - **fail closed**：权限文案宽匹配映射为
//!   [`NetworkError::InsufficientPrivileges`]；删除规则已不存在的文案按
//!   幂等成功；其他未知失败统一 [`NetworkError::ApplyRejected`] 并携带
//!   netsh 原文首行。

use crate::NetworkError;

/// 防火墙规则方向（netsh `dir=` 的受控取值）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallDirection {
    Inbound,
    Outbound,
}

impl FirewallDirection {
    fn as_str(self) -> &'static str {
        match self {
            FirewallDirection::Inbound => "in",
            FirewallDirection::Outbound => "out",
        }
    }
}

/// 防火墙规则动作（netsh `action=` 的受控取值）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallAction {
    Allow,
    Block,
}

impl FirewallAction {
    fn as_str(self) -> &'static str {
        match self {
            FirewallAction::Allow => "allow",
            FirewallAction::Block => "block",
        }
    }
}

/// 受控协议；`Any` 是 netsh 的缺省语义，显式渲染避免参数形状漂移。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallProtocol {
    Any,
    Tcp,
    Udp,
}

impl FirewallProtocol {
    fn as_str(self) -> &'static str {
        match self {
            FirewallProtocol::Any => "any",
            FirewallProtocol::Tcp => "tcp",
            FirewallProtocol::Udp => "udp",
        }
    }
}

/// 防火墙 profile；渲染顺序固定且与 netsh 常见写法一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FirewallProfile {
    Domain,
    Private,
    Public,
}

impl FirewallProfile {
    fn as_str(self) -> &'static str {
        match self {
            FirewallProfile::Domain => "domain",
            FirewallProfile::Private => "private",
            FirewallProfile::Public => "public",
        }
    }
}

/// 受控规则描述。计划层从类型化字段渲染，控制面不能注入任意 argv。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallRule {
    pub name: String,
    pub direction: FirewallDirection,
    pub action: FirewallAction,
    pub protocol: FirewallProtocol,
    /// netsh 端口词元（如 `51820`、`5000-5010` 或 `any`）；保持字符串是
    /// 为了完整覆盖 Windows 的范围/列表语法，执行层仍以单个 argv 传递。
    pub local_port: String,
    pub remote_port: String,
    /// `None` 渲染为 `profile=any`；有值时固定 domain/private/public 顺序。
    pub profiles: Option<Vec<FirewallProfile>>,
    /// netsh `description=`；规则计划可空，省略该参数。
    pub description: Option<String>,
}

/// 一条受控 netsh 防火墙命令（计划态；执行见 [exec]）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallRuleCommand {
    Add { rule: FirewallRule },
    Delete { name: String },
}

impl FirewallRuleCommand {
    /// netsh 参数（含 `advfirewall firewall add/delete rule` 前缀；计划与
    /// 未来执行层共用同一构造，避免参数漂移）。
    pub fn args(&self) -> Vec<String> {
        let mut args = vec!["advfirewall".into(), "firewall".into()];
        match self {
            FirewallRuleCommand::Add { rule } => {
                args.extend(["add".into(), "rule".into()]);
                args.push(named_value("name", &rule.name));
                args.push(format!("dir={}", rule.direction.as_str()));
                args.push(format!("action={}", rule.action.as_str()));
                args.push(format!("protocol={}", rule.protocol.as_str()));
                args.push(named_value("localport", &rule.local_port));
                args.push(named_value("remoteport", &rule.remote_port));
                args.push(format!(
                    "profile={}",
                    render_profiles(rule.profiles.as_deref())
                ));
                if let Some(description) = &rule.description {
                    args.push(named_value("description", description));
                }
            }
            FirewallRuleCommand::Delete { name } => {
                args.extend(["delete".into(), "rule".into()]);
                args.push(named_value("name", name));
            }
        }
        args
    }

    /// 操作名（错误消息点名用）。
    pub fn operation(&self) -> &'static str {
        match self {
            FirewallRuleCommand::Add { .. } => "firewall rule add",
            FirewallRuleCommand::Delete { .. } => "firewall rule delete",
        }
    }

    /// 受管规则名（错误消息点名用）。
    pub fn name(&self) -> &str {
        match self {
            FirewallRuleCommand::Add { rule } => &rule.name,
            FirewallRuleCommand::Delete { name } => name,
        }
    }

    pub fn is_delete(&self) -> bool {
        matches!(self, FirewallRuleCommand::Delete { .. })
    }
}

/// `key=value` 形式的 netsh 命名参数，**整个键值对是单个 argv 词元**，不内嵌
/// 引号；命令行层引号由 std 进程生成器负责。
fn named_value(key: &str, value: &str) -> String {
    format!("{key}={value}")
}

/// 多 profile 固定顺序渲染；重复项只保留一次，`any` 不与具体 profile 混用。
fn render_profiles(profiles: Option<&[FirewallProfile]>) -> String {
    match profiles {
        None => "any".into(),
        Some(profiles) => {
            let mut ordered = [
                FirewallProfile::Domain,
                FirewallProfile::Private,
                FirewallProfile::Public,
            ]
            .into_iter()
            .filter(|profile| profiles.contains(profile))
            .collect::<Vec<_>>();
            ordered.dedup();
            if ordered.is_empty() {
                "any".into()
            } else {
                ordered
                    .iter()
                    .map(|profile| profile.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            }
        }
    }
}

/// 判断 netsh 删除输出是否表示「没有匹配规则」；按子串宽匹配覆盖 Windows
/// 各版本/语言路径下的幂等删除文案差异。
pub fn firewall_rule_already_absent(output: &str) -> bool {
    let lowered = output.to_lowercase();
    lowered.contains("no rules match the specified criteria")
        || lowered.contains("rule does not exist")
        || lowered.contains("cannot find")
}

/// 分类 netsh 防火墙失败：幂等删除成功，权限失败明示提权，其余 fail closed。
///
/// `requires elevation` / `access is denied` 用子串宽匹配（大小写不敏感），
/// 覆盖 Windows 版本与重定向输出的文案差异；错误消息点名操作与规则名。
pub fn classify_netsh_firewall_failure(
    exit_code: i32,
    output: &str,
    operation: &str,
    name: &str,
) -> Result<(), NetworkError> {
    if operation == "firewall rule delete" && firewall_rule_already_absent(output) {
        return Ok(());
    }

    let lowered = output.to_lowercase();
    if lowered.contains("requires elevation") || lowered.contains("access is denied") {
        return Err(NetworkError::InsufficientPrivileges(format!(
            "netsh {operation} for rule `{name}` requires administrator \
             privileges (run from an elevated shell); netsh said: {}",
            first_nonempty_line(output)
        )));
    }

    Err(NetworkError::ApplyRejected(format!(
        "netsh {operation} for rule `{name}` failed (exit {exit_code}): {}",
        first_nonempty_line(output)
    )))
}

/// 输出的首个非空行（错误消息携带 netsh 原文，便于诊断）。
fn first_nonempty_line(output: &str) -> &str {
    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("(no output)")
}

/// 执行层（`#[cfg(windows)]`）：只负责把计划函数构造的参数交给 netsh、
/// 把输出交回计划层分类，没有其他逻辑。
///
/// **未在 Windows 上实测**（本仓无 Windows 运行时）。TODO #52 的环境走查
/// 之前 Windows 不接为 [crate::SystemBackend]——非 Linux 平台保持
/// [crate::unsupported] 的显式占位，不假装有数据面。
#[cfg(target_os = "windows")]
pub mod exec {
    use super::{classify_netsh_firewall_failure, FirewallRuleCommand};
    use crate::{ApplyResult, NetworkError};

    /// 执行一条受控 netsh 防火墙命令：成功/幂等成功/分类失败三态。
    pub fn run_firewall_command(
        command: &FirewallRuleCommand,
    ) -> Result<ApplyResult, NetworkError> {
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
        // 删除规则已不存在 = 幂等成功（清理路径清到空态不算失败）。
        if command.is_delete() {
            if super::firewall_rule_already_absent(&text) {
                return Ok(ApplyResult::ok());
            }
        }
        classify_netsh_firewall_failure(
            output.status.code().unwrap_or(-1),
            &text,
            command.operation(),
            command.name(),
        )?;
        Ok(ApplyResult::ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "windows")]
    mod exec_tests {
        use super::super::*;
        use super::rule;
        use crate::{ApplyResult, NetworkError};

        /// 编译期锁定 exec 入口：签名只接收计划命令、返回计划层结果，测试不
        /// 启动 netsh。
        #[test]
        fn exec_entrypoint_takes_planned_command_and_returns_planned_result() {
            fn assert_signature(
                _run: fn(&FirewallRuleCommand) -> Result<ApplyResult, NetworkError>,
            ) {
            }
            assert_signature(super::super::exec::run_firewall_command);
        }

        /// exec 的删除分支依赖计划层判定：不存在文案 = 幂等成功。
        #[test]
        fn exec_delete_absence_classifier_is_idempotent_success() {
            assert!(firewall_rule_already_absent(
                "No rules match the specified criteria."
            ));
            assert!(classify_netsh_firewall_failure(
                1,
                "No rules match the specified criteria.",
                FirewallRuleCommand::Delete {
                    name: "Meshlet WireGuard".into(),
                }
                .operation(),
                FirewallRuleCommand::Delete {
                    name: "Meshlet WireGuard".into(),
                }
                .name()
            )
            .is_ok());
        }

        /// exec 的非零退出码交回计划层：权限类必须仍归权限错误。
        #[test]
        fn exec_failure_classification_preserves_privilege_mapping() {
            let command = FirewallRuleCommand::Add { rule: rule() };
            assert!(matches!(
                classify_netsh_firewall_failure(
                    1,
                    "Access is denied.",
                    command.operation(),
                    command.name()
                ),
                Err(NetworkError::InsufficientPrivileges(_))
            ));
        }
    }

    fn rule() -> FirewallRule {
        FirewallRule {
            name: "Meshlet WireGuard".into(),
            direction: FirewallDirection::Inbound,
            action: FirewallAction::Allow,
            protocol: FirewallProtocol::Udp,
            local_port: "51820".into(),
            remote_port: "any".into(),
            profiles: Some(vec![
                FirewallProfile::Public,
                FirewallProfile::Domain,
                FirewallProfile::Public,
            ]),
            description: Some("Meshlet managed inbound tunnel".into()),
        }
    }

    #[test]
    fn add_renders_all_parameters_in_deterministic_order() {
        let command = FirewallRuleCommand::Add { rule: rule() };
        assert_eq!(
            command.args(),
            vec![
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=Meshlet WireGuard",
                "dir=in",
                "action=allow",
                "protocol=udp",
                "localport=51820",
                "remoteport=any",
                "profile=domain,public",
                "description=Meshlet managed inbound tunnel",
            ]
        );
    }

    #[test]
    fn delete_renders_only_the_controlled_rule_name() {
        let command = FirewallRuleCommand::Delete {
            name: "Meshlet WireGuard".into(),
        };
        assert_eq!(
            command.args(),
            vec![
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=Meshlet WireGuard",
            ]
        );
    }

    #[test]
    fn planning_is_deterministic() {
        let command = FirewallRuleCommand::Add { rule: rule() };
        assert_eq!(command.args(), command.args());
    }

    #[test]
    fn rule_name_with_spaces_remains_one_named_argv_token() {
        let args = FirewallRuleCommand::Add { rule: rule() }.args();
        assert_eq!(args[4], "name=Meshlet WireGuard");
        assert!(!args[4].contains('"'));
    }

    #[test]
    fn absence_output_is_idempotent_success_for_delete() {
        assert!(classify_netsh_firewall_failure(
            1,
            "No rules match the specified criteria.",
            "firewall rule delete",
            "Meshlet WireGuard"
        )
        .is_ok());
    }

    #[test]
    fn absence_output_does_not_succeed_for_add() {
        assert!(matches!(
            classify_netsh_firewall_failure(
                1,
                "No rules match the specified criteria.",
                "firewall rule add",
                "Meshlet WireGuard"
            ),
            Err(NetworkError::ApplyRejected(detail)) if detail.contains("exit 1")
        ));
    }

    #[test]
    fn elevation_and_denied_output_map_to_privileges() {
        for output in [
            "The requested operation requires elevation.",
            "Access is denied.",
        ] {
            assert!(matches!(
                classify_netsh_firewall_failure(1, output, "firewall rule add", "Meshlet WireGuard"),
                Err(NetworkError::InsufficientPrivileges(detail))
                    if detail.contains("`Meshlet WireGuard`")
            ));
        }
    }

    #[test]
    fn unknown_failure_fails_closed_with_original_text() {
        assert!(matches!(
            classify_netsh_firewall_failure(
                2,
                "\n  The parameter is incorrect.\n",
                "firewall rule add",
                "Meshlet WireGuard"
            ),
            Err(NetworkError::ApplyRejected(detail))
                if detail.contains("exit 2") && detail.contains("The parameter is incorrect.")
        ));
    }

    #[test]
    fn missing_profiles_render_any() {
        let mut value = rule();
        value.profiles = None;
        let args = FirewallRuleCommand::Add { rule: value }.args();
        assert_eq!(args[10], "profile=any");
    }
}
