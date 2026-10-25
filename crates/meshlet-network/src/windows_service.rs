//! Windows 服务计划层（[ADR-008](../../../docs/decisions/adr-008-windows-network-backend.md)）。
//!
//! 本模块包含**纯规划**与 `#[cfg(windows)]` 执行层：
//! `sc.exe create/start/stop/delete/config/failure` 的参数构造、失败文本
//! 分类与受控执行。计划层函数在任意平台编译并单测（本仓 CI 的 Linux 侧
//! 即可跑绿）；执行层真机验证（2026-10-26，中文 Windows Server）：
//! create / stop（含从未启动的 1062 幂等）/ delete / re-delete（1060
//! 幂等）全链路走通；完整验收前 Windows 仍保持
//! [crate::unsupported] 的显式占位，不接 [crate::SystemBackend]。
//!
//! 与 [windows_routes](windows_routes)、[windows_firewall](windows_firewall)
//! 同一纪律：
//!
//! - **受控命令**：只从受管服务名、受控二进制路径和枚举启动类型渲染；
//!   `Create` 的启动类型固定 `auto|disabled`；失败恢复固定三段 restart；
//! - **sc.exe 经典形状**：`binPath=` / `start=` / `reset=` / `actions=`
//!   是「键词元（含尾等号）+ 值独立词元」，不是 netsh 的单词元
//!   `key=value`；本模块按公开 CLI 形状锁定，尚未真机实测；
//! - **自启 + 恢复语义**：`config start= auto` 表达开机自启，`failure`
//!   的 reset/restart 动作表达崩溃后重启恢复；
//! - **fail closed**：权限文案宽匹配映射为
//!   [`NetworkError::InsufficientPrivileges`]；服务不存在对 Delete/Stop
//!   按幂等成功；其他未知失败统一 [`NetworkError::ApplyRejected`]。

use crate::NetworkError;

/// 服务启动类型（`sc` 的 `start=` 受控取值）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStartMode {
    Auto,
    Disabled,
}

impl ServiceStartMode {
    fn as_str(self) -> &'static str {
        match self {
            ServiceStartMode::Auto => "auto",
            ServiceStartMode::Disabled => "disabled",
        }
    }
}

/// 一条受控 `sc.exe` 命令（计划态；执行见 [exec]）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceCommand {
    /// `sc create <name> binPath= <path> start= <auto|disabled>`。
    Create {
        name: String,
        bin_path: String,
        start_mode: ServiceStartMode,
    },
    Start {
        name: String,
    },
    Stop {
        name: String,
    },
    Delete {
        name: String,
    },
    /// `sc config <name> start= <mode>`，用于把已存在服务恢复为开机自启。
    ConfigAutostart {
        name: String,
        start_mode: ServiceStartMode,
    },
    /// `sc failure <name> reset= <secs> actions= restart/…/restart/…/restart/…`。
    ConfigRecovery {
        name: String,
        reset_secs: u32,
        restart_delays_secs: [u32; 3],
    },
}

impl ServiceCommand {
    /// `sc.exe` 参数（不含 `sc.exe` 可执行文件路径；计划与未来执行层共用
    /// 同一构造，避免参数漂移）。
    pub fn args(&self) -> Vec<String> {
        match self {
            ServiceCommand::Create {
                name,
                bin_path,
                start_mode,
            } => vec![
                "create".into(),
                name.clone(),
                "binPath=".into(),
                bin_path.clone(),
                "start=".into(),
                start_mode.as_str().into(),
            ],
            ServiceCommand::Start { name } => vec!["start".into(), name.clone()],
            ServiceCommand::Stop { name } => vec!["stop".into(), name.clone()],
            ServiceCommand::Delete { name } => vec!["delete".into(), name.clone()],
            ServiceCommand::ConfigAutostart { name, start_mode } => vec![
                "config".into(),
                name.clone(),
                "start=".into(),
                start_mode.as_str().into(),
            ],
            ServiceCommand::ConfigRecovery {
                name,
                reset_secs,
                restart_delays_secs,
            } => vec![
                "failure".into(),
                name.clone(),
                "reset=".into(),
                reset_secs.to_string(),
                "actions=".into(),
                recovery_actions(*restart_delays_secs),
            ],
        }
    }

    /// 操作名（错误消息点名用）。
    pub fn operation(&self) -> &'static str {
        match self {
            ServiceCommand::Create { .. } => "service create",
            ServiceCommand::Start { .. } => "service start",
            ServiceCommand::Stop { .. } => "service stop",
            ServiceCommand::Delete { .. } => "service delete",
            ServiceCommand::ConfigAutostart { .. } => "service config autostart",
            ServiceCommand::ConfigRecovery { .. } => "service config recovery",
        }
    }

    /// 受管服务名（错误消息点名用）。
    pub fn name(&self) -> &str {
        match self {
            ServiceCommand::Create { name, .. }
            | ServiceCommand::Start { name }
            | ServiceCommand::Stop { name }
            | ServiceCommand::Delete { name }
            | ServiceCommand::ConfigAutostart { name, .. }
            | ServiceCommand::ConfigRecovery { name, .. } => name,
        }
    }
}

/// `sc.exe` 失败恢复动作值：三段失败均重启，延迟以秒表达并固定顺序。
fn recovery_actions(delays_secs: [u32; 3]) -> String {
    delays_secs
        .iter()
        .map(|delay| format!("restart/{delay}"))
        .collect::<Vec<_>>()
        .join("/")
}

/// 判断 `sc.exe` 输出是否表示「服务不存在」（幂等 Stop/Delete 的判据）。
pub fn service_absent(output: &str) -> bool {
    let lowered = output.to_lowercase();
    lowered.contains("service does not exist")
        || lowered.contains("error 1060")
        // zh-CN 真机取证（2026-10-25）：sc.exe 删除不存在服务返回
        // 「[SC] OpenService 失败 1060: 指定的服务未安装。」——本地化文本
        // 不含英文 "error" 前缀，按完整本地化文案匹配。
        || output.contains("指定的服务未安装")
}

/// 判断 `sc.exe` 输出是否表示「服务未运行」（ERROR_SERVICE_NOT_ACTIVE）。
/// Stop 的目标状态是「已停止」：服务未运行 = 目标已达成，按幂等成功。
pub fn service_not_active(output: &str) -> bool {
    let lowered = output.to_lowercase();
    lowered.contains("has not been started")
        || lowered.contains("service not active")
        // zh-CN 真机取证（2026-10-26）：从未启动的服务 stop 返回
        // 「[SC] ControlService 失败 1062: 服务尚未启动。」
        || output.contains("服务尚未启动")
}

/// 分类 `sc.exe` 失败：卸载重入按幂等成功，提权失败明示，其余 fail closed。
///
/// 权限文案用子串宽匹配（大小写不敏感），覆盖 Windows 版本/语言包差异；
/// `Delete` 或 `Stop` 遇到 service does not exist（ERROR 1060）视为成功，
/// 使卸载可从半清理状态重入；`Config*` 遇服务不存在不放行。
pub fn classify_sc_failure(
    exit_code: i32,
    output: &str,
    operation: &str,
    name: &str,
) -> Result<(), NetworkError> {
    // 退出码 1060 = ERROR_SERVICE_DOES_NOT_EXIST，与系统语言无关的权威
    // 信号；service_absent 文本分类是同一事实的宽匹配双通道
    // （zh-CN 文案见其注记）。
    let absent = exit_code == 1060 || service_absent(output);
    if (operation == "service delete" || operation == "service stop") && absent {
        return Ok(());
    }
    // Stop 的目标状态是「已停止」（ADR-008 生命周期）：服务未运行（1062）
    // = 目标已达成，同归幂等成功——卸载可从「建了服务但从未启动」的半
    // 状态重入；其余操作不借道放行。
    if operation == "service stop" && (exit_code == 1062 || service_not_active(output)) {
        return Ok(());
    }

    let lowered = output.to_lowercase();
    if lowered.contains("access is denied")
        || lowered.contains("requires elevation")
        || lowered.contains("elevation is required")
        || lowered.contains("not authorized")
        // zh-CN 标准本地化文案（「拒绝访问」= ERROR_ACCESS_DENIED；
        // 「需要提升」= ERROR_ELEVATION_REQUIRED）。宽匹配纪律不变。
        || output.contains("拒绝访问")
        || output.contains("需要提升")
    {
        return Err(NetworkError::InsufficientPrivileges(format!(
            "sc.exe {operation} for service `{name}` requires administrator \
             privileges (run from an elevated shell); sc.exe said: {}",
            first_nonempty_line(output)
        )));
    }

    Err(NetworkError::ApplyRejected(format!(
        "sc.exe {operation} for service `{name}` failed (exit {exit_code}): {}",
        first_nonempty_line(output)
    )))
}

/// 输出的首个非空行（错误消息携带 sc.exe 原文，便于诊断）。
fn first_nonempty_line(output: &str) -> &str {
    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("(no output)")
}

/// 执行层（`#[cfg(windows)]`）：只负责把计划函数构造的参数交给 sc.exe、
/// 把输出交回计划层分类，没有其他逻辑。
///
/// 真机实测（2026-10-26，中文 Windows Server）：create / stop（含从未启动
/// 的 1062 幂等）/ delete / re-delete（1060 幂等）全链路走通；本地化输出
/// 经 [crate::windows_console] 解码后分类闭环。TODO #52 保持未勾：接
/// [crate::SystemBackend] 仍以完整验收为准。
#[cfg(target_os = "windows")]
pub mod exec {
    use super::{classify_sc_failure, ServiceCommand};
    use crate::{ApplyResult, NetworkError};

    /// 执行一条受控 `sc.exe` 命令：成功/幂等成功/分类失败三态。
    pub fn run_service_command(command: &ServiceCommand) -> Result<ApplyResult, NetworkError> {
        let output = std::process::Command::new("sc.exe")
            .args(command.args())
            .output()
            .map_err(|error| NetworkError::Io(format!("spawn sc.exe: {error}")))?;
        // sc.exe 重定向输出按活动代码页编码（zh-CN 真机取证为 GBK），
        // UTF-8 优先 + CP_ACP 兑底解码，见 [windows_console]。
        let text = format!(
            "{}{}",
            crate::windows_console::decode_output(&output.stdout),
            crate::windows_console::decode_output(&output.stderr),
        );
        if output.status.success() {
            return Ok(ApplyResult::ok());
        }
        classify_sc_failure(
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

    fn create() -> ServiceCommand {
        ServiceCommand::Create {
            name: "meshlet".into(),
            bin_path: r"C:\Program Files\Meshlet\meshletd.exe".into(),
            start_mode: ServiceStartMode::Auto,
        }
    }

    #[test]
    fn create_renders_classic_sc_shape() {
        assert_eq!(
            create().args(),
            vec![
                "create",
                "meshlet",
                "binPath=",
                r"C:\Program Files\Meshlet\meshletd.exe",
                "start=",
                "auto",
            ]
        );
        assert_eq!(create().operation(), "service create");
        assert_eq!(create().name(), "meshlet");
    }

    #[test]
    fn recovery_renders_three_fixed_restart_delays() {
        assert_eq!(
            ServiceCommand::ConfigRecovery {
                name: "meshlet".into(),
                reset_secs: 60,
                restart_delays_secs: [0, 10, 60],
            }
            .args(),
            vec![
                "failure",
                "meshlet",
                "reset=",
                "60",
                "actions=",
                "restart/0/restart/10/restart/60",
            ]
        );
    }

    #[test]
    fn absent_service_is_idempotent_success_only_for_stop_and_delete() {
        for operation in ["service stop", "service delete"] {
            assert!(classify_sc_failure(
                1,
                "ERROR 1060: The specified service does not exist.",
                operation,
                "meshlet"
            )
            .is_ok());
        }
        assert!(matches!(
            classify_sc_failure(
                1,
                "ERROR 1060: The specified service does not exist.",
                "service config autostart",
                "meshlet"
            ),
            Err(NetworkError::ApplyRejected(_))
        ));
    }

    /// zh-CN 真机取证（2026-10-25）：中文缺失报文 + 退出码 1060 双通道命中
    /// 幂等；Config* 对服务不存在不放行（与英文路径同一纪律）。
    #[test]
    fn localized_absence_is_idempotent_only_for_stop_and_delete() {
        let output = "[SC] OpenService 失败 1060:\r\n\r\n指定的服务未安装。\r\n";
        for exit_code in [1, 1060] {
            for operation in ["service stop", "service delete"] {
                assert!(
                    classify_sc_failure(exit_code, output, operation, "meshlet").is_ok(),
                    "exit {exit_code} + zh-CN absence must be idempotent for {operation}"
                );
            }
        }
        assert!(matches!(
            classify_sc_failure(1060, output, "service config autostart", "meshlet"),
            Err(NetworkError::ApplyRejected(_))
        ));
    }

    /// zh-CN 标准权限文案归权限类。
    #[test]
    fn localized_privilege_text_maps_to_privileges() {
        assert!(matches!(
            classify_sc_failure(
                5,
                "[SC] OpenService 失败 5:\r\n\r\n拒绝访问。\r\n",
                "service create",
                "meshlet"
            ),
            Err(NetworkError::InsufficientPrivileges(_))
        ));
    }

    /// zh-CN 真机取证（2026-10-26）：从未启动的服务 stop 返回 1062
    /// 「服务尚未启动。」——Stop 的目标状态是「已停止」，未运行 = 已达成，
    /// 幂等成功（卸载可从「建了服务没启动」的半状态重入）。
    #[test]
    fn stop_of_never_started_service_is_idempotent_success() {
        let output = "[SC] ControlService 失败 1062:\r\n\r\n服务尚未启动。\r\n";
        assert!(classify_sc_failure(1062, output, "service stop", "meshlet").is_ok());
        // 英文同事实文案（1062 = ERROR_SERVICE_NOT_ACTIVE）双通道命中。
        assert!(classify_sc_failure(
            1,
            "[SC] ControlService failed 1062:\r\n\r\nThe service has not been started.\r\n",
            "service stop",
            "meshlet"
        )
        .is_ok());
        // 1062 宽容只归 Stop：其余操作不得借道放行。
        assert!(matches!(
            classify_sc_failure(1062, output, "service config autostart", "meshlet"),
            Err(NetworkError::ApplyRejected(_))
        ));
    }

    #[test]
    fn elevation_and_denied_output_map_to_privileges() {
        for output in [
            "Access is denied.",
            "The requested operation requires elevation.",
            "Elevation is required to perform this operation.",
            "This operation is not authorized.",
        ] {
            assert!(matches!(
                classify_sc_failure(1, output, "service create", "meshlet"),
                Err(NetworkError::InsufficientPrivileges(_))
            ));
        }
    }

    #[test]
    fn unknown_failure_fails_closed_with_original_text() {
        assert!(matches!(
            classify_sc_failure(2, "\nInvalid arguments.\n", "service create", "meshlet"),
            Err(NetworkError::ApplyRejected(detail))
                if detail.contains("exit 2") && detail.contains("Invalid arguments.")
        ));
    }

    #[cfg(target_os = "windows")]
    mod exec_tests {
        use super::{classify_sc_failure, create, ServiceCommand};
        use crate::NetworkError;

        /// 编译期锁定 exec 入口：签名只接收计划命令、返回计划层结果，测试不
        /// 启动 sc.exe。
        #[test]
        fn exec_entrypoint_takes_planned_command_and_returns_planned_result() {
            fn assert_signature(
                _run: fn(&ServiceCommand) -> Result<crate::ApplyResult, NetworkError>,
            ) {
            }
            assert_signature(super::super::exec::run_service_command);
        }

        /// exec 的非零退出码交回计划层：权限类必须仍归权限错误。
        #[test]
        fn exec_failure_classification_preserves_privilege_mapping() {
            let command = create();
            assert!(matches!(
                classify_sc_failure(1, "Access is denied.", command.operation(), command.name()),
                Err(NetworkError::InsufficientPrivileges(_))
            ));
        }

        /// exec 只透传计划层 argv，不重新拼命令形状。
        #[test]
        fn exec_renders_planned_sc_argv_without_shell() {
            assert_eq!(
                create().args(),
                vec![
                    "create",
                    "meshlet",
                    "binPath=",
                    r"C:\Program Files\Meshlet\meshletd.exe",
                    "start=",
                    "auto",
                ]
            );
        }
    }
}
