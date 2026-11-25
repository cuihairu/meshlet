//! The Windows service plan layer ([ADR-008](../../../docs/decisions/adr-008-windows-network-backend.md)).
//!
//! This module holds the **pure planning** and the `#[cfg(windows)]` execution
//! layer: the argument construction for
//! `sc.exe create/start/stop/delete/config/failure`, failure-text classification,
//! and controlled execution. The plan-layer functions compile and unit-test on
//! any platform (the Linux side of this repo's CI already runs green); the
//! execution layer was verified on a real machine (2026-10-26, a zh-CN Windows
//! Server): create / stop (including the idempotent 1062 for a never-started
//! service) / delete / re-delete (idempotent 1060) all work end to end. Until
//! full acceptance, Windows keeps the explicit placeholder of
//! [crate::unsupported] and does not wire up [crate::SystemBackend].
//!
//! The same discipline as [windows_routes](windows_routes) and
//! [windows_firewall](windows_firewall):
//!
//! - **Controlled commands**: rendered only from a managed service name, a
//!   controlled binary path, and an enum start type; the `Create` start type is
//!   fixed to `auto|disabled`; failure recovery is fixed to a three-stage
//!   restart;
//! - **The classic sc.exe shape**: `binPath=` / `start=` / `reset=` /
//!   `actions=` are "a key token (with the trailing equals sign) plus the value
//!   as a separate token", not netsh's single-token `key=value`; this module
//!   locks to the published CLI shape;
//! - **Autostart plus recovery semantics**: `config start= auto` expresses
//!   start-on-boot, and the `failure` reset/restart actions express
//!   restart-after-crash recovery;
//! - **fail closed**: privilege texts match broadly and map to
//!   [`NetworkError::InsufficientPrivileges`]; a missing service counts as an
//!   idempotent success for Delete/Stop; every other unknown failure becomes
//!   [`NetworkError::ApplyRejected`].

use crate::NetworkError;

/// The service start type (the controlled values of `sc`'s `start=`).
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

/// One controlled `sc.exe` command (plan state; execution in [exec]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceCommand {
    /// `sc create <name> binPath= <path> start= <auto|disabled>`.
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
    /// `sc config <name> start= <mode>`, used to restore an existing service to
    /// start on boot.
    ConfigAutostart {
        name: String,
        start_mode: ServiceStartMode,
    },
    /// `sc failure <name> reset= <secs> actions= restart/…/restart/…/restart/…`.
    ConfigRecovery {
        name: String,
        reset_secs: u32,
        restart_delays_secs: [u32; 3],
    },
}

impl ServiceCommand {
    /// The `sc.exe` arguments (without the `sc.exe` executable path; the plan and
    /// the future execution layer share the same construction so the arguments
    /// never drift).
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

    /// The operation name (used to name it in error messages).
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

    /// The managed service name (used to name it in error messages).
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

/// The `sc.exe` failure recovery actions value: all three failure stages
/// restart, with the delays expressed in seconds and in a fixed order.
fn recovery_actions(delays_secs: [u32; 3]) -> String {
    delays_secs
        .iter()
        .map(|delay| format!("restart/{delay}"))
        .collect::<Vec<_>>()
        .join("/")
}

/// Whether the `sc.exe` output means "the service does not exist" (the
/// criterion for idempotent Stop/Delete).
pub fn service_absent(output: &str) -> bool {
    let lowered = output.to_lowercase();
    lowered.contains("service does not exist")
        || lowered.contains("error 1060")
        // zh-CN real-machine forensics (2026-10-25): sc.exe deleting a
        // non-existent service returns "[SC] OpenService FAILED 1060:" followed by
        // the zh-CN localized "the specified service is not installed" — the
        // localized text carries no English "error" prefix, so the full localized
        // wording is matched.
        || output.contains("指定的服务未安装")
}

/// Whether the `sc.exe` output means "the service is not running"
/// (ERROR_SERVICE_NOT_ACTIVE).
/// Stop's target state is "stopped": a service that is not running = the target
/// already achieved, counted as an idempotent success.
pub fn service_not_active(output: &str) -> bool {
    let lowered = output.to_lowercase();
    lowered.contains("has not been started")
        || lowered.contains("service not active")
        // zh-CN real-machine forensics (2026-10-26): stopping a never-started
        // service returns "[SC] ControlService FAILED 1062:" followed by the
        // zh-CN localized "the service has not been started".
        || output.contains("服务尚未启动")
}

/// Classify an `sc.exe` failure: uninstall re-entry counts as an idempotent
/// success, an elevation failure is stated plainly, and the rest fail closed.
///
/// Privilege texts match broadly by substring (case-insensitive), covering
/// Windows version/language-pack differences; `Delete` or `Stop` hitting
/// service does not exist (ERROR 1060) is treated as success so the uninstall
/// can re-enter from a half-cleaned state; `Config*` is never let through on a
/// missing service.
pub fn classify_sc_failure(
    exit_code: i32,
    output: &str,
    operation: &str,
    name: &str,
) -> Result<(), NetworkError> {
    // Exit code 1060 = ERROR_SERVICE_DOES_NOT_EXIST, the authoritative signal
    // independent of the system language; the service_absent text classification
    // is the broad-match second channel for the same fact
    // (see its note for the zh-CN wording).
    let absent = exit_code == 1060 || service_absent(output);
    if (operation == "service delete" || operation == "service stop") && absent {
        return Ok(());
    }
    // Stop's target state is "stopped" (the ADR-008 lifecycle): a service not
    // running (1062) = the target already achieved, likewise an idempotent
    // success — the uninstall can re-enter from the half state "created the
    // service but never started it"; other operations are never let through on
    // it.
    if operation == "service stop" && (exit_code == 1062 || service_not_active(output)) {
        return Ok(());
    }

    let lowered = output.to_lowercase();
    if lowered.contains("access is denied")
        || lowered.contains("requires elevation")
        || lowered.contains("elevation is required")
        || lowered.contains("not authorized")
        // The standard zh-CN localized texts ("access denied" =
        // ERROR_ACCESS_DENIED; "requires elevation" =
        // ERROR_ELEVATION_REQUIRED). The broad-match discipline holds.
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

/// The first non-empty line of the output (error messages carry the raw sc.exe
/// text for diagnostics).
fn first_nonempty_line(output: &str) -> &str {
    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("(no output)")
}

/// The execution layer (`#[cfg(windows)]`): it only hands the arguments built by
/// the plan functions to sc.exe and hands the output back to the plan layer for
/// classification; nothing else.
///
/// Real-machine tests (2026-10-26, a zh-CN Windows Server): create / stop
/// (including the idempotent 1062 for a never-started service) / delete /
/// re-delete (idempotent 1060) all work end to end; the localized output is
/// decoded through [crate::windows_console] before classification closes the
/// loop. TODO #52 stays unchecked: wiring up [crate::SystemBackend] remains
/// gated on full acceptance.
#[cfg(target_os = "windows")]
pub mod exec {
    use super::{classify_sc_failure, ServiceCommand};
    use crate::windows_console::NoWindowCommand;
    use crate::{ApplyResult, NetworkError};

    /// Run one controlled `sc.exe` command: success / idempotent success /
    /// classified failure, three states.
    pub fn run_service_command(command: &ServiceCommand) -> Result<ApplyResult, NetworkError> {
        let output = std::process::Command::new("sc.exe")
            .args(command.args())
            .no_window()
            .output()
            .map_err(|error| NetworkError::Io(format!("spawn sc.exe: {error}")))?;
        // sc.exe's redirected output is encoded in the active code page (a
        // zh-CN real machine yields GBK); decode as UTF-8 first with a CP_ACP
        // fallback, see [windows_console].
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

    /// zh-CN real-machine forensics (2026-10-25): the zh-CN absent message plus
    /// exit code 1060 both hit the idempotent path (a dual channel); Config* is
    /// never let through on a missing service (the same discipline as the English
    /// path).
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

    /// The standard zh-CN privilege texts land in the privilege class.
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

    /// zh-CN real-machine forensics (2026-10-26): stopping a never-started
    /// service returns 1062 with the zh-CN localized "the service has not been
    /// started" — Stop's target state is "stopped", so not running = achieved,
    /// an idempotent success (the uninstall can re-enter from the half state
    /// "created the service but never started it").
    #[test]
    fn stop_of_never_started_service_is_idempotent_success() {
        let output = "[SC] ControlService 失败 1062:\r\n\r\n服务尚未启动。\r\n";
        assert!(classify_sc_failure(1062, output, "service stop", "meshlet").is_ok());
        // The English text for the same fact (1062 = ERROR_SERVICE_NOT_ACTIVE)
        // hits the second channel.
        assert!(classify_sc_failure(
            1,
            "[SC] ControlService failed 1062:\r\n\r\nThe service has not been started.\r\n",
            "service stop",
            "meshlet"
        )
        .is_ok());
        // The 1062 leniency belongs to Stop only: other operations are never let
        // through on it.
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

        /// Lock the exec entry at compile time: the signature takes only plan
        /// commands and returns the plan-layer result, so tests never launch
        /// sc.exe.
        #[test]
        fn exec_entrypoint_takes_planned_command_and_returns_planned_result() {
            fn assert_signature(
                _run: fn(&ServiceCommand) -> Result<crate::ApplyResult, NetworkError>,
            ) {
            }
            assert_signature(super::super::exec::run_service_command);
        }

        /// exec hands a non-zero exit code back to the plan layer: the privilege
        /// class must still land in the privilege error.
        #[test]
        fn exec_failure_classification_preserves_privilege_mapping() {
            let command = create();
            assert!(matches!(
                classify_sc_failure(1, "Access is denied.", command.operation(), command.name()),
                Err(NetworkError::InsufficientPrivileges(_))
            ));
        }

        /// exec passes the plan-layer argv through unchanged; the command shape is
        /// never reassembled.
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
