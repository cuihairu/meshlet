//! macOS 权限模型（③-A）：sudo 白名单——纯函数层，全平台编译+单测。
//!
//! boringtun 数据面的命令（`ifconfig`/`route`/`scutil`）需要 root；meshlet
//! agent 常驻非特权用户，经 `sudo -n` 前缀执行。本模块定义**可被 sudo 提升
//! 的程序白名单**：白名单外一律拒绝加 sudo 前缀（fail-closed，绝不静默降级
//! 为未提升执行——那只会以权限不足再次失败，且错误信息误导）。
//!
//! 完整 sudoers 建议条目与 launchd 特权 helper（SMAppService）后续增强见
//! [macOS Privileges](../../docs/macos-privileges.md)。

use crate::NetworkError;
use std::path::Path;

/// 可经 `sudo -n` 提升的程序白名单（argv[0] 的 basename）。
///
/// 与 [macOS Privileges](../../docs/macos-privileges.md) 的 sudoers 条目
/// 同步：boringtun 数据面经标准工具配哑 utun 的地址/路由/解析器，无需
/// 任意 shell。`wg`（UAPI socket，非 root 可读写）与 boringtun-cli（跑在
/// agent 用户）**不在**白名单内——它们不需要提升。
pub const SUDO_WHITELIST: &[&str] = &["ifconfig", "route", "scutil"];

/// 程序是否在 sudo 白名单内（argv[0] 可能是路径，取 basename 比较）。
pub fn is_sudo_allowed_program(program: &str) -> bool {
    let base = Path::new(program)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned());
    base.is_some_and(|base| SUDO_WHITELIST.contains(&base.as_str()))
}

/// 一条命令（argv）整体是否可加 sudo 前缀。空 argv 拒绝。
pub fn is_sudo_allowed_command(argv: &[String]) -> bool {
    argv.first()
        .is_some_and(|program| is_sudo_allowed_program(program))
}

/// 提升前白名单校验：命令在名单内返回 `Ok`，否则 `ApplyRejected`（fail
/// closed——调用方不得绕过此校验直接前缀 `sudo`）。
pub fn check_sudo_elevation(argv: &[String]) -> Result<(), NetworkError> {
    if is_sudo_allowed_command(argv) {
        Ok(())
    } else {
        Err(NetworkError::ApplyRejected(format!(
            "refusing to elevate `{}`: program not in the sudo whitelist \
             (docs/macos-privileges.md)",
            argv.join(" ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitelist_accepts_standard_programs() {
        for program in [
            "ifconfig",
            "/sbin/ifconfig",
            "route",
            "/sbin/route",
            "scutil",
            "/usr/sbin/scutil",
        ] {
            assert!(
                is_sudo_allowed_program(program),
                "expected {program} allowed"
            );
        }
    }

    #[test]
    fn whitelist_rejects_non_dataplane_programs() {
        for program in [
            "wg",
            "/usr/bin/wg",
            "sh",
            "/bin/sh",
            "tee",
            "sudo",
            "bash",
            "",
            "/",
        ] {
            assert!(
                !is_sudo_allowed_program(program),
                "expected {program:?} rejected"
            );
        }
    }

    #[test]
    fn command_elevation_check_ok_for_dataplane() {
        let argv: Vec<String> = [
            "ifconfig",
            "utun5",
            "inet",
            "10.240.0.7",
            "netmask",
            "255.255.0.0",
        ]
        .map(String::from)
        .to_vec();
        assert!(check_sudo_elevation(&argv).is_ok());
    }

    #[test]
    fn command_elevation_check_rejects_non_whitelisted() {
        let cases: Vec<Vec<&str>> = vec![
            vec!["sh", "-c", "echo pwned"],
            vec!["wg", "show", "meshlet"],
            vec!["tee", "/etc/resolver/example.com"],
            vec![],
        ];
        for case in cases {
            let argv: Vec<String> = case.iter().map(|s| s.to_string()).collect();
            let err = check_sudo_elevation(&argv).unwrap_err();
            assert!(
                matches!(err, NetworkError::ApplyRejected(_)),
                "expected ApplyRejected for {argv:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn absolute_path_forms_are_whitelisted() {
        // 执行层渲染 argv[0] 为绝对路径时同样放行（取 basename）。
        let argv: Vec<String> = ["/sbin/route", "-n", "add", "-net", "10.99.0.0"]
            .map(String::from)
            .to_vec();
        assert!(check_sudo_elevation(&argv).is_ok());
    }
}
