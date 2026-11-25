//! macOS privilege model (③-A): the sudo whitelist — a pure-function layer,
//! compiled and unit-tested on every platform.
//!
//! The boringtun data-plane commands (`ifconfig`/`route`/`scutil`) require root;
//! the meshlet agent runs as an unprivileged user and executes them with a
//! `sudo -n` prefix. This module defines the **whitelist of programs that may be
//! elevated by sudo**: anything outside the whitelist is refused the sudo prefix
//! (fail-closed, never silently degrading to an unelevated run — that would just
//! fail again with insufficient permissions and a misleading error message).
//!
//! The full suggested sudoers entry and the launchd privileged helper
//! (SMAppService) follow-up hardening live in
//! [macOS Privileges](../../docs/macos-privileges.md).

use crate::NetworkError;
use std::path::Path;

/// Programs eligible for elevation via `sudo -n` (the basename of argv[0]).
///
/// Kept in sync with the sudoers entry in
/// [macOS Privileges](../../docs/macos-privileges.md): the boringtun data plane
/// configures the dummy utun's address/routes/resolver through standard tools and
/// needs no arbitrary shell. `wg` (UAPI socket, readable and writable by a
/// non-root user) and boringtun-cli (run as the agent user) are **not** in the
/// whitelist — they need no elevation.
pub const SUDO_WHITELIST: &[&str] = &["ifconfig", "route", "scutil"];

/// Whether a program is in the sudo whitelist (argv[0] may be a path, so
/// compare the basename).
pub fn is_sudo_allowed_program(program: &str) -> bool {
    let base = Path::new(program)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned());
    base.is_some_and(|base| SUDO_WHITELIST.contains(&base.as_str()))
}

/// Whether a whole command (argv) may carry a sudo prefix. An empty argv is
/// refused.
pub fn is_sudo_allowed_command(argv: &[String]) -> bool {
    argv.first()
        .is_some_and(|program| is_sudo_allowed_program(program))
}

/// Whitelist check before elevation: a command in the list returns `Ok`,
/// anything else `ApplyRejected` (fail closed — callers must not bypass this
/// check and prefix `sudo` directly).
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
        // An absolute path rendered for argv[0] by the execution layer is
        // allowed too (the basename is taken).
        let argv: Vec<String> = ["/sbin/route", "-n", "add", "-net", "10.99.0.0"]
            .map(String::from)
            .to_vec();
        assert!(check_sudo_elevation(&argv).is_ok());
    }
}
