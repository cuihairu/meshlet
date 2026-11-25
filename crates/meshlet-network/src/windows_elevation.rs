//! Windows elevation planning layer
//! ([ADR-008](../../../docs/decisions/adr-008-windows-network-backend.md)).
//!
//! This module contains **pure planning** plus a `#[cfg(windows)]` execution
//! layer: managed client executable path validation, construction of the
//! `ShellExecuteW(runas)` equivalent command line, the current process
//! TokenElevation check, and UAC denial classification. The plan layer compiles
//! and unit-tests on any platform; the execution layer **must not be wired into**
//! [crate::SystemBackend] **before it has been real-machine tested on Windows**,
//! and non-Linux platforms keep the explicit placeholder of
//! [crate::unsupported] (§10.3, §12.2).
//!
//! Same discipline as [windows_cleanup](windows_cleanup),
//! [windows_routes](windows_routes), [windows_firewall](windows_firewall),
//! [windows_service](windows_service):
//!
//! - **managed paths**: only absolute `.exe` files under the Meshlet managed
//!   installation directory prefix are accepted; every other executable is
//!   [NetworkError::ApplyRejected];
//! - **no argument splitting**: each managed argument is escaped as a whole under
//!   the Windows command-line quoting rules, so paths containing spaces or quotes
//!   stay a single argument;
//! - **controlled execution**: the execution layer only calls ShellExecuteW with
//!   the `runas` verb and the current process TokenElevation query — no free
//!   Shell text is assembled;
//! - **fail closed**: elevation/denied wording maps to
//!   [`NetworkError::InsufficientPrivileges`], and all other failures keep their
//!   original error classification.

use std::path::{Path, PathBuf};

use crate::NetworkError;

/// The Meshlet managed installation directory prefix; the path validation only
/// accepts client executables under this directory.
pub const MANAGED_EXECUTABLE_DIRECTORY: &str = r"C:\Program Files\Meshlet";

/// Meshlet managed client executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedExecutablePath(PathBuf);

impl ManagedExecutablePath {
    /// Validate and wrap the managed executable path; relative paths, non-`.exe`
    /// files, and paths outside the managed directory are refused.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, NetworkError> {
        let path = path.as_ref();
        let path_text = path.to_string_lossy();
        let has_drive = path_text
            .as_bytes()
            .get(1)
            .is_some_and(|&separator| separator == b':')
            && path_text
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic);
        let has_root_separator = path_text.starts_with('\\') || path_text.starts_with('/');
        if !has_drive && !has_root_separator {
            return Err(NetworkError::ApplyRejected(format!(
                "managed executable path must be absolute: {}",
                path_text
            )));
        }
        if !path
            .extension()
            .and_then(|value| value.to_str())
            .map(|extension| extension.eq_ignore_ascii_case("exe"))
            .unwrap_or(false)
        {
            return Err(NetworkError::ApplyRejected(format!(
                "managed executable must be an .exe: {}",
                path_text
            )));
        }
        if !under_managed_directory(path) {
            return Err(NetworkError::ApplyRejected(format!(
                "executable is outside the Meshlet managed directory: {}",
                path_text
            )));
        }
        // fail closed: a path containing `..` segments can escape the managed
        // directory after normalization, so the plan layer does not parse it —
        // it is refused outright (the managed installation path is canonical, and
        // a normal path contains no parent segments).
        if windows_path_segments(path)
            .iter()
            .any(|segment| segment == "..")
        {
            return Err(NetworkError::ApplyRejected(format!(
                "managed executable path must be canonical (no `..` segments): {}",
                path_text
            )));
        }
        Ok(Self(path.to_path_buf()))
    }

    /// The managed executable path.
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// The Windows command-line string quoted as a whole (`lpFile` +
    /// `lpParameters`).
    pub fn command_line(&self, args: &[String]) -> String {
        format!(
            "{} {}",
            quote_windows_argument(self.0.to_string_lossy().as_ref()),
            parameter_command_line(args)
        )
    }
}

/// Construct the `ShellExecuteW(runas)` equivalent command line; the plan
/// assertions and the execution layer share this one shape.
pub fn elevation_runas_command(path: &ManagedExecutablePath, args: &[String]) -> String {
    path.command_line(args)
}

/// ShellExecuteW's `lpParameters`: excluding `lpFile`, each argument is escaped
/// as a whole under the Windows command-line rules (assertable at the plan layer,
/// consumed by the execution layer).
pub fn parameter_command_line(args: &[String]) -> String {
    args.iter()
        .map(|argument| quote_windows_argument(argument))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether the path is under the managed installation directory. **Windows
/// path semantics**: split on `\` / `/`, compare segment by segment, and
/// case-insensitively (NTFS is case-insensitive) — [`std::path::Path::starts_with`]
/// cannot be used, because on non-Windows platforms it treats a whole
/// backslash-separated string as a single component, which would split the
/// behavior between Linux unit tests and Windows real-machine tests.
pub fn under_managed_directory(path: &Path) -> bool {
    let segments = windows_path_segments(path);
    let managed = windows_path_segments(Path::new(MANAGED_EXECUTABLE_DIRECTORY));
    segments.len() >= managed.len()
        && segments[..managed.len()]
            .iter()
            .zip(&managed)
            .all(|(segment, base)| segment.eq_ignore_ascii_case(base))
}

/// Windows path segments: both `\` and `/` are separators, and empty segments
/// (repeated / leading separators) are skipped.
fn windows_path_segments(path: &Path) -> Vec<String> {
    path.to_string_lossy()
        .split(['\\', '/'])
        .filter(|segment| !segment.is_empty())
        .map(str::to_string)
        .collect()
}

/// The argv of the controlled check command for whether the current process is
/// elevated; the output is for upper-layer diagnostics, and no free text is
/// parsed.
pub fn is_elevated_check_command() -> Vec<String> {
    vec!["whoami.exe".into(), "/groups".into()]
}

/// The unified client action hint, reusable for upper layers.
pub fn elevation_required_hint() -> &'static str {
    "请以管理员身份运行 meshlet 客户端"
}

fn quote_windows_argument(argument: &str) -> String {
    if !argument.is_empty() && !argument.contains([' ', '\t', '"']) {
        return argument.to_string();
    }

    let mut quoted = String::with_capacity(argument.len() + 2);
    quoted.push('"');
    let mut backslashes = 0;
    for character in argument.chars() {
        if character == '\\' {
            backslashes += 1;
            continue;
        }
        if character == '"' {
            quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
            quoted.push('"');
            backslashes = 0;
            continue;
        }
        quoted.push_str(&"\\".repeat(backslashes));
        backslashes = 0;
        quoted.push(character);
    }
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}

/// Privilege-class Windows failure codes: `ERROR_ACCESS_DENIED`(5),
/// `ERROR_ELEVATION_REQUIRED`(740), and the ShellExecuteW failure return's
/// `SE_ERR_ACCESSDENIED`(5) and elevation required (1101). These codes all mean
/// "administrator required"; the remaining failures keep the
/// [`NetworkError::Io`] classification.
pub const PRIVILEGE_ERROR_CODES: [u32; 3] = [5, 740, 1101];

/// Failure classification (a pure function, unit-testable on Linux): a
/// privilege-class error code or a UAC text ->
/// [`NetworkError::InsufficientPrivileges`], everything else ->
/// [`NetworkError::Io`]; both keep the original error text, nothing is swallowed
/// (fail closed, see [`ManagedExecutablePath::new`]).
pub fn classify_elevation_failure(code: u32, message: &str) -> NetworkError {
    let lowered = message.to_lowercase();
    let needs_privileges = PRIVILEGE_ERROR_CODES.contains(&code)
        || lowered.contains("elevation")
        || lowered.contains("denied")
        || lowered.contains("requires administrator");
    if needs_privileges {
        return NetworkError::InsufficientPrivileges(message.to_string());
    }
    NetworkError::Io(message.to_string())
}

/// The Windows execution layer (`#[cfg(windows)]`): the UAC relaunch and the
/// TokenElevation query.
///
/// **Not yet real-machine tested on Windows**; it must not be wired into
/// [crate::SystemBackend] before that happens.
#[cfg(target_os = "windows")]
pub mod exec {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    use super::{
        classify_elevation_failure, elevation_runas_command, parameter_command_line,
        ManagedExecutablePath,
    };
    use crate::NetworkError;

    /// Launch the managed executable with the UAC `runas` verb.
    pub fn relaunch_elevated(
        path: &ManagedExecutablePath,
        args: &[String],
    ) -> Result<(), NetworkError> {
        let command_line = elevation_runas_command(path, args);
        let verb = to_wide("runas");
        let file = to_wide(path.as_path().to_string_lossy().as_ref());
        let parameters = to_wide(&parameter_command_line(args));
        let result = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                file.as_ptr(),
                parameters.as_ptr(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        if result as usize > 32 {
            return Ok(());
        }
        let code = result as isize;
        Err(classify_elevation_failure(
            code as u32,
            &format!("ShellExecuteW runas failed (code {code}): {command_line}"),
        ))
    }

    /// Query the current process TokenElevation; when it cannot be determined,
    /// fail closed.
    pub fn current_process_is_elevated() -> Result<bool, NetworkError> {
        let mut token = HANDLE::default();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(classify_windows_call("OpenProcessToken"));
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut return_length = 0;
        if unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut _ as *mut core::ffi::c_void,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut return_length,
            )
        } == 0
        {
            unsafe { CloseHandle(token) };
            return Err(classify_windows_call("GetTokenInformation(TokenElevation)"));
        }

        unsafe { CloseHandle(token) };
        Ok(elevation.TokenIsElevated != 0)
    }

    fn classify_windows_call(function: &str) -> NetworkError {
        let code = unsafe { GetLastError() };
        classify_elevation_failure(
            code,
            &format!("{function} failed with Windows error {code}"),
        )
    }

    fn to_wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain([0]).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn managed_path() -> ManagedExecutablePath {
        ManagedExecutablePath::new(r"C:\Program Files\Meshlet\meshlet.exe").unwrap()
    }

    #[test]
    fn runas_command_keeps_arguments_with_spaces_as_single_tokens() {
        let command = elevation_runas_command(
            &managed_path(),
            &[
                "--config".into(),
                r"C:\Program Files\Meshlet\config one.toml".into(),
            ],
        );
        assert_eq!(
            command,
            concat!(
                r#""C:\Program Files\Meshlet\meshlet.exe" --config "#,
                r#""C:\Program Files\Meshlet\config one.toml""#
            )
        );
    }

    #[test]
    fn runas_command_escapes_embedded_quotes() {
        let command = elevation_runas_command(
            &managed_path(),
            &[r#"argument with " quote and \ tail\"#.into()],
        );
        assert_eq!(
            command,
            concat!(
                r#""C:\Program Files\Meshlet\meshlet.exe" "#,
                r#""argument with \" quote and \ tail\\""#
            )
        );
    }

    /// A rule subset of CommandLineToArgvW (for tests): 2n backslashes followed by
    /// a quote -> n literal backslashes plus the quote as a delimiter; an odd
    /// number -> the trailing backslash escapes the quote itself; whitespace
    /// outside the quotes separates words.
    fn parse_windows_arguments(command_line: &str) -> Vec<String> {
        let mut arguments = Vec::new();
        let mut current = String::new();
        let mut quoted = false;
        let mut backslashes = 0;
        for character in command_line.chars() {
            match character {
                '\\' => backslashes += 1,
                '"' => {
                    current.push_str(&"\\".repeat(backslashes / 2));
                    if backslashes % 2 == 1 {
                        current.push('"');
                    } else {
                        quoted = !quoted;
                    }
                    backslashes = 0;
                }
                _ => {
                    current.push_str(&"\\".repeat(backslashes));
                    backslashes = 0;
                    if !quoted && character.is_whitespace() {
                        if !current.is_empty() {
                            arguments.push(std::mem::take(&mut current));
                        }
                    } else {
                        current.push(character);
                    }
                }
            }
        }
        current.push_str(&"\\".repeat(backslashes));
        if !current.is_empty() {
            arguments.push(current);
        }
        arguments
    }

    #[test]
    fn quoted_command_line_round_trips_through_the_windows_parser() {
        // Embedded quotes / trailing backslashes / spaces in the path: the
        // standard parser must restore the original arguments, proving the
        // escaping is not merely "plausible-looking" but system-recoverable.
        let arguments = [
            r"C:\Program Files\Meshlet\meshlet.exe",
            r#"argument with " quote and \ tail\"#,
            r"C:\Program Files\Meshlet\config one.toml",
            "--config",
        ];
        let command = elevation_runas_command(
            &ManagedExecutablePath::new(arguments[0]).unwrap(),
            &arguments[1..]
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>(),
        );
        assert_eq!(parse_windows_arguments(&command), arguments.to_vec());
    }

    #[test]
    fn paths_outside_the_managed_directory_are_rejected() {
        assert!(matches!(
            ManagedExecutablePath::new(r"C:\Windows\System32\cmd.exe"),
            Err(NetworkError::ApplyRejected(_))
        ));
        assert!(matches!(
            ManagedExecutablePath::new(r"meshlet.exe"),
            Err(NetworkError::ApplyRejected(_))
        ));
        assert!(matches!(
            ManagedExecutablePath::new(r"C:\Program Files\Meshlet\config.toml"),
            Err(NetworkError::ApplyRejected(_))
        ));
        // Component boundary: a path with the **same prefix string as but a
        // different directory from** the managed one must be refused.
        assert!(matches!(
            ManagedExecutablePath::new(r"C:\Program Files\MeshletX\evil.exe"),
            Err(NetworkError::ApplyRejected(_))
        ));
        assert!(matches!(
            ManagedExecutablePath::new(r"C:\Program Files\Meshlet\..\System32\cmd.exe"),
            Err(NetworkError::ApplyRejected(_))
        ));
    }

    #[test]
    fn managed_directory_matches_case_insensitive_and_forward_slashes() {
        // NTFS is case-insensitive; `/` is also a legal Windows separator.
        assert!(ManagedExecutablePath::new(r"c:\program files\MESHLET\Meshlet.exe").is_ok());
        assert!(ManagedExecutablePath::new(r"C:/Program Files/Meshlet/meshlet.exe").is_ok());
    }

    #[test]
    fn under_managed_directory_checks_components_not_prefix_text() {
        let managed = |text: &str| under_managed_directory(Path::new(text));
        assert!(managed(r"C:\Program Files\Meshlet\meshlet.exe"));
        assert!(managed(r"C:\Program Files\Meshlet\sub\helper.exe"));
        assert!(managed(r"c:\program files\meshlet\meshlet.exe"));
        assert!(!managed(r"C:\Program Files\MeshletX\evil.exe"));
        assert!(!managed(r"C:\Windows\System32\cmd.exe"));
        assert!(!managed(r"\\server\share\meshlet.exe"));
        assert!(!managed(r"meshlet.exe"));
    }

    #[test]
    fn parameter_command_line_omits_the_executable_path() {
        // lpParameters carries only the arguments: the UAC prompt window shows
        // lpFile, so the path is not repeated in the arguments.
        let parameters = parameter_command_line(&[
            "--config".into(),
            r"C:\Program Files\Meshlet\config one.toml".into(),
        ]);
        assert_eq!(
            parameters,
            r#"--config "C:\Program Files\Meshlet\config one.toml""#
        );
        assert!(!parameters.contains("meshlet.exe"));
    }

    #[test]
    fn privilege_error_codes_map_to_insufficient_privileges() {
        // 5 = ERROR_ACCESS_DENIED / SE_ERR_ACCESSDENIED; 740/1101 = elevation
        // required.
        for code in PRIVILEGE_ERROR_CODES {
            assert!(
                matches!(
                    classify_elevation_failure(code, "OpenProcessToken failed"),
                    NetworkError::InsufficientPrivileges(_)
                ),
                "code {code} must map to InsufficientPrivileges"
            );
        }
        // UAC texts (older-version texts where ShellExecuteW gives no code) still
        // match broadly by text.
        assert!(matches!(
            classify_elevation_failure(0, "The requested operation requires elevation"),
            NetworkError::InsufficientPrivileges(_)
        ));
        assert!(matches!(
            classify_elevation_failure(0, "netsh said: Access is denied."),
            NetworkError::InsufficientPrivileges(_)
        ));
    }

    #[test]
    fn non_privilege_failures_stay_io_with_the_original_text() {
        // 2 = ERROR_FILE_NOT_FOUND; the remaining failures are not privilege
        // issues and must not be misreported as elevation.
        let error = classify_elevation_failure(2, "ShellExecuteW runas failed (code 2)");
        assert!(matches!(error, NetworkError::Io(_)));
        assert_eq!(
            error.to_string(),
            "backend io failure: ShellExecuteW runas failed (code 2)"
        );
    }

    #[test]
    fn elevation_hint_is_stable() {
        assert_eq!(
            elevation_required_hint(),
            "请以管理员身份运行 meshlet 客户端"
        );
    }

    #[test]
    fn elevation_check_uses_controlled_whoami_argv() {
        assert_eq!(is_elevated_check_command(), vec!["whoami.exe", "/groups"]);
    }
}
