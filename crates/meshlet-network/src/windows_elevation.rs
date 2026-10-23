//! Windows 提权计划层（[ADR-008](../../../docs/decisions/adr-008-windows-network-backend.md)）。
//!
//! 本模块包含**纯规划**与 `#[cfg(windows)]` 执行层：受管客户端可执行路径
//! 校验、`ShellExecuteW(runas)` 等价命令行构造、当前进程 TokenElevation
//! 检查与 UAC 拒绝分类。计划层在任意平台编译并单测；执行层
//! **未在 Windows 上实测前**不得接为 [crate::SystemBackend]，非 Linux
//! 平台仍保持 [crate::unsupported] 的显式占位（§10.3、§12.2）。
//!
//! 与 [windows_cleanup](windows_cleanup)、[windows_routes](windows_routes)、
//! [windows_firewall](windows_firewall)、[windows_service](windows_service)
//! 同一纪律：
//!
//! - **受管路径**：只接受绝对 `.exe` 且位于 Meshlet 受管安装目录前缀下，
//!   其他可执行文件一律 [NetworkError::ApplyRejected]；
//! - **参数不拆词**：每个受管参数按 Windows 命令行引号规则整体转义，
//!   含空格或引号的路径保持单个参数；
//! - **受控执行**：执行层只调用 ShellExecuteW 的 `runas` 动词和当前进程
//!   TokenElevation 查询，不拼接自由 Shell；
//! - **fail closed**：elevation/denied 文案映射为
//!   [`NetworkError::InsufficientPrivileges`]，其余失败保持原错误分类。

use std::path::{Path, PathBuf};

use crate::NetworkError;

/// Meshlet 受管安装目录前缀；路径校验只允许该目录下的客户端可执行文件。
pub const MANAGED_EXECUTABLE_DIRECTORY: &str = r"C:\Program Files\Meshlet";

/// Meshlet 受管客户端可执行文件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedExecutablePath(PathBuf);

impl ManagedExecutablePath {
    /// 校验并封装受管可执行路径；拒绝相对路径、非 `.exe` 和受管目录外路径。
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
        // fail closed：含 `..` 段的路径规范化后可逃出受管目录，计划层不解析
        // 只拒绝（受管安装路径是规范的，正常路径不含父段）。
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

    /// 受管可执行路径。
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// 整体带引号转义的 Windows 命令行字符串（`lpFile` + `lpParameters`）。
    pub fn command_line(&self, args: &[String]) -> String {
        format!(
            "{} {}",
            quote_windows_argument(self.0.to_string_lossy().as_ref()),
            parameter_command_line(args)
        )
    }
}

/// 构造 `ShellExecuteW(runas)` 等价命令行；计划断言与执行层共用同一形状。
pub fn elevation_runas_command(path: &ManagedExecutablePath, args: &[String]) -> String {
    path.command_line(args)
}

/// ShellExecuteW 的 `lpParameters`：不含 `lpFile`，参数逐个按 Windows 命令行
/// 规则整体转义（计划层可断言、执行层消费）。
pub fn parameter_command_line(args: &[String]) -> String {
    args.iter()
        .map(|argument| quote_windows_argument(argument))
        .collect::<Vec<_>>()
        .join(" ")
}

/// 路径是否位于受管安装目录之下。**Windows 路径语义**：按 `\` / `/` 切段、
/// 逐段比较且大小写不敏感（NTFS 不区分大小写）——不能用
/// [`std::path::Path::starts_with`]，它在非 Windows 平台把整串反斜杠路径当作
/// 单个组件，导致校验在 Linux 单测与 Windows 实测行为分叉。
pub fn under_managed_directory(path: &Path) -> bool {
    let segments = windows_path_segments(path);
    let managed = windows_path_segments(Path::new(MANAGED_EXECUTABLE_DIRECTORY));
    segments.len() >= managed.len()
        && segments[..managed.len()]
            .iter()
            .zip(&managed)
            .all(|(segment, base)| segment.eq_ignore_ascii_case(base))
}

/// Windows 路径切段：`\` 与 `/` 都算分隔符，空段（重复分隔符 / 前导分隔符）跳过。
fn windows_path_segments(path: &Path) -> Vec<String> {
    path.to_string_lossy()
        .split(['\\', '/'])
        .filter(|segment| !segment.is_empty())
        .map(str::to_string)
        .collect()
}

/// 当前进程是否已提权的受控检查命令 argv；输出供上层诊断，不解析自由文本。
pub fn is_elevated_check_command() -> Vec<String> {
    vec!["whoami.exe".into(), "/groups".into()]
}

/// 供上层复用的统一客户端操作提示。
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

/// 权限类 Windows 失败码：`ERROR_ACCESS_DENIED`(5)、`ERROR_ELEVATION_REQUIRED`(740)、
/// 以及 ShellExecuteW 失败返回里的 `SE_ERR_ACCESSDENIED`(5) 与提升必需(1101)。
/// 这些码都表示「需要管理员」，其余失败保持 [`NetworkError::Io`] 分类。
pub const PRIVILEGE_ERROR_CODES: [u32; 3] = [5, 740, 1101];

/// 失败分类（纯函数，Linux 可单测）：权限类错误码或 UAC 文案 →
/// [`NetworkError::InsufficientPrivileges`]，其余 → [`NetworkError::Io`]；
/// 两类都保留原始报错文本，不吞信息（fail closed 见 [`ManagedExecutablePath::new`]）。
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

/// Windows 执行层（`#[cfg(windows)]`）：UAC 重启与 TokenElevation 查询。
///
/// **未在 Windows 上实测**；实测前不得接为 [crate::SystemBackend]。
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

    /// 以 UAC `runas` 动词启动受管可执行文件。
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

    /// 查询当前进程 TokenElevation；无法判定时 fail closed。
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

    /// CommandLineToArgvW 的规则子集（测试用）：2n 个反斜杠后跟引号 → n 个字面
    /// 反斜杠 + 引号定界；奇数个则末位反斜杠转义引号本身；引号外的空白分词。
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
        // 嵌入引号 / 尾随反斜杠 / 路径内空格：标准解析器必须还原出原参数，
        // 证明转义不是「看起来对」而是可被系统还原。
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
        // 组件边界：受管目录**前缀字符串相同但不是同一目录**的路径必须拒绝。
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
        // NTFS 不区分大小写；`/` 也是合法的 Windows 分隔符。
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
        // lpParameters 只带参数：UAC 提示窗显示的是 lpFile，参数里不再重复路径。
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
        // 5 = ERROR_ACCESS_DENIED / SE_ERR_ACCESSDENIED，740/1101 = 提升必需。
        for code in PRIVILEGE_ERROR_CODES {
            assert!(
                matches!(
                    classify_elevation_failure(code, "OpenProcessToken failed"),
                    NetworkError::InsufficientPrivileges(_)
                ),
                "code {code} must map to InsufficientPrivileges"
            );
        }
        // UAC 文案（ShellExecuteW 不给码的旧版本文案）仍按文本宽匹配。
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
        // 2 = ERROR_FILE_NOT_FOUND；其余失败不是权限问题，不得误报提权。
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
