//! Windows console output decoding (shared by the execution layer, ADR-008
//! TODO #52 real-machine forensics).
//!
//! Real-machine evidence (2026-10-25, Chinese Windows Server, CP936): the
//! **redirected output of netsh / sc.exe is encoded in the active code page,
//! not UTF-8** — netsh deleting a nonexistent route returned the bytes
//! `D5 D2 B2 BB B5 BD D4 AA CB D8 A1 A3` (the GBK encoding of the
//! "element not found" message). The execution layer previously decoded with
//! `String::from_utf8_lossy`, so the Chinese text was lost as U+FFFD
//! replacement garbage and every idempotent-delete message classification
//! failed (caught by the `windows_netsh` real-machine integration test).
//!
//! Discipline:
//! - **UTF-8 first**: valid UTF-8 (the en-US runner and any UTF-8 output)
//!   passes through unchanged, with zero change to existing green paths;
//! - **non-UTF-8 is decoded with the active code page**
//!   (`MultiByteToWideChar(CP_ACP)`), covering Simplified Chinese /
//!   Traditional Chinese / Japanese and other localized deployments without
//!   introducing new external dependencies;
//! - **never panic, never return empty text to feign success**: when decoding
//!   cannot proceed, fall back to UTF-8 lossy (§10.3 failures stay visible).

/// Decode process output using the console output code page (UTF-8 first).
///
/// Console tools (route/ping/netsh/sc) emit redirected output in the **OEM code
/// page** (`GetConsoleOutputCP`), not ANSI (CP_ACP): on en-US OEM=437 and
/// ANSI=1252, so decoding OEM bytes as ANSI always garbles them. Probe
/// `GetConsoleOutputCP` first and only fall back to CP_ACP (0) when that
/// fails.
pub fn decode_output(bytes: &[u8]) -> String {
    decode_output_with(bytes, console_output_code_page())
}

/// Console output code page: fetched on every call (the kernel32 call itself
/// is nearly free), falling back to 0 (CP_ACP, the old behavior) on failure.
#[cfg(target_os = "windows")]
fn console_output_code_page() -> u32 {
    // SAFETY: GetConsoleOutputCP takes no arguments and has no side effects.
    unsafe { windows_sys::Win32::System::Console::GetConsoleOutputCP() }
}

#[cfg(not(target_os = "windows"))]
fn console_output_code_page() -> u32 {
    0
}

/// Decoding core for an explicit code page (tests inject 936/GBK to verify
/// the real-machine forensic bytes without depending on the host language).
pub fn decode_output_with(bytes: &[u8], code_page: u32) -> String {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_string();
    }
    if bytes.is_empty() {
        return String::new();
    }
    decode_via_code_page(bytes, code_page)
}

/// Windows: `MultiByteToWideChar` converts to UTF-16 under the given code page,
/// then to `String`.
#[cfg(target_os = "windows")]
fn decode_via_code_page(bytes: &[u8], code_page: u32) -> String {
    // SAFETY: lpmultibytestr points at bytes and cbmultibyte matches its length;
    // the first call fetches the target UTF-16 length, the second writes into an
    // owning buffer of exactly that length.
    unsafe {
        use windows_sys::Win32::Globalization::MultiByteToWideChar;
        let len = MultiByteToWideChar(
            code_page,
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            std::ptr::null_mut(),
            0,
        );
        if len > 0 {
            let mut utf16 = vec![0u16; len as usize];
            let written = MultiByteToWideChar(
                code_page,
                0,
                bytes.as_ptr(),
                bytes.len() as i32,
                utf16.as_mut_ptr(),
                len,
            );
            if written == len {
                return String::from_utf16_lossy(&utf16);
            }
        }
    }
    String::from_utf8_lossy(bytes).into_owned()
}

/// Non-Windows: there is no system code page semantics, so this is a UTF-8
/// lossy fallback. This branch exists only to let plan-layer unit tests
/// compile on Linux CI; real decoding happens only in the Windows execution
/// layer.
#[cfg(not(target_os = "windows"))]
fn decode_via_code_page(bytes: &[u8], _code_page: u32) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Unified creation flags for spawning controlled console tools (injected
/// through the builder chain).
///
/// **Why it is necessary**: when a GUI-subsystem process (tray-app) spawns
/// console tools (route/powershell/ping/netsh/sc/reg/wireguard.exe), Windows
/// pops a new terminal window for every child by default — pinned down on a
/// real machine 2026-11-20 (cuihaitao's box): clicking the status panel →
/// `get_diag` → `diagnostics_sync()` spawned in a chain → terminal windows
/// flashed furiously (c3634c5 only fixed the two spots inside tray-app
/// itself). This crate's execution-layer spawns reach the same GUI process via
/// [`crate::SystemBackend`], so **every controlled spawn uniformly** adds
/// `CREATE_NO_WINDOW` through [`NoWindowCommand::no_window`].
///
/// **Why it has no side effects**: every spawn in this crate captures output
/// (piped stdio, no interactive semantics to lose); console-subsystem processes
/// (agent/CLI/server) already own a console, so the child pops no new window and
/// attaches to nothing — behavior unchanged. Non-Windows platforms get an
/// identity chain (keeping cross-platform compile semantics uniform).
pub trait NoWindowCommand {
    /// Adds the `CREATE_NO_WINDOW` (0x0800_0000) creation flag.
    fn no_window(&mut self) -> &mut Self;
}

impl NoWindowCommand for std::process::Command {
    fn no_window(&mut self) -> &mut Self {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            self.creation_flags(CREATE_NO_WINDOW);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real-machine forensic bytes (2026-10-25, local CP936): netsh's complete
    /// message when deleting a nonexistent route ("element not found").
    /// Referenced by real-machine tests only.
    #[cfg(target_os = "windows")]
    const GBK_ELEMENT_ABSENT: &[u8] = &[
        0xD5, 0xD2, 0xB2, 0xBB, 0xB5, 0xBD, 0xD4, 0xAA, 0xCB, 0xD8, 0xA1, 0xA3,
    ];

    /// Real-machine forensic bytes: "no rule matched the supplied criteria"
    /// (netsh firewall's complete message when deleting a nonexistent rule).
    /// Referenced by real-machine tests only.
    #[cfg(target_os = "windows")]
    const GBK_NO_RULE_MATCH: &[u8] = &[
        0xC3, 0xBB, 0xD3, 0xD0, 0xD3, 0xEB, 0xD6, 0xB8, 0xB6, 0xA8, 0xB1, 0xEA, 0xD7, 0xBC, 0xCF,
        0xE0, 0xC6, 0xA5, 0xC5, 0xE4, 0xB5, 0xC4, 0xB9, 0xE6, 0xD4, 0xF2, 0xA1, 0xA3,
    ];

    #[test]
    fn valid_utf8_passes_through_unchanged() {
        assert_eq!(
            decode_output_with(b"Element not found.\r\n", 936),
            "Element not found.\r\n"
        );
        assert_eq!(decode_output_with(&[], 936), "");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn gbk_absence_text_decodes_via_code_page_936() {
        assert_eq!(decode_output_with(GBK_ELEMENT_ABSENT, 936), "找不到元素。");
        assert_eq!(
            decode_output_with(GBK_NO_RULE_MATCH, 936),
            "没有与指定标准相匹配的规则。"
        );
    }

    #[test]
    fn gbk_bytes_never_panic_and_never_decode_to_empty() {
        // Probe every high byte one by one: no input panics and no decoded
        // result is empty (empty text would be misread by upstream as "success",
        // §10.3).
        for lead in 0x80u8..=0xFF {
            let decoded = decode_output_with(&[lead, b'x'], 936);
            assert!(!decoded.is_empty(), "lead {lead:#04x} decoded to empty");
        }
    }
}
