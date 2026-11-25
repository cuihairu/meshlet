use std::sync::atomic::Ordering;
use windows_sys::Win32::Foundation::{CloseHandle, HWND, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

/// Agent executable name (the binary that `install.ps1` installs into `%LOCALAPPDATA%\meshlet`).
pub(crate) const AGENT_EXE: &str = "meshlet-agent.exe";
/// Polling interval for agent process detection.
const AGENT_POLL: std::time::Duration = std::time::Duration::from_secs(2);
/// Grace polls before the agent first shows up (~30s): if `tray_dir` already exists the agent
/// has written state at least once, so a process enumeration that still misses it most likely
/// means the agent is dead — the tray leaves no orphan icon behind.
const FIRST_SIGHT_POLLS: u32 = 15;
/// Consecutive polls of absence after the agent has been seen and then died (~6s) -> the tray exits.
const GONE_POLLS: u32 = 3;

/// Second internal message besides the tray callback: the agent process is dead, so the tray exits too (④).
pub(crate) const WM_TRAY_EXIT: u32 = windows_sys::Win32::UI::WindowsAndMessaging::WM_APP + 2;

/// ④ Agent process linkage: poll for `meshlet-agent.exe`. Once the agent has been seen, sustained
/// absence (~6s) -> the tray exits; never seen but `tray_dir` already exists (the agent died right
/// after writing state) -> exit after the ~30s grace period, leaving no ownerless tray.
pub(crate) fn spawn_agent_watchdog(hwnd: HWND) {
    // HWND is a raw pointer (!Send), so the closure must capture an isize to post from another thread.
    let hwnd_raw = hwnd as isize;
    std::thread::spawn(move || {
        let mut seen = false;
        let mut gone_polls = 0u32;
        let mut first_sight_polls = 0u32;
        loop {
            if crate::tray::G_EXIT.load(Ordering::SeqCst) {
                return;
            }
            if agent_alive() {
                seen = true;
                gone_polls = 0;
            } else if seen {
                gone_polls += 1;
                if gone_polls >= GONE_POLLS {
                    unsafe {
                        windows_sys::Win32::UI::WindowsAndMessaging::PostMessageW(
                            hwnd_raw as HWND,
                            WM_TRAY_EXIT,
                            0,
                            0,
                        );
                    }
                    return;
                }
            } else {
                first_sight_polls += 1;
                if first_sight_polls >= FIRST_SIGHT_POLLS {
                    unsafe {
                        windows_sys::Win32::UI::WindowsAndMessaging::PostMessageW(
                            hwnd_raw as HWND,
                            WM_TRAY_EXIT,
                            0,
                            0,
                        );
                    }
                    return;
                }
            }
            std::thread::sleep(AGENT_POLL);
        }
    });
}

/// Finds the agent process PID by name (Toolhelp32 snapshot; opens no process handle, so it works across privilege levels).
fn agent_pid() -> Option<u32> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = None;
        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                if exe_name_matches(&entry.szExeFile) {
                    found = Some(entry.th32ProcessID);
                    break;
                }
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
        found
    }
}

fn agent_alive() -> bool {
    agent_pid().is_some()
}

/// Whether `szExeFile` (`[u16; 260]`, NUL-terminated) equals [`AGENT_EXE`] (case-insensitive).
pub(crate) fn exe_name_matches(name: &[u16]) -> bool {
    let want: Vec<u16> = AGENT_EXE.encode_utf16().collect();
    let actual_len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    actual_len == want.len()
        && name[..actual_len]
            .iter()
            .zip(want.iter())
            .all(|(a, b)| ascii_lower(*a) == ascii_lower(*b))
}

/// Lowercases an ASCII capital letter (process names / file names are ASCII); non-letters pass through unchanged.
fn ascii_lower(c: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&c) {
        c + 32
    } else {
        c
    }
}

/// "Quit" stops the agent: locate the PID by name -> `TerminateProcess`. Best-effort: insufficient
/// permissions or an already-dead process are only logged, and the tray still exits (D4: quitting
/// only stops the agent, it does not delete persistent tunnels).
pub(crate) fn terminate_agent() {
    let Some(pid) = agent_pid() else {
        tracing::warn!("no agent process to stop");
        return;
    };
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if handle.is_null() {
            tracing::warn!(
                "OpenProcess({pid}) failed: {}",
                std::io::Error::last_os_error()
            );
            return;
        }
        tracing::info!("stopping agent pid={pid}");
        TerminateProcess(handle, 0);
        CloseHandle(handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exe_name_matches_agent_binary_case_insensitively() {
        let want: Vec<u16> = "Meshlet-Agent.Exe".encode_utf16().collect();
        assert!(exe_name_matches(&want));
        let exact: Vec<u16> = "meshlet-agent.exe\0".encode_utf16().collect();
        assert!(exe_name_matches(&exact));
    }

    #[test]
    fn exe_name_matches_rejects_other_names() {
        let other: Vec<u16> = "meshlet-tray-host.exe".encode_utf16().collect();
        assert!(!exe_name_matches(&other));
        // A prefix must not match: meshlet-agent must not be mistaken for something else (or vice versa).
        let prefix: Vec<u16> = "meshlet-agent".encode_utf16().collect();
        assert!(!exe_name_matches(&prefix));
        // All NULs / an empty name.
        let empty = [0u16; 260];
        assert!(!exe_name_matches(&empty));
    }
}
