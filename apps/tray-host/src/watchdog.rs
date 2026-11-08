use std::sync::atomic::Ordering;
use windows_sys::Win32::Foundation::{CloseHandle, HWND, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

/// agent 可执行名（`install.ps1` 装到 `%LOCALAPPDATA%\meshlet` 的二进制）。
pub(crate) const AGENT_EXE: &str = "meshlet-agent.exe";
/// agent 进程探测轮询间隔。
const AGENT_POLL: std::time::Duration = std::time::Duration::from_secs(2);
/// agent 首次现身前的宽限轮数（~30s）：`tray_dir` 已存在说明 agent 至少写过
/// 一次状态，进程枚举仍未命中则大概率已死，托盘不留孤儿图标。
const FIRST_SIGHT_POLLS: u32 = 15;
/// agent 死后（已见过）持续缺席的轮数（~6s）→ 托盘退出。
const GONE_POLLS: u32 = 3;

/// 托盘回调之外的第二内部消息：agent 进程已死，托盘随之退出（④）。
pub(crate) const WM_TRAY_EXIT: u32 = windows_sys::Win32::UI::WindowsAndMessaging::WM_APP + 2;

/// ④ agent 进程联动：轮询 `meshlet-agent.exe`。已见过 agent 后持续缺席
/// （~6s）→ 托盘退出；从未见过但 `tray_dir` 已存在（agent 写过状态后即死）
/// → ~30s 宽限后退出，不留无主托盘。
pub(crate) fn spawn_agent_watchdog(hwnd: HWND) {
    // HWND 是裸指针（!Send），闭包须捕获 isize 才能在独立线程发送。
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

/// 按名字找 agent 进程 PID（Toolhelp32 快照；不打开进程句柄，跨特权可用）。
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

/// `szExeFile`（`[u16; 260]`，NUL 结尾）是否等于 [`AGENT_EXE`]（大小写不敏感）。
pub(crate) fn exe_name_matches(name: &[u16]) -> bool {
    let want: Vec<u16> = AGENT_EXE.encode_utf16().collect();
    let actual_len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    actual_len == want.len()
        && name[..actual_len]
            .iter()
            .zip(want.iter())
            .all(|(a, b)| ascii_lower(*a) == ascii_lower(*b))
}

/// ASCII 大写转小写（进程名/文件名均为 ASCII）；非字母原样返回。
fn ascii_lower(c: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&c) {
        c + 32
    } else {
        c
    }
}

/// 「退出」停止 agent：按名找 PID → `TerminateProcess`。best-effort：权限不足
/// 或进程已死只记日志，托盘仍会退出（D4：退出仅停 agent，不删持久隧道）。
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
        // 前缀不匹配：不能把 meshlet-agent 误认为别的（或反之）。
        let prefix: Vec<u16> = "meshlet-agent".encode_utf16().collect();
        assert!(!exe_name_matches(&prefix));
        // 全 NUL / 空名。
        let empty = [0u16; 260];
        assert!(!exe_name_matches(&empty));
    }
}
