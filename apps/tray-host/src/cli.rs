use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_INFO, NIIF_ERROR, NIIF_INFO, NIM_MODIFY, NOTIFYICONDATAW,
};
/// CLI 可执行名（与 `install.ps1` 同目录安装的 `meshlet-cli.exe`；
/// 「连接节点…」点击即 spawn 它 `peer dial <node>`，④）。
pub(crate) const CLI_EXE: &str = "meshlet-cli.exe";

/// ④ 点击「连接节点…」：spawn `meshlet-cli peer dial <node>`（异步；agent
/// 处理后 CLI 打印结果），结果以系统气泡（NIF_INFO）回显——成功/失败如
/// CLI 输出（`ok:` / `failed:`）同源呈现。
pub(crate) fn spawn_peer_dial(
    _hwnd: HWND,
    node: &str,
    state_dir: Option<&std::path::Path>,
    nid: *mut NOTIFYICONDATAW,
) {
    let node = node.to_string();
    let state_dir = state_dir.map(std::path::Path::to_path_buf);
    let nid_raw = nid as isize;
    std::thread::spawn(move || {
        let outcome = run_peer_dial(&node, state_dir.as_deref());
        // 与文件监听线程共用 nid 指针（既有模型）；气球字段只在
        // 本线程写，图标/tooltip 更新在另一线程——Shell_NotifyIconW
        // 各自原子完成，最坏互相覆盖一次，不构成数据竞争 UB。
        unsafe {
            show_balloon(nid_raw as *mut NOTIFYICONDATAW, &outcome);
        }
    });
}

/// 跑一次 `meshlet-cli peer dial <node>`（隐藏窗口），返回 (成功?, 汇报文本)。
/// CLI 与本进程同目录（install.ps1 三件套同装）；把 `LOCALAPPDATA` 指到
/// tray 实际使用的 state_dir 父父级（= `<local>/meshlet/state` 的 `<local>`，
/// 与 CLI `state_dir_from_local` 同构），保证 CLI 与 agent 读同一拨号文件。
fn run_peer_dial(node: &str, state_dir: Option<&std::path::Path>) -> (bool, String) {
    use std::os::windows::process::CommandExt;
    let Some(exe) = cli_exe_path() else {
        return (false, format!("找不到 {CLI_EXE}（应与本程序同目录安装）"));
    };
    let mut cmd = std::process::Command::new(&exe);
    cmd.args(["peer", "dial", node])
        .creation_flags(CREATE_NO_WINDOW);
    if let Some(local) = state_dir.and_then(|d| d.parent()).and_then(|d| d.parent()) {
        cmd.env("LOCALAPPDATA", local);
    }
    match cmd.output() {
        Ok(out) => {
            let ok = out.status.success();
            let text = String::from_utf8_lossy(if ok { &out.stdout } else { &out.stderr });
            let line = text
                .lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .map(str::trim)
                .unwrap_or(if ok { "dial finished" } else { "dial failed" });
            (ok, truncate_for_balloon(line))
        }
        Err(e) => (
            false,
            truncate_for_balloon(&format!("无法启动 {CLI_EXE}: {e}")),
        ),
    }
}

/// 气泡正文上限（`szInfo` 为 256 宽字符，含 NUL 留余量）。
pub(crate) fn truncate_for_balloon(text: &str) -> String {
    if text.chars().count() <= 250 {
        text.to_string()
    } else {
        let cut: String = text.chars().take(250).collect();
        format!("{cut}…")
    }
}

/// 结果气泡：成功 → 信息图标；失败 → 错误图标（结果与 CLI 输出同源）。
unsafe fn show_balloon(nid: *mut NOTIFYICONDATAW, outcome: &(bool, String)) {
    let (ok, text) = outcome;
    let info = wide_z(text);
    let title = wide_z(if *ok {
        "直连拨号成功"
    } else {
        "直连拨号失败"
    });
    for i in 0..256 {
        (*nid).szInfo[i] = info.get(i).copied().unwrap_or(0);
    }
    for i in 0..64 {
        (*nid).szInfoTitle[i] = title.get(i).copied().unwrap_or(0);
    }
    (*nid).dwInfoFlags = if *ok { NIIF_INFO } else { NIIF_ERROR };
    (*nid).uFlags |= NIF_INFO;
    Shell_NotifyIconW(NIM_MODIFY, nid);
}

/// `meshlet-cli.exe` 路径：本进程可执行文件的兄弟（install.ps1 把
/// `meshlet-{agent,cli,tray-host}.exe` 装到同一目录）。
fn cli_exe_path() -> Option<std::path::PathBuf> {
    let mut buf = [0u16; 260];
    let len =
        unsafe { GetModuleFileNameW(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32) }
            as usize;
    if len == 0 || len >= buf.len() {
        return None;
    }
    let exe = std::path::PathBuf::from(String::from_utf16_lossy(&buf[..len]));
    exe.parent().map(|dir| dir.join(CLI_EXE))
}

fn wide_z(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_for_balloon_caps_long_output() {
        let short = "ok: direct link established (p2p_direct)";
        assert_eq!(truncate_for_balloon(short), short);
        let long: String = "字".repeat(400);
        let cut = truncate_for_balloon(&long);
        assert!(cut.chars().count() <= 251);
        assert!(cut.ends_with('…'));
    }
}
