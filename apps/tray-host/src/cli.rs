use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_INFO, NIIF_ERROR, NIIF_INFO, NIM_MODIFY, NOTIFYICONDATAW,
};
/// CLI executable name (installed next to `install.ps1` as `meshlet-cli.exe`;
/// clicking "connect to node…" spawns it with `peer dial <node>`, item ④).
pub(crate) const CLI_EXE: &str = "meshlet-cli.exe";

/// ④ Clicking "connect to node…": spawn `meshlet-cli peer dial <node>`
/// (asynchronously; after the agent processes it the CLI prints the result), and echo the
/// result as a system balloon (NIF_INFO) — success/failure is presented from the same source
/// as the CLI output (`ok:` / `failed:`).
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
        // Shares the nid pointer with the file-watch thread (existing model); only the
        // balloon fields are written on this thread, icon/tooltip updates happen on the other —
        // each Shell_NotifyIconW call completes atomically, so at worst one overwrites the other
        // once; this is not a data-race UB.
        unsafe {
            show_balloon(nid_raw as *mut NOTIFYICONDATAW, &outcome);
        }
    });
}

/// Runs `meshlet-cli peer dial <node>` once (hidden window) and returns (succeeded?, report text).
/// The CLI lives next to this process (install.ps1 installs the three-piece set together); point
/// `LOCALAPPDATA` at the grandparent of the state_dir the tray actually uses (= the `<local>` of
/// `<local>/meshlet/state`, isomorphic to the CLI's `state_dir_from_local`), so the CLI and the agent
/// read the same dial files.
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

/// Cap for balloon body text (`szInfo` is 256 wide chars, leaving slack for the NUL).
pub(crate) fn truncate_for_balloon(text: &str) -> String {
    if text.chars().count() <= 250 {
        text.to_string()
    } else {
        let cut: String = text.chars().take(250).collect();
        format!("{cut}…")
    }
}

/// Result balloon: success -> info icon; failure -> error icon (the result shares the CLI output as its source).
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

/// Path of `meshlet-cli.exe`: a sibling of this process's executable (install.ps1 places
/// `meshlet-{agent,cli,tray-host}.exe` in the same directory).
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
