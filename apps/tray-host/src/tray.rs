use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicPtr, Ordering};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows_sys::Win32::UI::Shell::{Shell_NotifyIconW, NIM_DELETE, NOTIFYICONDATAW};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use crate::cli::spawn_peer_dial;
use crate::launcher::{open_console, open_local_panel};
use crate::menu::{
    build_menu, load_local_direct_peers, split_peer_views, status_line_text, CMD_DIAL_BASE,
    CMD_OPEN_CONSOLE, CMD_OPEN_LOCAL_PANEL, CMD_QUIT,
};
use crate::watchdog::{terminate_agent, WM_TRAY_EXIT};

pub(crate) static G_HWND: AtomicIsize = AtomicIsize::new(0);
pub(crate) static G_NID: AtomicPtr<NOTIFYICONDATAW> = AtomicPtr::new(std::ptr::null_mut());
pub(crate) static G_MENU: AtomicIsize = AtomicIsize::new(0);
pub(crate) static G_EXIT: AtomicBool = AtomicBool::new(false);
static G_STATE_DIR: std::sync::OnceLock<&'static std::path::Path> = std::sync::OnceLock::new();

pub(crate) fn set_state_dir(state_dir: &'static std::path::Path) {
    let _ = G_STATE_DIR.set(state_dir);
}

pub(crate) fn state_dir() -> Option<&'static std::path::Path> {
    G_STATE_DIR.get().copied()
}

pub(crate) unsafe extern "system" fn tray_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if msg == WM_APP + 1 {
        let event = lparam as u32;
        tracing::debug!("tray event={event:#x}");
        if event == WM_RBUTTONUP || event == WM_LBUTTONUP {
            // ①②④：每次右键按当前状态快照重建菜单——首行（设备名+虚拟 IP+
            // 状态）、「直连节点」（IP/模式/RTT）、「连接节点…」（可拨候选）。
            // 文件变化（status.json / direct-peers.json）由各自线程维护，无需
            // 常驻菜单；`TrackPopupMenuEx` 同步返回所选命令，快照即点即用。
            let state_dir = state_dir();
            let status_line = status_line_text(state_dir);
            let peers = load_local_direct_peers(state_dir);
            let (direct, relay) = split_peer_views(&peers);
            let hmenu = build_menu(&status_line, &direct, &relay);
            destroy_current_menu();
            G_MENU.store(hmenu as isize, Ordering::SeqCst);

            let mut pt: POINT = std::mem::zeroed();
            GetCursorPos(&mut pt);
            SetForegroundWindow(hwnd);
            PostMessageW(hwnd, WM_NULL, 0, 0);
            let cmd = TrackPopupMenuEx(
                hmenu,
                TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_RETURNCMD,
                pt.x,
                pt.y,
                hwnd,
                std::ptr::null(),
            ) as usize;
            tracing::debug!("menu cmd={cmd}");
            // 菜单已用毕，立即销毁（`TPM_RETURNCMD` 不投递 WM_COMMAND）。
            destroy_current_menu();
            match cmd {
                // 退出：停止当前用户会话 agent（best-effort，D4：不删持久隧道），
                // 再清托盘；若 agent 已死则仅清托盘（④ 的 watchdog 也会触发）。
                CMD_QUIT => {
                    terminate_agent();
                    do_exit();
                }
                CMD_OPEN_LOCAL_PANEL => {
                    open_local_panel(
                        hwnd,
                        crate::launcher::panel_url_global().map(String::as_str),
                    );
                }
                CMD_OPEN_CONSOLE => open_console(hwnd, state_dir),
                // ④ 连接节点…：点击候选 → spawn `meshlet-cli peer dial <node>`
                //（`<node>` 用可解析的名称/IP，非菜单展示串）。
                id if id >= CMD_DIAL_BASE => {
                    if let Some(node) = relay.get(id - CMD_DIAL_BASE) {
                        let nid_ptr = G_NID.load(Ordering::SeqCst);
                        if !nid_ptr.is_null() {
                            spawn_peer_dial(hwnd, &node.display_name(), state_dir, nid_ptr);
                        }
                    }
                }
                _ => {}
            }
        }
        return 0;
    }
    if msg == WM_TRAY_EXIT {
        tracing::info!("agent process gone, exiting tray");
        do_exit();
        return 0;
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

pub(crate) fn do_exit() {
    if G_EXIT.swap(true, Ordering::SeqCst) {
        return;
    }
    if let Some(state_dir) = state_dir() {
        meshlet_tray_host::panel::remove_url_file(state_dir);
    }
    let nid_ptr = G_NID.load(Ordering::SeqCst) as *mut NOTIFYICONDATAW;
    if !nid_ptr.is_null() {
        unsafe {
            Shell_NotifyIconW(NIM_DELETE, &*nid_ptr);
        }
    }
    let hmenu = G_MENU.load(Ordering::SeqCst) as HMENU;
    if !hmenu.is_null() {
        unsafe {
            DestroyMenu(hmenu);
        }
    }
    let hwnd = G_HWND.load(Ordering::SeqCst) as HWND;
    if !hwnd.is_null() {
        unsafe {
            DestroyWindow(hwnd);
        }
    }
}

pub(crate) fn destroy_current_menu() {
    let hmenu = G_MENU.swap(0, Ordering::SeqCst) as HMENU;
    if !hmenu.is_null() {
        unsafe {
            DestroyMenu(hmenu);
        }
    }
}
