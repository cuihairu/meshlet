// Release 构建（nightly msi/zip）以 GUI 子系统链接：无控制台，stdout/stderr
// 不可用，日志改走文件 appender（见 `init_tray_logging`）；debug 构建保留控制台
// 子系统，供 CI 的 stderr 重定向门禁（ci.yml tray 注册证据）照常工作。
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Windows 系统托盘宿主：消费 [TraySink] 的 PNG 状态图。
//!
//! 监听 agent 写出的 `status.json` + `icon-*.png`，通过 `Shell_NotifyIcon`
//! 在系统托盘显示当前状态。状态变化即换图，无需轮询。
//!
//! 用法：`meshlet-tray-host <state_dir>`

#[cfg(windows)]
mod cli;
#[cfg(windows)]
mod icon;
#[cfg(windows)]
mod launcher;
#[cfg(windows)]
mod menu;
#[cfg(windows)]
mod tray;
#[cfg(windows)]
mod watchdog;

#[cfg(windows)]
use std::sync::atomic::Ordering;
#[cfg(windows)]
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
#[cfg(windows)]
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NOTIFYICONDATAW,
};
#[cfg(windows)]
use windows_sys::Win32::UI::WindowsAndMessaging::*;

#[cfg(windows)]
use crate::icon::{create_green_icon, load_status_icon, rgba_to_icon, update_tray};
#[cfg(windows)]
use crate::launcher::{init_tray_logging, start_local_panel};
#[cfg(windows)]
use crate::tray::{set_state_dir, tray_wnd_proc, G_EXIT, G_HWND, G_NID};
#[cfg(windows)]
use crate::watchdog::spawn_agent_watchdog;

#[cfg(windows)]
fn main() {
    use std::path::PathBuf;

    let args: Vec<String> = std::env::args().collect();
    let state_dir = args.get(1).map(PathBuf::from).unwrap_or_else(|| {
        let local = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "C:/Users/Public".into());
        PathBuf::from(local).join("meshlet").join("state")
    });
    let tray_dir = state_dir.join("tray");
    let status_path = tray_dir.join("status.json");

    // `_log_guard` 必须绑定到 main 生命周期：non-blocking 写线程随 guard 存活。
    let _log_guard = init_tray_logging();

    // 本地面板：**先于托盘图标**绑定 loopback（定案 2026-11-06：托盘打开的是
    // 本地面板，数据只读本机状态文件——server 挂了、agent 还没写出状态图，面板
    // 照样开，缺数据只显示空态文案）。
    start_local_panel(&state_dir);

    tracing::info!("watching {}", tray_dir.display());

    while !tray_dir.exists() {
        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    // 「控制台(网页)」需要 agent 配置文件（`{state_dir}/..` 下）里的
    // server_url；菜单数据（状态首行 / 直连节点）读 state_dir 下的状态文件。
    let state_dir: &'static std::path::Path = Box::leak(state_dir.into_boxed_path());
    set_state_dir(state_dir);

    unsafe {
        let class_name: Vec<u16> = "MeshletTrayHost\0".encode_utf16().collect();
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: 0,
            lpfnWndProc: Some(tray_wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: GetModuleHandleW(std::ptr::null()),
            hIcon: std::ptr::null_mut(),
            hCursor: std::ptr::null_mut(),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: class_name.as_ptr(),
            hIconSm: std::ptr::null_mut(),
        };
        RegisterClassExW(&wc);

        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            std::ptr::null(),
            0,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            GetModuleHandleW(std::ptr::null()),
            std::ptr::null(),
        );
        tracing::debug!("hwnd={hwnd:p}");
        G_HWND.store(hwnd as isize, Ordering::SeqCst);

        let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = 1;
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        nid.uCallbackMessage = WM_APP + 1;
        nid.hIcon = load_status_icon(&status_path)
            .map(|(w, h, rgba)| rgba_to_icon(&rgba, w, h))
            .unwrap_or_else(create_green_icon);
        tracing::debug!("hIcon={:p}", nid.hIcon);
        let tip: Vec<u16> = "Meshlet\0".encode_utf16().collect();
        for (i, &w) in tip.iter().enumerate().take(127) {
            nid.szTip[i] = w;
        }
        let ok = Shell_NotifyIconW(NIM_ADD, &nid);
        tracing::info!("NIM_ADD = {ok}");

        // 菜单不再在此一次性构建：每次右键按当前状态快照重建（见
        // tray_wnd_proc / build_menu），首行 + 直连/连接子菜单均为新鲜数据。
        G_NID.store(&mut nid as *mut _, Ordering::SeqCst);

        // 启动时立即读取当前状态并应用图标
        update_tray(&status_path, &mut nid);

        // ④ agent 进程联动：agent 退出 → 托盘消失（watchdog 轮询进程名）。
        spawn_agent_watchdog(hwnd);

        // 文件监听放独立线程，主循环专心处理消息
        let watch_path = status_path.clone();
        std::thread::spawn(move || {
            let mut last_mtime: Option<std::time::SystemTime> = None;
            loop {
                if G_EXIT.load(Ordering::SeqCst) {
                    return;
                }
                if let Ok(meta) = std::fs::metadata(&watch_path) {
                    if let Ok(mtime) = meta.modified() {
                        if last_mtime.is_none_or(|old| mtime > old) {
                            last_mtime = Some(mtime);
                            let nid_ptr = G_NID.load(Ordering::SeqCst);
                            if !nid_ptr.is_null() {
                                update_tray(&watch_path, &mut *nid_ptr);
                            }
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        });

        // 阻塞消息循环
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        tracing::info!("message loop exited");
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("meshlet-tray-host is Windows-only");
    std::process::exit(1);
}
