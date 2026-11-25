// Release builds (nightly msi/zip) link the GUI subsystem: no console, so stdout/stderr
// are unavailable and logging goes through a file appender (see `init_tray_logging`); debug
// builds keep the console subsystem so CI's stderr-redirection gate (the tray registration
// evidence in ci.yml) keeps working as before.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Windows system tray host: consumes the PNG status icon from [TraySink].
//!
//! Watches the `status.json` + `icon-*.png` written by the agent and shows the current status
//! in the system tray via `Shell_NotifyIcon`. The icon is swapped as soon as the status changes —
//! no polling needed.
//!
//! Usage: `meshlet-tray-host <state_dir>`

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

    // `_log_guard` must be bound for the lifetime of main: the non-blocking writer thread lives as long as the guard.
    let _log_guard = init_tray_logging();

    // Local panel: bind the loopback **before the tray icon** (decided 2026-11-06: what the
    // tray opens is the local panel, and the data only reads local state files — even if the
    // server is down and the agent has not written a status icon yet, the panel still opens,
    // showing only empty-state wording for the missing data).
    start_local_panel(&state_dir);

    tracing::info!("watching {}", tray_dir.display());

    while !tray_dir.exists() {
        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    // "Console (web)" needs the server_url from the agent config file (under `{state_dir}/..`);
    // the menu data (status first row / direct nodes) reads the state files under state_dir.
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

        // The menu is no longer built once here: each right-click rebuilds it from the current
        // status snapshot (see tray_wnd_proc / build_menu), so the first row and the direct /
        // connect submenus all carry fresh data.
        G_NID.store(&mut nid as *mut _, Ordering::SeqCst);

        // Read the current status and apply the icon immediately at startup
        update_tray(&status_path, &mut nid);

        // ④ Agent process linkage: the agent exits -> the tray disappears (the watchdog polls for the process name).
        spawn_agent_watchdog(hwnd);

        // File watching runs on its own thread, leaving the main loop to handle messages
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

        // Blocking message loop
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
