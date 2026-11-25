//! Tray popup and settings window orchestration.

use crate::state::{clear_pending_goto, goto_zone_js, set_pending_goto};
use crate::tray::popup_origin;
use tauri::{Manager, PhysicalPosition, Position};

/// When window-creation failures only reach stderr, the GUI-subsystem tray process has no console
/// and no place for logs, so "clicking Settings does nothing" cannot self-diagnose (a disk sink added
/// after the 2026-11-25 user report). Write failures stay silent: the diagnostics channel must not become a new failure source.
#[cfg(target_os = "windows")]
pub(crate) fn log_diag(message: &str) {
    let Some(local) = std::env::var_os("LOCALAPPDATA") else {
        return;
    };
    let dir = std::path::Path::new(&local).join("meshlet").join("logs");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("tray.err.log"))
        .and_then(|mut f| {
            std::io::Write::write_all(&mut f, format!("{stamp} {message}\n").as_bytes())
        });
}

/// Non-Windows has no "GUI process without console" diagnostics gap; keep an identically named
/// stub so callers need not carry their own cfg.
#[cfg(not(target_os = "windows"))]
pub(crate) fn log_diag(_message: &str) {}

/// Place the popup near the tray: bottom-right on Windows (above the taskbar holding the tray),
/// and below the menu bar on the right on macOS.
pub(crate) fn position_popup(app: &tauri::AppHandle, window: &tauri::WebviewWindow) {
    let Some(monitor) = app.primary_monitor().ok().flatten() else {
        return;
    };
    let size = window
        .outer_size()
        .unwrap_or(tauri::PhysicalSize::new(320, 480));
    let (x, y) = popup_origin(
        monitor.size().width as i32,
        monitor.size().height as i32,
        size.width as i32,
        size.height as i32,
        monitor.scale_factor(),
        cfg!(target_os = "macos"),
    );
    let _ = window.set_position(Position::Physical(PhysicalPosition::new(x, y)));
}

/// Programmatically create the popup window (hidden), then show and focus it. Auto-hide on focus
/// loss is handled in the `run` event's `WindowEvent::Focused(false)`.
pub(crate) fn toggle_popup_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("popup") {
        if window.is_visible().unwrap_or(false) {
            let _ = window.hide();
            return;
        }
        position_popup(app, &window);
        reveal_window(&window);
        return;
    }
    if let Err(error) =
        tauri::WebviewWindowBuilder::new(app, "popup", tauri::WebviewUrl::App("popup.html".into()))
            .title("Meshlet")
            .inner_size(320.0, 480.0)
            .resizable(false)
            .decorations(false)
            .visible(false)
            .skip_taskbar(true)
            .always_on_top(true)
            .build()
    {
        eprintln!("meshlet-tray: build popup window failed: {error}");
        log_diag(&format!("build popup window failed: {error}"));
        return;
    }
    if let Some(window) = app.get_webview_window("popup") {
        position_popup(app, &window);
        reveal_window(&window);
    }
}

/// Open (or focus) the settings window and navigate to `zone`. The menu's "Diagnostics/Route table/Peers"
/// and the popup's shortcuts share this entry point.
pub(crate) fn open_settings_at_zone(app: &tauri::AppHandle, zone: &str) {
    set_pending_goto(zone);
    open_settings_window(app);
    if let Some(window) = app.get_webview_window("settings") {
        if let Some(js) = goto_zone_js(zone) {
            if window.eval(&js).is_ok() {
                // The eval reached a live window and the pending item was consumed — clear it now. Otherwise,
                // on window reload the script fetches it again via take_pending_goto and would replay a stale
                // navigation onto the freshly loaded page (jumping to a section the user never clicked).
                clear_pending_goto();
            }
        }
    }
}

/// Bring the window to the front: restore (if minimized) → show → focus. Shared by the settings
/// window and the status popup. unminimize must come first: tao's `show()` bottoms out at
/// `ShowWindow(SW_SHOW)` (tao-0.37.2 window_state.rs:458-468) and does not restore minimized windows,
/// while tao's `set_focus()` is guarded by `is_visible && !is_minimized && !is_foreground`
/// (tao-0.37.2 window.rs:139-150) and is a no-op while minimized — with show+focus alone a minimized
/// window stays in the taskbar untouched, which the user reads as "clicking Open Settings does nothing".
pub(crate) fn reveal_window<R: tauri::Runtime>(window: &tauri::WebviewWindow<R>) {
    if window.is_minimized().unwrap_or(false) {
        let _ = window.unminimize();
    }
    let _ = window.show();
    let _ = window.set_focus();
}

/// Show (or focus) the settings panel — used by the context menu's "Open Settings" item; behavior is
/// unchanged: always bring the window to the front.
pub(crate) fn open_settings_window<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    if let Some(window) = app.get_webview_window("settings") {
        reveal_window(&window);
        return;
    }
    build_settings_window(app);
}

/// Should a tray left click hide the panel (pure decision, testable): only a visible and **not**
/// minimized window counts as "in use" → hide. A minimized window's `is_visible()` is still true
/// (WS_VISIBLE is not cleared), and hiding on it would shove the minimized window further into the
/// taskbar from one tray click, never restoring it; the Windows tray convention is that a single click restores a minimized window.
pub(crate) fn settings_toggle_should_hide(is_visible: bool, is_minimized: bool) -> bool {
    is_visible && !is_minimized
}

/// Toggle the settings panel's visibility — the tray icon's left-click path: hide when visible,
/// otherwise show and focus. Unlike `open_settings_window` (always shows), a single click is a
/// "toggle" rather than a "pop-up", which is the mainstream Windows tray interaction convention.
pub(crate) fn toggle_settings_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("settings") {
        let visible = window.is_visible().unwrap_or(false);
        let minimized = window.is_minimized().unwrap_or(false);
        if settings_toggle_should_hide(visible, minimized) {
            let _ = window.hide();
        } else {
            reveal_window(&window);
        }
        return;
    }
    build_settings_window(app);
}

fn build_settings_window<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    // Creation failures are no longer swallowed silently: window-creation races or WebView faults
    // leave at least one diagnostic line (the previous `let _ =` made "clicking Open Settings does nothing" untraceable).
    if let Err(error) = tauri::WebviewWindowBuilder::new(
        app,
        "settings",
        tauri::WebviewUrl::App("index.html".into()),
    )
    .title("Meshlet 设置")
    .inner_size(760.0, 600.0)
    .min_inner_size(600.0, 480.0)
    .resizable(true)
    .build()
    {
        eprintln!("meshlet-tray: build settings window failed: {error}");
        log_diag(&format!("build settings window failed: {error}"));
    }
}

/// The exit-verification mini window (quit password protection path): it asks for the password, and a
/// `verify_exit_guard` match exits the whole app; cancel/close only closes the window without quitting.
/// Topmost and centered so the settings window can't cover it. The title reuses the menu's "Quit" text (it follows the tray language).
pub(crate) fn open_exit_guard_window<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    if let Some(window) = app.get_webview_window("exit-guard") {
        reveal_window(&window);
        return;
    }
    let title = crate::i18n::menu_texts(&crate::i18n::read_tray_lang()).quit;
    if let Err(error) = tauri::WebviewWindowBuilder::new(
        app,
        "exit-guard",
        tauri::WebviewUrl::App("exit-guard.html".into()),
    )
    .title(title)
    .inner_size(380.0, 200.0)
    .resizable(false)
    .center()
    .always_on_top(true)
    .skip_taskbar(true)
    .build()
    {
        eprintln!("meshlet-tray: build exit guard window failed: {error}");
        log_diag(&format!("build exit guard window failed: {error}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggle_hides_only_visible_unminimized_window() {
        assert!(settings_toggle_should_hide(true, false));
    }

    #[test]
    fn toggle_does_not_hide_minimized_window() {
        assert!(!settings_toggle_should_hide(true, true));
    }

    #[test]
    fn toggle_reveals_hidden_window() {
        assert!(!settings_toggle_should_hide(false, false));
        assert!(!settings_toggle_should_hide(false, true));
    }

    /// Contract: re-opening the exit-verification mini window reuses it (same label) rather than opening
    /// a second one. MockRuntime's show/focus legs are unobservable, so the window-reuse relation is
    /// pinned by a uniqueness assertion (same idea as the second_instance_focus contract test in main.rs).
    #[test]
    fn exit_guard_window_is_reused_when_present() {
        let app = tauri::test::mock_app();
        tauri::WebviewWindowBuilder::new(
            app.handle(),
            "exit-guard",
            tauri::WebviewUrl::App("exit-guard.html".into()),
        )
        .build()
        .unwrap();
        open_exit_guard_window(app.handle());
        let windows = app.webview_windows();
        assert_eq!(windows.len(), 1);
        assert!(windows.contains_key("exit-guard"));
    }

    /// Contract (window-creation branch): when no exit-guard window exists, build one (same label).
    #[test]
    fn exit_guard_window_is_built_when_missing() {
        let app = tauri::test::mock_app();
        assert!(app.get_webview_window("exit-guard").is_none());
        open_exit_guard_window(app.handle());
        assert!(app.get_webview_window("exit-guard").is_some());
    }
}
