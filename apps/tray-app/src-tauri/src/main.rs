#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod config_io;
mod exit_guard;
mod i18n;
mod state;
mod tray;
mod windows;

use tauri::{tray::TrayIconBuilder, Manager};

fn main() {
    tauri::Builder::default()
        // Single-instance protection must be registered first (official requirement; deep-link
        // scenarios are order-sensitive): a second instance calls back into this process with its
        // argv and then exits — so surface the existing settings panel instead of another
        // tray+window, avoiding dueling icons and menu clicks landing on a random instance.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            second_instance_focus(app);
        }))
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::get_config,
            commands::save_config,
            commands::get_peers,
            commands::get_direct_peers,
            commands::get_commands,
            commands::get_diag,
            commands::set_autostart,
            commands::open_log_dir,
            commands::set_tray_lang,
            commands::take_pending_goto,
            commands::open_settings_at,
            commands::exit_guard_status,
            commands::set_exit_guard,
            commands::clear_exit_guard,
            commands::verify_exit_guard
        ])
        .setup(|app| {
            // Tray menu (regrouped): status summary (disabled) │ Status panel │
            // Diagnostics/Route table/Peers │ Settings+Logs submenu │ Quit
            let menu = tray::build_tray_menu(app.handle())?;

            // Managed summary-row handle: the polling thread set_texts it every 3s to refresh state/peer counts.
            app.manage(std::sync::Mutex::new(Some(tray::build_summary_item(
                app.handle(),
            )?)));

            let tray = TrayIconBuilder::with_id("meshlet-tray")
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("Meshlet")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    // Quit password guard (user order 2026-11-20): with a password set, pop the
                    // verification mini window first and quit only on a match; when unset (or the
                    // record is corrupt, which exit_guard treats as unset) quit directly — the guard never locks the resident process.
                    "quit" => {
                        if crate::exit_guard::guard_is_set() {
                            windows::open_exit_guard_window(app);
                        } else {
                            std::process::exit(0);
                        }
                    }
                    "show" => windows::open_settings_window(app),
                    "popup" => windows::toggle_popup_window(app),
                    "diag" | "routes" | "peers" => {
                        windows::open_settings_at_zone(app, event.id.as_ref());
                    }
                    "logdir" => {
                        if let Err(error) = commands::open_log_dir() {
                            eprintln!("meshlet-tray: open log dir failed: {error}");
                        }
                    }
                    _ => {}
                })
                // Left click toggles panel visibility directly (the mainstream Windows convention is
                // single-click activation; requiring a double-click to pop it is a defect). On Windows a
                // physical double-click emits Click(Left,Up) → DoubleClick(Left) → Click(Left,Up) (the
                // release after the double-click), so toggling on every event would flash twice; route
                // everything through tray_activate_debounced to coalesce into a single toggle.
                .on_tray_icon_event(|tray, event| match event {
                    tauri::tray::TrayIconEvent::Click {
                        button: tauri::tray::MouseButton::Left,
                        button_state: tauri::tray::MouseButtonState::Up,
                        ..
                    }
                    | tauri::tray::TrayIconEvent::DoubleClick {
                        button: tauri::tray::MouseButton::Left,
                        ..
                    } if tray_activate_debounced() => {
                        windows::toggle_settings_window(tray.app_handle());
                    }
                    _ => {}
                })
                .build(app)?;

            start_status_polling(app.handle().clone(), tray);

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while running meshlet-tray")
        .run(|app_handle, event| {
            // Intercept window close requests: hide instead of quitting the app; the popup auto-hides on focus loss.
            if let tauri::RunEvent::WindowEvent { label, event, .. } = event {
                match event {
                    tauri::WindowEvent::CloseRequested { api, .. } => {
                        if label == "settings" || label == "popup" {
                            api.prevent_close();
                            if let Some(window) = app_handle.get_webview_window(&label) {
                                let _ = window.hide();
                            }
                        }
                    }
                    // Popup auto-hides on focus loss (clicking outside collapses it — standard tray popup behavior).
                    tauri::WindowEvent::Focused(false) if label == "popup" => {
                        if let Some(window) = app_handle.get_webview_window("popup") {
                            let _ = window.hide();
                        }
                    }
                    _ => {}
                }
            }
        });
}

/// The surface used by the single-instance second-launch callback: bring the existing
/// instance's settings panel to the front. A standalone generic function so contract tests run
/// the same call chain as the real callback on a mock runtime (Wry tray callbacks and the MockRuntime handle both land here).
fn second_instance_focus<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    windows::open_settings_window(app);
}

/// Status polling: updates the tooltip / icon / menu summary row and pushes status to the popup
/// (the popup has no poller of its own; it shares the main loop's clock).
fn start_status_polling(app_handle: tauri::AppHandle, tray: tauri::tray::TrayIcon<tauri::Wry>) {
    std::thread::spawn(move || loop {
        let status = commands::get_status();
        let tooltip = status["tooltip"].as_str().unwrap_or("Meshlet");
        let _ = tray.set_tooltip(Some(tooltip));

        // Swap the icon per state (loaded from the Resources dir next to the exe; prefer the
        // hand-tuned 16px variant, falling back to the 32px original when missing).
        let state = status["state"].as_str().unwrap_or("unknown");
        let (icon_preferred, icon_fallback) = state::icon_for_state(state);
        if let Ok(executable) = std::env::current_exe() {
            if let Some(directory) = executable.parent().and_then(|parent| parent.parent()) {
                let resources = directory.join("Resources");
                let icon_bytes = std::fs::read(resources.join(icon_preferred))
                    .or_else(|_| std::fs::read(resources.join(icon_fallback)));
                if let Ok(bytes) = icon_bytes {
                    if let Ok(icon) = tauri::image::Image::from_bytes(&bytes) {
                        let _ = tray.set_icon(Some(icon));
                    }
                }
            }
        }

        // Refresh the menu's first-row status summary (disabled) every round: state tier + peer count.
        let summary_text = tray::tray_summary_text();
        if let Some(slot) =
            app_handle.try_state::<std::sync::Mutex<Option<tauri::menu::MenuItem<tauri::Wry>>>>()
        {
            if let Some(summary) = slot.lock().unwrap().as_ref() {
                let _ = summary.set_text(&summary_text);
            }
        }

        // Push status while the popup is visible (shared poller); leave it alone while hidden.
        if let Some(popup) = app_handle.get_webview_window("popup") {
            if popup.is_visible().unwrap_or(false) {
                if let Ok(json) = serde_json::to_string(&status) {
                    let _ = popup.eval(format!(
                        "window.__meshletRefresh && window.__meshletRefresh({json})"
                    ));
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(3));
    });
}

/// Coalescing window for tray left-click activation: on Windows one physical double-click emits
/// Click → DoubleClick → Click (the post-double-click release), so toggling once per event would fire repeatedly.
/// This window swallows the follow-up events of a single activation gesture, toggling only once;
/// 250ms covers common double-click speeds while keeping a single click responsive (no delayed confirm).
const TRAY_ACTIVATE_DEDUP: std::time::Duration = std::time::Duration::from_millis(250);

/// Timestamp of the last tray left-click activation (panel toggle), used to coalesce Click/DoubleClick event pairs.
static LAST_TRAY_ACTIVATE: std::sync::Mutex<Option<std::time::Instant>> =
    std::sync::Mutex::new(None);

/// Pure decision (testable): this activation is due if `TRAY_ACTIVATE_DEDUP` has elapsed since the last one
/// (or there was never one); still inside the window means swallow it (a follow-up event of the same double-click).
fn tray_activate_due(last: Option<std::time::Instant>, now: std::time::Instant) -> bool {
    match last {
        Some(previous) => now.duration_since(previous) >= TRAY_ACTIVATE_DEDUP,
        None => true,
    }
}

/// Record this activation and report whether the panel should toggle. Single/double-click merging: only events
/// outside the window (>= 250ms) really fire; Click/DoubleClick events inside it are swallowed.
fn tray_activate_debounced() -> bool {
    let now = std::time::Instant::now();
    let mut last = LAST_TRAY_ACTIVATE.lock().unwrap();
    let due = tray_activate_due(*last, now);
    if due {
        *last = Some(now);
    }
    due
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tray_activate_due_allows_first_activation() {
        assert!(tray_activate_due(None, std::time::Instant::now()));
    }

    #[test]
    fn tray_activate_due_swallows_events_within_window() {
        let first = std::time::Instant::now();
        assert!(!tray_activate_due(
            Some(first),
            first + std::time::Duration::from_millis(50)
        ));
        assert!(tray_activate_due(Some(first), first + TRAY_ACTIVATE_DEDUP));
    }

    #[test]
    fn tray_activate_due_allows_events_after_window() {
        let first = std::time::Instant::now();
        assert!(tray_activate_due(
            Some(first),
            first + std::time::Duration::from_millis(300)
        ));
    }

    #[test]
    fn tray_activate_sequence_first_true_then_false() {
        let first = std::time::Instant::now();
        assert!(tray_activate_due(None, first));
        assert!(!tray_activate_due(
            Some(first),
            first + std::time::Duration::from_millis(120)
        ));
        assert!(!tray_activate_due(
            Some(first),
            first + std::time::Duration::from_millis(160)
        ));
    }

    /// Contract: the single-instance second-launch callback acts on the existing instance's own settings
    /// window — the reveal (reuse) branch rather than building another window, and never another label.
    /// MockRuntime's is_visible is always true (hardcoded in mock_runtime.rs), so the show/focus legs are
    /// unobservable on the mock; the window-reuse relation is pinned by the uniqueness assertion, while the
    /// real on-device display effect is backstopped by reveal_window, shared by every open path.
    #[test]
    fn second_instance_focus_reuses_existing_settings_window() {
        let app = tauri::test::mock_app();
        tauri::WebviewWindowBuilder::new(
            app.handle(),
            "settings",
            tauri::WebviewUrl::App("index.html".into()),
        )
        .build()
        .unwrap();
        second_instance_focus(app.handle());
        let windows = app.webview_windows();
        assert_eq!(windows.len(), 1);
        assert!(windows.contains_key("settings"));
    }

    /// Contract (window-creation branch): when no settings window exists the callback builds one (same label),
    /// so a second instance always surfaces that one label's window and never leaves an orphan window behind.
    #[test]
    fn second_instance_focus_builds_settings_window_when_missing() {
        let app = tauri::test::mock_app();
        assert!(app.get_webview_window("settings").is_none());
        second_instance_focus(app.handle());
        assert!(app.get_webview_window("settings").is_some());
    }
}
