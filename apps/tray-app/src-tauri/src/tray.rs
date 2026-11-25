//! Tray summary/menu construction and popup geometry.

use crate::commands::get_status;
use crate::i18n;
use crate::state::{get_peers, state_tier};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};

/// Current text of the menu's first-row summary (state + direct-peer count; language follows the tray language).
pub(crate) fn tray_summary_text() -> String {
    let status = get_status();
    let state = status["state"].as_str().unwrap_or("unknown");
    let peers = get_peers();
    let (online, total) = i18n::peers_summary(&peers);
    i18n::summary_line(state_tier(state), online, total, &i18n::read_tray_lang())
}

pub(crate) fn build_summary_item(
    app: &tauri::AppHandle,
) -> tauri::Result<tauri::menu::MenuItem<tauri::Wry>> {
    let text = tray_summary_text();
    MenuItem::with_id(app, "status_summary", text, false, None::<&str>)
}

/// Tray menu (one structure shared by both platforms, presented per platform convention):
/// [disabled status summary] │ Status panel │ Diagnostics/Route table/Peers │ Open Settings+Logs submenu │ Quit.
/// Accelerators are always written `CmdOrCtrl` (Tauri renders them as Ctrl+D / ⌘D per platform).
pub(crate) fn build_tray_menu(app: &tauri::AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let texts = i18n::menu_texts(&i18n::read_tray_lang());
    let summary = build_summary_item(app)?;
    let separator_1 = PredefinedMenuItem::separator(app)?;
    let popup = MenuItem::with_id(app, "popup", texts.popup, true, Some("CmdOrCtrl+I"))?;
    let separator_2 = PredefinedMenuItem::separator(app)?;
    let diagnostics = MenuItem::with_id(app, "diag", texts.diag, true, Some("CmdOrCtrl+D"))?;
    let routes = MenuItem::with_id(app, "routes", texts.routes, true, Some("CmdOrCtrl+R"))?;
    let peers = MenuItem::with_id(app, "peers", texts.peers, true, Some("CmdOrCtrl+P"))?;
    let separator_3 = PredefinedMenuItem::separator(app)?;
    let show = MenuItem::with_id(app, "show", texts.show, true, Some("CmdOrCtrl+S"))?;
    let log_open = MenuItem::with_id(app, "logdir", texts.log_open, true, None::<&str>)?;
    let logs = Submenu::with_id_and_items(app, "logs", texts.logs, true, &[&log_open])?;
    let separator_4 = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", texts.quit, true, None::<&str>)?;
    Menu::with_items(
        app,
        &[
            &summary,
            &separator_1,
            &popup,
            &separator_2,
            &diagnostics,
            &routes,
            &peers,
            &separator_3,
            &show,
            &logs,
            &separator_4,
            &quit,
        ],
    )
}

// ── Status popup window ───────────────────────────────────────────────────────
/// Popup positioning (pure function, testable): on Windows it hugs the bottom-right taskbar
/// (taskbar ≈48px + margin), on macOS the top-right menu bar (menu bar ≈25px + margin). All × scale (physical pixels).
pub(crate) fn popup_origin(
    monitor_width: i32,
    monitor_height: i32,
    window_width: i32,
    window_height: i32,
    scale: f64,
    macos: bool,
) -> (i32, i32) {
    let margin_x = (if macos { 8.0 } else { 16.0 } * scale).round() as i32;
    let x = (monitor_width - window_width - margin_x).max(0);
    let y = if macos {
        (34.0 * scale).round() as i32
    } else {
        (monitor_height - window_height - (72.0 * scale).round() as i32).max(0)
    };
    (x, y)
}
