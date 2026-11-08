//! Tray summary/menu construction and popup geometry.

use crate::commands::{get_peers, get_status};
use crate::i18n;
use crate::state::state_tier;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};

/// 菜单首行摘要的当前文案（状态 + 直连计数，语言跟随托盘语言）。
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

/// 托盘菜单（双平台共用结构，按各自惯例呈现）：
/// [disabled 状态摘要] │ 状态面板 │ 诊断/路由表/对等节点 │ 打开设置+日志子菜单 │ 退出。
/// 快捷键统一写 `CmdOrCtrl`（Tauri accelerator 按平台显示 Ctrl+D / ⌘D）。
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

// ── 状态弹层窗口 ───────────────────────────────────────────────────────
/// 弹层定位（纯函数，可测）：Windows 贴任务栏右下（任务栏 ≈48px + 余量），
/// macOS 贴菜单栏右上（菜单栏 ≈25px + 余量）。全部乘 scale（物理像素）。
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
