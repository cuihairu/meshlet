#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod config_io;
mod i18n;
mod state;
mod tray;
mod windows;

use tauri::{tray::TrayIconBuilder, Manager};

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::get_config,
            commands::save_config,
            commands::get_peers,
            commands::get_commands,
            commands::get_diag,
            commands::set_autostart,
            commands::open_log_dir,
            commands::set_tray_lang,
            commands::take_pending_goto,
            commands::open_settings_at
        ])
        .setup(|app| {
            // 托盘菜单（分组重设计）：状态摘要(disabled) │ 状态面板 │
            // 诊断/路由表/对等节点 │ 打开设置+日志子菜单 │ 退出
            let menu = tray::build_tray_menu(app.handle())?;

            // 托管摘要行句柄：轮询线程每 3s set_text 刷新状态/直连计数。
            app.manage(std::sync::Mutex::new(Some(tray::build_summary_item(
                app.handle(),
            )?)));

            let tray = TrayIconBuilder::with_id("meshlet-tray")
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("Meshlet")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "quit" => std::process::exit(0),
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
                // 左键单击直接切换面板显隐（Windows 主流约定是单击激活，
                // 双击才弹是缺陷）。Windows 上一次物理双击会依次产生
                // Click(Left,Up) → DoubleClick(Left) → Click(Left,Up)（双击
                // 后的抬起），若每个事件都翻转一次面板会闪两次；统一走
                // tray_activate_debounced 合并成一次翻转。
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
            // 拦截窗口关闭请求：隐藏而非退出应用；弹层另在失焦时自动隐藏。
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
                    // 弹层失焦自动隐藏（点外部即收起，托盘弹层惯例）。
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

/// 状态轮询：更新 tooltip / 图标 / 菜单摘要行，并把状态推给弹层
/// （弹层不自带轮询，与主循环共用同一时钟）。
fn start_status_polling(app_handle: tauri::AppHandle, tray: tauri::tray::TrayIcon<tauri::Wry>) {
    std::thread::spawn(move || loop {
        let status = commands::get_status();
        let tooltip = status["tooltip"].as_str().unwrap_or("Meshlet");
        let _ = tray.set_tooltip(Some(tooltip));

        // 根据状态换图标（从 exe 同级 Resources 目录加载；首选
        // 16px 微调变体，缺失时回落 32px 原图）。
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

        // 菜单首行状态摘要（disabled）每轮刷新：状态档位 + 直连计数。
        let summary_text = tray::tray_summary_text();
        if let Some(slot) =
            app_handle.try_state::<std::sync::Mutex<Option<tauri::menu::MenuItem<tauri::Wry>>>>()
        {
            if let Some(summary) = slot.lock().unwrap().as_ref() {
                let _ = summary.set_text(&summary_text);
            }
        }

        // 弹层可见时推送状态（共用车轮）；隐藏时不打扰。
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

/// 托盘左键激活的合并窗口。Windows 上一次物理双击会发出 Click → DoubleClick
/// → Click（双击后的抬起）三个事件；若每个事件都翻转一次面板会重复触发。
/// 该窗口把属于同一次激活手势的后续事件吞掉，只翻转一次。250ms 覆盖常见
/// 双击速度，同时让单击保持即时响应（无需延迟确认）。
const TRAY_ACTIVATE_DEDUP: std::time::Duration = std::time::Duration::from_millis(250);

/// 上次托盘左键激活（翻转面板）的时刻，用于合并 Click/DoubleClick 事件对。
static LAST_TRAY_ACTIVATE: std::sync::Mutex<Option<std::time::Instant>> =
    std::sync::Mutex::new(None);

/// 纯判定（可测）：距上次激活已过 `TRAY_ACTIVATE_DEDUP`（或从未激活过）则
/// 本次应触发；仍在窗口内则吞掉（属于同一次双击的后续事件）。
fn tray_activate_due(last: Option<std::time::Instant>, now: std::time::Instant) -> bool {
    match last {
        Some(previous) => now.duration_since(previous) >= TRAY_ACTIVATE_DEDUP,
        None => true,
    }
}

/// 记录本次激活并报告是否应翻转面板。合并单/双击：只有窗口外（>= 250ms）
/// 的事件才会真正触发，窗口内的 Click/DoubleClick 一律吞掉。
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
}
