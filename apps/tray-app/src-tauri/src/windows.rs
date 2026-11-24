//! Tray popup and settings window orchestration.

use crate::state::{clear_pending_goto, goto_zone_js, set_pending_goto};
use crate::tray::popup_origin;
use tauri::{Manager, PhysicalPosition, Position};

/// 窗口创建失败只往 stderr 打时，GUI 子系统的托盘进程没有控制台、日志无处可去，
/// 「设置窗点了没反应」就无法自诊断（2026-11-25 用户报障后加的落盘面）。
/// 写失败本身静默：诊断通道不能成为新的故障源。
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

/// 非 Windows 侧没有「GUI 进程无控制台」的自诊断缺口，保留同名空实现，
/// 让调用处不必各带一份 cfg。
#[cfg(not(target_os = "windows"))]
pub(crate) fn log_diag(_message: &str) {}

/// 把弹层摆到托盘附近：Windows 右下角（托盘所在的任务栏上方）、macOS
/// 菜单栏下方右侧。
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

/// 程序化创建弹层窗口（隐藏），随后展示并聚焦。失焦自动隐藏在
/// `run` 事件的 `WindowEvent::Focused(false)` 里处理。
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

/// 打开（或聚焦）设置窗并定位到 zone。菜单「诊断/路由表/对等节点」与
/// 弹层快捷入口共用此入口。
pub(crate) fn open_settings_at_zone(app: &tauri::AppHandle, zone: &str) {
    set_pending_goto(zone);
    open_settings_window(app);
    if let Some(window) = app.get_webview_window("settings") {
        if let Some(js) = goto_zone_js(zone) {
            if window.eval(&js).is_ok() {
                // eval 已送达存活窗口：挂起件已消费，立即清空。否则窗口
                // reload 时脚本重新经 take_pending_goto 取件，会把一次旧
                // 定位重放到新加载页（跳到用户并未点的那一区）。
                clear_pending_goto();
            }
        }
    }
}

/// 把窗口带回前台：先还原（最小化态）→ 显示 → 聚焦。设置窗与状态弹层
/// 共用。顺序不可省 unminimize：tao 的 `show()` 最终是 `ShowWindow(SW_SHOW)`
/// （tao-0.37.2 window_state.rs:458-468），不会还原最小化窗口；而 tao 的
/// `set_focus()` 守卫 `is_visible && !is_minimized && !is_foreground`
/// （tao-0.37.2 window.rs:139-150）在最小化时是 no-op——只 show+focus 时
/// 最小化的窗口原封不动留在任务栏，用户看就是「点打开设置没反应」。
pub(crate) fn reveal_window<R: tauri::Runtime>(window: &tauri::WebviewWindow<R>) {
    if window.is_minimized().unwrap_or(false) {
        let _ = window.unminimize();
    }
    let _ = window.show();
    let _ = window.set_focus();
}

/// 显示（或聚焦）设置面板——供右键菜单「打开设置」项使用，行为不变：
/// 始终把窗口带到前台。
pub(crate) fn open_settings_window<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    if let Some(window) = app.get_webview_window("settings") {
        reveal_window(&window);
        return;
    }
    build_settings_window(app);
}

/// 托盘左键单击是否应隐藏面板（纯判定，可测）：仅当窗口可见且**未**最小化
/// 才算「正在使用」→ 隐藏。最小化窗口的 `is_visible()` 仍为 true（WS_VISIBLE
/// 未清），若据它隐藏，单击托盘会把最小化窗口继续藏进任务栏，永远还原不了；
/// Windows 托盘惯例是单击还原最小化窗口。
pub(crate) fn settings_toggle_should_hide(is_visible: bool, is_minimized: bool) -> bool {
    is_visible && !is_minimized
}

/// 切换设置面板显隐——托盘图标左键单击路径。可见则隐藏，否则显示并聚焦。
/// 与 `open_settings_window`（总是显示）不同，单击是「切换」而不是「弹出」，
/// 这是 Windows 托盘的主流交互约定。
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
    // 创建失败不再静默吞掉：窗口创建竞态/WebView 故障时至少留一条诊断线
    //（此前 `let _ =` 让「点打开设置没反应」无迹可查）。
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

/// 退出验证小窗（退出密码保护路径）：提示输密码，`verify_exit_guard`
/// 匹配即整体退出；取消/关闭只关窗不退程序。置顶居中避免被设置窗压住。
/// 窗口标题复用菜单「退出」项文案（跟随托盘语言）。
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

    /// 契约：退出验证小窗重复打开走复用（同 label），不开第二扇。
    /// MockRuntime 的 show/focus 腿不可观测，窗口复用关系用唯一性断言钉住
    /// （与 main.rs 的 second_instance_focus 契约测试同思路）。
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

    /// 契约（建窗分支）：exit-guard 窗不存在时补建一个（同 label）。
    #[test]
    fn exit_guard_window_is_built_when_missing() {
        let app = tauri::test::mock_app();
        assert!(app.get_webview_window("exit-guard").is_none());
        open_exit_guard_window(app.handle());
        assert!(app.get_webview_window("exit-guard").is_some());
    }
}
