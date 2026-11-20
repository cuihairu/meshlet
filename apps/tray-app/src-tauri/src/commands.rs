//! Tauri IPC handlers for local state, settings, peers, diagnostics, and navigation.

use crate::config_io::{meshlet_config_path, rebuild_config};
// 仅 windows 分支用到（open_log_dir 的 explorer 调用）；非 windows 编译期
// 摘除，避免 unused import 破坏 linux 目标 -D warnings。
#[cfg(windows)]
use crate::config_io::meshlet_state_dir;
use crate::state::goto_zone_js;
use tauri::Manager;

#[tauri::command]
pub(crate) fn get_status() -> serde_json::Value {
    crate::state::get_status()
}

#[tauri::command]
pub(crate) fn get_config() -> serde_json::Value {
    let config_path = meshlet_config_path();
    let text = std::fs::read_to_string(config_path).unwrap_or_default();
    // 简单解析 TOML 为 JSON（避免额外依赖）
    let mut result = serde_json::Map::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            result.insert(
                key.trim().to_string(),
                serde_json::Value::String(value.trim().trim_matches('"').to_string()),
            );
        }
    }
    serde_json::Value::Object(result)
}

#[tauri::command]
pub(crate) fn save_config(
    server_url: String,
    device_name: String,
    hub_endpoint: String,
) -> Result<(), String> {
    let config_path = meshlet_config_path();
    let existing = std::fs::read_to_string(&config_path).unwrap_or_default();
    let content = rebuild_config(&existing, &server_url, &device_name, &hub_endpoint);
    std::fs::write(config_path, content).map_err(|error| error.to_string())
}

#[tauri::command]
pub(crate) async fn get_peers() -> Vec<serde_json::Value> {
    // wg 子进程同步执行曾把主线程堵死（设置窗卡死，2026-11-20 imac 实报）；
    // 移到阻塞线程池，主线程只 await。
    tauri::async_runtime::spawn_blocking(crate::state::get_peers)
        .await
        .unwrap_or_default()
}

#[tauri::command]
pub(crate) fn get_commands() -> Vec<meshlet_commands::CommandSpec> {
    meshlet_commands::COMMANDS.to_vec()
}

#[tauri::command]
pub(crate) async fn get_diag() -> Result<meshlet_network::NetworkDiagnostics, String> {
    // 诊断是同步全系统探测（同卡死风险类别），与 get_peers 同样移出主线程。
    tauri::async_runtime::spawn_blocking(|| {
        meshlet_network::SystemBackend::new()
            .diagnostics_sync()
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub(crate) fn set_autostart(enabled: bool) -> Result<(), String> {
    set_autostart_impl(enabled)
}

fn set_autostart_impl(enabled: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW：reg.exe 是 console 工具，GUI 进程直接 spawn 会闪窗。
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let executable = std::env::current_exe().map_err(|error| error.to_string())?;
        let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
        if enabled {
            let mut command = std::process::Command::new("reg");
            command
                .args([
                    "add",
                    key,
                    "/v",
                    "meshlet",
                    "/t",
                    "REG_SZ",
                    "/d",
                    &executable.to_string_lossy(),
                    "/f",
                ])
                .creation_flags(CREATE_NO_WINDOW);
            let output = command.output().map_err(|error| error.to_string())?;
            if !output.status.success() {
                return Err(String::from_utf8_lossy(&output.stderr).into_owned());
            }
        } else {
            let mut command = std::process::Command::new("reg");
            command
                .args(["delete", key, "/v", "meshlet", "/f"])
                .creation_flags(CREATE_NO_WINDOW);
            let output = command.output().map_err(|error| error.to_string())?;
            // 删除不存在的值：reg 报 "unable to find"，按幂等成功处理。
            if !output.status.success()
                && !String::from_utf8_lossy(&output.stderr).contains("unable to find")
            {
                return Err(String::from_utf8_lossy(&output.stderr).into_owned());
            }
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = enabled;
        Err("autostart is only supported on Windows".into())
    }
}

#[tauri::command]
pub(crate) fn open_log_dir() -> Result<(), String> {
    #[cfg(windows)]
    {
        let directory = meshlet_state_dir();
        std::process::Command::new("explorer")
            .arg(directory)
            .spawn()
            .map_err(|error| error.to_string())?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        Err("opening a log directory is only supported on Windows".into())
    }
}

#[tauri::command]
pub(crate) fn take_pending_goto() -> Option<String> {
    crate::state::take_pending_goto()
}

#[tauri::command]
pub(crate) fn open_settings_at(app: tauri::AppHandle, zone: String) -> Result<(), String> {
    if goto_zone_js(&zone).is_none() {
        return Err(format!("unknown zone: {zone}"));
    }
    crate::windows::open_settings_at_zone(&app, &zone);
    if let Some(window) = app.get_webview_window("popup") {
        let _ = window.hide();
    }
    Ok(())
}

#[tauri::command]
pub(crate) fn set_tray_lang(app: tauri::AppHandle, lang: String) -> Result<(), String> {
    if lang != "zh" && lang != "en" {
        return Err(format!("unsupported lang: {lang}"));
    }
    crate::i18n::write_tray_lang(&lang)?;
    let menu = crate::tray::build_tray_menu(&app).map_err(|error| error.to_string())?;
    if let Some(tray) = app.tray_by_id("meshlet-tray") {
        tray.set_menu(Some(menu))
            .map_err(|error| error.to_string())?;
    }
    let summary = crate::tray::build_summary_item(&app).map_err(|error| error.to_string())?;
    if let Some(slot) =
        app.try_state::<std::sync::Mutex<Option<tauri::menu::MenuItem<tauri::Wry>>>>()
    {
        *slot.lock().unwrap() = Some(summary);
    }
    Ok(())
}

// ── 退出密码（tray 侧独立文件，不进 agent.toml）───────────────────────

#[tauri::command]
pub(crate) fn exit_guard_status() -> bool {
    crate::exit_guard::guard_is_set()
}

/// 已设密码时 `current` 必须匹配才能改；首次设置传 None。
#[tauri::command]
pub(crate) fn set_exit_guard(current: Option<String>, new: String) -> Result<(), String> {
    crate::exit_guard::set_guard(current.as_deref(), &new)
}

#[tauri::command]
pub(crate) fn clear_exit_guard(current: Option<String>) -> Result<(), String> {
    crate::exit_guard::clear_guard(current.as_deref())
}

/// 退出小窗的验证入口：匹配即整体退出（`app.exit` 走正常退出事件）；
/// 不匹配返回 Err 由页面显示重试。
#[tauri::command]
pub(crate) fn verify_exit_guard(app: tauri::AppHandle, password: String) -> Result<(), String> {
    if crate::exit_guard::verify_quit(&password) {
        app.exit(0);
        Ok(())
    } else {
        Err("wrong password".into())
    }
}
