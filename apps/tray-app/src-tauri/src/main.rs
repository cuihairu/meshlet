#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager,
};

#[tauri::command]
fn get_status() -> serde_json::Value {
    // 与 tray-host（apps/tray-host/src/main.rs:40-42）及安装脚本
    // （scripts/install.ps1 的 state 目录）约定一致：状态写
    // `%LOCALAPPDATA%/meshlet/state/tray/status.json`。不在前端硬编码用户
    // 目录，避免用户名写死/换用户失效。
    let path = std::path::Path::new(&meshlet_state_dir())
        .join("tray")
        .join("status.json");
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::json!({"state": "unknown", "tooltip": "Meshlet"}))
}

/// 本机 Meshlet 状态目录：`%LOCALAPPDATA%/meshlet/state`（与安装脚本
/// `scripts/install.ps1` 生成 `state_dir = %LOCALAPPDATA%\meshlet\state` 一致）。
fn meshlet_state_dir() -> String {
    let local = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "C:/Users/Public".into());
    state_dir_from_local(&local)
}

/// 本机 agent 配置路径：`%LOCALAPPDATA%/meshlet/agent.toml`（安装脚本
/// `scripts/install.ps1` 把配置写到该路径；前端读写必须与之一致，否则
/// 托盘设置的保存/读取与 agent 实际配置脱节）。
fn meshlet_config_path() -> String {
    let local = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "C:/Users/Public".into());
    config_path_from_local(&local)
}

/// 纯路径构造（可测）：`<local>/meshlet/state`。
fn state_dir_from_local(local: &str) -> String {
    std::path::Path::new(local)
        .join("meshlet")
        .join("state")
        .to_string_lossy()
        .into_owned()
}

/// 纯路径构造（可测）：`<local>/meshlet/agent.toml`。
fn config_path_from_local(local: &str) -> String {
    std::path::Path::new(local)
        .join("meshlet")
        .join("agent.toml")
        .to_string_lossy()
        .into_owned()
}

#[tauri::command]
fn get_config() -> serde_json::Value {
    let config_path = meshlet_config_path();
    let path = std::path::Path::new(&config_path);
    let text = std::fs::read_to_string(path).unwrap_or_default();
    // 简单解析 TOML 为 JSON（避免额外依赖）
    let mut result = serde_json::Map::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim().to_string();
            let v = v.trim().trim_matches('"').to_string();
            result.insert(k, serde_json::Value::String(v));
        }
    }
    serde_json::Value::Object(result)
}

#[tauri::command]
fn save_config(
    server_url: String,
    device_name: String,
    hub_endpoint: String,
) -> Result<(), String> {
    let config_path = meshlet_config_path();
    let path = std::path::Path::new(&config_path);
    let content = format!(
        "server_url = \"{server_url}\"\n\
         device_name = \"{device_name}\"\n\
         \n\
         [dataplane]\n\
         enabled = true\n\
         interface = \"WireGuard\"\n\
         hub_endpoint = \"{hub_endpoint}\"\n"
    );
    std::fs::write(path, content).map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_status,
            get_config,
            save_config
        ])
        .setup(|app| {
            // 托盘菜单
            let show = MenuItem::with_id(app, "show", "打开设置", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;

            let _tray = TrayIconBuilder::with_id("meshlet-tray")
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("Meshlet")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "quit" => {
                        std::process::exit(0);
                    }
                    "show" => {
                        open_settings_window(app);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| match event {
                    tauri::tray::TrayIconEvent::DoubleClick { .. }
                    | tauri::tray::TrayIconEvent::Click {
                        button: tauri::tray::MouseButton::Left,
                        button_state: tauri::tray::MouseButtonState::Up,
                        ..
                    } => {
                        open_settings_window(tray.app_handle());
                    }
                    _ => {}
                })
                .build(app)?;

            // 状态轮询：更新 tooltip
            let app_handle = app.handle().clone();
            std::thread::spawn(move || loop {
                let status = get_status();
                let tooltip = status["tooltip"].as_str().unwrap_or("Meshlet");
                if let Some(tray) = app_handle.tray_by_id("meshlet-tray") {
                    let _ = tray.set_tooltip(Some(tooltip));
                    // 根据状态换图标（从 exe 同级 Resources 目录加载）
                    let state = status["state"].as_str().unwrap_or("unknown");
                    let icon_name = match state {
                        "online" | "connected" | "ready" | "up" | "ok" => "icon-teal.png",
                        "error" | "failed" | "disconnected" | "down" => "icon-copper.png",
                        _ => "icon-gray.png",
                    };
                    if let Ok(exe) = std::env::current_exe() {
                        if let Some(dir) = exe.parent().and_then(|d| d.parent()) {
                            let icon_path = dir.join("Resources").join(icon_name);
                            if let Ok(bytes) = std::fs::read(&icon_path) {
                                if let Ok(icon) = tauri::image::Image::from_bytes(&bytes) {
                                    let _ = tray.set_icon(Some(icon));
                                }
                            }
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_secs(3));
            });

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while running meshlet-tray")
        .run(|app_handle, event| {
            // 拦截设置窗口的关闭请求：隐藏而非退出应用
            if let tauri::RunEvent::WindowEvent {
                label,
                event: tauri::WindowEvent::CloseRequested { api, .. },
                ..
            } = event
            {
                if label == "settings" {
                    api.prevent_close();
                    if let Some(w) = app_handle.get_webview_window("settings") {
                        let _ = w.hide();
                    }
                }
            }
        });
}

fn open_settings_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("settings") {
        // 关闭（CloseRequested）已被拦截为 hide()，窗口的 VISIBLE 标志未置时
        // tao 的 set_focus 是 no-op，必须先 show() 再聚焦，否则再次点击托盘
        // 图标不会把隐藏的设置窗口带回前台。
        let _ = window.show();
        let _ = window.set_focus();
        return;
    }
    let _ = tauri::WebviewWindowBuilder::new(
        app,
        "settings",
        tauri::WebviewUrl::App("index.html".into()),
    )
    .title("Meshlet 设置")
    .inner_size(480.0, 400.0)
    .resizable(false)
    .build();
}

#[cfg(test)]
mod path_convention_tests {
    use super::*;

    #[test]
    fn state_dir_matches_install_script_convention() {
        // 安装脚本（scripts/install.ps1）把 state_dir 生成到
        // `%LOCALAPPDATA%\meshlet\state`；托盘宿主与 tray-app 必须用同一
        // 路径读 status.json，否则看不到 agent 写出的状态。
        let got = state_dir_from_local(r"C:\Users\bob\AppData\Local");
        assert!(got.contains("meshlet"));
        assert!(got.contains("state"));
        assert!(got.starts_with(r"C:\Users\bob\AppData\Local"));
    }

    #[test]
    fn config_path_matches_install_script_convention() {
        // 安装脚本把 agent.toml 写到 `%LOCALAPPDATA%\meshlet\agent.toml`；
        // 托盘设置读写的必须就是这份配置，不能写到别处。
        let got = config_path_from_local(r"C:\Users\bob\AppData\Local");
        assert!(got.contains("meshlet"));
        assert!(got.contains("agent.toml"));
        assert!(got.starts_with(r"C:\Users\bob\AppData\Local"));
    }
}
