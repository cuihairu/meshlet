#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager,
};

#[tauri::command]
fn get_status(state_dir: String) -> serde_json::Value {
    let path = std::path::Path::new(&state_dir).join("tray").join("status.json");
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::json!({"state": "unknown", "tooltip": "Meshlet"}))
}

#[tauri::command]
fn get_config() -> serde_json::Value {
    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:/Users/Public".into());
    let path = std::path::Path::new(&home).join(".meshlet").join("config.toml");
    let text = std::fs::read_to_string(&path).unwrap_or_default();
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
fn save_config(server_url: String, device_name: String, hub_endpoint: String) -> Result<(), String> {
    let home = std::env::var("USERPROFILE").map_err(|e| e.to_string())?;
    let path = std::path::Path::new(&home).join(".meshlet").join("config.toml");
    let content = format!(
        "server_url = \"{server_url}\"\n\
         device_name = \"{device_name}\"\n\
         \n\
         [dataplane]\n\
         enabled = true\n\
         interface = \"WireGuard\"\n\
         hub_endpoint = \"{hub_endpoint}\"\n"
    );
    std::fs::write(&path, content).map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_status, get_config, save_config])
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
                .on_tray_icon_event(|tray, event| {
                    if let tauri::tray::TrayIconEvent::DoubleClick { .. } = event {
                        open_settings_window(tray.app_handle());
                    }
                })
                .build(app)?;

            // 状态轮询：更新 tooltip
            let state_dir = std::env::var("LOCALAPPDATA")
                .unwrap_or_else(|_| "C:/Users/Public".into());
            let state_dir = format!("{state_dir}/meshlet/state");
            let app_handle = app.handle().clone();
            std::thread::spawn(move || loop {
                let status = get_status(state_dir.clone());
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
                                if let Some(icon) = tauri::image::Image::from_bytes(&bytes).ok() {
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
        .run(tauri::generate_context!())
        .expect("error while running meshlet-tray");
}

fn open_settings_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("settings") {
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
