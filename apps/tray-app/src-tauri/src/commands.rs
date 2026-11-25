//! Tauri IPC handlers for local state, settings, peers, diagnostics, and navigation.

use crate::config_io::{meshlet_config_path, rebuild_config};
// Used only by the windows branch (open_log_dir's explorer call); compiled out on non-windows
// so the unused import cannot break -D warnings on the linux target.
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
    // Parse TOML into JSON naively (avoids an extra dependency)
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
    // A synchronous wg subprocess once blocked the main thread (frozen settings window, 2026-11-20
    // imac report); moved to the blocking thread pool so the main thread only awaits.
    tauri::async_runtime::spawn_blocking(crate::state::get_peers)
        .await
        .unwrap_or_default()
}

/// Direct-peer table (`<state_dir>/direct-peers.json`, maintained by the agent's reconciliation loop).
/// Data source for the settings window's Direct tab: name/virtual_ipv4/endpoint/rtt_ms/last_handshake_at.
#[tauri::command]
pub(crate) fn get_direct_peers() -> Vec<serde_json::Value> {
    let path =
        std::path::Path::new(&crate::config_io::meshlet_state_dir()).join("direct-peers.json");
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(_) => return Vec::new(),
    };
    serde_json::from_str(&text).unwrap_or_default()
}

#[tauri::command]
pub(crate) fn get_commands() -> Vec<meshlet_commands::CommandSpec> {
    meshlet_commands::COMMANDS.to_vec()
}

#[tauri::command]
pub(crate) async fn get_diag() -> Result<meshlet_network::NetworkDiagnostics, String> {
    // Diagnostics is a synchronous whole-system probe (same freeze-risk class) and is moved off the main thread like get_peers.
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
        // CREATE_NO_WINDOW: reg.exe is a console tool; spawning it from a GUI process flashes a window.
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
            // Deleting a nonexistent value makes reg report "unable to find"; treat that as idempotent success.
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
        // The log dir points straight at `<state_dir>/logs` (where the agent rolls daily logs, fc8c3af);
        // create it if missing so explorer doesn't open onto the state root's raw data files.
        let log_dir = std::path::Path::new(&meshlet_state_dir()).join("logs");
        std::fs::create_dir_all(&log_dir)
            .map_err(|error| format!("create log dir {}: {error}", log_dir.display()))?;
        std::process::Command::new("explorer")
            .arg(&log_dir)
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

// ── Quit password (tray-side standalone file, not in agent.toml) ───────────────────────

#[tauri::command]
pub(crate) fn exit_guard_status() -> bool {
    crate::exit_guard::guard_is_set()
}

/// When a password is already set, `current` must match before it can change; pass None on first-time setup.
#[tauri::command]
pub(crate) fn set_exit_guard(current: Option<String>, new: String) -> Result<(), String> {
    crate::exit_guard::set_guard(current.as_deref(), &new)
}

#[tauri::command]
pub(crate) fn clear_exit_guard(current: Option<String>) -> Result<(), String> {
    crate::exit_guard::clear_guard(current.as_deref())
}

/// Verification entry for the exit mini window: a match exits the whole app (`app.exit` goes through
/// the normal quit events); a mismatch returns Err for the page to show a retry.
#[tauri::command]
pub(crate) fn verify_exit_guard(app: tauri::AppHandle, password: String) -> Result<(), String> {
    if crate::exit_guard::verify_quit(&password) {
        app.exit(0);
        Ok(())
    } else {
        Err("wrong password".into())
    }
}
