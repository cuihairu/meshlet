//! Tauri IPC handlers for local state, settings, peers, diagnostics, and navigation.

use crate::config_io::meshlet_config_path;
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

/// 只回设置页使用的三项（M-SET-UX-01）：不外泄 bootstrap_token /
/// private_key_file 等 agent 自管键（旧实现把整文件扁平键全发给前端）。
#[tauri::command]
pub(crate) fn get_config() -> serde_json::Value {
    let text = std::fs::read_to_string(meshlet_config_path()).unwrap_or_default();
    ui_config_payload(&text)
}

/// IPC 读面载荷（纯函数，可测）：配置文本 → 三字段 JSON。键集契约由
/// 测试钉住——多回一个键就是一次 IPC 面泄漏。
pub(crate) fn ui_config_payload(text: &str) -> serde_json::Value {
    let config = crate::config_io::read_ui_config(text);
    serde_json::json!({
        "server_url": config.server_url,
        "device_name": config.device_name,
        "hub_endpoint": config.hub_endpoint,
    })
}

/// 保存三项：先校验（与 agent 装载口径一致），再无损外科手术式重写
/// + 原子落盘。不改其他键/节/注释。返回错误键供前端按语言包映射。
#[tauri::command]
pub(crate) fn save_config(
    server_url: String,
    device_name: String,
    hub_endpoint: String,
) -> Result<(), String> {
    crate::config_io::validate_connection(&server_url, &device_name, &hub_endpoint)
        .map_err(|key| key.to_string())?;
    let path = std::path::PathBuf::from(meshlet_config_path());
    crate::config_io::save_ui_config_at(&path, &server_url, &device_name, &hub_endpoint)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub(crate) async fn get_peers() -> Vec<serde_json::Value> {
    // wg 子进程同步执行曾把主线程堵死（设置窗卡死，2026-11-20 imac 实报）；
    // 移到阻塞线程池，主线程只 await。
    tauri::async_runtime::spawn_blocking(crate::state::get_peers)
        .await
        .unwrap_or_default()
}

/// 直连节点表（`<state_dir>/direct-peers.json`，agent 对账循环维护）。
/// 设置窗「直连」tab 数据源：name/virtual_ipv4/endpoint/rtt_ms/last_handshake_at。
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

/// 平台能力位（M-SET-UX-05 前端按作用域显示/禁用）：自启与日志入口只在
/// Windows 可用；退出保护全平台可用（文件存储平台无关）。
#[tauri::command]
pub(crate) fn platform_caps() -> serde_json::Value {
    serde_json::json!({
        "os": std::env::consts::OS,
        "autostart": cfg!(windows),
        "open_log_dir": cfg!(windows),
    })
}

#[tauri::command]
pub(crate) fn open_log_dir() -> Result<(), String> {
    #[cfg(windows)]
    {
        // 日志目录直指 `<state_dir>/logs`（agent 每日滚动写这里，fc8c3af）；
        // 不存在则建，避免 explorer 打开 state 根只见一堆数据文件。
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

#[cfg(test)]
mod tests {
    use super::*;

    /// IPC 读面契约（M-SET-UX-01「IPC 只回界面使用的字段」）：含 agent
    /// 自管键的配置文本 → 载荷恰好三字段，token/私钥路径不外泄。
    #[test]
    fn ui_config_payload_exposes_only_ui_fields() {
        let text = "server_url = \"https://hub.example\"\n\
                    device_name = \"dev-a\"\n\
                    bootstrap_token = \"bt-secret-token\"\n\
                    private_key_file = \"C:\\\\keys\\\\priv.key\"\n\
                    [dataplane]\n\
                    hub_endpoint = \"10.0.0.1:51820\"\n";
        let payload = ui_config_payload(text);
        let object = payload.as_object().unwrap();
        assert_eq!(object.len(), 3, "exactly the three UI fields");
        assert_eq!(payload["server_url"], "https://hub.example");
        assert_eq!(payload["device_name"], "dev-a");
        assert_eq!(payload["hub_endpoint"], "10.0.0.1:51820");
        let rendered = payload.to_string();
        assert!(!rendered.contains("bt-secret-token"), "token must not leak");
        assert!(!rendered.contains("priv.key"), "key path must not leak");
    }

    /// 缺键回落空串：表单置空由用户补填，保存时校验拦住。
    #[test]
    fn ui_config_payload_defaults_missing_keys_to_empty() {
        assert_eq!(
            ui_config_payload(""),
            serde_json::json!({"server_url": "", "device_name": "", "hub_endpoint": ""})
        );
    }
}
