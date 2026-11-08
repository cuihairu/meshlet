#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem, Submenu},
    tray::TrayIconBuilder,
    {Manager, PhysicalPosition, Position},
};

mod i18n;

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
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let content = rebuild_config(&existing, &server_url, &device_name, &hub_endpoint);
    std::fs::write(path, content).map_err(|e| e.to_string())
}

/// 纯配置重建（可测）：只替换设置页管理的键（server_url/device_name/
/// hub_endpoint/interface/enabled），**保留** agent 自行管理的键
/// （state_dir/bootstrap_token/private_key_file/poll_interval_secs 等）——
/// 否则保存设置会丢掉 install.ps1 写入的键，破坏 agent 配置。
fn rebuild_config(
    existing: &str,
    server_url: &str,
    device_name: &str,
    hub_endpoint: &str,
) -> String {
    let cfg = parse_agent_toml(existing);
    let mut out = String::new();
    let push = |out: &mut String, k: &str, v: &str| out.push_str(&format!("{k} = {v}\n"));
    push(&mut out, "server_url", &quote(server_url));
    if let Some(v) = cfg.get("state_dir") {
        push(&mut out, "state_dir", &quote(v));
    }
    if let Some(v) = cfg.get("bootstrap_token") {
        push(&mut out, "bootstrap_token", &quote(v));
    }
    push(&mut out, "device_name", &quote(device_name));
    out.push('\n');
    out.push_str("[dataplane]\n");
    out.push_str("enabled = true\n");
    // 实际隧道名按 install.ps1/README 为 wg-meshlet（后端默认 meshlet），
    // 不再写死 "WireGuard"。
    out.push_str("interface = \"wg-meshlet\"\n");
    if let Some(v) = cfg.get("private_key_file") {
        push(&mut out, "private_key_file", &quote(v));
    }
    push(&mut out, "hub_endpoint", &quote(hub_endpoint));
    if let Some(v) = cfg.get("poll_interval_secs") {
        out.push_str(&format!("poll_interval_secs = {v}\n"));
    }
    out
}

/// 简单 TOML 键值解析（扁平，忽略 section 头/注释）：与 get_config 同解析
/// 口径；返回 键→去引号后的值。
fn parse_agent_toml(text: &str) -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
        }
    }
    map
}

/// TOML 字符串引号包裹（转义内嵌双引号）。
fn quote(v: &str) -> String {
    format!("\"{}\"", v.replace('"', "\\\""))
}

/// 从 WireGuard 读取直连 peer 信息。
#[tauri::command]
fn get_peers() -> Vec<serde_json::Value> {
    let wg_path = "C:\\Program Files\\WireGuard\\wg.exe";
    let output = std::process::Command::new(wg_path)
        .args(["show", "all", "dump"])
        .output();

    let mut peers = Vec::new();
    let output = match output {
        Ok(o) => o,
        Err(_) => return peers,
    };
    let text = String::from_utf8_lossy(&output.stdout);

    for line in text.lines() {
        let cols: Vec<&str> = line.split('\t').collect();
        // peer 行: <iface> <pubkey> <preshared> <endpoint> <allowed> <handshake> <rx> <tx> <keepalive>
        // 实际隧道名按 install.ps1/README 为 wg-meshlet（后端默认 meshlet）；
        // 硬编码 "WireGuard" 会把真实隧道读成恒为空，须按实际名匹配。
        if cols.len() >= 9 && is_tunnel_interface(cols[0]) {
            let pubkey = cols[1];
            let endpoint = cols[3];
            let allowed = cols[4];
            let handshake: u64 = cols[5].parse().unwrap_or(0);
            let rx: u64 = cols[6].parse().unwrap_or(0);
            let tx: u64 = cols[7].parse().unwrap_or(0);

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let last_seen = if handshake > 0 && now > handshake {
                format!("{} 秒前", now - handshake)
            } else {
                "从未".to_string()
            };

            let short_key: String = pubkey.chars().take(16).collect();
            peers.push(serde_json::json!({
                "public_key": format!("{short_key}…"),
                "endpoint": endpoint,
                "allowed_ips": allowed,
                "last_handshake": last_seen,
                "rx_bytes": rx,
                "tx_bytes": tx,
                "connected": handshake > 0 && (now - handshake) < 180,
            }));
        }
    }
    peers
}

/// 受管隧道接口名（与 install.ps1 的 `wg-meshlet` 及后端默认 `meshlet`
/// 两种约定兼容；不再把 "WireGuard" 当隧道名）。
fn is_tunnel_interface(name: &str) -> bool {
    name == "wg-meshlet" || name == "meshlet"
}

/// R-TRAY-1：命令目录（单一事实源，与 CLI `--help` 同源）——「命令」区据此
/// 渲染并按分组排列，新增命令自动出现，不手工维护清单。
#[tauri::command]
fn get_commands() -> Vec<meshlet_commands::CommandSpec> {
    meshlet_commands::COMMANDS.to_vec()
}

/// R-TRAY-1：本机网络诊断三快照（路由表/接口/wg 读数，联动 R-DIAG）。
/// 采集失败如实报 `Err`（诊断面绝不臆测默认值）。
#[tauri::command]
fn get_diag() -> Result<meshlet_network::NetworkDiagnostics, String> {
    meshlet_network::SystemBackend::new()
        .diagnostics_sync()
        .map_err(|e| e.to_string())
}

/// R-TRAY-1：开机自启开关（Windows `HKCU\...\Run` 注册表；其它平台如实报
/// 不支持——不假装成功）。
#[tauri::command]
fn set_autostart(enabled: bool) -> Result<(), String> {
    set_autostart_impl(enabled)
}

fn set_autostart_impl(enabled: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
        if enabled {
            let out = std::process::Command::new("reg")
                .args([
                    "add",
                    key,
                    "/v",
                    "meshlet",
                    "/t",
                    "REG_SZ",
                    "/d",
                    &exe.to_string_lossy(),
                    "/f",
                ])
                .output()
                .map_err(|e| e.to_string())?;
            if !out.status.success() {
                return Err(String::from_utf8_lossy(&out.stderr).into_owned());
            }
        } else {
            let out = std::process::Command::new("reg")
                .args(["delete", key, "/v", "meshlet", "/f"])
                .output()
                .map_err(|e| e.to_string())?;
            // 删除不存在的值：reg 报 "unable to find"，按幂等成功处理。
            if !out.status.success()
                && !String::from_utf8_lossy(&out.stderr).contains("unable to find")
            {
                return Err(String::from_utf8_lossy(&out.stderr).into_owned());
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

/// R-TRAY-1：打开日志目录（Windows 资源管理器；其它平台如实报不支持）。
#[tauri::command]
fn open_log_dir() -> Result<(), String> {
    #[cfg(windows)]
    {
        let dir = meshlet_state_dir();
        std::process::Command::new("explorer")
            .arg(&dir)
            .spawn()
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        Err("opening a log directory is only supported on Windows".into())
    }
}

// ── 状态分档（纯函数，可测）────────────────────────────────────────────
/// 四档状态分类：agent 写入 status.json 的一切 `state` 字符串统一归档。
/// 真实生产者值是 `accessible_name()` 全称句（见 `state_tier` 注释）；
/// 与 `apps/agent/src/tray.rs` 的 [`TrayState`] 四态对位：tunnel only/drift →
/// 降级（隧道通、控制通道断）；error/failed → 异常；offline/未知 → 离线。
/// `degraded` 后端暂不产出，此处先行对位（agent 后续补分档即自动生效）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tier {
    Online,
    Degraded,
    Error,
    Offline,
}

fn state_tier(state: &str) -> Tier {
    // 真实生产者是 agent 写出的 `accessible_name()`（apps/agent/src/tray.rs:106）
    // 全称句："Meshlet online" / "Meshlet tunnel only" / "Meshlet tunnel drift" /
    // "Meshlet offline"。故按**小写化后的子串**匹配（不区分大小写），而不是
    // snake_case 精确等值——后者对真实输入恒 miss，四档恒落 Offline。
    // 判定顺序固定：先降级（tunnel only/drift/degraded），再异常（error/
    // failed），再在线（online；"offline" 不含 "online" 子串，天然互斥），
    // 其余一律 Offline。snake_case（online/tunnel_only/degraded/error…）
    // 继续兼容，防 agent 侧未来增写字段。
    let s = state.to_lowercase();
    if s.contains("tunnel only")
        || s.contains("tunnel_only")
        || s.contains("tunnel drift")
        || s.contains("tunnel_drift")
        || s.contains("degraded")
    {
        return Tier::Degraded;
    }
    if s.contains("error") || s.contains("failed") {
        return Tier::Error;
    }
    // "up"/"ok" 等短词只做全等匹配：子串匹配会误吞 "setup"/"lookup" 类值。
    if s.contains("online") || s == "connected" || s == "ready" || s == "up" || s == "ok" {
        return Tier::Online;
    }
    Tier::Offline
}

/// 状态 → 托盘图标文件名。16px 变体手工像素级微调过（内孔不被抗锯齿残渣
/// 填塞，见 `icons/gen_icons.py`），Windows 托盘 100% DPI 原生 16px 直接
/// 1:1 渲染；32px 为兜底（高 DPI 或 16px 文件缺失时）。
fn icon_for_state(state: &str) -> (&'static str, &'static str) {
    match state_tier(state) {
        Tier::Online => ("icon-online-16.png", "icon-online.png"),
        Tier::Degraded => ("icon-degraded-16.png", "icon-degraded.png"),
        Tier::Error => ("icon-error-16.png", "icon-error.png"),
        Tier::Offline => ("icon-offline-16.png", "icon-offline.png"),
    }
}

/// `__gotoZone` 接受的定位目标白名单：4 个 Tab + 诊断区锚点 + 连接区 Peers。
// ── 设置窗定位（深链，纯函数可测）──────────────────────────────────────
const GOTO_ZONES: &[&str] = &[
    "conn", "diag", "cmd", "gen", "routes", "ifaces", "wg", "peers",
];

/// 定位 JS（可测）：带白名单校验，`zone` 来自菜单/弹层调用方，绝不拼接进
/// 未校验的字符串（防 JS 注入）。
fn goto_zone_js(zone: &str) -> Option<String> {
    if !GOTO_ZONES.contains(&zone) {
        return None;
    }
    let quoted = serde_json::to_string(zone).unwrap_or_else(|_| "\"\"".into());
    Some(format!("window.__gotoZone && window.__gotoZone({quoted})"))
}

/// 新建设置窗还在加载时，eval 的定位 JS 会落在 `__gotoZone` 定义之前：
/// 先把 zone 挂起到这里，设置窗脚本初始化时经 `take_pending_goto` 取走，
/// 双通道（eval + 启动取件）保证新旧窗口都能定位。
static PENDING_GOTO: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

fn set_pending_goto(zone: &str) {
    *PENDING_GOTO.lock().unwrap() = Some(zone.to_string());
}

#[tauri::command]
fn take_pending_goto() -> Option<String> {
    PENDING_GOTO.lock().unwrap().take()
}

/// 打开（或聚焦）设置窗并定位到 zone。菜单「诊断/路由表/对等节点」与
/// 弹层快捷入口共用此入口。
fn open_settings_at_zone(app: &tauri::AppHandle, zone: &str) {
    set_pending_goto(zone);
    open_settings_window(app);
    if let Some(window) = app.get_webview_window("settings") {
        if let Some(js) = goto_zone_js(zone) {
            if window.eval(&js).is_ok() {
                // eval 已送达存活窗口：挂起件已消费，立即清空。否则窗口
                // reload 时脚本重新经 take_pending_goto 取件，会把一次旧
                // 定位重放到新加载页（跳到用户并未点的那一区）。
                *PENDING_GOTO.lock().unwrap() = None;
            }
        }
    }
}

/// 弹层快捷入口命令：打开设置窗并定位，弹层自身随即收起。
#[tauri::command]
fn open_settings_at(app: tauri::AppHandle, zone: String) -> Result<(), String> {
    if goto_zone_js(&zone).is_none() {
        return Err(format!("unknown zone: {zone}"));
    }
    open_settings_at_zone(&app, &zone);
    if let Some(w) = app.get_webview_window("popup") {
        let _ = w.hide();
    }
    Ok(())
}

// ── 托盘语言切换命令（设置窗语言变更时回调）───────────────────────────
#[tauri::command]
fn set_tray_lang(app: tauri::AppHandle, lang: String) -> Result<(), String> {
    set_tray_lang_impl(&app, &lang)
}

fn set_tray_lang_impl(app: &tauri::AppHandle, lang: &str) -> Result<(), String> {
    if lang != "zh" && lang != "en" {
        return Err(format!("unsupported lang: {lang}"));
    }
    i18n::write_tray_lang(lang)?;
    let menu = build_tray_menu(app).map_err(|e| e.to_string())?;
    if let Some(tray) = app.tray_by_id("meshlet-tray") {
        tray.set_menu(Some(menu)).map_err(|e| e.to_string())?;
    }
    // 摘要行文本随语言重建；同步托管句柄供轮询线程 set_text。
    let summary = build_summary_item(app).map_err(|e| e.to_string())?;
    if let Some(slot) =
        app.try_state::<std::sync::Mutex<Option<tauri::menu::MenuItem<tauri::Wry>>>>()
    {
        *slot.lock().unwrap() = Some(summary);
    }
    Ok(())
}

/// 菜单首行摘要的当前文案（状态 + 直连计数，语言跟随托盘语言）。
fn tray_summary_text() -> String {
    let status = get_status();
    let state = status["state"].as_str().unwrap_or("unknown");
    let peers = get_peers();
    let (online, total) = i18n::peers_summary(&peers);
    i18n::summary_line(state_tier(state), online, total, &i18n::read_tray_lang())
}

fn build_summary_item(app: &tauri::AppHandle) -> tauri::Result<tauri::menu::MenuItem<tauri::Wry>> {
    let text = tray_summary_text();
    MenuItem::with_id(app, "status_summary", text, false, None::<&str>)
}

/// 托盘菜单（双平台共用结构，按各自惯例呈现）：
/// [disabled 状态摘要] │ 状态面板 │ 诊断/路由表/对等节点 │ 打开设置+日志子菜单 │ 退出。
/// 快捷键统一写 `CmdOrCtrl`（Tauri accelerator 按平台显示 Ctrl+D / ⌘D）。
fn build_tray_menu(app: &tauri::AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let t = i18n::menu_texts(&i18n::read_tray_lang());
    let summary = build_summary_item(app)?;
    let sep1 = PredefinedMenuItem::separator(app)?;
    let popup = MenuItem::with_id(app, "popup", t.popup, true, Some("CmdOrCtrl+I"))?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let diag = MenuItem::with_id(app, "diag", t.diag, true, Some("CmdOrCtrl+D"))?;
    let routes = MenuItem::with_id(app, "routes", t.routes, true, Some("CmdOrCtrl+R"))?;
    let peers = MenuItem::with_id(app, "peers", t.peers, true, Some("CmdOrCtrl+P"))?;
    let sep3 = PredefinedMenuItem::separator(app)?;
    let show = MenuItem::with_id(app, "show", t.show, true, Some("CmdOrCtrl+S"))?;
    let log_open = MenuItem::with_id(app, "logdir", t.log_open, true, None::<&str>)?;
    let logs = Submenu::with_id_and_items(app, "logs", t.logs, true, &[&log_open])?;
    let sep4 = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", t.quit, true, None::<&str>)?;
    Menu::with_items(
        app,
        &[
            &summary, &sep1, &popup, &sep2, &diag, &routes, &peers, &sep3, &show, &logs, &sep4,
            &quit,
        ],
    )
}

// ── 状态弹层窗口 ───────────────────────────────────────────────────────
/// 弹层定位（纯函数，可测）：Windows 贴任务栏右下（任务栏 ≈48px + 余量），
/// macOS 贴菜单栏右上（菜单栏 ≈25px + 余量）。全部乘 scale（物理像素）。
fn popup_origin(
    mon_w: i32,
    mon_h: i32,
    win_w: i32,
    win_h: i32,
    scale: f64,
    macos: bool,
) -> (i32, i32) {
    let margin_x = (if macos { 8.0 } else { 16.0 } * scale).round() as i32;
    let x = (mon_w - win_w - margin_x).max(0);
    let y = if macos {
        (34.0 * scale).round() as i32
    } else {
        (mon_h - win_h - (72.0 * scale).round() as i32).max(0)
    };
    (x, y)
}

/// 把弹层摆到托盘附近：Windows 右下角（托盘所在的任务栏上方）、macOS
/// 菜单栏下方右侧。
fn position_popup(app: &tauri::AppHandle, window: &tauri::WebviewWindow) {
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
fn toggle_popup_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("popup") {
        if window.is_visible().unwrap_or(false) {
            let _ = window.hide();
            return;
        }
        position_popup(app, &window);
        reveal_window(&window);
        return;
    }
    if let Err(e) =
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
        eprintln!("meshlet-tray: build popup window failed: {e}");
        return;
    }
    if let Some(window) = app.get_webview_window("popup") {
        position_popup(app, &window);
        reveal_window(&window);
    }
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_status,
            get_config,
            save_config,
            get_peers,
            get_commands,
            get_diag,
            set_autostart,
            open_log_dir,
            set_tray_lang,
            take_pending_goto,
            open_settings_at
        ])
        .setup(|app| {
            // 托盘菜单（分组重设计）：状态摘要(disabled) │ 状态面板 │
            // 诊断/路由表/对等节点 │ 打开设置+日志子菜单 │ 退出
            let menu = build_tray_menu(app.handle())?;

            // 托管摘要行句柄：轮询线程每 3s set_text 刷新状态/直连计数。
            app.manage(std::sync::Mutex::new(Some(build_summary_item(
                app.handle(),
            )?)));

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
                    "popup" => {
                        toggle_popup_window(app);
                    }
                    "diag" | "routes" | "peers" => {
                        open_settings_at_zone(app, event.id.as_ref());
                    }
                    "logdir" => {
                        if let Err(e) = open_log_dir() {
                            eprintln!("meshlet-tray: open log dir failed: {e}");
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
                        toggle_settings_window(tray.app_handle());
                    }
                    _ => {}
                })
                .build(app)?;

            // 状态轮询：更新 tooltip / 图标 / 菜单摘要行，并把状态推给弹层
            // （弹层不自带轮询，与主循环共用同一时钟）。
            let app_handle = app.handle().clone();
            std::thread::spawn(move || loop {
                let status = get_status();
                let tooltip = status["tooltip"].as_str().unwrap_or("Meshlet");
                if let Some(tray) = app_handle.tray_by_id("meshlet-tray") {
                    let _ = tray.set_tooltip(Some(tooltip));
                    // 根据状态换图标（从 exe 同级 Resources 目录加载；首选
                    // 16px 微调变体，缺失时回落 32px 原图）。
                    let state = status["state"].as_str().unwrap_or("unknown");
                    let (icon_preferred, icon_fallback) = icon_for_state(state);
                    if let Ok(exe) = std::env::current_exe() {
                        if let Some(dir) = exe.parent().and_then(|d| d.parent()) {
                            let resources = dir.join("Resources");
                            let icon_bytes = std::fs::read(resources.join(icon_preferred))
                                .or_else(|_| std::fs::read(resources.join(icon_fallback)));
                            if let Ok(bytes) = icon_bytes {
                                if let Ok(icon) = tauri::image::Image::from_bytes(&bytes) {
                                    let _ = tray.set_icon(Some(icon));
                                }
                            }
                        }
                    }
                }
                // 菜单首行状态摘要（disabled）每轮刷新：状态档位 + 直连计数。
                let summary_text = tray_summary_text();
                if let Some(slot) = app_handle
                    .try_state::<std::sync::Mutex<Option<tauri::menu::MenuItem<tauri::Wry>>>>()
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
                            if let Some(w) = app_handle.get_webview_window(&label) {
                                let _ = w.hide();
                            }
                        }
                    }
                    // 弹层失焦自动隐藏（点外部即收起，托盘弹层惯例）。
                    tauri::WindowEvent::Focused(false) if label == "popup" => {
                        if let Some(w) = app_handle.get_webview_window("popup") {
                            let _ = w.hide();
                        }
                    }
                    _ => {}
                }
            }
        });
}

/// 把窗口带回前台：先还原（最小化态）→ 显示 → 聚焦。设置窗与状态弹层
/// 共用。顺序不可省 unminimize：tao 的 `show()` 最终是 `ShowWindow(SW_SHOW)`
/// （tao-0.37.2 window_state.rs:458-468），不会还原最小化窗口；而 tao 的
/// `set_focus()` 守卫 `is_visible && !is_minimized && !is_foreground`
/// （tao-0.37.2 window.rs:139-150）在最小化时是 no-op——只 show+focus 时
/// 最小化的窗口原封不动留在任务栏，用户看就是「点打开设置没反应」。
fn reveal_window(window: &tauri::WebviewWindow) {
    if window.is_minimized().unwrap_or(false) {
        let _ = window.unminimize();
    }
    let _ = window.show();
    let _ = window.set_focus();
}

/// 显示（或聚焦）设置面板——供右键菜单「打开设置」项使用，行为不变：
/// 始终把窗口带到前台。
fn open_settings_window(app: &tauri::AppHandle) {
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
fn settings_toggle_should_hide(is_visible: bool, is_minimized: bool) -> bool {
    is_visible && !is_minimized
}

/// 切换设置面板显隐——托盘图标左键单击路径。可见则隐藏，否则显示并聚焦。
/// 与 `open_settings_window`（总是显示）不同，单击是「切换」而不是「弹出」，
/// 这是 Windows 托盘的主流交互约定。
fn toggle_settings_window(app: &tauri::AppHandle) {
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

fn build_settings_window(app: &tauri::AppHandle) {
    // 创建失败不再静默吞掉：窗口创建竞态/WebView 故障时至少留一条诊断线
    //（此前 `let _ =` 让「点打开设置没反应」无迹可查）。
    if let Err(e) = tauri::WebviewWindowBuilder::new(
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
        eprintln!("meshlet-tray: build settings window failed: {e}");
    }
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
        Some(prev) => now.duration_since(prev) >= TRAY_ACTIVATE_DEDUP,
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

    #[test]
    fn tunnel_interface_matches_install_conventions() {
        // 实际隧道名按 install.ps1/README 为 wg-meshlet，后端默认 meshlet；
        // 旧的 "WireGuard" 硬编码读不到真实隧道。
        assert!(is_tunnel_interface("wg-meshlet"));
        assert!(is_tunnel_interface("meshlet"));
        assert!(!is_tunnel_interface("WireGuard"));
        assert!(!is_tunnel_interface("wg0"));
    }

    #[test]
    fn save_config_preserves_agent_managed_keys() {
        // install.ps1 生成的 agent.toml 含 agent 自行管理的键；保存设置只
        // 改 server_url/device_name/interface/hub_endpoint，不得丢其余键。
        let existing = "server_url = \"https://old.example.com\"\n\
                        state_dir = \"C:\\\\Users\\\\bob\\\\AppData\\\\Local\\\\meshlet\\\\state\"\n\
                        bootstrap_token = \"bt-123\"\n\
                        device_name = \"old-name\"\n\
                        \n\
                        [dataplane]\n\
                        enabled = true\n\
                        interface = \"meshlet\"\n\
                        private_key_file = \"C:\\\\keys\\\\priv.key\"\n\
                        hub_endpoint = \"1.2.3.4:51820\"\n\
                        poll_interval_secs = 30\n";
        let rebuilt = rebuild_config(
            existing,
            "https://new.example.com",
            "new-name",
            "5.6.7.8:51820",
        );
        assert!(rebuilt.contains("server_url = \"https://new.example.com\""));
        assert!(rebuilt.contains("device_name = \"new-name\""));
        assert!(rebuilt.contains("hub_endpoint = \"5.6.7.8:51820\""));
        assert!(rebuilt.contains("interface = \"wg-meshlet\""));
        // 保留键一个不丢。
        assert!(rebuilt.contains("state_dir"));
        assert!(rebuilt.contains("bootstrap_token"));
        assert!(rebuilt.contains("private_key_file"));
        assert!(rebuilt.contains("poll_interval_secs = 30"));
        assert!(!rebuilt.contains("\"WireGuard\""));
    }

    #[test]
    fn save_config_handles_missing_optional_keys() {
        // 无 state_dir/bootstrap_token 等（配置缺失时）不 panic，仍写出托管键。
        let rebuilt = rebuild_config("", "https://x", "dev", "9.9.9.9:1");
        assert!(rebuilt.contains("server_url = \"https://x\""));
        assert!(rebuilt.contains("interface = \"wg-meshlet\""));
        assert!(!rebuilt.contains("state_dir"));
    }

    #[test]
    fn tray_activate_due_allows_first_activation() {
        // 从未激活过 → 立即触发。
        assert!(tray_activate_due(None, std::time::Instant::now()));
    }

    #[test]
    fn tray_activate_due_swallows_events_within_window() {
        let t0 = std::time::Instant::now();
        // 同一次双击的第二个事件（DoubleClick / 双击后抬起）在窗口内 → 吞掉。
        assert!(!tray_activate_due(
            Some(t0),
            t0 + std::time::Duration::from_millis(50)
        ));
        // 恰好等于窗口边界（>=）→ 允许。
        assert!(tray_activate_due(Some(t0), t0 + TRAY_ACTIVATE_DEDUP));
    }

    #[test]
    fn tray_activate_due_allows_events_after_window() {
        let t0 = std::time::Instant::now();
        // 超过窗口 → 允许（用户再次有意单击）。
        assert!(tray_activate_due(
            Some(t0),
            t0 + std::time::Duration::from_millis(300)
        ));
    }

    #[test]
    fn tray_activate_sequence_first_true_then_false() {
        // 模拟 Windows 一次物理双击产生的事件序列：
        // Click(Left,Up) → DoubleClick(Left) → Click(Left,Up)（双击后抬起）。
        // 只有第一个事件真正翻转面板，后两个被合并掉（不重复触发）。
        let t0 = std::time::Instant::now();
        assert!(tray_activate_due(None, t0)); // Click(up) → 翻转
        assert!(!tray_activate_due(
            Some(t0),
            t0 + std::time::Duration::from_millis(120)
        )); // DoubleClick → 吞
        assert!(!tray_activate_due(
            Some(t0),
            t0 + std::time::Duration::from_millis(160)
        )); // 抬起 → 吞
    }

    #[test]
    fn toggle_hides_only_visible_unminimized_window() {
        // 可见且未最小化（正在使用）→ 托盘单击隐藏（切换语义不变）。
        assert!(settings_toggle_should_hide(true, false));
    }

    #[test]
    fn toggle_does_not_hide_minimized_window() {
        // 回归（右键「打开设置」无响应同族）：最小化窗口的 is_visible() 仍为
        // true（WS_VISIBLE 未清），旧代码据此 hide()，单击托盘把窗口越藏越深，
        // 永远还原不了。最小化必须按「待还原」处理而不是隐藏。
        assert!(!settings_toggle_should_hide(true, true));
    }

    #[test]
    fn toggle_reveals_hidden_window() {
        // 隐藏（关闭被拦截为 hide）→ 不隐藏，走还原路径（reveal）。
        assert!(!settings_toggle_should_hide(false, false));
        assert!(!settings_toggle_should_hide(false, true));
    }

    // ── 四档状态分档（与 agent TrayState 对位）──────────────────────────
    #[test]
    fn state_tier_maps_real_producer_strings() {
        // 真实生产者：agent tray.rs:106 accessible_name() 写入 status.json
        // 的 `state` 全称句。四正例必须各归其档（B1 回归：旧 snake_case
        // 精确匹配对真实输入恒 miss，全部误落 Offline）。
        assert_eq!(state_tier("Meshlet online"), Tier::Online);
        assert_eq!(state_tier("Meshlet tunnel only"), Tier::Degraded);
        assert_eq!(state_tier("Meshlet tunnel drift"), Tier::Degraded);
        assert_eq!(state_tier("Meshlet offline"), Tier::Offline);
        // 不区分大小写（生产者若改首字母大小写也不破档）。
        assert_eq!(state_tier("meshlet ONLINE"), Tier::Online);
        assert_eq!(state_tier("MESHLET TUNNEL ONLY"), Tier::Degraded);
        // 反例：offline 不得被误判为 Online（"offline" 不含 "online"）。
        assert_ne!(state_tier("Meshlet offline"), Tier::Online);
        // 反例：tunnel only/drift 必须先于 online 判定，不得漏成 Online。
        assert_ne!(state_tier("Meshlet tunnel only"), Tier::Online);
        assert_ne!(state_tier("Meshlet tunnel drift"), Tier::Online);
    }

    #[test]
    fn state_tier_maps_agent_states() {
        // snake_case 兼容层：agent 旧字段（online/tunnel_only/error…）与
        // 状态机其它合法迁移产物，保留用例防未来回归到另一格式。
        assert_eq!(state_tier("online"), Tier::Online);
        assert_eq!(state_tier("tunnel_only"), Tier::Degraded); // 隧道通、控制通道断
        assert_eq!(state_tier("tunnel_drift"), Tier::Degraded);
        assert_eq!(state_tier("degraded"), Tier::Degraded); // agent 后续补分档即生效
        assert_eq!(state_tier("error"), Tier::Error);
        assert_eq!(state_tier("failed"), Tier::Error);
        assert_eq!(state_tier("disconnected"), Tier::Offline);
        assert_eq!(state_tier("down"), Tier::Offline);
        assert_eq!(state_tier("unknown"), Tier::Offline);
        assert_eq!(state_tier(""), Tier::Offline);
        // 反例：短词全等匹配不误吞子串（"up" ⊂ "setup" 类值）。
        assert_eq!(state_tier("setup"), Tier::Offline);
        assert_eq!(state_tier("lookok"), Tier::Offline);
    }

    #[test]
    fn icon_for_state_prefers_16px_variant() {
        // 每档都指向手工微调的 16px 变体 + 32px 兜底，一一对应仓内文件。
        assert_eq!(
            icon_for_state("Meshlet online"),
            ("icon-online-16.png", "icon-online.png")
        );
        assert_eq!(
            icon_for_state("Meshlet tunnel only"),
            ("icon-degraded-16.png", "icon-degraded.png")
        );
        assert_eq!(
            icon_for_state("Meshlet tunnel drift"),
            ("icon-degraded-16.png", "icon-degraded.png")
        );
        assert_eq!(
            icon_for_state("failed"),
            ("icon-error-16.png", "icon-error.png")
        );
        assert_eq!(
            icon_for_state("Meshlet offline"),
            ("icon-offline-16.png", "icon-offline.png")
        );
    }

    #[test]
    fn popup_origin_windows_bottom_right_above_taskbar() {
        // 1920x1080 @100%：右下角，任务栏（≈48px）+ 余量 24px。
        let (x, y) = popup_origin(1920, 1080, 320, 480, 1.0, false);
        assert_eq!(x, 1920 - 320 - 16);
        assert_eq!(y, 1080 - 480 - 72);
    }

    #[test]
    fn popup_origin_macos_below_menu_bar() {
        let (x, y) = popup_origin(2560, 1440, 320, 480, 2.0, true);
        assert_eq!(x, 2560 - 320 - 16); // 8 * 2
        assert_eq!(y, 68); // 34 * 2（Retina 物理像素）
    }

    #[test]
    fn popup_origin_clamps_into_screen() {
        // 弹层比屏幕还高时不越界（钳到 0）。
        let (x, y) = popup_origin(640, 480, 320, 480, 1.0, false);
        assert_eq!((x, y), (304, 0));
    }

    #[test]
    fn popup_origin_clamps_negative_origin_to_zero() {
        // 负坐标输入（屏幕小于窗口 / 极小显示器）双向钳到 0：x = 200-320-16
        // 与 y = 480-480-72 均为负，.max(0) 必须生效，绝不允许把弹层摆到
        // 屏幕外（负坐标会落到不可见的第二屏区域）。
        let (x, y) = popup_origin(200, 480, 320, 480, 1.0, false);
        assert_eq!((x, y), (0, 0));
        // 2x 缩放下 margin 放大后同样钳住。
        let (x, y) = popup_origin(300, 400, 320, 480, 2.0, false);
        assert_eq!((x, y), (0, 0));
    }

    // ── 设置窗定位（深链）──────────────────────────────────────────────
    #[test]
    fn goto_zone_js_quotes_whitelisted_zones() {
        let js = goto_zone_js("routes").unwrap();
        assert_eq!(js, "window.__gotoZone && window.__gotoZone(\"routes\")");
        assert!(goto_zone_js("peers").is_some());
        assert!(goto_zone_js("conn").is_some());
    }

    #[test]
    fn goto_zone_js_rejects_non_whitelisted_zones() {
        // 菜单/弹层之外的一切来源必须被白名单挡住（防 JS 注入）。
        assert!(goto_zone_js("").is_none());
        assert!(goto_zone_js("diag'); alert(1); ('").is_none());
        assert!(goto_zone_js("__proto__").is_none());
    }
}
