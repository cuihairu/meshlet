//! agent 状态分档、深链定位与 WireGuard 对等节点读取。

use crate::config_io::meshlet_state_dir;

// ── 状态分档（纯函数，可测）────────────────────────────────────────────
/// 四档状态分类：agent 写入 status.json 的一切 `state` 字符串统一归档。
/// 真实生产者值是 `accessible_name()` 全称句（见 `state_tier` 注释）；
/// 与 `apps/agent/src/tray.rs` 的 [`TrayState`] 四态对位：tunnel only/drift →
/// 降级（隧道通、控制通道断）；error/failed → 异常；offline/未知 → 离线。
/// `degraded` 后端暂不产出，此处先行对位（agent 后续补分档即自动生效）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tier {
    Online,
    Degraded,
    Error,
    Offline,
}

pub(crate) fn state_tier(state: &str) -> Tier {
    // 真实生产者是 agent 写出的 `accessible_name()`（apps/agent/src/tray.rs:106）
    // 全称句："Meshlet online" / "Meshlet tunnel only" / "Meshlet tunnel drift" /
    // "Meshlet offline"。故按**小写化后的子串**匹配（不区分大小写），而不是
    // snake_case 精确等值——后者对真实输入恒 miss，四档恒落 Offline。
    // 判定顺序固定：先降级（tunnel only/drift/degraded），再异常（error/
    // failed），再在线（online；"offline" 不含 "online" 子串，天然互斥），
    // 其余一律 Offline。snake_case（online/tunnel_only/degraded/error…）
    // 继续兼容，防 agent 侧未来增写字段。
    let state = state.to_lowercase();
    if state.contains("tunnel only")
        || state.contains("tunnel_only")
        || state.contains("tunnel drift")
        || state.contains("tunnel_drift")
        || state.contains("degraded")
    {
        return Tier::Degraded;
    }
    if state.contains("error") || state.contains("failed") {
        return Tier::Error;
    }
    // "up"/"ok" 等短词只做全等匹配：子串匹配会误吞 "setup"/"lookup" 类值。
    if state.contains("online")
        || state == "connected"
        || state == "ready"
        || state == "up"
        || state == "ok"
    {
        return Tier::Online;
    }
    Tier::Offline
}

/// 状态 → 托盘图标文件名。16px 变体手工像素级微调过（内孔不被抗锯齿残渣
/// 填塞，见 `icons/gen_icons.py`），Windows 托盘 100% DPI 原生 16px 直接
/// 1:1 渲染；32px 为兜底（高 DPI 或 16px 文件缺失时）。
pub(crate) fn icon_for_state(state: &str) -> (&'static str, &'static str) {
    match state_tier(state) {
        Tier::Online => ("icon-online-16.png", "icon-online.png"),
        Tier::Degraded => ("icon-degraded-16.png", "icon-degraded.png"),
        Tier::Error => ("icon-error-16.png", "icon-error.png"),
        Tier::Offline => ("icon-offline-16.png", "icon-offline.png"),
    }
}

// ── 设置窗定位（深链，纯函数可测）──────────────────────────────────────
/// `__gotoZone` 接受的定位目标白名单：4 个 Tab + 诊断区锚点 + 连接区 Peers。
const GOTO_ZONES: &[&str] = &[
    "conn", "diag", "cmd", "gen", "routes", "ifaces", "wg", "peers",
];

/// 定位 JS（可测）：带白名单校验，`zone` 来自菜单/弹层调用方，绝不拼接进
/// 未校验的字符串（防 JS 注入）。
pub(crate) fn goto_zone_js(zone: &str) -> Option<String> {
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

pub(crate) fn set_pending_goto(zone: &str) {
    *PENDING_GOTO.lock().unwrap() = Some(zone.to_string());
}

pub(crate) fn clear_pending_goto() {
    *PENDING_GOTO.lock().unwrap() = None;
}

pub(crate) fn take_pending_goto() -> Option<String> {
    PENDING_GOTO.lock().unwrap().take()
}

pub(crate) fn is_tunnel_interface(name: &str) -> bool {
    name == "wg-meshlet" || name == "meshlet"
}

pub(crate) fn get_status() -> serde_json::Value {
    // 与 tray-host（apps/tray-host/src/main.rs:40-42）及安装脚本
    // （scripts/install.ps1 的 state 目录）约定一致：状态写
    // `%LOCALAPPDATA%/meshlet/state/tray/status.json`。不在前端硬编码用户
    // 目录，避免用户名写死/换用户失效。
    let path = std::path::Path::new(&meshlet_state_dir())
        .join("tray")
        .join("status.json");
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|content| serde_json::from_str(&content).ok())
        .unwrap_or(serde_json::json!({"state": "unknown", "tooltip": "Meshlet"}))
}

pub(crate) fn get_peers() -> Vec<serde_json::Value> {
    let wg_path = "C:\\Program Files\\WireGuard\\wg.exe";
    let output = std::process::Command::new(wg_path)
        .args(["show", "all", "dump"])
        .output();

    let mut peers = Vec::new();
    let output = match output {
        Ok(output) => output,
        Err(_) => return peers,
    };
    let text = String::from_utf8_lossy(&output.stdout);

    for line in text.lines() {
        let columns: Vec<&str> = line.split('\t').collect();
        // peer 行: <iface> <pubkey> <preshared> <endpoint> <allowed> <handshake> <rx> <tx> <keepalive>
        // 实际隧道名按 install.ps1/README 为 wg-meshlet（后端默认 meshlet）；
        // 硬编码 "WireGuard" 会把真实隧道读成恒为空，须按实际名匹配。
        if columns.len() >= 9 && is_tunnel_interface(columns[0]) {
            let public_key = columns[1];
            let endpoint = columns[3];
            let allowed_ips = columns[4];
            let handshake: u64 = columns[5].parse().unwrap_or(0);
            let rx: u64 = columns[6].parse().unwrap_or(0);
            let tx: u64 = columns[7].parse().unwrap_or(0);

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let last_seen = if handshake > 0 && now > handshake {
                format!("{} 秒前", now - handshake)
            } else {
                "从未".to_string()
            };

            let short_key: String = public_key.chars().take(16).collect();
            peers.push(serde_json::json!({
                "public_key": format!("{short_key}…"),
                "endpoint": endpoint,
                "allowed_ips": allowed_ips,
                "last_handshake": last_seen,
                "rx_bytes": rx,
                "tx_bytes": tx,
                "connected": handshake > 0 && (now - handshake) < 180,
            }));
        }
    }
    peers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_interface_matches_install_conventions() {
        assert!(is_tunnel_interface("wg-meshlet"));
        assert!(is_tunnel_interface("meshlet"));
        assert!(!is_tunnel_interface("WireGuard"));
        assert!(!is_tunnel_interface("eth0"));
    }

    #[test]
    fn state_tier_maps_real_producer_strings() {
        assert_eq!(state_tier("Meshlet online"), Tier::Online);
        assert_eq!(state_tier("Meshlet tunnel only"), Tier::Degraded);
        assert_eq!(state_tier("Meshlet tunnel drift"), Tier::Degraded);
        assert_eq!(state_tier("Meshlet offline"), Tier::Offline);
        assert_eq!(state_tier("meshlet ONLINE"), Tier::Online);
        assert_eq!(state_tier("MESHLET TUNNEL ONLY"), Tier::Degraded);
        assert_ne!(state_tier("Meshlet offline"), Tier::Online);
        assert_ne!(state_tier("Meshlet tunnel only"), Tier::Online);
        assert_ne!(state_tier("Meshlet tunnel drift"), Tier::Online);
    }

    #[test]
    fn state_tier_maps_agent_states() {
        assert_eq!(state_tier("online"), Tier::Online);
        assert_eq!(state_tier("tunnel_only"), Tier::Degraded);
        assert_eq!(state_tier("tunnel_drift"), Tier::Degraded);
        assert_eq!(state_tier("degraded"), Tier::Degraded);
        assert_eq!(state_tier("error"), Tier::Error);
        assert_eq!(state_tier("failed"), Tier::Error);
        assert_eq!(state_tier("disconnected"), Tier::Offline);
        assert_eq!(state_tier("down"), Tier::Offline);
        assert_eq!(state_tier("unknown"), Tier::Offline);
        assert_eq!(state_tier(""), Tier::Offline);
        assert_eq!(state_tier("setup"), Tier::Offline);
        assert_eq!(state_tier("lookok"), Tier::Offline);
    }

    #[test]
    fn icon_for_state_prefers_16px_variant() {
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
    fn goto_zone_js_quotes_whitelisted_zones() {
        let js = goto_zone_js("routes").unwrap();
        assert_eq!(js, "window.__gotoZone && window.__gotoZone(\"routes\")");
        assert!(goto_zone_js("peers").is_some());
        assert!(goto_zone_js("conn").is_some());
    }

    #[test]
    fn goto_zone_js_rejects_non_whitelisted_zones() {
        assert!(goto_zone_js("").is_none());
        assert!(goto_zone_js("diag'); alert(1); ('").is_none());
        assert!(goto_zone_js("__proto__").is_none());
    }
}
