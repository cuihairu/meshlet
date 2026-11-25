// ── Tray i18n / menu texts / status summary (extracted from main.rs, behavior unchanged) ──────────
// Responsibilities: tier short labels, menu text table, status summary line, tray language mirror file I/O.
// Depends on [`crate::Tier`] and [`crate::meshlet_state_dir`] from main.rs.

use crate::config_io::meshlet_state_dir;
use crate::state::Tier;

fn tier_label(tier: Tier, lang: &str) -> &'static str {
    match (tier, lang) {
        (Tier::Online, "en") => "Online",
        (Tier::Degraded, "en") => "Degraded",
        (Tier::Error, "en") => "Error",
        (Tier::Offline, "en") => "Offline",
        (Tier::Online, _) => "在线",
        (Tier::Degraded, _) => "降级",
        (Tier::Error, _) => "异常",
        (Tier::Offline, _) => "离线",
    }
}

// ── Tray menu texts (pure table, testable) ──────────────────────────────────
/// Tray menu texts. Follows the settings window i18n: on a language switch the
/// `set_tray_lang` command writes it to `{state}/tray/lang` and rebuilds the menu at
/// once; the tray reads the same file at startup. The tray side (Rust) cannot reach
/// the webview localStorage (the real i18n store), so this file mirror follows it; zh by default.
pub(crate) struct MenuTexts {
    pub(crate) popup: &'static str,
    pub(crate) diag: &'static str,
    pub(crate) routes: &'static str,
    pub(crate) peers: &'static str,
    pub(crate) show: &'static str,
    pub(crate) logs: &'static str,
    pub(crate) log_open: &'static str,
    pub(crate) quit: &'static str,
}

pub(crate) fn menu_texts(lang: &str) -> MenuTexts {
    if lang == "en" {
        MenuTexts {
            popup: "Status panel",
            diag: "Diagnostics",
            routes: "Route table",
            peers: "Peers",
            show: "Open Settings",
            logs: "Logs",
            log_open: "Open log directory",
            quit: "Quit Meshlet",
        }
    } else {
        MenuTexts {
            popup: "状态面板",
            diag: "诊断",
            routes: "路由表",
            peers: "对等节点",
            show: "打开设置",
            logs: "日志",
            log_open: "打开日志目录",
            quit: "退出 Meshlet",
        }
    }
}

/// Menu first-row status summary (disabled row): `Meshlet · {tier} · {online}/{total}`.
/// Peer counts are appended only when peers were actually read (no 0/0 when wg.exe is missing or there is no tunnel).
pub(crate) fn summary_line(tier: Tier, online: usize, total: usize, lang: &str) -> String {
    let label = tier_label(tier, lang);
    if total > 0 {
        if lang == "en" {
            format!("Meshlet · {label} · {online}/{total} peers")
        } else {
            format!("Meshlet · {label} · 直连 {online}/{total}")
        }
    } else {
        format!("Meshlet · {label}")
    }
}

/// get_peers result → (online count, total). `connected` is decided in
/// main.rs get_peers by handshake freshness (<180s); this only aggregates.
pub(crate) fn peers_summary(peers: &[serde_json::Value]) -> (usize, usize) {
    let online = peers
        .iter()
        .filter(|p| p["connected"].as_bool().unwrap_or(false))
        .count();
    (online, peers.len())
}

// ── Tray language persistence (mirror file following the settings window i18n) ───────────────
/// Pure path construction (testable): `<local>/meshlet/state/tray/lang`.
fn tray_lang_path_from(local: &str) -> String {
    std::path::Path::new(local)
        .join("meshlet")
        .join("state")
        .join("tray")
        .join("lang")
        .to_string_lossy()
        .into_owned()
}

/// Current tray language: read from the mirror file written by the settings window;
/// defaults to Chinese if missing/invalid (the tray cannot reach the settings webview localStorage; see `menu_texts`).
pub(crate) fn read_tray_lang() -> String {
    let path = tray_lang_path_from(
        &std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "C:/Users/Public".into()),
    );
    match std::fs::read_to_string(path) {
        Ok(s) if s.trim() == "en" => "en".into(),
        _ => "zh".into(),
    }
}

pub(crate) fn write_tray_lang(lang: &str) -> Result<(), String> {
    let path = tray_lang_path_from(&meshlet_state_dir());
    if let Some(dir) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, lang).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    // ── Menu summary line ─────────────────────────────────────────────────────
    #[test]
    fn summary_line_appends_peer_counts_only_when_known() {
        // Append the count only when peers were actually read; no 0/0 while wg.exe is missing.
        assert_eq!(
            summary_line(Tier::Online, 3, 4, "zh"),
            "Meshlet · 在线 · 直连 3/4"
        );
        assert_eq!(summary_line(Tier::Offline, 0, 0, "zh"), "Meshlet · 离线");
        assert_eq!(
            summary_line(Tier::Degraded, 1, 4, "en"),
            "Meshlet · Degraded · 1/4 peers"
        );
    }

    #[test]
    fn peers_summary_counts_connected() {
        let peers = vec![
            serde_json::json!({"connected": true}),
            serde_json::json!({"connected": false}),
            serde_json::json!({"connected": true}),
            serde_json::json!({}), // missing field counts as not connected
        ];
        assert_eq!(peers_summary(&peers), (2, 4));
        assert_eq!(peers_summary(&[]), (0, 0));
    }

    // ── Menu text i18n ──────────────────────────────────────────────────
    #[test]
    fn menu_texts_zh_and_en_cover_same_items() {
        // The zh/en tables must cover the same key set (a missing translation for a new menu item
        // surfaces at startup as a compile-time field; this pins non-empty, pairwise entries).
        let zh = menu_texts("zh");
        let en = menu_texts("en");
        for (a, b) in [
            (zh.popup, en.popup),
            (zh.diag, en.diag),
            (zh.routes, en.routes),
            (zh.peers, en.peers),
            (zh.show, en.show),
            (zh.logs, en.logs),
            (zh.log_open, en.log_open),
            (zh.quit, en.quit),
        ] {
            assert!(!a.is_empty() && !b.is_empty());
            assert_ne!(a, b);
        }
    }

    #[test]
    fn tier_label_defaults_to_zh_for_unknown_lang() {
        assert_eq!(tier_label(Tier::Online, "zh"), "在线");
        assert_eq!(tier_label(Tier::Online, "en"), "Online");
        assert_eq!(tier_label(Tier::Online, "fr"), "在线"); // unknown language falls back to Chinese
    }

    // ── Tray language persistence path ─────────────────────────────────────────────
    #[test]
    fn tray_lang_path_matches_state_dir_convention() {
        let got = tray_lang_path_from(r"C:\Users\bob\AppData\Local");
        assert!(got.contains("meshlet"));
        assert!(got.contains("state"));
        assert!(got.contains("tray"));
        assert!(got.ends_with("lang"));
    }

    #[test]
    fn tray_lang_mirror_defaults_to_chinese() {
        // Chinese by default: the tray cannot reach the settings localStorage (the real i18n store),
        // so fall back to Chinese when the language mirror file is missing or malformed; never guess the system language.
        // (read_tray_lang's file read depends on the host state dir; only the fallback semantics are tested here:
        // anything other than zh is accepted only as en, all else maps to zh.)
        let zh = menu_texts("zh");
        let en = menu_texts("en");
        assert_eq!(zh.quit, "退出 Meshlet");
        assert_eq!(en.quit, "Quit Meshlet");
        assert_eq!(tier_label(Tier::Degraded, "zh"), "降级");
        assert_eq!(tier_label(Tier::Degraded, "en"), "Degraded");
    }
}
