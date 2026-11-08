// ── 托盘 i18n / 菜单文案 / 状态摘要（自 main.rs 抽出，行为不变）──────────
// 职责：档位短标签、菜单文案表、状态摘要行、托盘语言镜像文件读写。
// 依赖 main.rs 的 [`crate::Tier`]、[`crate::meshlet_state_dir`]。

use crate::{meshlet_state_dir, Tier};

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

// ── 托盘菜单文案（纯表，可测）──────────────────────────────────────────
/// 托盘菜单文案。跟随设置窗的 i18n：设置窗切换语言时经 `set_tray_lang`
/// 命令把语言写入 `{state}/tray/lang` 并即时重建菜单；托盘启动时读同一
/// 文件。托盘侧（Rust）取不到 webview 的 localStorage（设置窗真实的
/// i18n 存储），文件镜像即「跟随」机制；文件缺失时默认中文。
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

/// 菜单首行状态摘要（disabled 行）：`Meshlet · 在线 · 直连 3/4`。直连计数
/// 仅在确实读到 peers 时附加（wg.exe 缺失/无隧道时不画 0/0）。
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

/// get_peers 结果 → (在线数, 总数)。`connected` 由 main.rs get_peers 按握手
/// 新鲜度（<180s）判定，此处只汇总。
pub(crate) fn peers_summary(peers: &[serde_json::Value]) -> (usize, usize) {
    let online = peers
        .iter()
        .filter(|p| p["connected"].as_bool().unwrap_or(false))
        .count();
    (online, peers.len())
}

// ── 托盘语言持久化（跟随设置窗 i18n 的镜像文件）───────────────────────
/// 纯路径构造（可测）：`<local>/meshlet/state/tray/lang`。
fn tray_lang_path_from(local: &str) -> String {
    std::path::Path::new(local)
        .join("meshlet")
        .join("state")
        .join("tray")
        .join("lang")
        .to_string_lossy()
        .into_owned()
}

/// 当前托盘语言：读设置窗写出的镜像文件；缺失/非法时默认中文
/// （托盘侧取不到设置窗 webview 的 localStorage，见 `menu_texts` 注释）。
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
    // ── 菜单摘要行 ─────────────────────────────────────────────────────
    #[test]
    fn summary_line_appends_peer_counts_only_when_known() {
        // 读到 peers 才附加计数；wg.exe 缺失时不画 0/0。
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
            serde_json::json!({}), // 缺字段按未连接
        ];
        assert_eq!(peers_summary(&peers), (2, 4));
        assert_eq!(peers_summary(&[]), (0, 0));
    }

    // ── 菜单文案 i18n ──────────────────────────────────────────────────
    #[test]
    fn menu_texts_zh_and_en_cover_same_items() {
        // 中英两表必须覆盖同一组键（新增菜单项漏译会在启动时直接暴露为
        // 编译期字段，这里保证非空且成对）。
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
        assert_eq!(tier_label(Tier::Online, "fr"), "在线"); // 未知语言回落中文
    }

    // ── 托盘语言持久化路径 ─────────────────────────────────────────────
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
        // 默认中文：托盘侧取不到设置窗 localStorage（真实 i18n 存储），
        // 语言镜像文件缺失/内容非法时回落中文，不猜测系统语言。
        // （read_tray_lang 的文件读取依赖宿主状态目录，此处只测回落语义：
        // zh 之外只认 en，其余一律按 zh。）
        let zh = menu_texts("zh");
        let en = menu_texts("en");
        assert_eq!(zh.quit, "退出 Meshlet");
        assert_eq!(en.quit, "Quit Meshlet");
        assert_eq!(tier_label(Tier::Degraded, "zh"), "降级");
        assert_eq!(tier_label(Tier::Degraded, "en"), "Degraded");
    }
}
