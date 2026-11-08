use windows_sys::Win32::UI::WindowsAndMessaging::*;

use meshlet_tray_host::panel::mode_label;

/// 右键菜单命令 ID（`TPM_RETURNCMD` 下 `TrackPopupMenuEx` 的返回值）。
pub(crate) const CMD_QUIT: usize = 1;
/// 「控制台(网页)」：浏览器打开 server 根路径托管的控制台（原「打开面板」
/// 行为）。本地面板另立一项，见 [`CMD_OPEN_LOCAL_PANEL`]——定案 2026-11-06：
/// 托盘「打开面板」必须开本地面板，控制台是另一个入口。
pub(crate) const CMD_OPEN_CONSOLE: usize = 2;
/// 菜单首行「设备名 + 虚拟 IP + 状态」展示项（禁用态；随 `status.json`
/// tooltip 重建——① 用户要求首行 = 设备名 + 虚拟 IPv4 + 状态）。
pub(crate) const CMD_STATUS: usize = 3;
/// 「本地面板」：打开 tray-host 自托管的 loopback 只读页（当前节点 / 直连
/// 节点 / 本地路由，见 `meshlet_tray_host::panel`）。
pub(crate) const CMD_OPEN_LOCAL_PANEL: usize = 4;
/// 「连接节点…」子菜单项命令基址：第 i 个候选 = `CMD_DIAL_BASE + i`。
pub(crate) const CMD_DIAL_BASE: usize = 100;

/// `direct-peers.json` 单条（agent 直连探测周期发布；字段与
/// `meshlet-network::dial::DirectPeerView` 一致——此处仅反序列化，不引
/// meshlet-network 依赖，托盘宿主保持 windows-sys + serde 的零数据面依赖）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub(crate) struct DirectPeerView {
    #[serde(default)]
    pub(crate) name: String,
    pub(crate) virtual_ipv4: std::net::Ipv4Addr,
    #[serde(default)]
    pub(crate) public_key: String,
    #[serde(default)]
    pub(crate) mode: String,
    #[serde(default)]
    pub(crate) rtt_ms: Option<u64>,
}

impl DirectPeerView {
    /// 菜单展示名：设备名缺失（旧服务端）时退回虚拟 IP——`peer dial` 亦按
    /// IP 解析，两种展示都可点击。
    pub(crate) fn display_name(&self) -> String {
        if self.name.trim().is_empty() {
            self.virtual_ipv4.to_string()
        } else {
            self.name.clone()
        }
    }

    /// ②「直连节点」子菜单行：名字/IP/模式/RTT（数据展示，禁用态）。
    /// 名字在前（用户令 2026-11-07：直连节点行须带节点名/nickname，纯 IP 行
    /// 认不出是哪台机器）；名字缺失（旧服务端）时退回 IP，不出现空段。
    fn menu_label(&self) -> String {
        format!(
            "{} · {} · {} · {}",
            self.display_name(),
            self.virtual_ipv4,
            mode_label(&self.mode),
            self.rtt_ms
                .map(|r| format!("{r} ms"))
                .unwrap_or_else(|| "--".into()),
        )
    }

    /// ④「连接节点…」子菜单行：可拨候选（点击触发 `peer dial`）。
    fn dial_menu_label(&self) -> String {
        format!("{}  {}", self.virtual_ipv4, self.display_name())
    }
}

/// 测试构造 fixture（仅测试用；真实数据来自 agent 的 direct-peers.json）。
#[cfg(test)]
impl DirectPeerView {
    pub(crate) fn sample(name: &str, ip: &str, mode: &str, rtt: Option<u64>) -> Self {
        Self {
            name: name.into(),
            virtual_ipv4: ip.parse().unwrap(),
            public_key: String::new(),
            mode: mode.into(),
            rtt_ms: rtt,
        }
    }
}

/// 把 agent 发布的直连视图一分为二（②「直连节点」 / ④「连接节点…」）：
/// 已直连/拨号中 → direct；候选但走中继（`hub_relay`）→ relay（可拨目标）。
pub(crate) fn split_peer_views(
    peers: &[DirectPeerView],
) -> (Vec<&DirectPeerView>, Vec<&DirectPeerView>) {
    peers
        .iter()
        .partition(|p| matches!(p.mode.as_str(), "p2p_direct" | "direct_pending"))
}

/// 读取 agent 发布的 `{state_dir}/direct-peers.json`（②④ 数据源；与 `peers`
/// 命令同一链路）。缺失/损坏 → 空表（子菜单显示「（无）」）。
pub(crate) fn load_local_direct_peers(state_dir: Option<&std::path::Path>) -> Vec<DirectPeerView> {
    state_dir
        .and_then(|dir| std::fs::read_to_string(dir.join("direct-peers.json")).ok())
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// ① 菜单首行/tooltip 正文：`status.json` 的 `tooltip` 字段——agent 侧已是
/// 「Meshlet「设备名」 <虚拟IP>：状态」（与 `info` 同一数据链路）。
pub(crate) fn status_line_text(state_dir: Option<&std::path::Path>) -> String {
    state_dir
        .and_then(|dir| std::fs::read_to_string(dir.join("tray").join("status.json")).ok())
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|v| v.get("tooltip").and_then(|t| t.as_str()).map(String::from))
        .unwrap_or_else(|| "Meshlet".into())
}

/// MCP 状态行（定案 2026-11-08）：读 `{state_dir}/mcp.json`（agent 写）。
/// 无交接文件 → 「MCP：关闭」；有 → 「MCP：开启 [port]」；缺 port（损坏/
/// 旧形态）→「MCP：开启」，不猜值。tray 只读展示——开启/切换经 agent.toml
/// `[mcp] enabled` 显式配置。
pub(crate) fn mcp_line_text(state_dir: Option<&std::path::Path>) -> String {
    let Some(dir) = state_dir else {
        return "MCP：关闭".into();
    };
    let Ok(text) = std::fs::read_to_string(dir.join("mcp.json")) else {
        return "MCP：关闭".into();
    };
    let Ok(endpoint) = serde_json::from_str::<serde_json::Value>(&text) else {
        return "MCP：开启".into();
    };
    match endpoint.get("port").and_then(|p| p.as_u64()) {
        Some(port) => format!("MCP：开启 {port}"),
        None => "MCP：开启".into(),
    }
}

/// UTF-16 + NUL（Win32 菜单/气泡文本）。
pub(crate) fn wide_z(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn append_item(menu: HMENU, flags: u32, id: usize, text: &str) {
    let wide = wide_z(text);
    AppendMenuW(menu, flags, id, wide.as_ptr());
}

/// 追加一个弹出式子菜单（`MF_POPUP`，`id` 槽位放子菜单句柄）。
unsafe fn append_popup(menu: HMENU, text: &str, sub: HMENU) {
    let wide = wide_z(text);
    AppendMenuW(menu, MF_POPUP, sub as usize, wide.as_ptr());
}

/// 按当前快照重建整个右键菜单（首行状态 + 直连节点/连接节点… 子菜单 +
/// MCP 状态行 + 本地面板 + 控制台(网页) + 退出）。返回新建的 HMENU；调用方
/// （`tray_wnd_proc`）在用毕后立即销毁。①②④ 的数据都来自本函数被调时的
/// 文件快照，非缓存。`mcp_line` 为 [mcp_line_text] 的当前值（MCP 状态行）。
pub(crate) fn build_menu(
    status_line: &str,
    direct: &[&DirectPeerView],
    relay: &[&DirectPeerView],
    mcp_line: &str,
) -> HMENU {
    unsafe {
        let hmenu = CreatePopupMenu();
        // ① 首行：设备名 + 虚拟 IP + 状态（tooltip 原文，禁用展示项）。
        append_item(hmenu, MF_STRING | MF_GRAYED, CMD_STATUS, status_line);
        AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());

        // ②「直连节点」：IP/模式/RTT（数据页面，禁用展示项）。
        let sub = CreatePopupMenu();
        if direct.is_empty() {
            append_item(sub, MF_STRING | MF_GRAYED, 0, "（无）");
        } else {
            for p in direct {
                append_item(sub, MF_STRING | MF_GRAYED, 0, &p.menu_label());
            }
        }
        append_popup(hmenu, "直连节点", sub);
        AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());

        // ④「连接节点…」：中继候选可点击 → spawn `meshlet-cli peer dial <node>`。
        let sub = CreatePopupMenu();
        if relay.is_empty() {
            append_item(sub, MF_STRING | MF_GRAYED, 0, "（无）");
        } else {
            for (i, p) in relay.iter().enumerate() {
                append_item(sub, MF_STRING, CMD_DIAL_BASE + i, &p.dial_menu_label());
            }
        }
        append_popup(hmenu, "连接节点…", sub);
        AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());

        // MCP 状态行（定案 2026-11-08）：tray 显示 MCP 是否开启 + 端口。
        // 禁用展示项（v1 只读；开启/切换经 agent.toml 显式配置）。
        append_item(hmenu, MF_STRING | MF_GRAYED, 0, mcp_line);
        AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());

        // 入口分流（定案 2026-11-06）：本地面板 = 本机自托管只读页（默认入口，
        // 数据在本机，不依赖 server）；控制台(网页) = 原 dashboard 行为。
        append_item(hmenu, MF_STRING, CMD_OPEN_LOCAL_PANEL, "本地面板");
        append_item(hmenu, MF_STRING, CMD_OPEN_CONSOLE, "控制台(网页)");
        AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());
        append_item(hmenu, MF_STRING, CMD_QUIT, "退出");
        hmenu
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 建一个 `<base>/state` 结构（与 `install.ps1` 的
    /// `%LOCALAPPDATA%\meshlet\{agent.toml,state}` 同形），返回 state 目录。
    fn temp_state_dir(tag: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!(
            "meshlet-tray-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = base.join("state");
        std::fs::create_dir_all(&state).unwrap();
        state
    }

    #[test]
    fn status_line_reads_tooltip_from_status_json() {
        let state = temp_state_dir("status-line");
        std::fs::create_dir_all(state.join("tray")).unwrap();
        // 无文件 → 兜底 "Meshlet"。
        assert_eq!(status_line_text(Some(&state)), "Meshlet");
        assert_eq!(status_line_text(None), "Meshlet");
        std::fs::write(
            state.join("tray").join("status.json"),
            r#"{"state":"Meshlet online","tooltip":"Meshlet「office」 10.240.0.5：在线：…"}"#,
        )
        .unwrap();
        assert_eq!(
            status_line_text(Some(&state)),
            "Meshlet「office」 10.240.0.5：在线：…"
        );
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn mode_label_maps_known_modes_and_keeps_unknowns() {
        assert_eq!(meshlet_tray_host::panel::mode_label("p2p_direct"), "直连");
        assert_eq!(
            meshlet_tray_host::panel::mode_label("direct_pending"),
            "拨号中"
        );
        assert_eq!(meshlet_tray_host::panel::mode_label("hub_relay"), "中继");
        // 未知模式原样展示（不吞数据）。
        assert_eq!(
            meshlet_tray_host::panel::mode_label("something_new"),
            "something_new"
        );
    }

    #[test]
    fn split_peer_views_partitions_direct_and_relay() {
        let peers = vec![
            DirectPeerView::sample("a", "10.240.0.2", "p2p_direct", Some(12)),
            DirectPeerView::sample("b", "10.240.0.3", "direct_pending", None),
            DirectPeerView::sample("", "10.240.0.4", "hub_relay", None),
        ];
        let (direct, relay) = split_peer_views(&peers);
        assert_eq!(direct.len(), 2);
        assert_eq!(relay.len(), 1);
        // ②「直连节点」行 = 名字/IP/模式/RTT；RTT 未测 → "--"；无名 → IP 代名。
        assert_eq!(direct[0].menu_label(), "a · 10.240.0.2 · 直连 · 12 ms");
        assert_eq!(direct[1].menu_label(), "b · 10.240.0.3 · 拨号中 · --");
        // ④「连接节点…」行 = IP + 名称；无名候选以 IP 代名。
        assert_eq!(relay[0].dial_menu_label(), "10.240.0.4  10.240.0.4");
    }

    #[test]
    fn mcp_line_reads_endpoint_or_defaults_closed() {
        let state = temp_state_dir("mcp-line");
        // 无交接文件 → 关闭。
        assert_eq!(mcp_line_text(Some(&state)), "MCP：关闭");
        assert_eq!(mcp_line_text(None), "MCP：关闭");
        // 交接文件有端口 → 开启 + 端口。
        std::fs::write(
            state.join("mcp.json"),
            r#"{"url":"http://127.0.0.1:8765/mcp","port":8765,"pid":1234}"#,
        )
        .unwrap();
        assert_eq!(mcp_line_text(Some(&state)), "MCP：开启 8765");
        // 交接文件缺端口（损坏/旧形态）→ 开启不加端口，不猜值。
        std::fs::write(
            state.join("mcp.json"),
            r#"{"url":"http://127.0.0.1:0/mcp"}"#,
        )
        .unwrap();
        assert_eq!(mcp_line_text(Some(&state)), "MCP：开启");
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn direct_peer_views_load_from_state_dir_or_default_empty() {
        let state = temp_state_dir("direct-peers");
        // 缺失 → 空表（子菜单显示「（无）」）。
        assert!(load_local_direct_peers(Some(&state)).is_empty());
        assert!(load_local_direct_peers(None).is_empty());
        // 损坏 → 空表，不 panic。
        std::fs::write(state.join("direct-peers.json"), "not json").unwrap();
        assert!(load_local_direct_peers(Some(&state)).is_empty());
        // 正常读取：字段与 meshlet-network::dial::DirectPeerView 一致。
        std::fs::write(
            state.join("direct-peers.json"),
            r#"[{"name":"peer-b","virtual_ipv4":"10.240.0.3","public_key":"abc==","mode":"hub_relay","rtt_ms":null,"endpoint":"","last_handshake_at":null}]"#,
        )
        .unwrap();
        let peers = load_local_direct_peers(Some(&state));
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name, "peer-b");
        assert_eq!(peers[0].mode, "hub_relay");
        // 旧服务端缺省字段（name/mode/rtt 缺席）也能读（serde default）。
        std::fs::write(
            state.join("direct-peers.json"),
            r#"[{"virtual_ipv4":"10.240.0.3","public_key":"abc=="}]"#,
        )
        .unwrap();
        let peers = load_local_direct_peers(Some(&state));
        assert_eq!(peers[0].mode, "");
        assert_eq!(peers[0].rtt_ms, None);
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    // ── ①②④ 菜单结构（AGENT-WIN-3/4 Windows 真机验证：CI windows-latest
    //    的 workspace test 腿实跑本文件——真实 Win32 菜单创建 + 内容读回）──

    #[cfg(all(test, target_os = "windows"))]
    mod windows_menu_tests {
        use super::*;

        /// 按位置读菜单项文本（`GetMenuStringW` 两段式：先量长度再取）。
        fn menu_string(hmenu: HMENU, pos: u32) -> String {
            let len = unsafe { GetMenuStringW(hmenu, pos, std::ptr::null_mut(), 0, MF_BYPOSITION) };
            if len <= 0 {
                return String::new();
            }
            let mut buf = vec![0u16; len as usize + 1];
            unsafe {
                GetMenuStringW(
                    hmenu,
                    pos,
                    buf.as_mut_ptr(),
                    buf.len() as i32,
                    MF_BYPOSITION,
                );
            }
            String::from_utf16_lossy(&buf[..len as usize])
        }

        #[test]
        fn build_menu_contains_status_direct_dial_mcp_local_panel_console_and_quit() {
            let peers = vec![
                DirectPeerView::sample("nas", "10.240.0.2", "p2p_direct", Some(12)),
                DirectPeerView::sample("", "10.240.0.4", "hub_relay", None),
            ];
            let (direct, relay) = split_peer_views(&peers);
            let hmenu = build_menu(
                "Meshlet「dev」 10.240.0.5：在线",
                &direct,
                &relay,
                "MCP：开启 8765",
            );
            unsafe {
                // 结构：首行 / sep / 直连节点 / sep / 连接节点… / sep /
                // MCP 状态行 / sep / 本地面板 / 控制台(网页) / sep / 退出。
                assert_eq!(GetMenuItemCount(hmenu), 12, "menu layout must be intact");

                // ① 首行 = 设备名 + 虚拟 IP + 状态（禁用展示项）。
                assert_eq!(menu_string(hmenu, 0), "Meshlet「dev」 10.240.0.5：在线");
                assert_ne!(GetMenuState(hmenu, 0, MF_BYPOSITION) & MF_GRAYED, 0);

                // ② 直连节点子菜单：IP/模式/RTT 数据行，禁用态。
                let direct_sub = GetSubMenu(hmenu, 2);
                assert!(!direct_sub.is_null(), "直连节点 must be a submenu");
                assert_eq!(GetMenuItemCount(direct_sub), 1);
                assert_eq!(
                    menu_string(direct_sub, 0),
                    "nas · 10.240.0.2 · 直连 · 12 ms"
                );
                assert_ne!(GetMenuState(direct_sub, 0, MF_BYPOSITION) & MF_GRAYED, 0);

                // ④ 连接节点… 子菜单：中继候选可点击（非禁用）。
                let dial_sub = GetSubMenu(hmenu, 4);
                assert!(!dial_sub.is_null(), "连接节点… must be a submenu");
                assert_eq!(GetMenuItemCount(dial_sub), 1);
                assert_eq!(menu_string(dial_sub, 0), "10.240.0.4  10.240.0.4");
                assert_eq!(
                    GetMenuState(dial_sub, 0, MF_BYPOSITION) & MF_GRAYED,
                    0,
                    "dial candidates must be clickable"
                );

                // MCP 状态行（定案 2026-11-08）：禁用展示项，显示开启+端口。
                assert_eq!(menu_string(hmenu, 6), "MCP：开启 8765");
                assert_ne!(GetMenuState(hmenu, 6, MF_BYPOSITION) & MF_GRAYED, 0);

                // 入口分流（定案 2026-11-06）：本地面板是默认入口，控制台另列。
                assert_eq!(menu_string(hmenu, 8), "本地面板");
                assert_eq!(menu_string(hmenu, 9), "控制台(网页)");
                assert_eq!(menu_string(hmenu, 11), "退出");

                DestroyMenu(hmenu);
            }
        }

        #[test]
        fn build_menu_shows_empty_placeholders_without_peers() {
            let hmenu = build_menu("Meshlet", &[], &[], "MCP：关闭");
            unsafe {
                let direct_sub = GetSubMenu(hmenu, 2);
                let dial_sub = GetSubMenu(hmenu, 4);
                assert_eq!(GetMenuItemCount(direct_sub), 1);
                assert_eq!(menu_string(direct_sub, 0), "（无）");
                assert_eq!(GetMenuItemCount(dial_sub), 1);
                assert_eq!(menu_string(dial_sub, 0), "（无）");
                assert_eq!(menu_string(hmenu, 6), "MCP：关闭");
                DestroyMenu(hmenu);
            }
        }
    }
}
