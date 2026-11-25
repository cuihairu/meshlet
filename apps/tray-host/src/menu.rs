use windows_sys::Win32::UI::WindowsAndMessaging::*;

use meshlet_tray_host::panel::mode_label;

/// Right-click menu command IDs (the return value of `TrackPopupMenuEx` under `TPM_RETURNCMD`).
pub(crate) const CMD_QUIT: usize = 1;
/// "Console (web)": opens in a browser the console hosted at the server root path (the former
/// "open panel" behaviour). The local panel gets its own item, see [`CMD_OPEN_LOCAL_PANEL`] —
/// decided 2026-11-06: the tray's "open panel" must open the local panel; the console is a separate entry.
pub(crate) const CMD_OPEN_CONSOLE: usize = 2;
/// First menu row "device name + virtual IP + status" display item (disabled; rebuilt from the
/// `status.json` tooltip — ① the user required row one = device name + virtual IPv4 + status).
pub(crate) const CMD_STATUS: usize = 3;
/// "Local panel": opens the tray-host's own self-hosted loopback read-only page (current node /
/// direct nodes / local routes, see `meshlet_tray_host::panel`).
pub(crate) const CMD_OPEN_LOCAL_PANEL: usize = 4;
/// Command base for the "connect to node…" submenu items: candidate i = `CMD_DIAL_BASE + i`.
pub(crate) const CMD_DIAL_BASE: usize = 100;

/// One entry of `direct-peers.json` (published periodically by the agent's direct probe; fields
/// match `meshlet-network::dial::DirectPeerView` — here it is only deserialized, no
/// meshlet-network dependency, keeping the tray host at a zero data-plane dependency of
/// windows-sys + serde).
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
    /// Menu display name: when the device name is missing (older server) fall back to the virtual
    /// IP — `peer dial` also resolves by IP, so both displays are clickable.
    pub(crate) fn display_name(&self) -> String {
        if self.name.trim().is_empty() {
            self.virtual_ipv4.to_string()
        } else {
            self.name.clone()
        }
    }

    /// ② A "direct nodes" submenu row: name/IP/mode/RTT (data display, disabled).
    /// The name comes first (user directive 2026-11-07: a direct-node row must carry the node
    /// name/nickname — a bare IP row cannot tell which machine it is); when the name is missing
    /// (older server) fall back to the IP, never an empty segment.
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

    /// ④ A "connect to node…" submenu row: a dialable candidate (clicking triggers `peer dial`).
    fn dial_menu_label(&self) -> String {
        format!("{}  {}", self.virtual_ipv4, self.display_name())
    }
}

/// Fixture construction for tests (test-only; real data comes from the agent's direct-peers.json).
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

/// Splits the agent-published direct views in two (② "direct nodes" / ④ "connect to node…"):
/// already-direct / dialing -> direct; candidates still on the relay (`hub_relay`) -> relay (dialable targets).
pub(crate) fn split_peer_views(
    peers: &[DirectPeerView],
) -> (Vec<&DirectPeerView>, Vec<&DirectPeerView>) {
    peers
        .iter()
        .partition(|p| matches!(p.mode.as_str(), "p2p_direct" | "direct_pending"))
}

/// Reads the agent-published `{state_dir}/direct-peers.json` (the ②④ data source; the same chain
/// as the `peers` command). Missing / corrupted -> an empty list (the submenu
/// shows the empty placeholder).
pub(crate) fn load_local_direct_peers(state_dir: Option<&std::path::Path>) -> Vec<DirectPeerView> {
    state_dir
        .and_then(|dir| std::fs::read_to_string(dir.join("direct-peers.json")).ok())
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// ① Menu first row / tooltip body: the `tooltip` field of `status.json` — the agent side already
/// produces "Meshlet「device」 <virtual IP>: status" (the same data chain as `info`).
pub(crate) fn status_line_text(state_dir: Option<&std::path::Path>) -> String {
    state_dir
        .and_then(|dir| std::fs::read_to_string(dir.join("tray").join("status.json")).ok())
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|v| v.get("tooltip").and_then(|t| t.as_str()).map(String::from))
        .unwrap_or_else(|| "Meshlet".into())
}

/// MCP status line (decided 2026-11-08): reads `{state_dir}/mcp.json` (written by the agent).
/// No handoff file -> disabled; present -> enabled plus [port]; port missing
/// (corrupt / older shape) -> enabled without a port, never guessing a value.
/// The tray only displays read-only —
/// enabling / switching goes through the explicit `agent.toml` `[mcp] enabled` setting.
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

/// UTF-16 + NUL (Win32 menu / balloon text).
pub(crate) fn wide_z(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn append_item(menu: HMENU, flags: u32, id: usize, text: &str) {
    let wide = wide_z(text);
    AppendMenuW(menu, flags, id, wide.as_ptr());
}

/// Appends a popup submenu (`MF_POPUP`, the `id` slot carrying the submenu handle).
unsafe fn append_popup(menu: HMENU, text: &str, sub: HMENU) {
    let wide = wide_z(text);
    AppendMenuW(menu, MF_POPUP, sub as usize, wide.as_ptr());
}

/// Rebuilds the whole right-click menu from the current snapshot (first status row +
/// direct nodes / connect to node… submenus + MCP status row + local panel + console (web) + quit).
/// Returns the newly created HMENU; the caller (`tray_wnd_proc`) destroys it immediately after use.
/// The ①②④ data all come from the file snapshot taken when this function is called, not from a cache.
/// `mcp_line` is the current value of [mcp_line_text] (the MCP status row).
pub(crate) fn build_menu(
    status_line: &str,
    direct: &[&DirectPeerView],
    relay: &[&DirectPeerView],
    mcp_line: &str,
) -> HMENU {
    unsafe {
        let hmenu = CreatePopupMenu();
        // ① First row: device name + virtual IP + status (the tooltip verbatim, disabled display item).
        append_item(hmenu, MF_STRING | MF_GRAYED, CMD_STATUS, status_line);
        AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());

        // ② "Direct nodes": IP/mode/RTT (data page, disabled display items).
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

        // ④ "Connect to node…": relay candidates are clickable -> spawn `meshlet-cli peer dial <node>`.
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

        // MCP status row (decided 2026-11-08): the tray shows whether MCP is enabled + the port.
        // Disabled display item (v1 is read-only; enabling / switching goes through the explicit agent.toml setting).
        append_item(hmenu, MF_STRING | MF_GRAYED, 0, mcp_line);
        AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());

        // Entry split (decided 2026-11-06): local panel = self-hosted read-only page on this machine
        // (the default entry; the data lives locally and does not need the server); console (web) = the former dashboard behaviour.
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

    /// Builds a `<base>/state` structure (isomorphic to `install.ps1`'s
    /// `%LOCALAPPDATA%\meshlet\{agent.toml,state}`) and returns the state directory.
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
        // No file -> fall back to "Meshlet".
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
        // Unknown modes are shown as-is (no data swallowed).
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
        // ② A "direct node" row = name/IP/mode/RTT; unmeasured RTT -> "--"; no name -> the IP stands in.
        assert_eq!(direct[0].menu_label(), "a · 10.240.0.2 · 直连 · 12 ms");
        assert_eq!(direct[1].menu_label(), "b · 10.240.0.3 · 拨号中 · --");
        // ④ A "connect to node…" row = IP + name; an unnamed candidate uses the IP as its name.
        assert_eq!(relay[0].dial_menu_label(), "10.240.0.4  10.240.0.4");
    }

    #[test]
    fn mcp_line_reads_endpoint_or_defaults_closed() {
        let state = temp_state_dir("mcp-line");
        // No handoff file -> closed.
        assert_eq!(mcp_line_text(Some(&state)), "MCP：关闭");
        assert_eq!(mcp_line_text(None), "MCP：关闭");
        // Handoff file with a port -> enabled + the port.
        std::fs::write(
            state.join("mcp.json"),
            r#"{"url":"http://127.0.0.1:8765/mcp","port":8765,"pid":1234}"#,
        )
        .unwrap();
        assert_eq!(mcp_line_text(Some(&state)), "MCP：开启 8765");
        // Handoff file missing the port (corrupt / older shape) -> enabled without a port, never guessing a value.
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
        // Missing -> an empty list (the submenu shows the empty placeholder).
        assert!(load_local_direct_peers(Some(&state)).is_empty());
        assert!(load_local_direct_peers(None).is_empty());
        // Corrupt -> an empty list, without panicking.
        std::fs::write(state.join("direct-peers.json"), "not json").unwrap();
        assert!(load_local_direct_peers(Some(&state)).is_empty());
        // Normal read: fields consistent with meshlet-network::dial::DirectPeerView.
        std::fs::write(
            state.join("direct-peers.json"),
            r#"[{"name":"peer-b","virtual_ipv4":"10.240.0.3","public_key":"abc==","mode":"hub_relay","rtt_ms":null,"endpoint":"","last_handshake_at":null}]"#,
        )
        .unwrap();
        let peers = load_local_direct_peers(Some(&state));
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name, "peer-b");
        assert_eq!(peers[0].mode, "hub_relay");
        // Older servers omitting fields (name/mode/rtt absent) still parse (serde defaults).
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

    // ── ①②④ menu structure (AGENT-WIN-3/4 verified on real Windows machines: the CI
    //    windows-latest workspace-test leg actually runs this file — real Win32 menu creation + content read-back) ──

    #[cfg(all(test, target_os = "windows"))]
    mod windows_menu_tests {
        use super::*;

        /// Reads a menu item's text by position (`GetMenuStringW` in two passes: measure the length first, then fetch).
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
                // Structure: first row / sep / direct nodes / sep / connect to node… / sep /
                // MCP status row / sep / local panel / console (web) / sep / quit.
                assert_eq!(GetMenuItemCount(hmenu), 12, "menu layout must be intact");

                // ① First row = device name + virtual IP + status (disabled display item).
                assert_eq!(menu_string(hmenu, 0), "Meshlet「dev」 10.240.0.5：在线");
                assert_ne!(GetMenuState(hmenu, 0, MF_BYPOSITION) & MF_GRAYED, 0);

                // ② Direct nodes submenu: IP/mode/RTT data rows, disabled.
                let direct_sub = GetSubMenu(hmenu, 2);
                assert!(!direct_sub.is_null(), "直连节点 must be a submenu");
                assert_eq!(GetMenuItemCount(direct_sub), 1);
                assert_eq!(
                    menu_string(direct_sub, 0),
                    "nas · 10.240.0.2 · 直连 · 12 ms"
                );
                assert_ne!(GetMenuState(direct_sub, 0, MF_BYPOSITION) & MF_GRAYED, 0);

                // ④ Connect to node… submenu: relay candidates are clickable (not disabled).
                let dial_sub = GetSubMenu(hmenu, 4);
                assert!(!dial_sub.is_null(), "连接节点… must be a submenu");
                assert_eq!(GetMenuItemCount(dial_sub), 1);
                assert_eq!(menu_string(dial_sub, 0), "10.240.0.4  10.240.0.4");
                assert_eq!(
                    GetMenuState(dial_sub, 0, MF_BYPOSITION) & MF_GRAYED,
                    0,
                    "dial candidates must be clickable"
                );

                // MCP status row (decided 2026-11-08): a disabled display item showing enabled + port.
                assert_eq!(menu_string(hmenu, 6), "MCP：开启 8765");
                assert_ne!(GetMenuState(hmenu, 6, MF_BYPOSITION) & MF_GRAYED, 0);

                // Entry split (decided 2026-11-06): the local panel is the default entry, the console is listed separately.
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
