//! Agent state tiering, deep-link navigation, and WireGuard peer reading.

use crate::config_io::meshlet_state_dir;

// ── State tiering (pure functions, testable) ────────────────────────────────────────────
/// Four-tier state classification: buckets every `state` string the agent writes to status.json.
/// Real producer values are `accessible_name()` full sentences (see the `state_tier` comment);
/// maps onto the four [`TrayState`] states in `apps/agent/src/tray.rs`: tunnel only/drift →
/// Degraded (tunnel up, control channel down); error/failed → Error; offline/unknown → Offline.
/// `degraded` isn't produced by the backend yet — mapped here ahead of time (takes effect once the agent adds it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tier {
    Online,
    Degraded,
    Error,
    Offline,
}

pub(crate) fn state_tier(state: &str) -> Tier {
    // The real producer is the agent's `accessible_name()` (apps/agent/src/tray.rs:106)
    // full sentence: "Meshlet online" / "Meshlet tunnel only" / "Meshlet tunnel drift" /
    // "Meshlet offline". Hence match **lowercased substrings** (case-insensitive) instead of
    // exact snake_case equality — the latter always misses real input and lands on Offline for all four tiers.
    // Fixed check order: Degraded first (tunnel only/drift/degraded), then Error (error/
    // failed), then Online ("offline" lacks the "online" substring, so they are naturally
    // exclusive); everything else is Offline. snake_case (online/tunnel_only/degraded/error…)
    // stays supported in case the agent adds those fields later.
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
    // Short words like "up"/"ok" use equality only: substring matching would swallow values such as "setup"/"lookup".
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

/// State → tray icon file name. The 16px variants were hand-tuned pixel by pixel (inner hole not
/// clogged by antialiasing residue, see `icons/gen_icons.py`) and render 1:1 at the Windows tray's
/// native 16px @100% DPI; the 32px files are the fallback (high DPI or missing 16px files).
pub(crate) fn icon_for_state(state: &str) -> (&'static str, &'static str) {
    match state_tier(state) {
        Tier::Online => ("icon-online-16.png", "icon-online.png"),
        Tier::Degraded => ("icon-degraded-16.png", "icon-degraded.png"),
        Tier::Error => ("icon-error-16.png", "icon-error.png"),
        Tier::Offline => ("icon-offline-16.png", "icon-offline.png"),
    }
}

// ── Settings window navigation (deep links, pure testable functions) ───────────────────────────────
/// Whitelist of navigation targets accepted by `__gotoZone`: 4 tabs + the diagnostics anchor + the connection tab's Peers.
const GOTO_ZONES: &[&str] = &[
    "conn", "diag", "cmd", "gen", "routes", "ifaces", "wg", "peers",
];

/// Navigation JS (testable): whitelist-validated; `zone` comes from menu/popup callers and is
/// never concatenated from unvalidated strings (guards against JS injection).
pub(crate) fn goto_zone_js(zone: &str) -> Option<String> {
    if !GOTO_ZONES.contains(&zone) {
        return None;
    }
    let quoted = serde_json::to_string(zone).unwrap_or_else(|_| "\"\"".into());
    Some(format!("window.__gotoZone && window.__gotoZone({quoted})"))
}

/// While a freshly built settings window is still loading, the eval'd navigation JS may land
/// before `__gotoZone` is defined: park the zone here and have the settings script fetch it via
/// `take_pending_goto` at init — the dual channel (eval + startup pickup) lets both old and new windows navigate.
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
    // Matches the tray-host (apps/tray-host/src/main.rs:40-42) and installer
    // (scripts/install.ps1 state dir) conventions: status is written to
    // `%LOCALAPPDATA%/meshlet/state/tray/status.json`. Never hardcode the user
    // dir in the frontend — a baked-in username would break when the user changes.
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
    let mut command = std::process::Command::new(wg_path);
    command.args(["show", "all", "dump"]);
    // CREATE_NO_WINDOW: the tray is a GUI-subsystem process, and spawning the
    // console tool wg.exe directly would flash a terminal window on every poll (2026-11-20 imac report).
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let output = command.output();

    let mut peers = Vec::new();
    let output = match output {
        Ok(output) => output,
        Err(_) => return peers,
    };
    let text = String::from_utf8_lossy(&output.stdout);

    for line in text.lines() {
        let columns: Vec<&str> = line.split('\t').collect();
        // peer row: <iface> <pubkey> <preshared> <endpoint> <allowed> <handshake> <rx> <tx> <keepalive>
        // The real tunnel name is wg-meshlet per install.ps1/README (backend default meshlet);
        // hardcoding "WireGuard" would read the real tunnel as permanently empty — match the actual name.
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
            // R-UI-1: hand the raw epoch to the frontend fmtEpoch for uniform rendering. This used to hardcode
            // "{} seconds ago", so a handshake older than a day showed "61028 seconds ago" — telling neither the day nor
            // allowing a time sort. Seconds/minutes and other relative formats all belong to the frontend.
            let last_seen = handshake;

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
