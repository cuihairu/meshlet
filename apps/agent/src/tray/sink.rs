//! Writing tray artifacts to disk: [`TraySink`] writes the status icons and `status.json` into
//! `{state_dir}/tray/`, and skips rewriting when the content is identical (idempotent publishing, "discipline two");
//! it is a no-op when headless (no directory, no files, no panic, "discipline four").
//! [`TrayStatus`] is the published record: state + text equivalents (tooltip / accessible_name,
//! "discipline three": color alone is never sufficient).

use std::path::{Path, PathBuf};

use super::env::EnvProbe;
use super::icon::IconSize;
use super::png::png_encode;
use super::state::TrayState;

/// State + text equivalents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayStatus {
    pub state: TrayState,
    /// Tooltip (shown on panel hover; carries the device name and a full sentence of explanation).
    pub tooltip: String,
    /// Accessibility short name.
    pub accessible_name: &'static str,
}

impl TrayStatus {
    /// Tooltip carrying the device name, **this machine's virtual IP**, and the network interface (the tooltip
    /// is the text equivalent, and color alone is never sufficient). `virtual_ip` comes from the plan's tunnel address
    /// (`plan.tunnel.address`, the same path as the `info` command) - the user requires tray tooltip / first menu
    /// line = device name + virtual IPv4 + state. `None` while pending approval (no plan).
    pub fn new(
        state: TrayState,
        device_name: Option<&str>,
        virtual_ip: Option<std::net::Ipv4Addr>,
        interface: &str,
    ) -> Self {
        let mut who = device_name
            .map(|n| format!("「{n}」"))
            .unwrap_or_else(|| format!("接口 {interface}"));
        if let Some(ip) = virtual_ip {
            who.push(' ');
            who.push_str(&ip.to_string());
        }
        Self {
            tooltip: format!("Meshlet{who}：{}", state.tooltip()),
            state,
            accessible_name: state.accessible_name(),
        }
    }
}

/// The outcome of one write to disk (distinguishing "skipped", "written", and "content unchanged").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayWrite {
    /// Headless: no files written at all.
    Skipped,
    /// Content unchanged: not rewritten (idempotent).
    Unchanged,
    /// State changed, new icons written.
    Written,
}

/// Writing tray artifacts: `{state_dir}/tray/{icon-16.png,icon-24.png,status.json}`.
///
/// A no-op when headless (no directory, no files, no panic).
pub struct TraySink {
    dir: PathBuf,
}

impl TraySink {
    pub fn new(state_dir: impl AsRef<Path>) -> Self {
        Self {
            dir: state_dir.as_ref().join("tray"),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Convenience entry point: probes the real environment.
    pub fn publish(&self, status: &TrayStatus) -> Result<TrayWrite, String> {
        self.publish_with(status, &EnvProbe::from_env())
    }

    /// Injected environment probe (for tests and CI).
    pub fn publish_with(&self, status: &TrayStatus, env: &EnvProbe) -> Result<TrayWrite, String> {
        if !env.has_desktop_session() {
            return Ok(TrayWrite::Skipped);
        }
        // The idempotency comparison looks only at semantic fields (state + tooltip + version + env):
        // `updated_at` changes every time, so it is excluded from the comparison, otherwise every tick would rewrite.
        if status_unchanged(&self.dir, status, env) {
            return Ok(TrayWrite::Unchanged);
        }
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("create tray dir: {e}"))?;
        for size in [IconSize::Px16, IconSize::Px24] {
            let (_, _, rgba) = status.state.icon_rgba(size);
            let png = png_encode(size.px(), size.px(), &rgba);
            let name = format!("icon-{}.png", size.px());
            write_file(&self.dir.join(&name), &png).map_err(|e| format!("write {name}: {e}"))?;
        }
        let body = serde_json::json!({
            "state": status.state.accessible_name(),
            "tooltip": status.tooltip,
            "icon_16": "icon-16.png",
            "icon_24": "icon-24.png",
            "updated_at": chrono::Utc::now().to_rfc3339(),
            // Display fields for the local panel (tray-host `panel` module): version + desktop session probe.
            // Both are readings this process already has, so no new collection is added; `status_unchanged` compares
            // them together - a legacy file is backfilled at the first publish after an upgrade, and then is not rewritten every tick.
            "version": env!("CARGO_PKG_VERSION"),
            "env": env_json(env),
        });
        write_file(&self.dir.join("status.json"), body.to_string().as_bytes())
            .map_err(|e| format!("write status.json: {e}"))?;
        Ok(TrayWrite::Written)
    }
}

fn read_file(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// EnvProbe -> the `env` object of `status.json` (published and idempotency comparison share the same
/// construction, guaranteeing the two sides are field-for-field comparable).
fn env_json(env: &EnvProbe) -> serde_json::Value {
    serde_json::json!({
        "display": env.display.clone(),
        "wayland_display": env.wayland_display.clone(),
        "session_type": env.session_type.clone(),
        "session_name": env.session_name.clone(),
        "console_session": env.console_session,
    })
}

/// Whether the previous `status.json`'s semantic fields (state + tooltip + version + EnvProbe)
/// match this one.
///
/// `version` / `env` take part in the comparison: a legacy file written before the upgrade is backfilled at the
/// **first publish after upgrading** (otherwise, with state/tooltip unchanged, the rewrite would never come around and
/// the local panel would lack both fields for a long time); after backfilling, as long as all four stay unchanged it
/// still skips idempotently and does not rewrite every tick.
fn status_unchanged(dir: &Path, status: &TrayStatus, env: &EnvProbe) -> bool {
    read_file(&dir.join("status.json"))
        .and_then(|prev| serde_json::from_str::<serde_json::Value>(&prev).ok())
        .map(|v| {
            v.get("state").and_then(|s| s.as_str()) == Some(status.state.accessible_name())
                && v.get("tooltip").and_then(|t| t.as_str()) == Some(status.tooltip.as_str())
                && v.get("version").and_then(|s| s.as_str()) == Some(env!("CARGO_PKG_VERSION"))
                && v.get("env") == Some(&env_json(env))
        })
        .unwrap_or(false)
}

fn write_file(path: &Path, body: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, body)
}

#[cfg(test)]
mod tests {
    use super::super::state::all_states;
    use super::*;

    // -- Disciplines two/three: text equivalents, never color alone ----------------------------

    #[test]
    fn every_state_has_a_nonempty_text_equivalent() {
        for state in all_states() {
            assert!(!state.accessible_name().is_empty());
            assert!(!state.tooltip().is_empty());
            let status = TrayStatus::new(
                state,
                Some("office-laptop"),
                Some("10.240.0.5".parse().unwrap()),
                "meshlet0",
            );
            assert!(status.tooltip.contains("office-laptop"));
            assert!(status.tooltip.contains("10.240.0.5"));
            assert_eq!(status.accessible_name, state.accessible_name());
        }
    }

    /// (1) User requirement: tray tooltip / first menu line = device name + virtual IPv4 + state.
    /// The virtual IP is injected from the plan's tunnel address (`plan.tunnel.address`, the same path as `info`).
    #[test]
    fn tooltip_carries_device_name_and_virtual_ip() {
        let status = TrayStatus::new(
            TrayState::Online,
            Some("office-laptop"),
            Some("10.240.0.5".parse().unwrap()),
            "meshlet0",
        );
        assert!(status
            .tooltip
            .starts_with("Meshlet「office-laptop」 10.240.0.5："));
        assert!(status.tooltip.contains("在线"));
        // No device name: fall back to the interface name; no IP (pending approval): no empty placeholder.
        let no_name = TrayStatus::new(TrayState::Offline, None, None, "mesh0");
        assert!(no_name.tooltip.starts_with("Meshlet接口 mesh0："));
        assert!(!no_name.tooltip.contains("： "));
        // No device name but an IP present.
        let ip_only = TrayStatus::new(
            TrayState::TunnelOnly,
            None,
            Some("10.240.0.5".parse().unwrap()),
            "mesh0",
        );
        assert!(ip_only
            .tooltip
            .starts_with("Meshlet接口 mesh0 10.240.0.5："));
    }

    // -- Headless no-op (discipline four) --------------------------------------------------

    #[test]
    fn headless_publish_is_a_noop_without_touching_the_filesystem() {
        let dir = std::env::temp_dir().join("meshlet-tray-headless");
        let _ = std::fs::remove_dir_all(&dir);
        let sink = TraySink::new(&dir);
        let env = EnvProbe::default(); // everything empty = tty / CI
        assert!(!env.has_desktop_session());

        let write = sink
            .publish_with(
                &TrayStatus::new(TrayState::Online, None, None, "meshlet0"),
                &env,
            )
            .expect("headless publish must not error");
        assert_eq!(write, TrayWrite::Skipped);
        assert!(
            !dir.exists(),
            "headless publish must not create the tray dir"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn writes_icons_and_status_on_a_desktop_session_then_stays_idempotent() {
        let dir = std::env::temp_dir().join("meshlet-tray-desktop");
        let _ = std::fs::remove_dir_all(&dir);
        let sink = TraySink::new(&dir);
        let env = EnvProbe {
            display: Some(":0".into()),
            ..EnvProbe::default()
        };
        assert!(env.has_desktop_session());

        let first = TrayStatus::new(TrayState::Online, Some("laptop"), None, "meshlet0");
        assert_eq!(
            sink.publish_with(&first, &env).expect("desktop publish"),
            TrayWrite::Written
        );
        // Publishing the same content again = no rewrite (idempotent).
        assert_eq!(
            sink.publish_with(&first, &env).unwrap(),
            TrayWrite::Unchanged
        );

        // A state change = a new set of icons.
        let second = TrayStatus::new(TrayState::Offline, Some("laptop"), None, "meshlet0");
        assert_eq!(
            sink.publish_with(&second, &env).expect("state change"),
            TrayWrite::Written
        );
        let status = std::fs::read_to_string(sink.dir().join("status.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&status).unwrap();
        assert_eq!(value["state"], "Meshlet offline");
        let updated = value["updated_at"]
            .as_str()
            .expect("updated_at must be written");
        assert!(
            chrono::DateTime::parse_from_rfc3339(updated).is_ok(),
            "updated_at must be RFC3339, got {updated}"
        );
        for name in ["icon-16.png", "icon-24.png"] {
            let bytes = std::fs::read(sink.dir().join(name)).unwrap();
            assert!(
                bytes.starts_with(&[0x89, b'P', b'N', b'G']),
                "{name} must be a PNG"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Upgrade regression: a `status.json` written by an older agent (without `version`/`env`) must be
    /// backfilled at the **first publish after upgrading** - otherwise, with state/tooltip unchanged, the rewrite
    /// would never come around and the local panel would lack both fields for a long time; after backfilling it still
    /// skips idempotently, and writes once more only when the EnvProbe changes.
    #[test]
    fn status_upgrade_backfills_version_and_env_without_rewriting_every_tick() {
        let dir = std::env::temp_dir().join("meshlet-tray-status-upgrade");
        let _ = std::fs::remove_dir_all(&dir);
        let sink = TraySink::new(&dir);
        let env = EnvProbe {
            display: Some(":0".into()),
            ..EnvProbe::default()
        };
        let status = TrayStatus::new(TrayState::Online, Some("laptop"), None, "meshlet0");
        std::fs::create_dir_all(sink.dir()).unwrap();
        // The older agent's file: state/tooltip are already current, but version/env are missing.
        let legacy = serde_json::json!({
            "state": status.state.accessible_name(),
            "tooltip": status.tooltip,
            "icon_16": "icon-16.png",
            "icon_24": "icon-24.png",
            "updated_at": "2026-11-03T00:00:00Z",
        });
        std::fs::write(sink.dir().join("status.json"), legacy.to_string()).unwrap();

        assert_eq!(
            sink.publish_with(&status, &env).expect("upgrade publish"),
            TrayWrite::Written
        );
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(sink.dir().join("status.json")).unwrap())
                .unwrap();
        assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(value["env"]["display"], ":0");
        // After backfilling, the same content -> still idempotent (no rewrite every tick).
        assert_eq!(
            sink.publish_with(&status, &env).unwrap(),
            TrayWrite::Unchanged
        );
        // EnvProbe changes -> one more write (the comparison really does cover env).
        let moved = EnvProbe {
            display: Some(":1".into()),
            ..EnvProbe::default()
        };
        assert_eq!(
            sink.publish_with(&status, &moved).unwrap(),
            TrayWrite::Written
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
