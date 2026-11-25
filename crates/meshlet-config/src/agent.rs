//! Agent-side config ([`AgentConfig`]): the raw TOML schema (`Raw*`, crate-private),
//! the public structs and defaults, [`AgentConfig::from_toml`] validation; tray / upgrade /
//! dataplane / direct_connect / probe / mcp / ssh_config_sync sub-configs.

use crate::ConfigError;
use serde::Deserialize;

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawDataplaneConfig {
    enabled: Option<bool>,
    interface: Option<String>,
    private_key_file: Option<String>,
    hub_endpoint: Option<String>,
    poll_interval_secs: Option<u64>,
    /// Windows dataplane backend selection (WG-NT-SWITCH wiring batch): `"service"` (default) |
    /// `"nt"`. Ignored on other platforms.
    tunnel_backend: Option<String>,
    direct_connect: Option<RawDirectConnectConfig>,
    probe: Option<RawProbeConfig>,
    backoff: Option<RawBackoffConfig>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawBackoffConfig {
    /// FLIP-002 demote backoff: initial cooldown (milliseconds, default 30_000 = 30s).
    backoff_base_ms: Option<u64>,
    /// Cooldown cap (milliseconds, default 900_000 = 15min).
    backoff_cap_ms: Option<u64>,
    /// Consecutive healthy-face evidence rounds that reset the backoff (default 3).
    recovery_confirmations: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawDirectConnectConfig {
    enabled: Option<bool>,
    listen_port: Option<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawProbeConfig {
    enabled: Option<bool>,
    interval_secs: Option<u64>,
    window: Option<usize>,
    /// SEL-002 hysteresis switching: the new path must win N consecutive samples and beat the current path by ≥ margin.
    /// `margin` is given in percent (30 = 30%). Defaults 3 / 30%.
    switch_required: Option<usize>,
    switch_margin_percent: Option<f64>,
    /// SEL-003 recovery gate: after direct degrades back to relay, N consecutive healthy rounds are required before switching back (default 3).
    recovery_required: Option<usize>,
    /// SEL-003 latency degradation threshold (milliseconds): window RTT median ≥ this value means degrade back to relay
    /// (default 800, rationale at ProbeConfig::degrade_rtt_ms).
    degrade_rtt_ms: Option<u64>,
    /// SEL-003 loss-spike threshold (percent, 20 = 20%): window loss rate ≥ this value means degrade
    /// (default 20, rationale at ProbeConfig::loss_spike).
    loss_spike_percent: Option<f64>,
    /// SEL-002 switch cooldown (seconds, scheme 1): default = interval×required×2 (clamped ≤60).
    switch_cooldown_secs: Option<u64>,
    /// SEL-003 young-window exemption floor (scheme 1, default 4).
    degrade_min_samples: Option<usize>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawAgentConfig {
    server_url: Option<String>,
    state_dir: Option<String>,
    device_token: Option<String>,
    /// Bootstrap code (the entry credential for ZeroTier-style bootstrap registration): when `device_token` is absent, use it against
    /// `POST /api/v1/device-registrations` to self-register; once approved it becomes a regular device.
    bootstrap_token: Option<String>,
    /// Device name reported during bootstrap registration (unique within a network, across devices/pending applications).
    device_name: Option<String>,
    tray: Option<RawTrayConfig>,
    upgrade: Option<RawUpgradeConfig>,
    dataplane: RawDataplaneConfig,
    ssh_config_sync: Option<RawSshConfigSyncConfig>,
    mcp: Option<RawMcpConfig>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawMcpConfig {
    enabled: Option<bool>,
    port: Option<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawSshConfigSyncConfig {
    enabled: Option<bool>,
    manage_include: Option<bool>,
    target_homes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawUpgradeConfig {
    enabled: Option<bool>,
    check_interval_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawTrayConfig {
    notifications: Option<bool>,
    status_notifier_item: Option<bool>,
}

/// Agent configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentConfig {
    pub server_url: String,
    pub state_dir: String,
    /// Device credential (the agent token returned by enrollment, handed out exactly once): used to
    /// pull the desired config; startup fails immediately when `[dataplane] enabled` and this is unset.
    pub device_token: Option<String>,
    /// Bootstrap code (ZeroTier-style): when `device_token` is missing, register the device with it, landing in
    /// Pending awaiting control-center approval. **The raw credential only ever goes in the 0600 config file**; the server stores just a digest (§11.3).
    pub bootstrap_token: Option<String>,
    /// Device name for bootstrap registration (must be set explicitly — the registered name must be human-readable, no default is taken).
    pub device_name: Option<String>,
    /// Desktop integration (P1/P2): the two capabilities are independently switched, both off by default.
    pub tray: TrayConfig,
    pub upgrade: UpgradeConfig,
    pub dataplane: DataplaneConfig,
    /// SSH alias sync (`[ssh_config_sync]`): writing into the user's `~/.ssh` is a sensitive surface,
    /// **off by default** — only when `enabled` is on does it write `~/.ssh/meshlet.conf` (a meshlet-only
    /// file, the user's config is never touched); only when `manage_include` is on does it append
    /// `Include meshlet.conf` to `~/.ssh/config` (backing up the original once beforehand); `target_homes`
    /// explicitly lists the target home directories (empty = only the running account's own home).
    pub ssh_config_sync: SshConfigSyncConfig,
    /// Local MCP service (`[mcp]`): AI clients query this machine's mesh facts over loopback HTTP.
    /// **Off by default** — the listener does not open unless `enabled = true` is set explicitly (2026-11-08).
    pub mcp: McpConfig,
}

/// Agent-side MCP service switches (off by default: the listener must be opened explicitly).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct McpConfig {
    /// Master switch: off = no port is listened on (default).
    pub enabled: bool,
    /// Listen port; `0` = random (the real port is written to the `{state_dir}/mcp.json` handoff file).
    pub port: u16,
}

impl McpConfig {
    /// The off state (for tests/default construction, semantically identical to [`Default::default`]).
    pub const OFF: Self = Self {
        enabled: false,
        port: 0,
    };
}

/// Agent-side SSH alias sync switches (all off by default).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SshConfigSyncConfig {
    /// Master switch: off = no `~/.ssh` file is written (default).
    pub enabled: bool,
    /// Include-line management: on = detect and append `Include meshlet.conf` to
    /// `~/.ssh/config` (append when missing, back up the original first). Off = write the fragment only,
    /// with the panel prompting for a manual Include.
    pub manage_include: bool,
    /// Target home directories (array of absolute paths): with the agent running as a root service the default writes
    /// only root's own home — once this is set on a multi-account machine, for each target home it writes
    /// `<home>/.ssh/meshlet.conf` (ownership pinned to that home's owning user, 0600), and
    /// Include append/backup likewise follows the target home. Empty array = keeps the old "current
    /// `$HOME` single home" semantics (default).
    pub target_homes: Vec<std::path::PathBuf>,
}

impl SshConfigSyncConfig {
    pub const OFF: Self = Self {
        enabled: false,
        manage_include: false,
        target_homes: Vec::new(),
    };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeConfig {
    pub enabled: bool,
    pub check_interval_secs: u64,
}

impl Default for UpgradeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            check_interval_secs: 86_400,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrayConfig {
    /// Explicitly opt in to `org.freedesktop.Notifications`; no local popups by default.
    pub notifications: bool,
    /// Explicitly opt in to StatusNotifierItem registration.
    pub status_notifier_item: bool,
}

impl TrayConfig {
    pub const OFF: Self = Self {
        notifications: false,
        status_notifier_item: false,
    };
}

/// Dataplane backend selection (WG-NT-SWITCH wiring batch + WG-MAC-BT wiring batch).
///
/// - [`Service`](TunnelBackend::Service) (default): the Windows `wireguard.exe`
///   tunnel-service model (managed `installtunnelservice` service + netsh routes) — the current
///   path on the three machines in production.
/// - [`Nt`](TunnelBackend::Nt): the Windows wireguard-nt 0.5.0 embedded-adapter
///   binding (one adapter per network, carried by a single agent process; cures the service model's §1.2 same-name stomping /
///   §2.5 port-binding collisions).
/// - [`MacBoringtun`](TunnelBackend::MacBoringtun): the macOS boringtun userspace
///   backend (spawns boringtun-cli + wg.sock UAPI; see the `macos_wireguard_bt`
///   module in meshlet-network; wiring batch ③-C).
///
/// Effective per platform: `service`/`nt` are Windows-only, `mac-boringtun` is macOS-only. A platform/variant
/// mismatch fails closed (the agent wiring errors out explicitly, never silently falling back to the default backend).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TunnelBackend {
    /// The `wireguard.exe` tunnel-service model (current path).
    #[default]
    Service,
    /// The wireguard-nt embedded-adapter binding.
    Nt,
    /// The macOS boringtun userspace backend (wiring batch ③-C).
    MacBoringtun,
}

impl TunnelBackend {
    /// The config string (the inverse of the [AgentConfig::from_toml] parse side, pinned by round-trip).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Nt => "nt",
            Self::MacBoringtun => "mac-boringtun",
        }
    }
}

/// Agent dataplane config ([ADR-007](../../docs/decisions/adr-007-linux-network-backend.md)):
/// **off in every respect by default** -- when disabled the agent only prints
/// its state and never touches the kernel.
#[derive(Debug, Clone, PartialEq)]
pub struct DataplaneConfig {
    pub enabled: bool,
    /// Dataplane backend selection (see [`TunnelBackend`]). The default is
    /// [`Service`](TunnelBackend::Service) (unchanged behaviour); `nt` only
    /// exists on Windows, `mac-boringtun` only on macOS, and each is only
    /// meaningful once its wiring batch is complete and accepted.
    pub tunnel_backend: TunnelBackend,
    /// The managed WireGuard interface name.
    pub interface: String,
    /// This device's WireGuard private-key file (injected locally; the server
    /// never carries it -- ADR-010).
    pub private_key_file: Option<String>,
    /// Fallback reachable hub endpoint (`host:port`): used when the server has
    /// not advertised one through `[dataplane] advertise_ip` + `listen_port`.
    ///
    /// Comma-separated multiple endpoints are supported (failover batch):
    /// `hub_endpoint = "a:51820,b:51820"` -- the agent walks them in order and
    /// rotates to the next when the active one's handshake times out (see
    /// [`DataplaneConfig::hub_endpoints`]). The single-endpoint spelling is
    /// unchanged (backwards compatible).
    pub hub_endpoint: Option<String>,
    /// Poll interval (seconds): when due, pull the desired config from the
    /// server and replay only if it changed (§10.1).
    pub poll_interval_secs: u64,
    /// P2P direct connection (§12 P2P): the agent reports candidate endpoints in
    /// every heartbeat frame and the dataplane tries to reach the peer directly,
    /// bypassing the hub; it falls back to hub relay when unreachable.
    /// **On by default** (a product decision after the batch ④ firewall
    /// integration landed and the walk-through passed on two real machines -- a
    /// direct path is the core goal and hub relay is only the safety net):
    /// enabling it pins the dataplane wg interface to a fixed listen port and
    /// that UDP port must be allowed through.
    /// Explicitly disable with `[dataplane.direct_connect] enabled = false`.
    pub direct_connect: DirectConnectConfig,
    /// SEL-001 candidate-endpoint probing: send a light ICMP probe to every
    /// candidate endpoint of every peer, collecting sliding windows of
    /// RTT / loss / jitter. **On by default** (turned on alongside the
    /// direct_connect master switch after the 2026-11-13 spoke incident -- the
    /// probe is the direct path's safety net); probes are actually sent only
    /// when `direct_connect.enabled` and a candidate endpoint exists.
    pub probe: ProbeConfig,
    /// FLIP-002 demote backoff: exponential backoff cooling on the promote side
    /// after repeated demotes (affects promote only, not the sensitivity of the
    /// SEL-003 degradation decision). See [`BackoffConfig`] for the defaults.
    pub backoff: BackoffConfig,
}

/// P2P direct-connection switch and WireGuard listen port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectConnectConfig {
    pub enabled: bool,
    /// Dataplane WireGuard listen port (used by direct-connection candidate
    /// endpoints): the firewall must allow this UDP port.
    pub listen_port: u16,
}

impl Default for DirectConnectConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_port: 51820,
        }
    }
}

/// SEL-001 candidate-endpoint probe config (task spec: an agent-side period,
/// 5s by default, configurable).
#[derive(Debug, Clone, PartialEq)]
pub struct ProbeConfig {
    /// Whether candidate-endpoint probing is on. On by default (flipped from off
    /// after the 2026-11-13 spoke cross-disconnect incident): `direct_connect`
    /// has been on by default since 98c75fe and the probe is its safety net --
    /// the SEL-003 degradation decision (loss spike / timeout -> return to
    /// relay immediately) only consumes the probe window, so with probing off a
    /// degraded direct path stays pinned to a black hole forever (on real
    /// hardware, 2026-11-13: the imac<->work5 direct path lost all payload inside
    /// a ZT degradation window while the handshake stayed fresh, and never
    /// healed itself for hours). The switch still needs `direct_connect.enabled`
    /// and a candidate endpoint to actually send probes (no candidates = no
    /// target, a no-op).
    pub enabled: bool,
    /// Probe period (seconds): 5s by default (task spec). Minimum 1.
    pub interval_secs: u64,
    /// Per-target sliding window capacity (the last N probes): the SEL-002
    /// scoring / hysteresis decision runs on this window, and a window that is
    /// too small flips on every single jitter. Default 20.
    pub window: usize,
    /// SEL-002 hysteresis switching: the new path must win **consecutively** N
    /// samples (default 3) and score at least `switch_margin` better than the
    /// current path before switching -- anti-chatter (no switching in jittery
    /// conditions).
    pub switch_required: usize,
    /// SEL-002 hysteresis margin (0.0..=1.0; default 0.30 = 30%).
    pub switch_margin: f64,
    /// SEL-003 recovery gate: after the direct path degrades back to relay it
    /// must stay healthy for **consecutive** N rounds before switching back
    /// (anti-chatter). Default 3.
    pub recovery_required: usize,
    /// SEL-003 latency degradation threshold (milliseconds): a probe-window RTT
    /// median at or above this value counts as a degraded direct path and
    /// returns to relay immediately. Default 800.
    ///
    /// **Rationale for the default** (follow-up on 2026-11-13, settled by the
    /// SEL-002 two-machine acceptance): the probe transport timeout is 1000ms
    /// (Linux `ping -W 1` / Windows `ping -w 1000`) -- timed-out samples are
    /// already recorded as Lost and covered by the loss / timeout rules; 800ms
    /// exactly fills the pre-timeout blind band where "the probe succeeded but
    /// the RTT is badly degraded" (on real hardware a 1715ms `probe_ok` kept a
    /// direct path pinned for hours). 800ms is ~50x the healthy-mesh baseline
    /// (measured 8-17ms) and far above any sane same-segment LAN direct figure;
    /// at that level of degradation hub relay (the hub's own view measured 8-14ms
    /// over the same window) is strictly better. The median semantics mean "N
    /// consecutive ticks above the threshold" (a window of 20 @5s is ~100s
    /// sustained before it hits, so a single jitter does not trigger); recovery
    /// still goes through the recovery_required hysteresis.
    /// Note: a value above 1000 falls outside the probe timeout and is nearly
    /// unreachable (those samples are already Lost) -- setting it high is the
    /// same as switching the latency dimension off.
    pub degrade_rtt_ms: u64,
    /// SEL-003 loss-spike threshold (0.0..=1.0): a window loss rate at or above
    /// this value counts as a degraded direct path and returns to relay
    /// immediately; the same decision is also the inverse gate for the
    /// FLIP-001 "probes confirm healthy" face (`window_is_healthy`). Default
    /// 0.20 (20%).
    ///
    /// **Rationale for the default** (narrowed on 2026-11-17 by user decision,
    /// formerly 0.5): at the old threshold a face losing 49% was a healthy face
    /// "below the spike" -- the recovery gate's bypass would pull the direct path
    /// back onto such a degraded face, which is exactly where the measured ping
    /// three-state flapping (100% timeout <-> 1.7-3.3s huge latency <-> 12ms
    /// full speed) felt like a degraded face being waved through. 20% is the same
    /// order of magnitude as the SEL-002 score's heavy loss penalty
    /// (`LOSS_PENALTY` is 10x: 20% loss already triples the score) -- a face the
    /// scoring regards as "clearly worse" is no longer waved through by the
    /// degradation decision.
    pub loss_spike: f64,
    /// SEL-002 switch cooldown (seconds, scheme 1): within this time after a
    /// switch, no further switch is allowed and the current path may not be judged
    /// degraded (the gate records `last_switch_at`). Default = interval×required×2,
    /// capped at 60s (see [`ProbeConfig::interval_secs`]×[`ProbeConfig::switch_required`];
    /// 5×3×2 = 30). An overly long cooldown delays real failover, so an explicit
    /// value is capped at 60 as well.
    pub switch_cooldown_secs: u64,
    /// SEL-003 young-window exemption (scheme 1): a window with fewer samples
    /// than this is never judged degraded (same "no baseline" exemption semantics
    /// -- exempt "not enough readings", never "bad readings"). Default 4; must be
    /// ≤ `window` (otherwise the window is forever young and the degradation
    /// decision is disabled outright).
    pub degrade_min_samples: usize,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 5,
            window: 20,
            switch_required: 3,
            switch_margin: 0.30,
            recovery_required: 3,
            degrade_rtt_ms: 800,
            loss_spike: 0.20,
            // interval×required×2 = 5×3×2, under the 60 cap.
            switch_cooldown_secs: 30,
            degrade_min_samples: 4,
        }
    }
}

/// FLIP-002 demote backoff config: exponential backoff on the promote side
/// after consecutive demotes.
///
/// **Rationale for the defaults** (fliploop 24h-window verdict of 2026-11-15,
/// JMrE: 262 promote→demote loops / median 1.48min): `backoff_base_ms = 30_000`
/// (30s, about one direct-reconciliation period -- the first cooldown stops
/// promote from immediately retrying the same face); growth by 2x per step with
/// `backoff_cap_ms = 900_000` (15min, per the task spec -- while the degradation
/// source persists, pointless retries collapse from minute-scale loops to a
/// handful of attempts); `recovery_confirmations = 3` (cleared after 3
/// consecutive healthy-face probe rounds, matching the SEL-003 recovery gate
/// `recovery_required` default -- the same probe evidence source, the same
/// anti-chatter rule). The backoff applies to the promote side only; the
/// demote decision's sensitivity is unaffected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackoffConfig {
    /// First cooldown (milliseconds); the Nth consecutive demote cools down for
    /// base × 2^(N-1). Default 30_000.
    pub backoff_base_ms: u64,
    /// Cooldown cap (milliseconds). Default 900_000 (15min).
    pub backoff_cap_ms: u64,
    /// Consecutive healthy-face rounds that clear the backoff (the next demote
    /// starts over from base). Default 3.
    pub recovery_confirmations: u32,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            backoff_base_ms: 30_000,
            backoff_cap_ms: 900_000,
            recovery_confirmations: 3,
        }
    }
}

impl Default for DataplaneConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tunnel_backend: TunnelBackend::default(),
            interface: "wg0".into(),
            private_key_file: None,
            hub_endpoint: None,
            poll_interval_secs: 30,
            direct_connect: DirectConnectConfig::default(),
            probe: ProbeConfig::default(),
            backoff: BackoffConfig::default(),
        }
    }
}

impl DataplaneConfig {
    /// Hub endpoint list (comma-separated `hub_endpoint`): each item trimmed,
    /// empty segments dropped, deduplicated.
    ///
    /// - absent / empty string -> empty table (the original "no fallback"
    ///   semantics are kept, the plan is returned as-is);
    /// - single endpoint -> one-element table (the failover decision degenerates
    ///   to always picking it, matching the old behavior);
    /// - multiple endpoints -> ordered candidates (failover batch: rotate to the
    ///   next one when the active endpoint's handshake times out).
    ///
    /// This only splits syntactically and does not validate endpoint shape --
    /// old configs allow any `host:port` (including hostnames); failover
    /// activates only when `len() > 1`, and single/empty endpoint behavior is
    /// unchanged to the byte.
    pub fn hub_endpoints(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if let Some(value) = &self.hub_endpoint {
            for part in value.split(',') {
                let part = part.trim();
                if !part.is_empty() && !out.iter().any(|e| e == part) {
                    out.push(part.to_string());
                }
            }
        }
        out
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server_url: "https://127.0.0.1".into(),
            state_dir: "/var/lib/meshlet".into(),
            device_token: None,
            bootstrap_token: None,
            device_name: None,
            tray: TrayConfig::default(),
            upgrade: UpgradeConfig::default(),
            dataplane: DataplaneConfig::default(),
            ssh_config_sync: SshConfigSyncConfig::OFF,
            mcp: McpConfig::default(),
        }
    }
}

impl AgentConfig {
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let raw: RawAgentConfig =
            toml::from_str(input).map_err(|e| ConfigError::Parse(e.to_string()))?;
        let default = Self::default();
        let server_url = raw.server_url.unwrap_or(default.server_url);
        if !(server_url.starts_with("http://") || server_url.starts_with("https://")) {
            return Err(ConfigError::InvalidServerUrl(server_url));
        }
        let dataplane = raw.dataplane;
        let tray = match raw.tray {
            Some(raw_tray) => TrayConfig {
                notifications: raw_tray.notifications.unwrap_or(default.tray.notifications),
                status_notifier_item: raw_tray
                    .status_notifier_item
                    .unwrap_or(default.tray.status_notifier_item),
            },
            None => default.tray,
        };
        let raw_upgrade = raw.upgrade.unwrap_or_default();
        let check_interval_secs = raw_upgrade
            .check_interval_secs
            .unwrap_or(default.upgrade.check_interval_secs);
        if check_interval_secs < 1 {
            return Err(ConfigError::InvalidUpgrade(
                "upgrade.check_interval_secs must be at least 1".into(),
            ));
        }
        let upgrade = UpgradeConfig {
            enabled: raw_upgrade.enabled.unwrap_or(default.upgrade.enabled),
            check_interval_secs,
        };
        let dp_interface = dataplane
            .interface
            .map(|s| s.trim().to_string())
            .unwrap_or(default.dataplane.interface);
        if dp_interface.is_empty() {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.interface must not be empty".into(),
            ));
        }
        let poll_interval_secs = dataplane
            .poll_interval_secs
            .unwrap_or(default.dataplane.poll_interval_secs);
        if poll_interval_secs < 1 {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.poll_interval_secs must be at least 1".into(),
            ));
        }
        let tunnel_backend = match dataplane.tunnel_backend.as_deref() {
            None => default.dataplane.tunnel_backend,
            Some("service") => TunnelBackend::Service,
            Some("nt") => TunnelBackend::Nt,
            Some("mac-boringtun") => TunnelBackend::MacBoringtun,
            Some(other) => {
                return Err(ConfigError::InvalidDataPlane(format!(
                    "dataplane.tunnel_backend must be \"service\", \"nt\", or \
                     \"mac-boringtun\", got \"{other}\""
                )));
            }
        };
        let raw_dc = dataplane.direct_connect.unwrap_or_default();
        let direct_connect = DirectConnectConfig {
            enabled: raw_dc
                .enabled
                .unwrap_or(default.dataplane.direct_connect.enabled),
            listen_port: raw_dc
                .listen_port
                .unwrap_or(default.dataplane.direct_connect.listen_port),
        };
        if direct_connect.listen_port == 0 {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.direct_connect.listen_port must be 1..=65535".into(),
            ));
        }
        let raw_probe = dataplane.probe.unwrap_or_default();
        // The switch-cooldown default = interval×required×2 (per the proposal),
        // so both must be resolved first.
        let probe_interval = raw_probe
            .interval_secs
            .unwrap_or(default.dataplane.probe.interval_secs);
        let probe_switch_required = raw_probe
            .switch_required
            .unwrap_or(default.dataplane.probe.switch_required);
        let probe = ProbeConfig {
            enabled: raw_probe.enabled.unwrap_or(default.dataplane.probe.enabled),
            interval_secs: probe_interval,
            window: raw_probe.window.unwrap_or(default.dataplane.probe.window),
            switch_required: probe_switch_required,
            switch_margin: raw_probe
                .switch_margin_percent
                .map(|p| p / 100.0)
                .unwrap_or(default.dataplane.probe.switch_margin),
            recovery_required: raw_probe
                .recovery_required
                .unwrap_or(default.dataplane.probe.recovery_required),
            degrade_rtt_ms: raw_probe
                .degrade_rtt_ms
                .unwrap_or(default.dataplane.probe.degrade_rtt_ms),
            loss_spike: raw_probe
                .loss_spike_percent
                .map(|p| p / 100.0)
                .unwrap_or(default.dataplane.probe.loss_spike),
            switch_cooldown_secs: raw_probe
                .switch_cooldown_secs
                .unwrap_or_else(|| (probe_interval * probe_switch_required as u64 * 2).min(60)),
            degrade_min_samples: raw_probe
                .degrade_min_samples
                .unwrap_or(default.dataplane.probe.degrade_min_samples),
        };
        if probe.interval_secs < 1 {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.probe.interval_secs must be at least 1".into(),
            ));
        }
        if probe.window < 1 {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.probe.window must be at least 1".into(),
            ));
        }
        if probe.switch_required < 1 {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.probe.switch_required must be at least 1".into(),
            ));
        }
        if !(0.0..=1.0).contains(&probe.switch_margin) {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.probe.switch_margin_percent must be 0..=100".into(),
            ));
        }
        if probe.recovery_required < 1 {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.probe.recovery_required must be at least 1".into(),
            ));
        }
        if probe.degrade_rtt_ms < 1 {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.probe.degrade_rtt_ms must be at least 1".into(),
            ));
        }
        if !(0.0..=1.0).contains(&probe.loss_spike) {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.probe.loss_spike_percent must be 0..=100".into(),
            ));
        }
        if probe.switch_cooldown_secs > 60 {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.probe.switch_cooldown_secs must be at most 60".into(),
            ));
        }
        if probe.degrade_min_samples < 1 {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.probe.degrade_min_samples must be at least 1".into(),
            ));
        }
        if probe.degrade_min_samples > probe.window {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.probe.degrade_min_samples must be at most probe.window".into(),
            ));
        }
        let raw_backoff = dataplane.backoff.unwrap_or_default();
        let backoff = BackoffConfig {
            backoff_base_ms: raw_backoff
                .backoff_base_ms
                .unwrap_or(default.dataplane.backoff.backoff_base_ms),
            backoff_cap_ms: raw_backoff
                .backoff_cap_ms
                .unwrap_or(default.dataplane.backoff.backoff_cap_ms),
            recovery_confirmations: raw_backoff
                .recovery_confirmations
                .unwrap_or(default.dataplane.backoff.recovery_confirmations),
        };
        if backoff.backoff_base_ms < 1 {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.backoff.backoff_base_ms must be at least 1".into(),
            ));
        }
        if backoff.backoff_cap_ms < backoff.backoff_base_ms {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.backoff.backoff_cap_ms must be >= backoff_base_ms".into(),
            ));
        }
        if backoff.recovery_confirmations < 1 {
            return Err(ConfigError::InvalidDataPlane(
                "dataplane.backoff.recovery_confirmations must be at least 1".into(),
            ));
        }
        Ok(Self {
            server_url,
            state_dir: raw.state_dir.unwrap_or(default.state_dir),
            device_token: raw
                .device_token
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            bootstrap_token: raw
                .bootstrap_token
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            device_name: raw
                .device_name
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            tray,
            upgrade,
            dataplane: DataplaneConfig {
                enabled: dataplane.enabled.unwrap_or(default.dataplane.enabled),
                tunnel_backend,
                interface: dp_interface,
                private_key_file: dataplane.private_key_file,
                hub_endpoint: dataplane
                    .hub_endpoint
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
                poll_interval_secs,
                direct_connect,
                probe,
                backoff,
            },
            ssh_config_sync: match raw.ssh_config_sync {
                Some(raw_sync) => SshConfigSyncConfig {
                    enabled: raw_sync.enabled.unwrap_or(default.ssh_config_sync.enabled),
                    manage_include: raw_sync
                        .manage_include
                        .unwrap_or(default.ssh_config_sync.manage_include),
                    target_homes: raw_sync
                        .target_homes
                        // The template default is always empty = the legacy
                        // single-home semantics (see the struct docs).
                        .unwrap_or_default()
                        .into_iter()
                        .map(|s| std::path::PathBuf::from(s.trim()))
                        .filter(|p| !p.as_os_str().is_empty())
                        .collect(),
                },
                None => SshConfigSyncConfig::OFF,
            },
            mcp: match raw.mcp {
                Some(raw_mcp) => McpConfig {
                    enabled: raw_mcp.enabled.unwrap_or(default.mcp.enabled),
                    port: raw_mcp.port.unwrap_or(default.mcp.port),
                },
                None => McpConfig::default(),
            },
        })
    }
}

#[cfg(test)]
mod tests;
