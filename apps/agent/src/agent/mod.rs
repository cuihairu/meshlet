//! The agent main body: pull plan → reconcile → apply → heartbeat, in a loop.
//!
//! Every kernel operation goes through [`meshlet_network::SystemBackend`]
//! (ADR-007; on Windows it is already wired to
//! `windows::WindowsNetworkBackend` per ADR-008 (tunnel-only v1, NAT-bearing
//! plans explicitly rejected); the other non-Linux platforms remain
//! Unsupported placeholders): this module only decides **when** to call it
//! and **what config to feed it** (plans come from the server, never locally
//! assembled shell commands, §16.4).
mod direct;
mod direct_port;
mod direct_report;
pub(super) mod endpoint;
mod evidence;
pub(super) mod handshake;
mod heartbeat;
mod hub_failover;
pub(super) mod paths;
pub(super) mod plan_adapter;
mod publish;
mod receipts;
pub(super) mod reconcile;
pub(super) mod rtt_source;
pub(super) mod scope;
mod ssh;
mod tasks;
mod tray;
pub(super) mod update;
pub(super) mod verdict;
pub(super) mod views;

use crate::agent::paths::{direct_ledger_path, task_ledger_path};
use crate::agent::publish::PublishRuntime;
use crate::agent::receipts::PendingReceipt;
pub use paths::read_private_key;

use std::path::Path;
use std::time::Duration;
use std::time::Instant;

use meshlet_config::{AgentConfig, DataplaneConfig, TunnelBackend};
use meshlet_network::probe::RecoveryGate;
use meshlet_network::{NetworkBackend, SystemBackend};

#[cfg(target_os = "linux")]
use crate::dbus::DesktopClient;
use crate::desktop::DesktopPublish;
#[cfg(not(target_os = "linux"))]
use crate::desktop_unsupported::DesktopClient;
use crate::direct::DirectManager;
use crate::reconcile::state_path;
use crate::server;
use crate::tray::{TraySink, TrayState};
use meshlet_config::TrayConfig;

/// Backoff cap in seconds for sustained pull failures: do not flood the log
/// while the server is unreachable.
///
/// 2026-11-12 user directive (P1): a 300s cap meant the worst case after a
/// disconnect was one retry per 5 minutes — the direct source of "keeps
/// failing to connect" — so it is capped at 30s; network-change events
/// additionally trigger an **immediate** retry ([`crate::net_event`]), so an
/// early network recovery does not have to wait out the backoff cycle.
pub const BACKOFF_MAX_SECS: u64 = 30;
/// The normal polling interval after consecutive successes is governed by
/// `[dataplane] poll_interval_secs`.
const BACKOFF_MIN_SECS: u64 = 1;
/// Throttle floor for network-event wakeups (real-machine evidence: one
/// network change fires a burst of netlink messages within a fraction of a
/// second; without a floor that becomes a tick flood — 1s granularity still
/// counts as "immediate").
const NET_WAKE_FLOOR: Duration = Duration::from_secs(1);

/// Device-side agent: pull plan → reconcile → apply → heartbeat, in a loop.
pub struct Agent {
    server_url: String,
    token: String,
    dataplane: DataplaneConfig,
    backend: SystemBackend,
    private_key: Option<String>,
    /// Ledger state file (`{state_dir}/applied.json`).
    state_path: std::path::PathBuf,
    state_dir: String,
    upgrade: meshlet_config::UpgradeConfig,
    last_update_check: Option<Instant>,
    pending_receipts: std::collections::VecDeque<PendingReceipt>,
    /// Tray state persistence (`{state_dir}/tray/`); a no-op under headless,
    /// see [`crate::tray`] and the TODO "runtime system tray icon".
    tray: TraySink,
    desktop: std::cell::RefCell<DesktopClient>,
    desktop_config: TrayConfig,
    last_desktop_state: std::cell::RefCell<Option<TrayState>>,
    /// This machine's device name (the text equivalent used by the tray tooltip).
    device_name: Option<String>,
    /// Service publish runtime (R-06): forwarding/HTTP/DNS listeners + probe
    /// scheduling + undelivered reports.
    publish: PublishRuntime,
    /// §12 P2P direct-connect manager: a per-peer link state machine +
    /// restart recovery (ledger).
    direct: DirectManager,
    /// Persistence file for the direct keep set (`{state_dir}/direct.json`).
    direct_ledger: std::path::PathBuf,
    /// WIN-PORT-1 B2 effective listen port (the single source for conf,
    /// firewall, and reporting): resolved every reconcile round (probe
    /// fallback on Windows, see [`direct_port`]); `None` = unresolved or all
    /// candidates blocked (`direct_report` then reports no candidate endpoints).
    resolved_direct_port: Option<u16>,
    /// Effective-port resolution is currently in the "all candidates blocked"
    /// state (already explicitly reported once): log once on entry and once
    /// on exit, never spamming every 30s.
    direct_port_blocked: bool,
    /// Last direct probe time (30s throttle; `None` = never probed, so probe
    /// on the first round).
    last_direct_probe: Option<Instant>,
    /// R-DIAG-2 direct-RTT background runtime: pings direct peers on its own
    /// thread (does not block the tick).
    direct_rtt: crate::direct_rtt::DirectRttRuntime,
    /// MT-002 task channel: a background worker (its own thread pulls pending
    /// tasks and ack → execute → receipt). The main-loop tick only submits via
    /// [kick](crate::tasks::TaskRuntime::kick) and returns immediately, so a
    /// single task no longer blocks heartbeat/data-plane reconcile for up to
    /// [DEFAULT_TIMEOUT_SECS]. The ledger (`{state_dir}/tasks.json`; re-dispatch
    /// after a disconnect re-reports from it and never re-runs) is held by the
    /// worker.
    task_runtime: crate::tasks::TaskRuntime,
    /// SEL-001 candidate-endpoint probe runtime: an independent thread sends
    /// ICMP probes to every candidate endpoint of every peer every 5s
    /// (configurable), collecting sliding windows of RTT/loss/jitter. The
    /// candidate set is refreshed every 30s by [`Agent::reconcile_direct`]
    /// (zero control-plane load).
    probe: crate::probe::ProbeRuntime,
    /// FLIP-001 endpoint candidate table: the set of candidate faces from the
    /// three sources config (server-authoritative) / roaming (kernel-observed)
    /// / discovered (probe-confirmed), see [`crate::candidates`]. After
    /// returning to relay, SEL-001 keeps probing the faces in the table — a
    /// healthy face takes the recovery-gate bypass straight to promote, instead
    /// of only watching the server's single endpoint for degradation.
    candidates: crate::candidates::CandidateTable,
    /// FLIP-002 demote backoff: an exponential backoff cooldown on the promote
    /// side after consecutive demotes (it blocks promote only and does not
    /// affect SEL-003 degradation-verdict sensitivity), see
    /// [`crate::backoff`].
    backoff: crate::backoff::DemoteBackoff,
    /// SEL-003 recovery gate: after a degraded direct link falls back to relay,
    /// N consecutive healthy rounds are required before switching back
    /// (debounce).
    recovery: RecoveryGate,
    /// SSH alias sync switch and status path (all off by default: writes no
    /// file under `~/.ssh`).
    ssh_config_sync: meshlet_config::SshConfigSyncConfig,
    ssh_sync_status_path: std::path::PathBuf,
    /// MCP local service (`[mcp] enabled`, off by default): lets AI clients
    /// query this machine's mesh facts over loopback. `None` = not enabled
    /// (not listening).
    ///
    /// **Held means running**: the field value is never read; on drop,
    /// `McpServer`'s `Drop` stops the service and removes `mcp.json` —
    /// deliberately unread, hence `#[allow(dead_code)]`.
    #[allow(dead_code)]
    mcp_server: Option<crate::mcp::McpServer>,
}

impl Agent {
    /// also holds in an environment that is already root or already
    /// passwordless).
    ///
    /// `tunnel_backend = "nt"` (Windows) loads the wireguard-nt runtime: a
    /// missing dll / load failure **refuses to start** (returns `Err`) — never
    /// silently falling back to the service model (running the service model
    /// when config explicitly named nt is a model mismatch, not a downgrade).
    ///
    /// `tunnel_backend = "mac-boringtun"` (macOS) switches to the boringtun
    /// data plane; selecting that variant on a **non-macOS platform is an
    /// explicit `Err` (fail-closed)** — never silently falling back to the
    /// default backend (config contract: each backend is effective only on its
    /// platform, a platform mismatch is a model mismatch).
    pub fn new(config: AgentConfig, private_key: Option<String>) -> Result<Self, String> {
        let backend = SystemBackend::new().with_interface(config.dataplane.interface.clone());
        // fail-closed: mac-boringtun is effective only on macOS; other
        // platforms refuse to start.
        #[cfg(not(target_os = "macos"))]
        if config.dataplane.tunnel_backend == TunnelBackend::MacBoringtun {
            return Err("tunnel_backend=mac-boringtun is a macOS-only setting".into());
        }
        #[cfg(target_os = "macos")]
        let backend = if config.dataplane.tunnel_backend == TunnelBackend::MacBoringtun {
            tracing::info!(
                interface = %config.dataplane.interface,
                "data plane backend: mac-boringtun"
            );
            backend.with_mac_boringtun()
        } else {
            backend
        };
        #[cfg(target_os = "windows")]
        let backend = if config.dataplane.tunnel_backend == TunnelBackend::Nt {
            let runtime =
                meshlet_network::windows_wireguard_nt::NtRuntime::load().map_err(|e| {
                    format!(
                    "tunnel_backend=nt requested but the wireguard-nt runtime is unavailable: {e}"
                )
                })?;
            tracing::info!(
                interface = %config.dataplane.interface,
                "data plane backend: wireguard-nt"
            );
            backend.with_nt_runtime(runtime)
        } else {
            backend
        };
        #[cfg(not(target_os = "windows"))]
        if config.dataplane.tunnel_backend == TunnelBackend::Nt {
            tracing::warn!(
                "tunnel_backend=nt is a Windows-only setting; using this platform's data plane"
            );
        }
        Ok(Self::with_backend(config, private_key, backend))
    }

    /// Inject a backend (for netns integration tests; production goes through
    /// [`Agent::new`]).
    #[allow(clippy::default_constructed_unit_structs)]
    pub fn with_backend(
        config: AgentConfig,
        private_key: Option<String>,
        backend: SystemBackend,
    ) -> Self {
        // Start the probe runtime before moving config: field initialization
        // is evaluated in written order, and `dataplane` gets moved earlier
        // inside the struct literal, so the probe runtime must read the probe
        // config before that.
        let probe = crate::probe::ProbeRuntime::start(&config.dataplane.probe);
        let recovery_required = config.dataplane.probe.recovery_required;
        // Take out the FLIP-002 backoff parameters early (config is moved
        // field by field right after this).
        let backoff = crate::backoff::DemoteBackoff::new(
            config.dataplane.backoff.backoff_base_ms,
            config.dataplane.backoff.backoff_cap_ms,
            config.dataplane.backoff.recovery_confirmations,
        );
        // Take out the task worker's parameters early (config is moved field
        // by field right after this, so it can no longer be borrowed).
        let server_url = config.server_url.clone();
        let device_token = config.device_token.clone().unwrap_or_default();
        let task_ledger_path = task_ledger_path(&config.state_dir);
        let task_ledger = crate::tasks::TaskLedger::load(&task_ledger_path);
        let notify_enabled = config.tray.notifications;
        // MCP local service: `[mcp] enabled` is off by default (not listening);
        // it starts only when explicitly enabled. A bind failure is not fatal —
        // record it truthfully and continue (the agent does not exit because
        // the MCP port is occupied).
        let mcp_server = if config.mcp.enabled {
            match crate::mcp::start(std::path::Path::new(&config.state_dir), config.mcp.port) {
                Ok(server) => {
                    tracing::info!(
                        port = server.port(),
                        "mcp server started (AI can query this node)"
                    );
                    Some(server)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "mcp server failed to start; AI query unavailable");
                    None
                }
            }
        } else {
            None
        };
        // R-DIAG-2: RTT probing is decoupled from the data plane (background
        // thread). The backend is Clone (it only carries netns/sudo/interface
        // config), so `ping_rtt_ms` inside the worker thread does not drag on
        // the main loop.
        let direct_rtt = crate::direct_rtt::DirectRttRuntime::start(backend.clone());
        Self {
            server_url: config.server_url,
            token: config.device_token.unwrap_or_default(),
            state_path: state_path(&config.state_dir),
            state_dir: config.state_dir.clone(),
            upgrade: config.upgrade,
            last_update_check: None,
            pending_receipts: std::collections::VecDeque::new(),
            tray: TraySink::new(&config.state_dir),
            desktop: std::cell::RefCell::new(DesktopClient::default()),
            desktop_config: config.tray,
            last_desktop_state: std::cell::RefCell::new(None),
            device_name: config.device_name.clone(),
            dataplane: config.dataplane,
            private_key,
            backend,
            publish: PublishRuntime::new(),
            direct_ledger: direct_ledger_path(&config.state_dir),
            direct: DirectManager::load(&direct_ledger_path(&config.state_dir)),
            resolved_direct_port: None,
            direct_port_blocked: false,
            last_direct_probe: None,
            direct_rtt,
            task_runtime: crate::tasks::TaskRuntime::start(
                server_url,
                device_token,
                task_ledger,
                task_ledger_path,
                // MT-004: task arrival (after ack) triggers a tray balloon.
                // Notification is best-effort: it honors `tray.notifications`
                // (off by default) exactly like the status balloon and is sent
                // inside the worker thread — D-Bus connections/calls can block
                // (an unresponsive notification daemon) and must never affect
                // the main loop's heartbeat and data-plane reconcile.
                move |task: &meshlet_domain::Task| {
                    if !notify_enabled {
                        return;
                    }
                    let call =
                        crate::desktop::task_notify_call(&task.id.to_string(), &task.payload.cmd);
                    let env = crate::tray::EnvProbe::from_env();
                    let mut client = DesktopClient::default();
                    let result = client.notify_task(&call, &env);
                    if !matches!(result, DesktopPublish::Published) {
                        tracing::debug!(result = ?result, "task arrival not shown");
                    }
                },
            ),
            probe,
            candidates: crate::candidates::CandidateTable::new(),
            backoff,
            recovery: RecoveryGate::new(recovery_required),
            ssh_config_sync: config.ssh_config_sync,
            ssh_sync_status_path: crate::ssh_sync::status_path(&config.state_dir),
            mcp_server,
        }
    }

    /// Path of the ledger state file (for tests and ops troubleshooting).
    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    /// Main loop: reconcile immediately on the first round (startup
    /// reconcile), then poll by `poll_interval_secs`; consecutive failures
    /// back off exponentially up to the cap ([`BACKOFF_MAX_SECS`], 30s). The
    /// wait can be **woken for an immediate retry** by network-change events
    /// (interface up/down, address add/remove, [`crate::net_event`]) — so an
    /// early network recovery does not sit through the backoff cycle; the
    /// normal polling interval can likewise be woken (reconcile as soon as
    /// possible after a network change). When watching is unavailable it falls
    /// back to plain sleep and never busy-spins. The event burst is throttled
    /// by [`NET_WAKE_FLOOR`]: the event burst of a single network change must
    /// not become a tick flood.
    pub fn run(mut self) -> ! {
        let mut backoff = Duration::from_secs(BACKOFF_MIN_SECS);
        let net_events = crate::net_event::watch();
        let mut last_net_wake: Option<Instant> = None;
        loop {
            match self.tick() {
                Ok(()) => backoff = Duration::from_secs(BACKOFF_MIN_SECS),
                Err(e) => {
                    tracing::warn!(error = %e, retry_in_secs = backoff.as_secs(), "agent tick failed");
                }
            }
            let wait = if backoff <= Duration::from_secs(BACKOFF_MIN_SECS) {
                Duration::from_secs(self.dataplane.poll_interval_secs.max(1))
            } else {
                backoff
            };
            match net_events.recv_timeout(wait) {
                Ok(()) => {
                    // Drain the events already queued: one batch triggers only
                    // one immediate retry.
                    while net_events.try_recv().is_ok() {}
                    // Debounce the event burst: if a network event already
                    // caused a retry within the last 1s, wait out the full 1s
                    // before the next one (real-machine evidence: one DHCP-like
                    // action fired 17 messages within 400ms; without the floor
                    // that would be a tick flood).
                    if let Some(last) = last_net_wake {
                        let since = last.elapsed();
                        if since < NET_WAKE_FLOOR {
                            std::thread::sleep(NET_WAKE_FLOOR - since);
                            while net_events.try_recv().is_ok() {}
                        }
                    }
                    last_net_wake = Some(Instant::now());
                    // FLIP-001: a network-change event → refresh the direct
                    // candidate table + probe immediately. Reset the 30s
                    // throttle so the next tick (right after this round's
                    // backoff) runs the full direct reconcile: actively probe
                    // every known endpoint and promote a reachable new face via
                    // the recovery-gate bypass — without waiting on the old
                    // "demote first, then wait for the recovery gate" path.
                    self.last_direct_probe = None;
                    tracing::info!("network change observed: retrying immediately");
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                // The watcher thread is gone (subscription failed / exited):
                // fall back to plain sleep — Disconnected returns immediately,
                // and ignoring it would be busy-spinning.
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    std::thread::sleep(wait);
                }
            }
            backoff = (backoff * 2).min(Duration::from_secs(BACKOFF_MAX_SECS));
        }
    }

    /// One round: pull plan → apply if needed → heartbeat report. While pending
    /// approval (self-service registration, ZeroTier-style) no plan can be
    /// pulled: the heartbeat keeps the control center seeing the device as
    /// alive, and once approved it naturally moves into the normal loop.
    pub fn tick(&mut self) -> Result<(), String> {
        self.flush_pending_receipts();
        let plan = match server::fetch_plan(&self.server_url, &self.token) {
            Ok(plan) => plan,
            // Server contract: the desired endpoint of a Pending application
            // returns 404 with a message containing "pending approval"
            // (migration 008 trade-off: it does not enter the desired config
            // before approval).
            Err(e) if e.contains("pending approval") => {
                self.report_heartbeat(None);
                // Pending approval means no desired plan: tear down the publish
                // listeners left over from the previous round; leave no local
                // listener standing.
                self.apply_publish(None);
                tracing::info!("registration pending approval: heartbeat sent, plan withheld");
                // Pending approval = the tunnel is not established yet: present
                // it as "disconnected" (the counterpart of
                // `PresenceState::Offline`) rather than misleadingly as
                // "online". No plan → the virtual IP is unknown (`None`).
                self.publish_tray(TrayState::Offline, None);
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        // AGENT-ISO-1: foreign-overlay isolation **runs every round** (not
        // waiting for a plan change — rules can be flushed externally, and the
        // managed tunnel races zerotier startup, so patching them only at apply
        // time would miss some; on 2026-11-23 the whole rule batch was lost in
        // practice → recursive encapsulation amplification of 185:1). Failure
        // only logs and does not interrupt the data plane: isolation is
        // hardening, not a tunnel precondition (the doctor surface reports FAIL).
        if let Err(error) = self.backend.ensure_overlay_isolation() {
            tracing::warn!(%error, "foreign-overlay isolation not enforced");
        }
        let result = self.reconcile(&plan);
        let error = result.as_ref().err().map(String::as_str);
        if let Err(error) = server::report_apply(&self.server_url, &self.token, &plan, error) {
            self.enqueue_receipt(plan.clone(), Some(error));
        }
        // Publish reconcile and kernel reconcile are independent (local
        // listeners do not depend on the tunnel): align the publish state first
        // even if the kernel replay failed; a publish failure only logs and
        // never interrupts the data-plane loop.
        self.apply_publish(plan.publish.as_ref());
        self.report_publish_health();
        self.apply_ssh_sync(&plan);
        let decision = result?;
        let control_ok = self.report_heartbeat(Some(&plan));
        // §12: probe direct only after the heartbeat (which carries this
        // machine's direct candidates) — the server sees our endpoints first, so
        // by the next round's candidate pull the data is already in place; a
        // direct failure only logs and does not affect the data-plane loop.
        self.reconcile_direct(&plan);
        // MT-002: the task channel (dispatch and receipts) is independent of
        // the data-plane loop — a task failure only logs and never interrupts
        // tunnel/routes/heartbeat; a pull failure likewise only logs and
        // retries next round.
        self.process_tasks();
        // Tray state: reason × control channel × tunnel handshake (mapping
        // rationale in [`crate::tray`]). The virtual IP uses the same chain as
        // the `info` command: it takes the planned tunnel address
        // (`plan.tunnel.address`).
        self.publish_tray(
            TrayState::derive(decision.reason, control_ok, self.last_handshake().is_some()),
            Some(plan.tunnel.address),
        );
        self.maybe_self_update();
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
