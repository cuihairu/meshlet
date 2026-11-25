//! WIN-PORT-1 B2: effective-port resolution for the direct-connect listen port (probe-bind probing with fallback).
//!
//! On Windows the configured port may be blocked by a UDP excluded-port range (`netsh interface ipv4 show
//! excludedportrange protocol=udp`) or by another occupant — the `WireGuardTunnel$` service fails to bind
//! with `0xc0000022` (STATUS_ACCESS_DENIED; proven by `wireguard.exe /dumplog` logging
//! `Could not bind socket to 0.0.0.0:51820`; switching to a high port fixed it). This module
//! probe-binds the same port agent-side before apply (if we cannot bind, the service cannot either —
//! the same excluded range rejects any process), and picks a fallback port from a deterministic window when blocked.
//!
//! Resolution order ([`resolve`]; avoiding self-occupancy misreads and churn are hard constraints):
//! 1. Snapshot port == configured port → use the configured port directly (already bound in production, zero probing);
//! 2. Probe shows the configured port bindable → configured port (self-heals back once the excluded range clears);
//! 3. Ledger port == snapshot port (in active use) → keep the ledger port (switching ports only causes pointless
//!    disconnects and the peer's candidate faces must re-converge — no per-round port-switch churn);
//! 4. Fallback window scan (starting at [`FALLBACK_PORT_BASE`]) → first bindable port; a snapshot port
//!    inside the window counts as evidence the port is actively bound (kept even if the ledger is lost);
//! 5. No candidate binds → [`PortResolution::Blocked`] — the caller reports an explicit error (with the
//!    netsh troubleshooting command), the plan pins no port, `direct_report` stays silent about it — never
//!    silently ride the relay while pretending direct connect is fine.
//!
//! The resolution is persisted to `{state_dir}/direct-port.json` ([load]/[save]); conf
//! `ListenPort`, the firewall allow rule (`ensure_direct_udp_firewall_sync`) and
//! `direct_report` all take the same effective port (hard invariant; call sites in
//! `super::reconcile`). Linux neither probes nor writes the ledger (behavior unchanged, always the configured port).

/// Fallback scan window base: 52900. Deterministic (rescans on the same machine converge on the same port, keeping peer candidate faces stable);
/// above WireGuard's default 51820 common cluster range; the window includes 52931, verified
/// usable by manual mitigation on a real machine (cuihaitao's box: 51820 rejected with `0xc0000022`, 52931 bindable).
pub(super) const FALLBACK_PORT_BASE: u16 = 52900;
/// Fallback scan window size: `52900..=53099`, 200 candidates.
pub(super) const FALLBACK_PORT_COUNT: u16 = 200;

/// Resolution outcome for the direct-connect listen port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PortResolution {
    /// Effective listen port: conf `ListenPort`, the firewall allow rule and `direct_report`
    /// must all take this same value.
    Port(u16),
    /// Neither the configured port nor any fallback candidate binds: the plan pins no port, no candidate
    /// endpoint is reported, an explicit error is raised (troubleshooting command in the module docs); never pretend direct connect is fine.
    Blocked,
}

/// Resolve the effective listen port (pure function; probe is injectable for cross-platform unit tests).
///
/// - `configured`: the `[dataplane.direct_connect] listen_port` config value;
/// - `snapshot_port`: the `tunnel_listen_port` reading from `inspect_sync()` (evidence of the
///   active binding; `Some(0)` = a tunnel reading with a failed bind, treated as unbound);
/// - `persisted`: the previous round's effective port from the ledger ([load]);
/// - `is_windows`: probe fallback is Windows-only; other platforms always take the configured port (behavior unchanged);
/// - `probe`: port-bindability probe ([`probe_bind`] in production).
pub(super) fn resolve(
    configured: u16,
    snapshot_port: Option<u16>,
    persisted: Option<u16>,
    is_windows: bool,
    probe: &dyn Fn(u16) -> bool,
) -> PortResolution {
    if !is_windows {
        return PortResolution::Port(configured);
    }
    // A service that failed to bind reports 0 in the dump (reading exists but nothing bound): not active-binding evidence.
    let snapshot_port = snapshot_port.filter(|p| *p != 0);
    // ① The configured port is actively bound: probing would always self-occupy — use it directly with zero probes.
    if snapshot_port == Some(configured) {
        return PortResolution::Port(configured);
    }
    // ② The configured port is bindable (covers self-healing back to it once the excluded range clears).
    if probe(configured) {
        return PortResolution::Port(configured);
    }
    // ③ Actively bound on the ledger port: keep it, never switch (churn only causes pointless disconnects).
    if let (Some(ledger_port), Some(in_use)) = (persisted, snapshot_port) {
        if ledger_port == in_use {
            return PortResolution::Port(ledger_port);
        }
    }
    // ④ Fallback window scan; a snapshot port inside the window = active-binding evidence (kept even if the ledger is lost).
    for offset in 0..FALLBACK_PORT_COUNT {
        let port = FALLBACK_PORT_BASE + offset;
        if Some(port) == snapshot_port || probe(port) {
            return PortResolution::Port(port);
        }
    }
    // ⑤ Nothing binds: explicit Blocked; the caller gates off and reports the error.
    PortResolution::Blocked
}

/// Port-bindability probe: bind `0.0.0.0:<port>` (UDP) in the same shape as `wireguard.exe`;
/// close immediately on success (the probe socket is discarded). Rejection by an excluded range (WSAEACCES, the
/// user-mode equivalent of the service-side `0xc0000022`) and occupation (WSAEADDRINUSE) both count as unbindable —
/// probe-bind matches the service-side bind semantics and is the strongest evidence available before apply
/// (a TOCTOU gap remains between probe and service start, covered by the reconcile port-drift verdict).
pub(super) fn probe_bind(port: u16) -> bool {
    std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, port)).is_ok()
}

/// Effective-port ledger path: `{state_dir}/direct-port.json`.
pub(super) fn ledger_path(state_dir: &str) -> std::path::PathBuf {
    std::path::Path::new(state_dir).join("direct-port.json")
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct DirectPortLedger {
    /// The previous round's effective listen port; `null` = all candidates blocked (direct connect gated off).
    listen_port: Option<u16>,
}

/// Read the ledger: missing/corrupt is treated as "no ledger" (`None`; the next resolution round re-converges —
/// bad data is never taken as active-binding evidence).
pub(super) fn load(state_dir: &str) -> Option<u16> {
    let raw = std::fs::read_to_string(ledger_path(state_dir)).ok()?;
    serde_json::from_str::<DirectPortLedger>(&raw)
        .ok()
        .and_then(|ledger| ledger.listen_port)
}

/// Write the ledger (failures are only logged by the caller: the ledger is an anti-churn optimization, never blocks the data plane).
pub(super) fn save(state_dir: &str, port: Option<u16>) -> Result<(), String> {
    let path = ledger_path(state_dir);
    let raw = serde_json::to_string(&DirectPortLedger { listen_port: port })
        .map_err(|e| format!("serialize direct-port ledger: {e}"))?;
    std::fs::write(&path, raw).map_err(|e| format!("write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stub recording the probe call order: returns a preset bindable set; tests assert which ports were probed.
    struct ProbeRecorder {
        bindable: Vec<u16>,
        calls: std::cell::RefCell<Vec<u16>>,
    }

    impl ProbeRecorder {
        fn new(bindable: &[u16]) -> Self {
            Self {
                bindable: bindable.to_vec(),
                calls: std::cell::RefCell::new(Vec::new()),
            }
        }
        fn probe(&self, port: u16) -> bool {
            self.calls.borrow_mut().push(port);
            self.bindable.contains(&port)
        }
        fn called(&self) -> Vec<u16> {
            self.calls.borrow().clone()
        }
    }

    #[test]
    fn non_windows_keeps_configured_port_and_never_probes() {
        // Linux behavior unchanged: always the configured port; probing and ledger never participate.
        let recorder = ProbeRecorder::new(&[]);
        let resolved = resolve(51820, None, Some(52931), false, &|p| recorder.probe(p));
        assert_eq!(resolved, PortResolution::Port(51820));
        assert!(recorder.called().is_empty());
    }

    /// ① Configured port actively bound: used directly with zero probes (probing the active port always self-occupies).
    #[test]
    fn snapshot_at_configured_port_short_circuits_without_probing() {
        let recorder = ProbeRecorder::new(&[]);
        let resolved = resolve(51820, Some(51820), None, true, &|p| recorder.probe(p));
        assert_eq!(resolved, PortResolution::Port(51820));
        assert!(recorder.called().is_empty());
    }

    /// Configured port bindable: converges after one probe (covers the self-heal path once the excluded range clears).
    #[test]
    fn bindable_configured_port_wins() {
        let recorder = ProbeRecorder::new(&[51820]);
        let resolved = resolve(51820, None, Some(52931), true, &|p| recorder.probe(p));
        assert_eq!(resolved, PortResolution::Port(51820));
        assert_eq!(recorder.called(), vec![51820]);
    }

    /// ③ Configured port blocked + actively bound on the ledger port: keep the ledger port, never switch
    /// (churn only causes pointless disconnects).
    #[test]
    fn persisted_port_in_use_is_kept_without_churn() {
        let recorder = ProbeRecorder::new(&[]);
        let resolved = resolve(51820, Some(52931), Some(52931), true, &|p| {
            recorder.probe(p)
        });
        assert_eq!(resolved, PortResolution::Port(52931));
        // Only the configured port probed once (the anti-self-occupancy active-binding check runs first); no fallback-window scan.
        assert_eq!(recorder.called(), vec![51820]);
    }

    /// ④ Both configured and ledger ports unavailable (tunnel absent): scan the fallback window for the first bindable port.
    #[test]
    fn tunnel_absent_falls_back_to_first_bindable_candidate() {
        // 52900/52901 blocked, 52902 bindable.
        let recorder = ProbeRecorder::new(&[52902]);
        let resolved = resolve(51820, None, Some(52931), true, &|p| recorder.probe(p));
        assert_eq!(resolved, PortResolution::Port(FALLBACK_PORT_BASE + 2));
        assert_eq!(recorder.called(), vec![51820, 52900, 52901, 52902]);
    }

    /// Snapshot port inside the fallback window with the ledger lost: taken as active-binding evidence and adopted directly
    /// (prevents the "ledger gone, switch ports" churn).
    #[test]
    fn snapshot_inside_fallback_window_is_adopted_without_ledger() {
        let recorder = ProbeRecorder::new(&[]);
        let resolved = resolve(51820, Some(52931), None, true, &|p| recorder.probe(p));
        assert_eq!(resolved, PortResolution::Port(52931));
        // The active port itself is not probed (being active is the evidence): only the configured port + 52900..=52930 probed.
        let mut expected = vec![51820];
        expected.extend(FALLBACK_PORT_BASE..52931);
        assert_eq!(recorder.called(), expected);
    }

    /// A tunnel that failed to bind reports port 0 in the dump: not active-binding evidence (Some(0) is treated as
    /// unbound; 0 is never adopted as the effective port).
    #[test]
    fn snapshot_port_zero_is_treated_as_unbound() {
        let recorder = ProbeRecorder::new(&[52900]);
        let resolved = resolve(51820, Some(0), None, true, &|p| recorder.probe(p));
        assert_eq!(resolved, PortResolution::Port(52900));
        assert_eq!(recorder.called(), vec![51820, 52900]);
    }

    /// ⑤ Neither the configured port nor the whole fallback window binds: explicit Blocked (the caller gates off and reports —
    /// never silently ride the relay while pretending direct connect is fine).
    #[test]
    fn all_candidates_blocked_reports_blocked() {
        let recorder = ProbeRecorder::new(&[]);
        let resolved = resolve(51820, None, None, true, &|p| recorder.probe(p));
        assert_eq!(resolved, PortResolution::Blocked);
        // Probed the configured port + the full window (boundary-aligned: FALLBACK_PORT_COUNT candidates).
        assert_eq!(recorder.called().len(), 1 + FALLBACK_PORT_COUNT as usize);
        assert_eq!(recorder.called()[0], 51820);
    }

    /// Probe ground truth: an occupied port reads false, a released one true (probe-bind matches real bind semantics).
    /// The holder socket must also be a wildcard bind — Windows allows "specific 127.0.0.1" and
    /// "wildcard 0.0.0.0" to coexist on the same port (Linux rejects it; verified on CI windows-latest),
    /// so wildcard-vs-wildcard is the conflict semantics consistent across all three platforms, and also the production shape
    /// (wireguard.exe and the probe both bind 0.0.0.0).
    #[test]
    fn probe_bind_reports_real_bindability() {
        let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        assert!(!probe_bind(port), "held port must read as not bindable");
        drop(socket);
        assert!(probe_bind(port), "released port must read as bindable");
    }

    /// Ledger round-trip: both Some/None persist and read back; a corrupt file reads as no ledger.
    #[test]
    fn ledger_round_trips_and_corruption_reads_as_absent() {
        let dir = std::env::temp_dir().join(format!(
            "meshlet-direct-port-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let state_dir = dir.to_str().unwrap().to_string();
        assert_eq!(load(&state_dir), None);
        save(&state_dir, Some(52931)).unwrap();
        assert_eq!(load(&state_dir), Some(52931));
        save(&state_dir, None).unwrap();
        assert_eq!(load(&state_dir), None);
        std::fs::write(ledger_path(&state_dir), "not json").unwrap();
        assert_eq!(load(&state_dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
