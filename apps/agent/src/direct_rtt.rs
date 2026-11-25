//! Direct-peer RTT background runtime (R-DIAG-2).
//!
//! `ping_rtt_ms` spends up to 2s per peer. Running it inline in the agent tick
//! could stop heartbeat/route reconciliation for seconds with several peers.
//! This runtime owns a dedicated worker thread: the tick only updates the
//! candidate set (and `kick`s an immediate probe) then reads the latest snapshot
//! — it never waits on a ping.
//!
//! Each candidate is probed against its overlay VIP first; when that gets no
//! ICMP reply (WireGuard interfaces / firewalls commonly drop overlay ICMP
//! while the tunnel is perfectly alive — fresh handshake proves it), the probe
//! falls back to the peer's endpoint underlay address. Only when both paths
//! stay silent is the peer reported unprovable (`RttSource::Unreachable`);
//! the latest handshake remains the primary liveness evidence in the UI.
//!
//! Results are best-effort (a probe in flight when the tick reads may be missing;
//! the tick uses the last known value, same as before). No control-plane load is
//! added: candidates come from the existing 30s direct reconciliation.

use std::collections::{BTreeMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use meshlet_network::SystemBackend;

/// Worker idle timeout between rounds when no candidate refresh happens.
const RTT_IDLE_TIMEOUT_SECS: u64 = 5;

/// The verdict of one probe for a single peer: the RTT reading + its source.
///
/// WireGuard interfaces / firewalls often do not answer ICMP to the overlay VIP (a real
/// imac lost 100% of packets while the handshake was fresh = the link is alive), so when the
/// overlay is unreachable the probe falls back to pinging the peer endpoint's underlay
/// address - only when both paths are silent is it ruled "unmeasurable"; the latest handshake
/// remains the primary liveness evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RttProbe {
    /// Measured round-trip milliseconds; `None` = both paths unresponsive (unmeasurable).
    pub rtt_ms: Option<u64>,
    /// The source of the reading.
    pub source: RttSource,
}

impl RttProbe {
    /// Placeholder used when the snapshot has no reading for this peer yet (probe in flight): not probed.
    pub fn unknown() -> Self {
        Self {
            rtt_ms: None,
            source: RttSource::Unprobed,
        }
    }
}

/// The source of an RTT reading (the tooltip basis for the panel/console RTT column), an **honest four-way**:
/// measured successfully, handshake-fresh fallback, measurement failed, not yet in turn - never misreporting
/// "not measured" as "the link is dead", nor "handshake fresh, link alive" as "unmeasured".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RttSource {
    /// The direct path measured successfully (overlay VIP up, or the underlay endpoint fallback up).
    Overlay,
    /// Both the overlay and the endpoint unresponsive, with no fresh handshake to fall back on: measurement failed.
    Unreachable,
    /// The probe has not produced a result yet (no snapshot record): not in turn, not a verdict.
    Unprobed,
}

impl RttSource {
    /// Stable string key (goes into the ledger / `direct-peers.json` / the heartbeat; the display layer translates).
    /// Honest four-way: measured successfully = `probe_ok`; unmeasurable but a fresh handshake exists =
    /// `handshake_fresh` (overridden and annotated on the agent side from the handshake reading); both paths
    /// unresponsive and the handshake stale = `probe_failed`; probe in flight = `unprobed`.
    pub fn as_str(self) -> &'static str {
        match self {
            RttSource::Overlay => "probe_ok",
            RttSource::Unreachable => "probe_failed",
            RttSource::Unprobed => "unprobed",
        }
    }
}

/// Pure selection logic (unit-testable): overlay up -> the overlay reading; down -> fall back to the
/// endpoint (succeeds only if an endpoint exists and pings through); both down / no endpoint to fall back to
/// -> measurement failed (whether rtt_source falls back to handshake_fresh is annotated on the agent side from the handshake reading).
fn resolve_rtt(
    overlay_ms: Option<u128>,
    endpoint_ip: Option<Ipv4Addr>,
    endpoint_ms: Option<u128>,
) -> RttProbe {
    let cap = |v: Option<u128>| v.map(|value| value.min(u64::MAX as u128) as u64);
    if let Some(ms) = overlay_ms {
        return RttProbe {
            rtt_ms: cap(Some(ms)),
            source: RttSource::Overlay,
        };
    }
    match (endpoint_ip, endpoint_ms) {
        (Some(_), Some(ms)) => RttProbe {
            rtt_ms: cap(Some(ms)),
            source: RttSource::Overlay,
        },
        _ => RttProbe {
            rtt_ms: None,
            source: RttSource::Unreachable,
        },
    }
}

type Rtts = BTreeMap<String, RttProbe>;
/// One probe candidate: public key + overlay VIP + the peer endpoint's underlay address
/// (`None` when there is no direct endpoint or parsing failed, meaning the peer has no fallback path).
pub type RttCandidate = (String, Ipv4Addr, Option<Ipv4Addr>);

/// Dedicated RTT probe worker. Candidate set and RTT snapshot are shared with
/// the agent tick via short critical sections; the worker never blocks the tick.
pub struct DirectRttRuntime {
    candidates: Arc<Mutex<Vec<RttCandidate>>>,
    rtts: Arc<Mutex<Rtts>>,
    kick: Arc<Mutex<VecDeque<()>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl DirectRttRuntime {
    pub fn start(backend: SystemBackend) -> Self {
        let candidates: Arc<Mutex<Vec<RttCandidate>>> = Arc::new(Mutex::new(Vec::new()));
        let rtts = Arc::new(Mutex::new(BTreeMap::new()));
        let kick = Arc::new(Mutex::new(VecDeque::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = {
            let candidates = Arc::clone(&candidates);
            let rtts = Arc::clone(&rtts);
            let kick = Arc::clone(&kick);
            let stop = Arc::clone(&stop);
            std::thread::Builder::new()
                .name("meshlet-direct-rtt".into())
                .spawn(move || loop {
                    wait_kick_or_timeout(&kick, &stop, RTT_IDLE_TIMEOUT_SECS);
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let batch = candidates.lock().unwrap_or_else(|e| e.into_inner()).clone();
                    let mut next = BTreeMap::new();
                    for (public_key, vip, endpoint_ip) in batch {
                        if stop.load(Ordering::Relaxed) {
                            return;
                        }
                        let overlay = backend.ping_rtt_ms(vip);
                        let endpoint = match overlay {
                            Some(_) => None, // overlay is up, so the endpoint costs no further 2s.
                            None => endpoint_ip.and_then(|ip| backend.ping_rtt_ms(ip)),
                        };
                        next.insert(public_key, resolve_rtt(overlay, endpoint_ip, endpoint));
                    }
                    *rtts.lock().unwrap_or_else(|e| e.into_inner()) = next;
                })
                .expect("spawn direct RTT thread")
        };
        Self {
            candidates,
            rtts,
            kick,
            stop,
            handle: Some(handle),
        }
    }

    /// Replace candidates and wake the worker to probe immediately (background;
    /// the caller never waits). Empty set clears the snapshot on the next round.
    /// The tuple's third element = the peer endpoint's underlay address (the port stripped off `ip:port`;
    /// `None` when there is no direct endpoint or parsing failed, meaning the peer has no fallback path).
    pub fn update_candidates(&self, candidates: Vec<RttCandidate>) {
        *self.candidates.lock().unwrap_or_else(|e| e.into_inner()) = candidates;
        self.kick
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(());
    }

    /// Latest RTT snapshot. Never blocks on ping.
    pub fn snapshot(&self) -> Rtts {
        self.rtts.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Whether the worker thread is alive.
    pub fn is_running(&self) -> bool {
        self.handle.is_some()
    }
}

impl Drop for DirectRttRuntime {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        drop(self.handle.take());
    }
}

/// Wait for a kick signal or idle timeout; stop returns immediately.
fn wait_kick_or_timeout(kick: &Mutex<VecDeque<()>>, stop: &AtomicBool, timeout_secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        if kick
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front()
            .is_some()
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fallback selection logic (gate test): overlay up = measured reading; overlay down ->
    /// fall back to the endpoint; both paths down (or no endpoint to fall back to) = measurement failed. The source
    /// key is an honest four-way (probe_ok / probe_failed / unprobed + agent-side handshake_fresh).
    #[test]
    fn rtt_fallback_prefers_overlay_then_endpoint_then_unreachable() {
        let underlay: Ipv4Addr = "203.0.113.7".parse().unwrap();

        // Overlay up: use the overlay reading directly, spending no second probe.
        assert_eq!(
            resolve_rtt(Some(12), Some(underlay), None),
            RttProbe {
                rtt_ms: Some(12),
                source: RttSource::Overlay
            }
        );
        // Overlay down, endpoint up: fall back to the endpoint reading - likewise a measured success (probe_ok).
        assert_eq!(
            resolve_rtt(None, Some(underlay), Some(35)),
            RttProbe {
                rtt_ms: Some(35),
                source: RttSource::Overlay
            }
        );
        // Overlay down and endpoint down too: measurement failed (the panel shows an em dash + the honest source;
        // if the handshake is fresh, the agent side overrides the annotation to handshake_fresh).
        assert_eq!(
            resolve_rtt(None, Some(underlay), None),
            RttProbe {
                rtt_ms: None,
                source: RttSource::Unreachable
            }
        );
        // Overlay down and no endpoint to fall back to either (no direct path): likewise measurement failed.
        assert_eq!(
            resolve_rtt(None, None, None),
            RttProbe {
                rtt_ms: None,
                source: RttSource::Unreachable
            }
        );
        // The source key is a stable string (goes into the ledger / direct-peers.json / the heartbeat).
        assert_eq!(RttSource::Overlay.as_str(), "probe_ok");
        assert_eq!(RttSource::Unreachable.as_str(), "probe_failed");
        assert_eq!(RttSource::Unprobed.as_str(), "unprobed");
        assert_eq!(RttProbe::unknown().source.as_str(), "unprobed");
    }

    #[test]
    fn snapshot_never_blocks_and_reflects_background_probe() {
        let backend = SystemBackend::new();
        let rt = DirectRttRuntime::start(backend);
        assert!(rt.is_running());
        // Update candidates and immediately read snapshot: must return fast,
        // never waiting on the worker's ping.
        let start = Instant::now();
        rt.update_candidates(vec![(
            "peer-a".into(),
            "10.240.0.3".parse().unwrap(),
            Some("203.0.113.7".parse().unwrap()),
        )]);
        let _snap = rt.snapshot();
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "snapshot read must not block on ping"
        );
        // First snapshot may be empty (probe in flight); poll until the worker
        // records a result. The platform backend decides whether it is Some or
        // None; the reader never blocks on that probe.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let snap = rt.snapshot();
            if let Some(rtt) = snap.get("peer-a") {
                // Real Linux backend may or may not reach the address; the point
                // is the worker recorded *something* without blocking the reader.
                let _ = rtt;
                break;
            }
            if Instant::now() >= deadline {
                panic!("RTT worker did not record peer-a in time");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        drop(rt);
    }

    #[test]
    fn empty_candidates_clear_snapshot() {
        let backend = SystemBackend::new();
        let rt = DirectRttRuntime::start(backend);
        rt.update_candidates(vec![("peer-a".into(), "10.240.0.3".parse().unwrap(), None)]);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if rt.snapshot().contains_key("peer-a") {
                break;
            }
            if Instant::now() >= deadline {
                panic!("worker did not record initial candidate");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        // Empty set: next round records an empty snapshot.
        rt.update_candidates(Vec::new());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if rt.snapshot().is_empty() {
                break;
            }
            if Instant::now() >= deadline {
                panic!("worker did not clear snapshot");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        drop(rt);
    }
}
