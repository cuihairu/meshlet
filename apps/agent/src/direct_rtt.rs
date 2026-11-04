//! Direct-peer RTT background runtime (R-DIAG-2).
//!
//! `ping_rtt_ms` spends up to 2s per peer. Running it inline in the agent tick
//! could stop heartbeat/route reconciliation for seconds with several peers.
//! This runtime owns a dedicated worker thread: the tick only updates the
//! candidate set (and `kick`s an immediate probe) then reads the latest snapshot
//! — it never waits on a ping.
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

type Rtts = BTreeMap<String, Option<u64>>;

/// Dedicated RTT probe worker. Candidate set and RTT snapshot are shared with
/// the agent tick via short critical sections; the worker never blocks the tick.
pub struct DirectRttRuntime {
    candidates: Arc<Mutex<Vec<(String, Ipv4Addr)>>>,
    rtts: Arc<Mutex<Rtts>>,
    kick: Arc<Mutex<VecDeque<()>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl DirectRttRuntime {
    pub fn start(backend: SystemBackend) -> Self {
        let candidates = Arc::new(Mutex::new(Vec::new()));
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
                    for (public_key, vip) in batch {
                        if stop.load(Ordering::Relaxed) {
                            return;
                        }
                        let rtt = backend
                            .ping_rtt_ms(vip)
                            .map(|value| value.min(u64::MAX as u128) as u64);
                        next.insert(public_key, rtt);
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
    pub fn update_candidates(&self, candidates: Vec<(String, Ipv4Addr)>) {
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

    #[test]
    fn snapshot_never_blocks_and_reflects_background_probe() {
        let backend = SystemBackend::new();
        let rt = DirectRttRuntime::start(backend);
        assert!(rt.is_running());
        // Update candidates and immediately read snapshot: must return fast,
        // never waiting on the worker's ping.
        let start = Instant::now();
        rt.update_candidates(vec![("peer-a".into(), "10.240.0.3".parse().unwrap())]);
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
        rt.update_candidates(vec![("peer-a".into(), "10.240.0.3".parse().unwrap())]);
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
