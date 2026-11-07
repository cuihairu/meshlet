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
//! 「最近握手」 remains the primary liveness evidence in the UI.
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

/// 单对端一次探测的结论：RTT 读数 + 来源。
///
/// WireGuard 接口 / 防火墙常不答 overlay VIP 的 ICMP（真机 imac 100% 丢包
/// 但握手新鲜 = 链路活），所以 overlay 不通时回退 ping 对端 endpoint 的
/// underlay 地址——两路都无响应才判「不可测」；「最近握手」仍是活性主证据。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RttProbe {
    /// 实测往返毫秒；`None` = 两路都无响应（不可测）。
    pub rtt_ms: Option<u64>,
    /// 读数来源。
    pub source: RttSource,
}

impl RttProbe {
    /// 快照里还没有该对端的读数（探测在途）时的占位：未测。
    pub fn unknown() -> Self {
        Self {
            rtt_ms: None,
            source: RttSource::Unprobed,
        }
    }
}

/// RTT 读数来源（面板/控制台 RTT 列的 tooltip 依据），**如实四态**：
/// 实测成功、握手新鲜兜底、实测失败、没轮到——不把「没测到」谎报成
/// 「链路死了」，也不把「握手新鲜链路活着」谎报成「未测」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RttSource {
    /// 直连路径实测成功（overlay VIP 通，或回退 underlay endpoint 通）。
    Overlay,
    /// overlay 与 endpoint 均无响应，且无新鲜握手可兜底：实测失败。
    Unreachable,
    /// 探测尚未出结果（快照无记录）：没轮到，不是结论。
    Unprobed,
}

impl RttSource {
    /// 稳定字符串键（进 ledger / `direct-peers.json` / 心跳，展示层再翻译）。
    /// 如实四态：实测成功 = `probe_ok`；不可测但有新鲜握手 = `handshake_fresh`
    /// （由 agent 侧按握手读数覆盖标注）；两路均无响应且握手不新鲜 =
    /// `probe_failed`；探测在途 = `unprobed`。
    pub fn as_str(self) -> &'static str {
        match self {
            RttSource::Overlay => "probe_ok",
            RttSource::Unreachable => "probe_failed",
            RttSource::Unprobed => "unprobed",
        }
    }
}

/// 纯选择逻辑（可单测）：overlay 通 → overlay 读数；不通 → 回退 endpoint
/// （有 endpoint 且 ping 通才成功）；两路都不通 / 无 endpoint 可回退 → 实测
/// 失败（rtt_source 是否兜底为 handshake_fresh 由 agent 侧按握手读数标注）。
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
/// 一个探测候选：公钥 + overlay VIP + 对端 endpoint 的 underlay 地址
/// （无直连 endpoint / 解析失败为 `None`，该对端没有回退路径）。
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
                            Some(_) => None, // overlay 通，endpoint 无需再花 2s。
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
    /// 元组第三项 = 对端 endpoint 的 underlay 地址（`ip:port` 去端口；无直连
    /// endpoint / 解析失败为 `None`，该对端没有回退路径）。
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

    /// 回退选择逻辑（门禁测试）：overlay 通 = 实测读数；overlay 不通 →
    /// 回退 endpoint；两路都不通（或无 endpoint 可回退）= 实测失败。来源键
    /// 如实四态（probe_ok / probe_failed / unprobed + agent 侧 handshake_fresh）。
    #[test]
    fn rtt_fallback_prefers_overlay_then_endpoint_then_unreachable() {
        let underlay: Ipv4Addr = "203.0.113.7".parse().unwrap();

        // overlay 通：直接用 overlay 读数，不花第二次探测。
        assert_eq!(
            resolve_rtt(Some(12), Some(underlay), None),
            RttProbe {
                rtt_ms: Some(12),
                source: RttSource::Overlay
            }
        );
        // overlay 不通、endpoint 通：回退 endpoint 读数——同为实测成功（probe_ok）。
        assert_eq!(
            resolve_rtt(None, Some(underlay), Some(35)),
            RttProbe {
                rtt_ms: Some(35),
                source: RttSource::Overlay
            }
        );
        // overlay 不通、endpoint 也不通：实测失败（面板显示「—」+ 如实来源；
        // 若握手新鲜，agent 侧覆盖标注为 handshake_fresh）。
        assert_eq!(
            resolve_rtt(None, Some(underlay), None),
            RttProbe {
                rtt_ms: None,
                source: RttSource::Unreachable
            }
        );
        // overlay 不通、也没有 endpoint 可回退（无直连路径）：同样实测失败。
        assert_eq!(
            resolve_rtt(None, None, None),
            RttProbe {
                rtt_ms: None,
                source: RttSource::Unreachable
            }
        );
        // 来源键是稳定字符串（进 ledger / direct-peers.json / 心跳）。
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
