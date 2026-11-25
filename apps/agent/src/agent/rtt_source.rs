//! RTT source labeling.

use crate::direct_rtt::RttProbe;

/// rtt_source labeled honestly (pure function, four states):
/// - measured successfully (`probe_ok`): the RTT has a reading, and its source is
///   that measurement;
/// - no reading obtained but **the last handshake is fresh**
///   (<= [`meshlet_domain::DIRECT_PROMOTE_FRESH_SECS`]) -> `handshake_fresh`: the
///   liveness evidence is the handshake, not a ping - the Windows mesh firewall
///   drops ICMP to the wg interface 100% of the time (imac evidence 2026-11-07),
///   so reporting "not measurable" as a link conclusion would mislead;
/// - everything else (both paths unresponsive and the handshake is not fresh /
///   no reading and no handshake) -> the probe thread's honest verdict
///   (`probe_failed` / `unprobed`).
pub(super) fn honest_rtt_source(
    probe: &RttProbe,
    last_handshake_at: Option<u64>,
    now_secs: u64,
) -> Option<&'static str> {
    if probe.rtt_ms.is_some() {
        return Some("probe_ok");
    }
    if last_handshake_at.is_some_and(|ts| {
        ts > 0 && ts <= now_secs && now_secs - ts <= meshlet_domain::DIRECT_PROMOTE_FRESH_SECS
    }) {
        return Some("handshake_fresh");
    }
    Some(probe.source.as_str())
}
