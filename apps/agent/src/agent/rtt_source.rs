//! RTT source labeling.

use crate::direct_rtt::RttProbe;

/// rtt_source 如实标注（纯函数，四态）：
/// - 实测成功（`probe_ok`）：RTT 有读数，来源就是实测；
/// - 没测到读数但**最近握手新鲜**（≤ [`meshlet_domain::DIRECT_PROMOTE_FRESH_SECS`]）
///   → `handshake_fresh`：活性证据是握手不是 ping——Windows 网格防火墙对
///   wg 接口 ICMP 100% 丢包（imac 2026-11-07 取证），「不可测」谎报成链路
///   结论会误导；
/// - 其余（两路均无响应且握手也不新鲜 / 读数缺失且无握手）→ 探测线程的如实
///   结论（`probe_failed` / `unprobed`）。
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
