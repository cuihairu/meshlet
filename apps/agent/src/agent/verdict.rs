//! Peer-dial verdict helpers.

use meshlet_domain::PeerLinkState;

/// `peer dial` 结果判定（纯函数，可测）：目标对端当前状态 → (ok, mode, message)。
/// `None` = 对端不在管（本周期候选集外）——按失败呈现，绝不假装成功。
pub(super) fn dial_verdict(
    status: Option<&crate::direct::DirectPeer>,
) -> (bool, &'static str, &'static str) {
    match status {
        Some(peer) => match peer.state {
            PeerLinkState::Direct => (true, "p2p_direct", "direct link established"),
            PeerLinkState::DirectPending { .. } => {
                (true, "direct_pending", "dial initiated, awaiting handshake")
            }
            PeerLinkState::Relay => (false, "hub_relay", "no direct path; keeping hub relay"),
        },
        None => (false, "hub_relay", "node is not a direct candidate"),
    }
}
