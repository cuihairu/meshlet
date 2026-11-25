//! Peer-dial verdict helpers.

use meshlet_domain::PeerLinkState;

/// `peer dial` verdict (pure function, testable): the target peer's current state
/// -> (ok, mode, message). `None` = the peer is out of scope (outside this cycle's
/// candidate set) - present as failure, never pretend success.
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
