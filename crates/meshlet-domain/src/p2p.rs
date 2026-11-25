//! P2P node direct connect ([ADR-015](../../docs/decisions/adr-015-p2p-direct-connect.md)):
//! types, direct-path decisions and the peer link state machine.
//!
//! Pure logic layer, no IO: candidate endpoint classification (public / LAN), direct-path
//! decision (same-LAN direct / public hole punch / keep hub relay), the `/32` split and conflict
//! check of a direct Peer's AllowedIPs, and the promotion/demotion state machine driven by
//! 30s probes. Interface enumeration, `wg` commands and hole-punch packets belong to the agent / meshlet-network execution layer.
//!
//! Design points (mapping the spec point by point):
//! - candidate endpoints pushed by the hub are a **suggestion**, not a promise: the decision
//!   function falls back to relay for any unreachable candidate, and never errors;
//! - a direct Peer's AllowedIPs carries only the peer's overlay `/32` - WireGuard's longest-prefix
//!   match makes `/32` naturally outrank the hub peer's whole-segment route, so removing `/32`
//!   falls back to the hub automatically, without reconfiguring any other node;
//! - promotion and fallback are a local state machine on the same agent host ([PeerLinkState]),
//!   transitioning once per probe cycle, idempotent and replayable.
//!
//! Sub-modules, split by responsibility:
//! - `endpoint`: candidate endpoint types, RFC1918 / same-subnet checks and the direct-path decision;
//! - `report`: hub-side reporting and distribution - candidate merging, `peers/endpoints` aggregation;
//! - `allowed_ips`: a direct Peer's AllowedIPs `/32` and conflict checks;
//! - `link`: peer link state machine, probe classification, hysteresis constants and the §12.3 link status report contract.

mod allowed_ips;
mod endpoint;
mod link;
mod report;

#[cfg(test)]
mod test_support;

pub use allowed_ips::{direct_peer_allowed_ips, DirectPeerError};
pub use endpoint::{
    decide_direct_path, is_lan_reachable, is_private_ip, DirectDecision, EndpointCandidate,
    EndpointKind,
};
pub use link::{
    classify_probe, classify_promote_probe, on_probe, DirectCandidateStatus, DirectLinkStatus,
    PeerLinkAction, PeerLinkState, ProbeResult, DIRECT_HEALTH_WINDOW_SECS,
    DIRECT_PERSISTENT_KEEPALIVE_SECS, DIRECT_PROBE_INTERVAL_SECS, DIRECT_PROMOTE_FRESH_SECS,
    MAX_PROMOTE_ATTEMPTS,
};
pub use report::{
    endpoint_candidates, peer_endpoints_for, public_candidate, DeviceDirectState,
    DirectEndpointReport, PeerEndpoints,
};
