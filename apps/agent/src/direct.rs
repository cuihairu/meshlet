//! P2P direct-connection manager (§12): drives the domain-layer state machine per
//! directly-connectable peer ([on_probe]) and translates state transitions into `wg
//! set` kernel calls (via the `meshlet_network` backend). Pure logic
//! ([plan_updates], [DirectManager] state retention) is separated from IO (fetching
//! endpoints, `wg set`): the former is unit-testable without privileges, the latter
//! is executed in [crate::agent::Agent]. Each cycle:
//! - pull the directly-connectable candidates published by the server
//!   (advice, not a promise);
//! - per candidate peer: `decide_direct_path` (same LAN / public hole punch /
//!   relay) → `classify_probe` (handshake age) → `on_probe` (state
//!   transition) → actions;
//! - peers no longer in the candidate set (revoked/offline): fall back to hub
//!   and remove;
//! - actions are **local** wg config additions/removals (allowed-ips only
//!   carries the peer `/32`); never touches other nodes nor the server plan
//!   (§12).
//!
//! Restart recovery: direct peers are persisted in the local
//! ledger (`{state_dir}/direct.json`, keep set only) — after a restart the ledger
//! restores them as "established" (Direct); the next cycle converges on handshake
//! health (stale → fall back, healthy → keep). **Never guess from the kernel**: if
//! any non-hub kernel peer were treated as an owned direct peer, drift detection
//! for foreign peers would be defeated (a live-machine test once caught exactly
//! that regression).

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::Path;

use meshlet_domain::{
    classify_probe, classify_promote_probe, decide_direct_path, direct_peer_allowed_ips,
    is_lan_reachable, on_probe, DirectDecision, DirectLinkStatus, EndpointCandidate, EndpointKind,
    Ipv4Cidr, PeerEndpoints, PeerLinkAction, PeerLinkState, DIRECT_HEALTH_WINDOW_SECS,
    DIRECT_PERSISTENT_KEEPALIVE_SECS, DIRECT_PROMOTE_FRESH_SECS, MAX_PROMOTE_ATTEMPTS,
};

/// Per-peer direct-connection management state (domain state machine state +
/// the peer's overlay address).
#[derive(Debug, Clone, PartialEq)]
pub struct DirectPeer {
    /// Peer overlay address (source of the AllowedIPs `/32`; the domain layer
    /// guarantees it is within the routed range).
    pub virtual_ipv4: Ipv4Addr,
    /// Current direct link state.
    pub state: PeerLinkState,
    /// Direct handshake age (seconds) at the last probe. Snapshotted at probe
    /// time (not re-read from the kernel at heartbeat time — the state
    /// machine's decision input and the reported signal share one source);
    /// `None` = pending or read failure.
    pub last_handshake_age_secs: Option<u64>,
    /// Peer name (R-DIAG-2 display; read from candidates).
    pub peer_name: String,
    /// Current direct endpoint (`ip:port`); empty when not established / no
    /// candidate.
    pub endpoint: String,
    /// Measured RTT (ms) on the last direct path probe.
    pub rtt_ms: Option<u64>,
    /// RTT source (`overlay` / `endpoint` / `unreachable`; `None` = unprobed).
    pub rtt_source: Option<String>,
    /// Last handshake Unix timestamp (seconds).
    pub last_handshake_at: Option<u64>,
    /// Total received bytes (wg reading).
    pub rx_bytes: u64,
    /// Total sent bytes (wg reading).
    pub tx_bytes: u64,
    /// SEL-004 candidate endpoint details (endpoint/RTT/loss/selected and
    /// reason); filled by the agent probe cycle
    /// ([DirectManager::record_candidates]).
    pub candidates: Vec<meshlet_domain::DirectCandidateStatus>,
    /// Memory face: the endpoint actually in use by the last direct link
    /// (recorded on promote, refreshed by kernel readings as wg roams).
    /// Re-promotion after falling back to relay prefers it — such faces
    /// (especially kernel-roamed source faces) are often absent from the
    /// server candidate table, and are the safest face against "no probe
    /// target → ever-present SEL-003 misjudgment"; picking SameLan by lowest
    /// IP from the candidate table would let a 10.x ZT face outrank it
    /// (2026-11-13 stranded incident). Cleared when pending verification
    /// fails (3 rounds without a handshake) — a dead face must not deadlock.
    /// Reset after restart (not persisted in the ledger).
    pub last_direct: Option<meshlet_domain::EndpointCandidate>,
}

/// Direct manager: peer public key → management state. Retained across cycles
/// (the state machine must remember pending attempt counts).
#[derive(Debug, Default)]
pub struct DirectManager {
    peers: BTreeMap<String, DirectPeer>,
}

/// Direct actions for one cycle (the executor issues `wg set` from these).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectUpdate {
    /// Establish direct: `allowed-ips` carries only the peer `/32` plus the
    /// direct endpoint and keepalive.
    Promote {
        public_key: String,
        allowed_ips: Vec<Ipv4Cidr>,
        endpoint: SocketAddrV4,
    },
    /// Fall back to hub: remove the peer's direct peer entry (the hub's whole
    /// routed range takes over automatically).
    Demote { public_key: String },
}

impl DirectManager {
    /// Build an empty manager (at agent startup).
    pub fn new() -> Self {
        Self::default()
    }

    /// Public keys of direct peers that should survive a plan replay
    /// (non-Relay state = we want them present).
    pub fn keep_keys(&self) -> BTreeSet<String> {
        self.peers
            .iter()
            .filter(|(_, peer)| peer.state != PeerLinkState::Relay)
            .map(|(key, _)| key.clone())
            .collect()
    }
    /// Whether this host can still reach a peer directly (for tray/diag;
    /// currently just "state is not Relay").
    pub fn is_direct(&self, public_key: &str) -> bool {
        self.peers
            .get(public_key)
            .is_some_and(|peer| peer.state == PeerLinkState::Direct)
    }

    /// A peer's current management state (for judging `peer dial` results).
    /// Returns `None` when the peer is unmanaged — not a candidate (outside
    /// this cycle's candidate set), so the dial result is reported as failed.
    pub fn status_of(&self, public_key: &str) -> Option<&DirectPeer> {
        self.peers.get(public_key)
    }

    /// One cycle: pull candidates → domain state machine → in-place update →
    /// return pending actions and decision records. See
    /// [plan_updates_logged]; the executor issues `wg set` per action
    /// (failures are only logged), and decision records are persisted after
    /// the executor fills in the evidence summary (decision log + mode-flip
    /// events).
    #[allow(clippy::too_many_arguments)]
    pub fn apply_plan(
        &mut self,
        wanted: &[PeerEndpoints],
        my_lan_subnets: &[Ipv4Cidr],
        scope: Ipv4Cidr,
        self_vip: Ipv4Addr,
        handshake_ages: &BTreeMap<String, u64>,
        degraded: &BTreeMap<String, bool>,
        unhealthy_faces: &BTreeSet<(String, EndpointCandidate)>,
        hold_relay: &BTreeSet<String>,
        suppress_promote: &BTreeMap<String, String>,
    ) -> (Vec<DirectUpdate>, Vec<PeerDecisionRecord>) {
        plan_updates_logged(
            wanted,
            my_lan_subnets,
            scope,
            self_vip,
            &mut self.peers,
            handshake_ages,
            degraded,
            unhealthy_faces,
            hold_relay,
            suppress_promote,
        )
    }

    /// Direct toggle turned off: clear management state and fall back all
    /// established direct links (hand back to hub). Returns the actions to
    /// issue (all [DirectUpdate::Demote]).
    pub fn demote_all(&mut self) -> Vec<DirectUpdate> {
        let keys: Vec<String> = self.peers.keys().cloned().collect();
        self.peers.clear();
        keys.into_iter()
            .map(|public_key| DirectUpdate::Demote { public_key })
            .collect()
    }

    /// Persist the keep set (`{state_dir}/direct.json`): the restart recovery
    /// source for "established". Writes only non-Relay peers; write failure
    /// is merely reported for the caller to log (the ledger is an
    /// accelerator, not the source of truth — losing it costs at most one
    /// extra probe cycle to rebuild direct links).
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        #[derive(serde::Serialize)]
        struct Entry<'a> {
            public_key: &'a str,
            virtual_ipv4: Ipv4Addr,
        }
        let peers: Vec<Entry> = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.state != PeerLinkState::Relay)
            .map(|(key, peer)| Entry {
                public_key: key,
                virtual_ipv4: peer.virtual_ipv4,
            })
            .collect();
        std::fs::write(path, serde_json::to_vec(&peers).unwrap_or_default())
    }

    /// Restore from the ledger (agent startup): all registered peers are held
    /// as "established" (Direct); the next cycle converges on handshake
    /// health. Missing/corrupt file → empty manager (leftover direct peers in
    /// the kernel get swept as drift by reconciliation, then rebuilt by the
    /// probe cycle — self-healing, no guessing).
    pub fn load(path: &Path) -> Self {
        #[derive(serde::Deserialize)]
        struct Entry {
            public_key: String,
            #[serde(default)]
            virtual_ipv4: Option<Ipv4Addr>,
        }
        let mut manager = Self::new();
        let Ok(raw) = std::fs::read(path) else {
            return manager;
        };
        let Ok(entries) = serde_json::from_slice::<Vec<Entry>>(&raw) else {
            return manager;
        };
        for entry in entries {
            manager.peers.insert(
                entry.public_key,
                DirectPeer {
                    virtual_ipv4: entry.virtual_ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    state: PeerLinkState::Direct,
                    last_handshake_age_secs: None,
                    peer_name: String::new(),
                    endpoint: String::new(),
                    rtt_ms: None,
                    rtt_source: None,
                    last_handshake_at: None,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    candidates: vec![],
                    last_direct: None,
                },
            );
        }
        manager
    }

    /// §12.3 link status report: one entry per managed peer (sorted by public
    /// key, deterministic). Carried to the hub with the heartbeat (console
    /// shows P2P/relay). Relay-state peers are not listed — they have no
    /// direct link, and the UI shows them as "relay" by default.
    pub fn link_statuses(&self) -> Vec<DirectLinkStatus> {
        self.peers
            .iter()
            .filter(|(_, peer)| peer.state != PeerLinkState::Relay)
            .map(|(key, peer)| DirectLinkStatus {
                public_key: key.clone(),
                virtual_ipv4: peer.virtual_ipv4,
                link_state: peer.state.as_str().to_string(),
                last_handshake_age_secs: peer.last_handshake_age_secs,
                peer_name: peer.peer_name.clone(),
                connection_mode: match peer.state {
                    PeerLinkState::Direct => "p2p_direct".into(),
                    PeerLinkState::DirectPending { .. } => "direct_pending".into(),
                    PeerLinkState::Relay => "hub_relay".into(),
                },
                endpoint: peer.endpoint.clone(),
                rtt_ms: peer.rtt_ms,
                rtt_source: peer.rtt_source.clone(),
                last_handshake_at: peer.last_handshake_at,
                rx_bytes: peer.rx_bytes,
                tx_bytes: peer.tx_bytes,
                candidates: peer.candidates.clone(),
            })
            .collect()
    }

    /// SEL-004: fill in a peer's candidate endpoint details (called by the
    /// executor each probe cycle). No-op when the peer is unmanaged or in
    /// Relay (no direct link to show).
    pub fn record_candidates(
        &mut self,
        public_key: &str,
        candidates: Vec<meshlet_domain::DirectCandidateStatus>,
    ) {
        if let Some(peer) = self.peers.get_mut(public_key) {
            if peer.state != PeerLinkState::Relay {
                peer.candidates = candidates;
            }
        }
    }

    /// Peers currently in a direct-related state (non-Relay): public key +
    /// overlay address, for the probe cycle's kernel readings and direct-path
    /// latency measurements (R-DIAG-2).
    pub fn direct_candidates(&self) -> Vec<(String, Ipv4Addr)> {
        self.peers
            .iter()
            .filter(|(_, peer)| peer.state != PeerLinkState::Relay)
            .map(|(key, peer)| (key.clone(), peer.virtual_ipv4))
            .collect()
    }

    /// Record the established direct endpoint (called by the executor after a
    /// successful Promote and on kernel-reading refreshes; §12.3 status
    /// report and console/CLI display). No-op when the peer is unmanaged or
    /// in Relay (no direct link). The memory face tracks kernel reality — the
    /// real source face after wg roaming (often absent from the candidate
    /// table) is exactly what re-promotion must be able to select again.
    pub fn record_endpoint(&mut self, public_key: &str, endpoint: String) {
        if let Some(peer) = self.peers.get_mut(public_key) {
            if peer.state != PeerLinkState::Relay {
                peer.last_direct = crate::agent::endpoint::parse_endpoint_candidate(&endpoint);
                peer.endpoint = endpoint;
            }
        }
    }

    /// Clear the direct endpoint and RTT (called by the executor after a
    /// Demote falls back to hub).
    pub fn clear_endpoint(&mut self, public_key: &str) {
        if let Some(peer) = self.peers.get_mut(public_key) {
            peer.endpoint.clear();
            peer.rtt_ms = None;
            peer.rtt_source = None;
        }
    }

    /// Refresh direct status readings (called by the executor each probe
    /// cycle): measured direct-path RTT (ms) + source (honest four states:
    /// `probe_ok` / `handshake_fresh` / `probe_failed` / `unprobed`, see
    /// [`crate::direct_rtt::RttSource`]), last handshake Unix seconds, and
    /// total rx/tx bytes (wg readings). No-op when the peer is unmanaged or
    /// in Relay (no direct link to measure).
    pub fn record_peer_status(
        &mut self,
        public_key: &str,
        rtt_ms: Option<u64>,
        rtt_source: Option<&str>,
        last_handshake_at: Option<u64>,
        rx_bytes: u64,
        tx_bytes: u64,
    ) {
        if let Some(peer) = self.peers.get_mut(public_key) {
            if peer.state != PeerLinkState::Relay {
                peer.rtt_ms = rtt_ms;
                peer.rtt_source = rtt_source.map(str::to_string);
                peer.last_handshake_at = last_handshake_at;
                peer.rx_bytes = rx_bytes;
                peer.tx_bytes = tx_bytes;
            }
        }
    }
}

/// Replay record of one peer decision (produced by every branch of [`plan_updates_logged`]; the executor writes them to the
/// `agent-decisions.jsonl` decision log, with mode flips converted into
/// switch-events). Post-mortems can replay the reasons and evidence inputs
/// even without a console context (Windows service / schtasks SYSTEM) — a
/// diagnostic gap from the 2026-11-14 inspection sheet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDecisionRecord {
    /// Peer wg public key.
    pub public_key: String,
    /// Peer name (display name read from candidates).
    pub peer_name: String,
    /// Mode before the decision (`p2p_direct` / `direct_pending` /
    /// `hub_relay`).
    pub from_mode: &'static str,
    /// Mode after the decision.
    pub to_mode: &'static str,
    /// Action: `promote` / `demote` / `hold_relay` / `probe` / `defer`.
    pub action: &'static str,
    /// Reason for the decision (human-readable).
    pub reason: String,
    /// Evidence input: last direct handshake age (seconds; kernel snapshot).
    pub handshake_age_secs: Option<u64>,
    /// Evidence input: SEL-003 probe-window degradation verdict.
    pub degraded: bool,
    /// Endpoint involved (promote target; the active face on demote; empty =
    /// none).
    pub endpoint: String,
}

/// [`PeerLinkState`] → ledger/report mode string (shared by decision records
/// and events).
fn mode_str(state: PeerLinkState) -> &'static str {
    match state {
        PeerLinkState::Direct => "p2p_direct",
        PeerLinkState::DirectPending { .. } => "direct_pending",
        PeerLinkState::Relay => "hub_relay",
    }
}
/// State-transition plan for one cycle (pure function, no IO; returns peers sorted by
/// public key, deterministic). For the replay-augmented version see
/// [`plan_updates_logged`].
///
/// Parameters:
/// - `wanted`: directly-connectable candidates published by the server
///   (already filtered to this device's routed range);
/// - `my_lan_subnets`: local LAN subnets (for same-subnet checks);
/// - `scope` / `self_vip`: this device's routable range and its own overlay
///   address (for AllowedIPs `/32` conflict checks);
/// - `current`: the manager's current state (**updated in place**, retained
///   across cycles);
/// - `handshake_ages`: seconds since each peer's last handshake (kernel
///   readings).
///
/// Behavior:
/// - peers outside the candidate set (revoked/offline/moved segments) → fall
///   back and remove;
/// - inside the set: `decide_direct_path` with no viable path → stay on relay
///   (no error); a path exists → `on_probe` transition (Relay→Promote,
///   Pending timeout→Demote, Direct broken→Demote, recovered→Promote again).
/// - `unhealthy_faces`: (public key, candidate face) pairs the probe window
///   deems degraded (promote prefers healthy faces: pre-filter for promotion
///   path selection). Probing off / empty set = no filtering (legacy
///   behavior).
/// - `suppress_promote`: the FLIP-002 demote-backoff suppression table
///   (public key → defer reason string). Suppressed peers **do not start a
///   promote** this cycle (stay on relay, keep the memory face) — it only
///   affects the promote side; degradation checks / demote are untouched.
///   Empty table = no suppression (legacy behavior).
#[allow(clippy::too_many_arguments)]
pub fn plan_updates_logged(
    wanted: &[PeerEndpoints],
    my_lan_subnets: &[Ipv4Cidr],
    scope: Ipv4Cidr,
    self_vip: Ipv4Addr,
    current: &mut BTreeMap<String, DirectPeer>,
    handshake_ages: &BTreeMap<String, u64>,
    degraded: &BTreeMap<String, bool>,
    unhealthy_faces: &BTreeSet<(String, EndpointCandidate)>,
    hold_relay: &BTreeSet<String>,
    suppress_promote: &BTreeMap<String, String>,
) -> (Vec<DirectUpdate>, Vec<PeerDecisionRecord>) {
    let mut updates = Vec::new();
    let mut records = Vec::new();

    // Outside the candidate set: fall back and remove (collect first to avoid
    // borrow conflicts).
    let wanted_keys: BTreeMap<&str, ()> = wanted
        .iter()
        .map(|peer| (peer.public_key.as_str(), ()))
        .collect();
    let stale: Vec<(String, PeerLinkState, String)> = current
        .iter()
        .filter(|(key, _)| !wanted_keys.contains_key(key.as_str()))
        .map(|(key, entry)| (key.clone(), entry.state, entry.peer_name.clone()))
        .collect();
    for (key, state, peer_name) in stale {
        let handshake_age_secs = handshake_ages.get(&key).copied();
        current.remove(&key);
        records.push(PeerDecisionRecord {
            public_key: key.clone(),
            peer_name,
            from_mode: mode_str(state),
            to_mode: "hub_relay",
            action: "demote",
            reason: "peer left the candidate set".into(),
            handshake_age_secs,
            degraded: false,
            endpoint: String::new(),
        });
        updates.push(DirectUpdate::Demote { public_key: key });
    }

    for peer in wanted {
        let key = peer.public_key.clone();
        let state = current
            .get(&key)
            .map(|entry| entry.state)
            .unwrap_or(PeerLinkState::Relay);
        // Decide the direct path. Re-promotion after falling back to relay
        // prefers the memory face: the endpoint actually used by the last
        // direct link (including kernel-roamed faces absent from the server
        // candidate table). The candidate-table decision is only the fallback
        // when there is no memory (first promotion / memory already cleared
        // by failed verification).
        //
        // Promote prefers healthy faces (2026-11-14 inspection sheet
        // nov14-1410 delegated decision, option two of three): if the memory
        // face / candidate face is currently degraded per the probe window
        // (unhealthy_faces), do not pick it this cycle — re-promoting on a
        // degraded face just degrades again immediately (the flip loop of
        // SEL-003 demote → memory-face fallback → degrade again, recorded in
        // the 930f137 decision log). If healthy faces remain after filtering,
        // use them; if only degraded faces remain → defer this cycle (stay on
        // relay until faces recover, recorded in the decision log). Faces
        // without a baseline / with probing off are not in unhealthy_faces
        // (never blanket-blacklist them), matching legacy behavior.
        let mut used_memory_face = false;
        let mut deferred_face: Option<EndpointCandidate> = None;
        // AGENT-ISO-2: an endpoint inside the local overlay range = using an
        // in-tunnel address as the tunnel endpoint — packets must first enter
        // the tunnel to reach it, pure hairpin waste. Measured on the imac
        // 2026-11-23: 1750ms RTT in this shape vs 19ms same-subnet direct.
        // Filter both candidate faces and the memory face: the memory face
        // bypasses decide_direct_path and is picked directly, so filtering
        // candidates alone cannot stop it from coming back.
        // `scope` is exactly the whole overlay of a single-segment network (the owning
        // segment prefix for segmented networks), which is precisely the
        // semantics needed here.
        let candidates: Vec<EndpointCandidate> = peer
            .endpoints
            .iter()
            .copied()
            .filter(|c| !scope.contains(c.ip))
            .collect();
        let unhealthy = |c: &EndpointCandidate| unhealthy_faces.contains(&(key.clone(), *c));
        // The memory face is only reusable if it is **still qualified**: it
        // was written by history/kernel roaming and is picked directly,
        // bypassing decide_direct_path — without re-checking, a stale address
        // from before the LAN-criteria change (e.g. the peer's ZeroTier
        // address, no longer same-subnet to us) would keep getting selected,
        // and the physical face would never be reached. Same criterion as the
        // source filter ([is_viable_endpoint]).
        let memory = current
            .get(&key)
            .and_then(|entry| entry.last_direct)
            .filter(|c| is_viable_endpoint(c, my_lan_subnets, scope));
        let decision = match state {
            PeerLinkState::Relay => {
                match memory {
                    Some(c) if !unhealthy(&c) => {
                        used_memory_face = true;
                        DirectDecision::SameLan(c)
                    }
                    _ => {
                        let healthy: Vec<_> = candidates
                            .iter()
                            .copied()
                            .filter(|c| !unhealthy(c))
                            .collect();
                        let filtered = decide_direct_path(my_lan_subnets, &healthy);
                        if matches!(filtered, DirectDecision::Relay) {
                            let full = decide_direct_path(my_lan_subnets, &candidates);
                            if let DirectDecision::SameLan(c) | DirectDecision::HolePunch(c) = full
                            {
                                deferred_face = Some(c);
                            } else if let Some(c) = memory {
                                // No candidate-table path and the memory face
                                // was vetoed as degraded: the bad point is the
                                // memory face.
                                deferred_face = Some(c);
                            }
                        }
                        filtered
                    }
                }
            }
            _ => decide_direct_path(my_lan_subnets, &candidates),
        };
        // SEL-003 recovery gate: fewer than N consecutive healthy rounds since
        // falling back to relay → stay on relay (no immediate switch back;
        // debouncing). The state machine may Promote again only once health
        // is stable (ready). The memory face persists through the hold —
        // re-promotion after the gate opens still prefers it.
        if hold_relay.contains(&key) && matches!(state, PeerLinkState::Relay) {
            let last_direct = current.get(&key).and_then(|entry| entry.last_direct);
            records.push(PeerDecisionRecord {
                public_key: key.clone(),
                peer_name: peer.name.clone(),
                from_mode: "hub_relay",
                to_mode: "hub_relay",
                action: "hold_relay",
                reason: "recovery gate: not yet N consecutive healthy rounds".into(),
                handshake_age_secs: handshake_ages.get(&key).copied(),
                degraded: degraded.get(&key).copied().unwrap_or(false),
                endpoint: String::new(),
            });
            current.insert(
                key.clone(),
                DirectPeer {
                    virtual_ipv4: peer.virtual_ipv4,
                    state: PeerLinkState::Relay,
                    last_handshake_age_secs: None,
                    peer_name: peer.name.clone(),
                    endpoint: String::new(),
                    rtt_ms: None,
                    rtt_source: None,
                    last_handshake_at: None,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    candidates: vec![],
                    last_direct,
                },
            );
            continue;
        }
        // FLIP-002 demote backoff: suppressed peers do not promote this cycle
        // (stay on relay, keep the memory face) — exponential backoff widens
        // the retry interval, turning minute-scale futile retry loops on a
        // degraded face into single-digit attempts. Only promotes are
        // blocked: degradation checks and demote are unaffected.
        if matches!(state, PeerLinkState::Relay) {
            if let Some(reason) = suppress_promote.get(&key) {
                let last_direct = current.get(&key).and_then(|entry| entry.last_direct);
                records.push(PeerDecisionRecord {
                    public_key: key.clone(),
                    peer_name: peer.name.clone(),
                    from_mode: "hub_relay",
                    to_mode: "hub_relay",
                    action: "defer",
                    reason: reason.clone(),
                    handshake_age_secs: handshake_ages.get(&key).copied(),
                    degraded: degraded.get(&key).copied().unwrap_or(false),
                    endpoint: String::new(),
                });
                current.insert(
                    key.clone(),
                    DirectPeer {
                        virtual_ipv4: peer.virtual_ipv4,
                        state: PeerLinkState::Relay,
                        last_handshake_age_secs: None,
                        peer_name: peer.name.clone(),
                        endpoint: String::new(),
                        rtt_ms: None,
                        rtt_source: None,
                        last_handshake_at: None,
                        rx_bytes: 0,
                        tx_bytes: 0,
                        candidates: vec![],
                        last_direct,
                    },
                );
                continue;
            }
        }
        // Promote defer: only degraded faces remain among candidates → no
        // promotion this cycle (stay on relay until faces recover). Do not
        // hole-punch/handshake on a degraded face — SEL-003 would just
        // degrade it again into flip noise. The memory face is kept, not
        // cleared (once faces recover, the memory face is preferred again as
        // usual).
        if let Some(face) = deferred_face {
            let last_direct = current.get(&key).and_then(|entry| entry.last_direct);
            records.push(PeerDecisionRecord {
                public_key: key.clone(),
                peer_name: peer.name.clone(),
                from_mode: "hub_relay",
                to_mode: "hub_relay",
                action: "defer",
                reason: "promote deferred: candidate face degraded (probe window)".into(),
                handshake_age_secs: handshake_ages.get(&key).copied(),
                degraded: true,
                endpoint: face.socket().to_string(),
            });
            current.insert(
                key.clone(),
                DirectPeer {
                    virtual_ipv4: peer.virtual_ipv4,
                    state: PeerLinkState::Relay,
                    last_handshake_age_secs: None,
                    peer_name: peer.name.clone(),
                    endpoint: String::new(),
                    rtt_ms: None,
                    rtt_source: None,
                    last_handshake_at: None,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    candidates: vec![],
                    last_direct,
                },
            );
            continue;
        }
        // SEL-003: direct degradation (loss spike / timeout / deeply degraded
        // RTT) → fall back to relay immediately, don't wait for handshake
        // expiry. (Degradation has top priority: even with fresh handshake
        // evidence, degradation still falls back — the demotion criteria are
        // not relaxed. This closes the "fresh handshake short-circuit" hole:
        // freshness alone must not judge Healthy; probing must participate —
        // the 2026-11-13 SEL-002 two-machine acceptance run pinned the direct
        // link with a handshake frozen at 133–203s, exactly the missing
        // latency/probe veto path.)
        if degraded.get(&key).copied().unwrap_or(false)
            && matches!(
                state,
                PeerLinkState::Direct | PeerLinkState::DirectPending { .. }
            )
        {
            // Memory face on a degradation fallback: keep it for established
            // Direct links (the face is probably still there; if truly dead,
            // the next promote's failed verification clears it naturally);
            // discard it for pending — an interrupted endpoint has never
            // verified a handshake.
            let mut last_direct = current.get(&key).and_then(|entry| entry.last_direct);
            if matches!(state, PeerLinkState::DirectPending { .. }) {
                last_direct = None;
            }
            let prev_endpoint = current
                .get(&key)
                .map(|e| e.endpoint.clone())
                .unwrap_or_default();
            records.push(PeerDecisionRecord {
                public_key: key.clone(),
                peer_name: peer.name.clone(),
                from_mode: mode_str(state),
                to_mode: "hub_relay",
                action: "demote",
                reason: "sel003 degraded: probe window (consecutive-lost / median-rtt gate)".into(),
                handshake_age_secs: handshake_ages.get(&key).copied(),
                degraded: true,
                endpoint: prev_endpoint,
            });
            current.insert(
                key.clone(),
                DirectPeer {
                    virtual_ipv4: peer.virtual_ipv4,
                    state: PeerLinkState::Relay,
                    last_handshake_age_secs: None,
                    peer_name: peer.name.clone(),
                    endpoint: String::new(),
                    rtt_ms: None,
                    rtt_source: None,
                    last_handshake_at: None,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    candidates: vec![],
                    last_direct,
                },
            );
            updates.push(DirectUpdate::Demote { public_key: key });
            continue;
        }
        // Probe interpretation: pending uses a **handshake-evidence-first**
        // promotion gate (a fresh recent handshake counts as direct-link
        // verification success; ICMP probe failure/unavailability does not
        // block promotion — the Windows mesh firewall drops 100% of packets
        // to the wg interface, per imac forensics 2026-11-07); other states
        // keep the health-window criteria (Direct broken → fall back, etc.).
        let handshake_age = handshake_ages.get(&key).copied();
        let probe = match state {
            PeerLinkState::DirectPending { .. } => classify_promote_probe(
                handshake_age,
                DIRECT_PROMOTE_FRESH_SECS,
                DIRECT_HEALTH_WINDOW_SECS,
            ),
            _ => classify_probe(state, handshake_age, DIRECT_HEALTH_WINDOW_SECS),
        };
        let (next_state, mut action) = on_probe(state, decision, probe, MAX_PROMOTE_ATTEMPTS);
        // AGENT-ISO-3: force re-selection when the active face is unqualified.
        // A bad face left by history / kernel roaming (the peer's ZeroTier
        // // address, self-overlay hairpin) stays `Keep`ed by the state machine // as long as its handshake is healthy —
        // the source filter never gets a // chance to apply (2026-11-23: the endpoint survived a restart // unchanged). Add
        // a correction here: if a qualified alternative face // exists, Promote over it directly (no Demote first, keeping the
        // // existing handshake). Once switched, the active face qualifies and // this stops firing — convergent, no flapping; if
        // the active face // cannot be read, do not act arbitrarily (§7.5), keep the original // action.
        if matches!(action, PeerLinkAction::Keep) {
            let current_viable = current
                .get(&key)
                .and_then(|entry| crate::agent::endpoint::parse_endpoint_candidate(&entry.endpoint))
                .map(|c| is_viable_endpoint(&c, my_lan_subnets, scope))
                .unwrap_or(true);
            if !current_viable
                && matches!(
                    decision,
                    DirectDecision::SameLan(_) | DirectDecision::HolePunch(_)
                )
            {
                tracing::info!(
                    public_key = %key,
                    current = %current.get(&key).map(|e| e.endpoint.as_str()).unwrap_or(""),
                    "direct endpoint not viable; re-selecting"
                );
                action = PeerLinkAction::Promote(decision);
            }
        }
        // Memory-face maintenance: promote records the face being dialed; a
        // pending verification failure discards the memory (that endpoint
        // never established a handshake; a dead face must not lock up
        // re-promotion); a fallback from an established direct link keeps it
        // (the face is probably still there; same semantics as the
        // degradation branch).
        let mut last_direct = current.get(&key).and_then(|entry| entry.last_direct);
        match &action {
            PeerLinkAction::Promote(path) => {
                if let DirectDecision::SameLan(c) | DirectDecision::HolePunch(c) = *path {
                    last_direct = Some(c);
                }
            }
            PeerLinkAction::Demote => {
                if matches!(state, PeerLinkState::DirectPending { .. }) {
                    last_direct = None;
                }
            }
            PeerLinkAction::Keep => {}
        }
        let prev_endpoint = current
            .get(&key)
            .map(|e| e.endpoint.clone())
            .unwrap_or_default();
        current.insert(
            key.clone(),
            DirectPeer {
                virtual_ipv4: peer.virtual_ipv4,
                state: next_state,
                last_handshake_age_secs: handshake_age,
                peer_name: peer.name.clone(),
                // endpoint is provided by the Promote action; Relay/Demote
                // keep the last value, and the executor clears it on Demote
                // (see agent.apply_direct_update).
                endpoint: prev_endpoint.clone(),
                rtt_ms: None,
                rtt_source: None,
                last_handshake_at: None,
                rx_bytes: 0,
                tx_bytes: 0,
                candidates: vec![],
                last_direct,
            },
        );
        // Ledger the decision: record one entry for any state transition or
        // non-Keep action (evidence inputs like probe window / handshake age
        // are filled in by the executor before persisting; see
        // agent.reconcile_direct).
        if next_state != state || !matches!(action, PeerLinkAction::Keep) {
            let (action_str, reason) = match &action {
                PeerLinkAction::Promote(_) => (
                    "promote",
                    if matches!(state, PeerLinkState::Relay) {
                        format!(
                            "promote attempt via {} (probe {probe:?})",
                            if used_memory_face {
                                "memory face (last_direct)"
                            } else {
                                "candidate table"
                            }
                        )
                    } else {
                        format!("pending verified: fresh handshake (probe {probe:?})")
                    },
                ),
                PeerLinkAction::Demote => (
                    "demote",
                    match state {
                        PeerLinkState::Direct => {
                            format!("handshake stale beyond health window (probe {probe:?})")
                        }
                        PeerLinkState::DirectPending { attempts } => {
                            format!("pending attempts exhausted after {attempts} rounds (probe {probe:?})")
                        }
                        PeerLinkState::Relay => "relay demoted".into(),
                    },
                ),
                PeerLinkAction::Keep => {
                    // Keep with a state change = pending gate verdict:
                    // verified (→Direct) or keep waiting (attempts+1).
                    // Verification is promote-like in nature (promotion).
                    if matches!(next_state, PeerLinkState::Direct) {
                        (
                            "promote",
                            format!("pending verified: fresh handshake (probe {probe:?})"),
                        )
                    } else if let PeerLinkState::DirectPending { attempts } = next_state {
                        (
                            "probe",
                            format!("waiting for handshake (attempt {attempts})"),
                        )
                    } else {
                        ("probe", "state advanced (probe gate)".into())
                    }
                }
            };
            records.push(PeerDecisionRecord {
                public_key: key.clone(),
                peer_name: peer.name.clone(),
                from_mode: mode_str(state),
                to_mode: mode_str(next_state),
                action: action_str,
                reason,
                handshake_age_secs: handshake_age,
                degraded: degraded.get(&key).copied().unwrap_or(false),
                endpoint: match &action {
                    PeerLinkAction::Promote(path) => path_endpoint(*path).to_string(),
                    _ => prev_endpoint.clone(),
                },
            });
        }
        match action {
            PeerLinkAction::Keep => {}
            PeerLinkAction::Demote => updates.push(DirectUpdate::Demote { public_key: key }),
            PeerLinkAction::Promote(path) => {
                // Conflict boundaries (self / outside the routed range) are
                // re-checked by the domain layer; on error, give up the direct
                // link (stay on relay — never issue an out-of-range or
                // self-referential peer).
                let Ok(allowed_ips) = direct_peer_allowed_ips(scope, self_vip, peer.virtual_ipv4)
                else {
                    continue;
                };
                updates.push(DirectUpdate::Promote {
                    public_key: key,
                    allowed_ips,
                    endpoint: path_endpoint(path),
                });
            }
        }
    }
    (updates, records)
}

/// Convenience wrapper returning only the action sequence (entry point for
/// callers that do not need decision records).
#[allow(clippy::too_many_arguments)]
pub fn plan_updates(
    wanted: &[PeerEndpoints],
    my_lan_subnets: &[Ipv4Cidr],
    scope: Ipv4Cidr,
    self_vip: Ipv4Addr,
    current: &mut BTreeMap<String, DirectPeer>,
    handshake_ages: &BTreeMap<String, u64>,
    degraded: &BTreeMap<String, bool>,
    unhealthy_faces: &BTreeSet<(String, EndpointCandidate)>,
    hold_relay: &BTreeSet<String>,
    suppress_promote: &BTreeMap<String, String>,
) -> Vec<DirectUpdate> {
    plan_updates_logged(
        wanted,
        my_lan_subnets,
        scope,
        self_vip,
        current,
        handshake_ages,
        degraded,
        unhealthy_faces,
        hold_relay,
        suppress_promote,
    )
    .0
}

/// Whether an endpoint still qualifies as a direct face (AGENT-ISO-3, shared
/// by the source filter and the memory-face re-check).
///
/// Same criterion as [decide_direct_path]: **same-subnet reachable, or
/// public and hole-punchable**. This rejects three classes of bad faces:
/// - inside the local overlay range → hairpin self-loop (packets must first
///   enter the tunnel to reach it; measured on the imac 2026-11-23:
///   1750ms vs 19ms same-subnet);
/// - private but neither same-subnet nor in the overlay → **foreign subnet**
///   (the peer's ZeroTier address); using it as the endpoint means riding
// / another tunnel this host does not control; / - other remote-LAN private ranges → unreachable from
// here anyway; keep / them out of the candidate table so the probe window and SEL-002
///   switching cannot bypass the decision layer and make one the active
///   face.
///
/// `scope` = the local overlay routable range (the whole overlay for a
/// single-segment network).
pub(crate) fn is_viable_endpoint(
    candidate: &EndpointCandidate,
    my_lan_subnets: &[Ipv4Cidr],
    scope: Ipv4Cidr,
) -> bool {
    if scope.contains(candidate.ip) {
        return false;
    }
    is_lan_reachable(my_lan_subnets, candidate) || candidate.kind == EndpointKind::Public
}

/// The endpoint of the decision path (SameLan / HolePunch each yield a direct
/// address).
fn path_endpoint(path: DirectDecision) -> SocketAddrV4 {
    match path {
        DirectDecision::SameLan(candidate) | DirectDecision::HolePunch(candidate) => {
            candidate.socket()
        }
        DirectDecision::Relay => {
            // `on_probe` only issues Promote on a non-Relay decision; this
            // arm is unreachable.
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)
        }
    }
}

/// Fallback merge of handshake readings (pure function): when `dedicated`
/// (the `wg show latest-handshakes` dedicated reading) is empty or missing a
/// peer, fill in the age derived from the diagnostic dump (`wg show dump`,
/// another projection of the same kernel reading). During Windows tunnel
// / service reinstall churn, latest-handshakes can be unreadable ("Unable to / access interface", imac forensics 2026-11-07) — a failed dedicated reading / must
// not lose the handshake evidence wholesale, otherwise the promotion / gate gets no input and the direct link stays stuck on "dialing".
pub fn merge_handshake_ages(
    dedicated: BTreeMap<String, u64>,
    dump: BTreeMap<String, u64>,
) -> BTreeMap<String, u64> {
    let mut merged = dedicated;
    for (key, age) in dump {
        merged.entry(key).or_insert(age);
    }
    merged
}

/// Keepalive period (domain-layer constant; the executor issues it).
pub fn keepalive_secs() -> u32 {
    DIRECT_PERSISTENT_KEEPALIVE_SECS
}

#[cfg(test)]
mod tests;
