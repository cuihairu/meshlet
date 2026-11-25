//! Endpoint candidate table (FLIP-001 brings the roaming surface under the table): three source
//! classes - the server-delivered surface (`Config`) + the kernel roaming observed surface (`Roaming`)
//! + the probe-confirmed reachable surface (`Discovered`) - merged agent-side into an "effective
//! candidate set" consumed by SEL-001 probing and the direct-connect state machine.
//!
//! Why: kernel wg roaming is the strongest evidence that "the peer changed networks / a new face is
//! available" (the kernel roaming to an endpoint the moment it receives a legitimately authenticated
//! packet from a new source face), but such faces are often absent from the server's candidate
//! table - the old path only passively followed them via the memory surface (`last_direct`) while
//! direct, and after falling back to relay the evidence was lost along with `wg set peer` removal,
//! leaving promote to pick the config surface again and wait for it to degrade (the root of the flip
//! loop that fliploop pinned down, see docs/acceptance-evidence/fliploop-imac-2026-11-14.md).
//! The candidate table persists roaming faces as entries with a `last_seen`: after falling back to
//! relay, SEL-001 keeps probing them, and at promote time they compete on equal footing with other
//! faces (degrade filtering unchanged) - a healthy face wins, instead of staring at a single config
//! surface waiting for it to degrade and then falling back to relay.
//!
//! Source semantics ([`FaceSource`]):
//! - `Config`: the server-delivered candidate set (authoritative, does not expire, kept fresh by each
//!   reconciliation round);
//! - `Roaming`: a peer endpoint observed by the kernel's `wg dump` (expires after
//!   [`Self::ROAMING_TTL_SECS`] with no new observation - once the peer leaves that network, the stale
//!   face no longer misleads routing);
//! - `Discovered`: a roaming face confirmed healthy by the SEL-001 window (upgraded by the executor),
//!   also expiring by `last_seen` (as long as the probe thread keeps sampling it, it stays fresh).
//!
//! Pure logic, no IO: kernel observations are fed by the executor (`wg dump` endpoint), and probe
//! confirmation is decided by the SEL-001 window (see `crate::probe::face_healthy`).

use std::collections::BTreeMap;

use meshlet_domain::{EndpointCandidate, PeerEndpoints};

/// Origin of a candidate face.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FaceSource {
    /// Delivered in the server's candidate set (authoritative, does not expire).
    Config,
    /// Kernel roaming observation (valid within the TTL).
    Roaming,
    /// A roaming face confirmed healthy by the SEL-001 window (valid within the TTL).
    Discovered,
}

impl FaceSource {
    /// Lowercase identifier for display / decision logs.
    pub fn as_str(self) -> &'static str {
        match self {
            FaceSource::Config => "config",
            FaceSource::Roaming => "roaming",
            FaceSource::Discovered => "discovered",
        }
    }
}

/// TTL (seconds) for roaming / discovered faces: 30min. The kernel refreshes its observation of active
/// paths every reconciliation period (30s), so under normal operation the TTL is never hit; the TTL only
/// reclaims stale faces from "peers that have left that network" - 30min is enough to keep evidence across
/// several probe rounds while not misleading routing indefinitely.
pub const ROAMING_TTL_SECS: u64 = 1_800;

/// One candidate-table entry: source + the time of the latest evidence (Unix seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaceEntry {
    pub source: FaceSource,
    pub last_seen_secs: u64,
}

/// Endpoint candidate table: `(peer public key, candidate)` -> entry.
#[derive(Debug, Default)]
pub struct CandidateTable {
    entries: BTreeMap<(String, EndpointCandidate), FaceEntry>,
}

impl CandidateTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Server candidate-set sync: insert / refresh all config faces (a face that already has a roaming /
    /// discovered entry is upgraded to Config - the server's view is the authoritative source).
    pub fn sync_config(&mut self, wanted: &[PeerEndpoints], now_secs: u64) {
        for peer in wanted {
            for candidate in &peer.endpoints {
                self.entries.insert(
                    (peer.public_key.clone(), *candidate),
                    FaceEntry {
                        source: FaceSource::Config,
                        last_seen_secs: now_secs,
                    },
                );
            }
        }
    }

    /// Kernel roaming observation: feed a peer endpoint into the candidate table. Returns whether it is a
    /// **new face** (no prior (key, candidate) entry) - a new face is a network-change signal, and the
    /// executor triggers an immediate probe on it (not waiting for the 30s throttle). A known face only has
    /// its `last_seen` refreshed (active paths never expire) and its source is never downgraded (Config/discovered kept).
    pub fn observe_roaming(
        &mut self,
        public_key: &str,
        candidate: EndpointCandidate,
        now_secs: u64,
    ) -> bool {
        match self.entries.get_mut(&(public_key.to_string(), candidate)) {
            Some(entry) => {
                entry.last_seen_secs = now_secs;
                false
            }
            None => {
                self.entries.insert(
                    (public_key.to_string(), candidate),
                    FaceEntry {
                        source: FaceSource::Roaming,
                        last_seen_secs: now_secs,
                    },
                );
                true
            }
        }
    }

    /// Probe-confirmed upgrade: a roaming face healthy in the SEL-001 window -> `Discovered` (and refreshed).
    /// Config faces are unaffected; an already-discovered face only has its `last_seen` refreshed.
    pub fn mark_discovered(
        &mut self,
        public_key: &str,
        candidate: EndpointCandidate,
        now_secs: u64,
    ) {
        if let Some(entry) = self.entries.get_mut(&(public_key.to_string(), candidate)) {
            if entry.source == FaceSource::Roaming {
                entry.source = FaceSource::Discovered;
            }
            entry.last_seen_secs = now_secs;
        }
    }

    /// Expiry reclaim: roaming / discovered faces with no new evidence (kernel observation or probe
    /// sampling) for more than [`Self::ROAMING_TTL_SECS`] are removed; config faces never expire (server authority).
    pub fn expire(&mut self, now_secs: u64) {
        self.entries.retain(|_, entry| {
            entry.source == FaceSource::Config
                || now_secs.saturating_sub(entry.last_seen_secs) <= ROAMING_TTL_SECS
        });
    }

    /// Reclaim peers not in the candidate set (revoked / offline / moved segments).
    pub fn retain_peers(&mut self, wanted: &[PeerEndpoints]) {
        let live: std::collections::BTreeSet<&str> =
            wanted.iter().map(|p| p.public_key.as_str()).collect();
        self.entries
            .retain(|(key, _), _| live.contains(key.as_str()));
    }

    /// Merge into the effective candidate set: server candidates come first (in original order), and
    /// table-only faces are appended sorted by `(ip, port)` (deterministic). Faces are deduplicated
    /// (server candidates win).
    pub fn merge_into(&self, wanted: &[PeerEndpoints]) -> Vec<PeerEndpoints> {
        wanted
            .iter()
            .map(|peer| {
                let mut endpoints: Vec<_> = peer.endpoints.to_vec();
                let mut extra: Vec<_> = self
                    .entries
                    .keys()
                    .filter(|(key, candidate)| {
                        key == &peer.public_key && !endpoints.contains(candidate)
                    })
                    .map(|(_, candidate)| *candidate)
                    .collect();
                extra.sort_by_key(|c| (c.ip, c.port));
                endpoints.extend(extra);
                PeerEndpoints {
                    device_id: peer.device_id.clone(),
                    public_key: peer.public_key.clone(),
                    virtual_ipv4: peer.virtual_ipv4,
                    name: peer.name.clone(),
                    endpoints,
                }
            })
            .collect()
    }

    /// All entries of one peer (candidate + source), sorted by candidate (deterministic).
    pub fn faces(&self, public_key: &str) -> Vec<(EndpointCandidate, FaceSource)> {
        self.entries
            .iter()
            .filter(|((key, _), _)| key == public_key)
            .map(|((_, candidate), entry)| (*candidate, entry.source))
            .collect()
    }

    /// All roaming entries (the iteration input for probe-confirmed upgrades).
    pub fn roaming_faces(&self) -> Vec<(String, EndpointCandidate)> {
        self.entries
            .iter()
            .filter(|(_, entry)| entry.source == FaceSource::Roaming)
            .map(|((key, candidate), _)| (key.clone(), *candidate))
            .collect()
    }

    /// Probe-evidence refresh (FLIP-001): entries healthy in the probe window are kept fresh (`last_seen`
    /// advanced) and roaming faces upgraded to `Discovered`. This is the discovered face's life-support
    /// mechanism after falling back to relay - kernel observation is gone (the peer was removed), so
    /// continued SEL-001 answers keep it fresh; faces outside the healthy set are untouched (reclaimed
    /// naturally at TTL expiry). Config faces keep their source (authoritative, never expires).
    pub fn refresh_probe_evidence(
        &mut self,
        healthy: &std::collections::BTreeSet<(String, EndpointCandidate)>,
        now_secs: u64,
    ) {
        for (public_key, candidate) in healthy {
            self.mark_discovered(public_key, *candidate, now_secs);
        }
    }

    /// Total entry count (diagnostics / testing).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Recovery-gate bypass decision (FLIP-001, pure function): when the candidate table has a face for this
/// peer that is "probe-confirmed healthy" -> `true` (no hold_relay waiting on the gate; the state
/// machine's promote is allowed straight through this round).
/// `healthy` is the probe runtime's healthy-face set ([`crate::probe::ProbeRuntime::healthy_faces`]).
pub fn has_probe_healthy_face(
    public_key: &str,
    table_faces: &[(EndpointCandidate, FaceSource)],
    healthy: &std::collections::BTreeSet<(String, EndpointCandidate)>,
) -> bool {
    table_faces
        .iter()
        .any(|(candidate, _)| healthy.contains(&(public_key.to_string(), *candidate)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshlet_domain::EndpointKind;

    fn lan(ip: &str, port: u16) -> EndpointCandidate {
        EndpointCandidate {
            ip: ip.parse().unwrap(),
            port,
            kind: EndpointKind::Lan,
        }
    }

    fn public(ip: &str, port: u16) -> EndpointCandidate {
        EndpointCandidate {
            ip: ip.parse().unwrap(),
            port,
            kind: EndpointKind::Public,
        }
    }

    fn peer(key: &str, endpoints: &[EndpointCandidate]) -> PeerEndpoints {
        PeerEndpoints {
            device_id: meshlet_domain::DeviceId("dev".into()),
            public_key: key.into(),
            virtual_ipv4: "10.240.0.3".parse().unwrap(),
            name: String::new(),
            endpoints: endpoints.to_vec(),
        }
    }

    #[test]
    fn sync_config_marks_and_refreshes_config_faces() {
        let mut table = CandidateTable::new();
        let wanted = vec![peer("pk", &[lan("192.168.1.50", 51820)])];
        table.sync_config(&wanted, 100);
        assert_eq!(
            table.faces("pk"),
            vec![(lan("192.168.1.50", 51820), FaceSource::Config)]
        );
        // Re-syncing (the next reconciliation round) refreshes it, and it never expires.
        table.sync_config(&wanted, 100_000);
        table.expire(100_000 + ROAMING_TTL_SECS + 1);
        assert_eq!(table.len(), 1, "config face never expires");
    }

    #[test]
    fn observe_roaming_flags_new_face_only_once() {
        let mut table = CandidateTable::new();
        assert!(
            table.observe_roaming("pk", lan("192.168.5.11", 51820), 100),
            "first kernel observation is a new face"
        );
        assert!(
            !table.observe_roaming("pk", lan("192.168.5.11", 51820), 130),
            "known face observation refreshes, not a change"
        );
    }

    #[test]
    fn roaming_face_expires_after_ttl_but_refresh_keeps_it() {
        let mut table = CandidateTable::new();
        table.observe_roaming("pk", lan("192.168.5.11", 51820), 100);
        table.expire(100 + ROAMING_TTL_SECS);
        assert_eq!(table.len(), 1, "within TTL");
        table.expire(100 + ROAMING_TTL_SECS + 1);
        assert!(table.is_empty(), "stale roaming face expires");
        // Active paths refresh every period -> never expire.
        table.observe_roaming("pk", lan("192.168.5.11", 51820), 100);
        for t in 1..=10u64 {
            table.observe_roaming("pk", lan("192.168.5.11", 51820), 100 + t * 200);
        }
        table.expire(100 + 10 * 200 + ROAMING_TTL_SECS);
        assert_eq!(table.len(), 1, "actively refreshed face survives");
    }

    #[test]
    fn discovered_upgrade_then_expiry() {
        let mut table = CandidateTable::new();
        table.observe_roaming("pk", public("203.0.113.9", 51820), 100);
        table.mark_discovered("pk", public("203.0.113.9", 51820), 110);
        assert_eq!(
            table.faces("pk"),
            vec![(public("203.0.113.9", 51820), FaceSource::Discovered)]
        );
        table.mark_discovered("pk", public("203.0.113.9", 51820), 120);
        assert_eq!(
            table.faces("pk"),
            vec![(public("203.0.113.9", 51820), FaceSource::Discovered)]
        );
        table.expire(120 + ROAMING_TTL_SECS + 1);
        assert!(table.is_empty(), "discovered faces expire like roaming");
    }

    #[test]
    fn config_authority_upgrades_roaming_entry() {
        let mut table = CandidateTable::new();
        table.observe_roaming("pk", lan("192.168.1.50", 51820), 100);
        table.sync_config(&[peer("pk", &[lan("192.168.1.50", 51820)])], 130);
        assert_eq!(
            table.faces("pk"),
            vec![(lan("192.168.1.50", 51820), FaceSource::Config)],
            "server-known face upgrades to config authority"
        );
    }

    #[test]
    fn merge_into_appends_table_only_faces_sorted_and_dedupes() {
        let mut table = CandidateTable::new();
        let wanted = vec![peer(
            "pk",
            &[public("203.0.113.5", 51820), lan("192.168.1.9", 51820)],
        )];
        table.sync_config(&wanted, 100);
        table.observe_roaming("pk", lan("192.168.1.2", 51820), 110);
        table.observe_roaming("pk", lan("192.168.1.7", 51820), 110);
        let merged = table.merge_into(&wanted);
        assert_eq!(
            merged[0].endpoints,
            vec![
                public("203.0.113.5", 51820),
                lan("192.168.1.9", 51820),
                // Table-only faces appended by (ip, port), deterministic.
                lan("192.168.1.2", 51820),
                lan("192.168.1.7", 51820),
            ]
        );
    }

    #[test]
    fn retain_peers_drops_entries_of_peers_outside_candidate_set() {
        let mut table = CandidateTable::new();
        table.observe_roaming("pk-a", lan("192.168.1.2", 51820), 100);
        table.observe_roaming("pk-b", lan("192.168.1.3", 51820), 100);
        table.retain_peers(&[peer("pk-a", &[])]);
        assert_eq!(table.faces("pk-a").len(), 1);
        assert!(table.faces("pk-b").is_empty(), "left the candidate set");
    }

    /// Probe-evidence refresh: healthy faces kept fresh (TTL life support) + roaming -> discovered upgrade;
    /// unhealthy faces untouched (reclaimed at TTL expiry).
    #[test]
    fn refresh_probe_evidence_keeps_healthy_faces_alive() {
        let mut table = CandidateTable::new();
        table.observe_roaming("pk", lan("192.168.1.2", 51820), 100);
        table.observe_roaming("pk", lan("192.168.1.3", 51820), 100);
        let mut healthy = std::collections::BTreeSet::new();
        healthy.insert(("pk".to_string(), lan("192.168.1.2", 51820)));
        // Refresh health evidence every 200s (an accelerated simulation of the 5s probe round): still alive far past the TTL.
        for round in 0..20u64 {
            table.refresh_probe_evidence(&healthy, 100 + (round + 1) * 200);
        }
        table.expire(100 + 20 * 200 + ROAMING_TTL_SECS);
        assert_eq!(table.faces("pk").len(), 1, "healthy face kept alive");
        assert_eq!(
            table.faces("pk")[0].1,
            FaceSource::Discovered,
            "roaming upgraded to discovered by probe evidence"
        );
        // The unhealthy face (.3, no probe evidence) expired long ago.
        assert!(
            !table
                .faces("pk")
                .iter()
                .any(|(c, _)| *c == lan("192.168.1.3", 51820)),
            "unprobed face expired"
        );
    }

    /// Bypass decision: allow only when table faces intersect the probe healthy set non-emptily; a face outside
    /// the table (healthy-window residue) and an unhealthy table face are both denied.
    #[test]
    fn has_probe_healthy_face_requires_table_and_probe_agreement() {
        let face_a = lan("192.168.1.2", 51820);
        let face_b = lan("192.168.1.3", 51820);
        let faces = vec![(face_a, FaceSource::Roaming)];
        let mut healthy = std::collections::BTreeSet::new();
        healthy.insert(("pk".to_string(), face_a));
        assert!(super::has_probe_healthy_face("pk", &faces, &healthy));
        // The face is unhealthy -> denied.
        assert!(!super::has_probe_healthy_face(
            "pk",
            &faces,
            &std::collections::BTreeSet::new()
        ));
        // The healthy face is not in the table (expired residue window) -> denied.
        healthy.clear();
        healthy.insert(("pk".to_string(), face_b));
        assert!(!super::has_probe_healthy_face("pk", &faces, &healthy));
        // Another peer's healthy face -> denied.
        healthy.insert(("other".to_string(), face_a));
        assert!(!super::has_probe_healthy_face("pk", &faces, &healthy));
    }
}
