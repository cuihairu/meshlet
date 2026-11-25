//! Per-network configuration revision ledger (ADR-009): recording, querying, boot rebuild and interruption convergence.
//! apply/rollback semantics (state-machine transitions and backend interaction) live in the `apply` submodule.

use crate::entities::{ApplyStatus, ConfigRevision, NetworkId, RevisionError, Timestamp};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    #[error("revision {revision} not found in network {network_id}")]
    RevisionNotFound { network_id: String, revision: u64 },
    /// Rollback target already superseded by a newer revision (§10.4): the superseded failed
    /// revision never took effect, so rolling it back by its intent would cross-touch objects
    /// owned by the newer revision — retry on the current revision or record a new one.
    #[error(
        "revision {revision} superseded by {latest} in network {network_id}; \
            roll back the current revision or record a new one"
    )]
    SupersededRevision {
        network_id: String,
        revision: u64,
        latest: u64,
    },
    #[error(transparent)]
    IllegalTransition(#[from] RevisionError),
}

/// Per-network configuration revision ledger (ADR-009): version numbers strictly monotonic
/// within a network (§10.4 ordering — config edits serialized by recording before applying).
#[derive(Debug, Clone, Default)]
pub struct ConfigLedger {
    revisions: HashMap<NetworkId, Vec<ConfigRevision>>,
}

impl ConfigLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one desired-config change: version number = previous version in this network + 1,
    /// initial status `Pending` (only the DB write has happened at this point, **not yet in effect**).
    pub fn record(
        &mut self,
        network_id: &NetworkId,
        desired_config_hash: String,
        now: Timestamp,
    ) -> u64 {
        let revisions = self.revisions.entry(network_id.clone()).or_default();
        let revision = revisions.last().map(|r| r.revision + 1).unwrap_or(1);
        revisions.push(ConfigRevision::new(
            network_id.clone(),
            revision,
            desired_config_hash,
            now,
        ));
        revision
    }

    /// All revisions of a network (ascending by version number; unknown network returns an empty slice).
    pub fn revisions(&self, network_id: &NetworkId) -> &[ConfigRevision] {
        self.revisions
            .get(network_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// A single revision.
    pub fn get(&self, network_id: &NetworkId, revision: u64) -> Option<&ConfigRevision> {
        self.revisions(network_id)
            .iter()
            .find(|r| r.revision == revision)
    }

    /// Current desired revision = the latest one not rolled back (the console treats this as authoritative, §10.1).
    pub fn current(&self, network_id: &NetworkId) -> Option<&ConfigRevision> {
        self.revisions(network_id)
            .iter()
            .rev()
            .find(|r| r.apply_status != ApplyStatus::RolledBack)
    }

    /// Load persisted revisions (§17.3 boot rebuild): grouped by network, filled in ascending
    /// by version, identical to the DB — subsequent [`Self::record`] calls keep incrementing
    /// from the last entry without reusing numbers. Callers (boot) must ensure uniqueness.
    pub fn restore(&mut self, revisions: Vec<ConfigRevision>) {
        let mut grouped: HashMap<NetworkId, Vec<ConfigRevision>> = HashMap::new();
        for r in revisions {
            grouped.entry(r.network_id.clone()).or_default().push(r);
        }
        for (network_id, mut rs) in grouped {
            rs.sort_by_key(|r| r.revision);
            self.revisions.insert(network_id, rs);
        }
    }

    /// Replace the stored conclusion for an already selected revision after an
    /// isolated apply/rollback task completes. Callers must still hold the
    /// network revision lock so concurrent tasks cannot overwrite each other.
    pub fn restore_revision(&mut self, revision: ConfigRevision) {
        let network_revisions = self
            .revisions
            .entry(revision.network_id.clone())
            .or_default();
        if let Some(existing) = network_revisions
            .iter_mut()
            .find(|r| r.revision == revision.revision)
        {
            *existing = revision;
        }
    }

    pub fn reserve_apply(&mut self, network_id: &NetworkId, revision: u64) -> bool {
        self.get_mut(network_id, revision)
            .filter(|r| r.apply_status == ApplyStatus::Pending)
            .is_some_and(|r| {
                r.apply_status = ApplyStatus::Applying;
                true
            })
    }

    pub fn reserve_rollback(&mut self, network_id: &NetworkId, revision: u64) -> bool {
        self.get_mut(network_id, revision)
            .filter(|r| r.apply_status == ApplyStatus::Failed)
            .is_some_and(|r| {
                r.apply_status = ApplyStatus::RollbackPending;
                true
            })
    }

    /// §10.3 interruption convergence (§17.3 restart recovery): after a restart, a revision left
    /// in `Applying` has an unknown outcome — always land `Failed` with an interruption diagnostic,
    /// **never pretend success**. `RollbackPending` is preserved (unconfirmed, retryable);
    /// `Applied`/`RolledBack` are terminal and untouched. Returns the converged revisions' identity.
    pub fn interrupt_applying(&mut self, error_summary: &str) -> Vec<(NetworkId, u64)> {
        let mut converged = Vec::new();
        for (network_id, revisions) in self.revisions.iter_mut() {
            for r in revisions.iter_mut() {
                if r.apply_status == ApplyStatus::Applying
                    && r.transition(ApplyStatus::Failed).is_ok()
                {
                    r.error_summary = Some(error_summary.to_string());
                    converged.push((network_id.clone(), r.revision));
                }
            }
        }
        converged
    }

    pub(super) fn get_mut(
        &mut self,
        network_id: &NetworkId,
        revision: u64,
    ) -> Option<&mut ConfigRevision> {
        self.revisions
            .get_mut(network_id)
            .and_then(|rs| rs.iter_mut().find(|r| r.revision == revision))
    }
}

#[cfg(test)]
mod tests {
    use super::ConfigLedger;
    use crate::config_state::test_support::{net, T0, T1, T2};
    use crate::entities::{ApplyStatus, ConfigRevision};

    #[test]
    fn revisions_are_monotonic_per_network_and_independent_across_networks() {
        let mut l = ConfigLedger::new();
        let (a, b) = (net("net-a"), net("net-b"));
        assert_eq!(l.record(&a, "h1".into(), T0.into()), 1);
        assert_eq!(l.record(&a, "h2".into(), T0.into()), 2);
        // Another network counts independently (§10.4 version ordering is per-network isolated).
        assert_eq!(l.record(&b, "h1".into(), T0.into()), 1);
        assert_eq!(l.current(&a).unwrap().revision, 2);
        assert_eq!(l.get(&a, 1).unwrap().desired_config_hash, "h1");
        assert_eq!(l.get(&b, 1).unwrap().desired_config_hash, "h1");
    }

    #[test]
    fn recorded_revision_is_pending_without_applied_at_or_error() {
        // Acceptance baseline: DB write != shown-in-effect — a new revision must not claim Applied.
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h".into(), T0.into());
        let r = l.current(&id).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::Pending);
        assert!(r.applied_at.is_none());
        assert!(r.error_summary.is_none());
    }

    #[test]
    fn restore_replays_revisions_and_continues_numbering() {
        // §17.3 boot rebuild: persisted revisions are restored verbatim, subsequent records continue incrementing without reusing numbers.
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        let r1 = ConfigRevision::new(id.clone(), 1, "h1".into(), T0.into());
        let mut r2 = ConfigRevision::new(id.clone(), 2, "h2".into(), T1.into());
        r2.apply_status = ApplyStatus::Applied;
        r2.applied_at = Some(T2.into());
        l.restore(vec![r2.clone(), r1.clone()]); // out-of-order input is still sorted by revision number
        assert_eq!(l.revisions(&id), &[r1, r2]);
        assert_eq!(l.current(&id).unwrap().desired_config_hash, "h2");
        // New change after restart: numbering continues from 3.
        assert_eq!(l.record(&id, "h3".into(), T2.into()), 3);
    }

    #[test]
    fn interrupted_applying_lands_failed_with_summary() {
        // §10.3: a revision stuck in applying has an unknown outcome → lands failed with an interruption diagnostic.
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        let mk = |rev: u64, status: ApplyStatus| {
            let mut r = ConfigRevision::new(id.clone(), rev, format!("h{rev}"), T0.into());
            r.apply_status = status;
            r
        };
        l.restore(vec![
            mk(1, ApplyStatus::Applied),
            mk(2, ApplyStatus::Applying),
            mk(3, ApplyStatus::RollbackPending),
        ]);
        let converged = l.interrupt_applying("interrupted: process restarted while applying");
        assert_eq!(converged, vec![(id.clone(), 2)]);
        assert_eq!(
            l.get(&id, 2).unwrap().apply_status,
            ApplyStatus::Failed,
            "uncertain outcome must not pretend success"
        );
        assert_eq!(
            l.get(&id, 2).unwrap().error_summary.as_deref(),
            Some("interrupted: process restarted while applying")
        );
        // Terminal states and the unconfirmed-rollback state are unaffected.
        assert_eq!(l.get(&id, 1).unwrap().apply_status, ApplyStatus::Applied);
        assert_eq!(
            l.get(&id, 3).unwrap().apply_status,
            ApplyStatus::RollbackPending
        );
        // Idempotent: converging again no longer matches any revision.
        assert!(l.interrupt_applying("again").is_empty());
    }

    #[test]
    fn concurrent_record_assigns_unique_contiguous_revisions() {
        // §10.4 version ordering: with concurrent records (caller holds the network mutex) version
        // numbers are unique, contiguous and strictly increasing — no interleaving, gaps or duplicates.
        use std::sync::{Arc, Mutex};
        const THREADS: u64 = 8;
        const PER_THREAD: u64 = 25;

        let ledger = Arc::new(Mutex::new(ConfigLedger::new()));
        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let ledger = Arc::clone(&ledger);
                std::thread::spawn(move || {
                    let mut mine = Vec::new();
                    for i in 0..PER_THREAD {
                        let rev = ledger.lock().unwrap().record(
                            &net("net-1"),
                            format!("h-{t}-{i}"),
                            T0.into(),
                        );
                        mine.push(rev);
                    }
                    mine
                })
            })
            .collect();
        let mut all = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(all.len() as u64, THREADS * PER_THREAD);
        all.sort_unstable();
        let expected: Vec<u64> = (1..=THREADS * PER_THREAD).collect();
        assert_eq!(all, expected, "unique, contiguous, strictly increasing");

        let guard = ledger.lock().unwrap();
        let numbers: Vec<u64> = guard
            .revisions(&net("net-1"))
            .iter()
            .map(|r| r.revision)
            .collect();
        assert_eq!(numbers, expected);
    }
}
