//! apply/rollback semantics (§10.3–§10.4): revision state-machine transitions and backend interaction.
//!
//! Transition discipline: an `Applied` revision returns idempotently without calling the backend;
//! `Failed` disallows in-place retry (retry = record a new revision); rollback targets only the
//! **current** revision, and failures / uncertain outcomes land explicitly in `Failed`/`RollbackPending` with a diagnosable `error_summary`.

use crate::config_state::backend::ConfigApplyBackend;
use crate::config_state::ledger::{ConfigLedger, LedgerError};
use crate::entities::{ApplyStatus, ConfigRevision, NetworkId, RevisionError, Timestamp};

impl ConfigLedger {
    /// Apply one revision: `pending → applying → applied | failed`.
    ///
    /// - Already `Applied`: idempotent return, **backend not called again** (§10.3 re-apply must
    ///   not break the network);
    /// - backend failure (incl. uncertain outcome): enter `Failed` and record `error_summary`,
    ///   returning the updated revision — the caller must surface it to the console, never swallow it;
    /// - other illegal transitions (e.g. in-place retry of `Failed`) return
    ///   [`LedgerError::IllegalTransition`]; the retry path is recording a new revision.
    pub fn apply(
        &mut self,
        network_id: &NetworkId,
        revision: u64,
        backend: &mut dyn ConfigApplyBackend,
        now: Timestamp,
    ) -> Result<ConfigRevision, LedgerError> {
        // Read-only checks first: unknown revisions / idempotent replays of an applied version need no mutable borrow.
        match self.get(network_id, revision) {
            None => {
                return Err(LedgerError::RevisionNotFound {
                    network_id: network_id.to_string(),
                    revision,
                })
            }
            Some(r) if r.apply_status == ApplyStatus::Applied => return Ok(r.clone()),
            Some(_) => {}
        }
        if let Some(latest) = self.current(network_id) {
            if latest.revision != revision {
                return Err(LedgerError::SupersededRevision {
                    network_id: network_id.to_string(),
                    revision,
                    latest: latest.revision,
                });
            }
        }
        let r = self.get_mut(network_id, revision).unwrap();
        if r.apply_status == ApplyStatus::Pending {
            r.transition(ApplyStatus::Applying)?;
        }
        match backend.apply(r) {
            Ok(()) => {
                r.transition(ApplyStatus::Applied)?;
                r.applied_at = Some(now);
                r.error_summary = None;
            }
            Err(summary) => {
                // Explicit landing on failure (incl. uncertain outcome): error_summary is diagnosable (§12.2).
                r.transition(ApplyStatus::Failed)?;
                r.error_summary = Some(summary);
            }
        }
        Ok(self.get(network_id, revision).cloned().unwrap())
    }

    /// A provisional kernel success is not committed until its outcome is durable.
    /// Correct it to an explicit failure when persistence of that outcome fails.
    pub fn mark_apply_unconfirmed(&mut self, network_id: &NetworkId, revision: u64, error: String) {
        if let Some(r) = self.get_mut(network_id, revision) {
            if matches!(r.apply_status, ApplyStatus::Applied | ApplyStatus::Applying) {
                r.apply_status = ApplyStatus::Failed;
                r.applied_at = None;
                r.error_summary = Some(error);
            }
        }
    }

    /// Keep a rollback unconfirmed when its durable outcome cannot be committed.
    pub fn mark_rollback_unconfirmed(
        &mut self,
        network_id: &NetworkId,
        revision: u64,
        error: String,
    ) {
        if let Some(r) = self.get_mut(network_id, revision) {
            if matches!(
                r.apply_status,
                ApplyStatus::RolledBack | ApplyStatus::RollbackPending
            ) {
                r.apply_status = ApplyStatus::RollbackPending;
                let prior = r.error_summary.take().unwrap_or_default();
                r.error_summary = Some(format!("{prior}; {error}"));
            }
        }
    }

    /// Roll back a `Failed` revision: `failed → rollback_pending → rolled_back`.
    /// The rollback action likewise goes to the backend; a previous unconfirmed rollback
    /// (`RollbackPending`) may be retried, and an already `RolledBack` revision returns idempotently.
    /// After a successful rollback the current desired revision falls back to the earlier non-rolled-back one (see [`ConfigLedger::current`]).
    ///
    /// Only the **current** (latest non-rolled-back) revision may be rolled back: a `Failed`
    /// revision superseded by a newer one never took effect, so rolling it back by its intent would
    /// cross-touch the newer revision's objects (§10.4); return [`LedgerError::SupersededRevision`].
    pub fn rollback(
        &mut self,
        network_id: &NetworkId,
        revision: u64,
        backend: &mut dyn ConfigApplyBackend,
    ) -> Result<ConfigRevision, LedgerError> {
        // Read-only checks first: unknown revisions / idempotent replays / illegal transitions need no mutable borrow.
        match self.get(network_id, revision) {
            None => {
                return Err(LedgerError::RevisionNotFound {
                    network_id: network_id.to_string(),
                    revision,
                })
            }
            Some(r) => match r.apply_status {
                ApplyStatus::RolledBack => return Ok(r.clone()), // idempotent
                // Failed proceeds into rollback normally; RollbackPending is the retry entry for a previously unconfirmed rollback.
                ApplyStatus::Failed | ApplyStatus::RollbackPending => {}
                other => {
                    return Err(LedgerError::IllegalTransition(
                        RevisionError::IllegalTransition {
                            from: other,
                            to: ApplyStatus::RollbackPending,
                        },
                    ))
                }
            },
        }
        // Supersession check (§10.4 cross-damage): only the current revision may be rolled back.
        if let Some(latest) = self.current(network_id) {
            if latest.revision != revision {
                return Err(LedgerError::SupersededRevision {
                    network_id: network_id.to_string(),
                    revision,
                    latest: latest.revision,
                });
            }
        }
        let r = self.get_mut(network_id, revision).unwrap();
        if r.apply_status == ApplyStatus::Failed {
            r.transition(ApplyStatus::RollbackPending)?;
        }
        match backend.rollback(r) {
            Ok(()) => {
                r.transition(ApplyStatus::RolledBack)?;
            }
            Err(err) => {
                // Rollback failure: stay in RollbackPending (explicitly unfinished), keep the original
                // failure diagnostic and append the rollback error — states are distinguishable, failures visible.
                let mut msg = r.error_summary.take().unwrap_or_default();
                if !msg.is_empty() {
                    msg.push_str("; ");
                }
                msg.push_str("rollback failed: ");
                msg.push_str(&err);
                r.error_summary = Some(msg);
            }
        }
        Ok(self.get(network_id, revision).cloned().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::{ConfigLedger, LedgerError};
    use crate::config_state::backend::ConfigApplyBackend;
    use crate::config_state::test_support::{
        net, BrokenBackend, CountingBackend, OkBackend, T0, T1, T2,
    };
    use crate::entities::{ApplyStatus, ConfigRevision};

    #[test]
    fn apply_success_transitions_to_applied_and_sets_applied_at() {
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h".into(), T0.into());
        let r = l.apply(&id, 1, &mut OkBackend, T1.into()).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::Applied);
        assert_eq!(r.applied_at.as_deref(), Some(T1));
        assert!(r.error_summary.is_none());
    }

    #[test]
    fn apply_failure_is_visible_in_failed_state_with_verbatim_summary() {
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h".into(), T0.into());
        let mut backend = BrokenBackend::new("wg setconf exit 1: line 3 invalid", "unused");
        let r = l.apply(&id, 1, &mut backend, T1.into()).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::Failed);
        assert!(r.applied_at.is_none());
        assert_eq!(
            r.error_summary.as_deref(),
            Some("wg setconf exit 1: line 3 invalid")
        );
    }

    #[test]
    fn uncertain_backend_outcome_lands_in_failed_not_applied() {
        // §10.3: an uncertain outcome lands in an explicit failure state, never pretending success.
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h".into(), T0.into());
        let mut backend =
            BrokenBackend::new("result unknown: connection lost while applying", "unused");
        let r = l.apply(&id, 1, &mut backend, T1.into()).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::Failed);
        assert_eq!(
            r.error_summary.as_deref(),
            Some("result unknown: connection lost while applying")
        );
    }

    #[test]
    fn uncertain_durable_outcomes_stay_explicitly_unconfirmed() {
        let mut ledger = ConfigLedger::new();
        let network = net("net-1");
        ledger.record(&network, "h1".into(), T0.into());
        ledger
            .apply(&network, 1, &mut OkBackend, T1.into())
            .unwrap();
        ledger.mark_apply_unconfirmed(&network, 1, "apply commit io failed".into());
        let revision = ledger.get(&network, 1).unwrap().clone();
        assert_eq!(revision.apply_status, ApplyStatus::Failed);
        assert_eq!(revision.applied_at, None);
        assert_eq!(
            revision.error_summary.as_deref(),
            Some("apply commit io failed")
        );

        ledger.mark_rollback_unconfirmed(&network, 1, "pending state ignored".into());
        assert_eq!(
            ledger.get(&network, 1).unwrap().apply_status,
            ApplyStatus::Failed
        );

        let rollback = ledger.rollback(&network, 1, &mut OkBackend).unwrap();
        assert_eq!(rollback.apply_status, ApplyStatus::RolledBack);
        ledger.mark_rollback_unconfirmed(&network, 1, "rollback commit io failed".into());
        let revision = ledger.get(&network, 1).unwrap();
        assert_eq!(revision.apply_status, ApplyStatus::RollbackPending);
        assert_eq!(
            revision.error_summary.as_deref(),
            Some("apply commit io failed; rollback commit io failed")
        );

        ledger.mark_apply_unconfirmed(&network, 99, "missing".into());
        ledger.mark_rollback_unconfirmed(&network, 99, "missing".into());
    }

    #[test]
    fn unknown_or_superseded_revisions_are_refused_before_touching_backends() {
        let mut ledger = ConfigLedger::new();
        let network = net("net-1");
        ledger.record(&network, "h1".into(), T0.into());
        ledger
            .apply(
                &network,
                1,
                &mut BrokenBackend::new("apply failed", "unused"),
                T1.into(),
            )
            .unwrap();
        let mut backend = CountingBackend { calls: 0 };

        assert!(matches!(
            ledger.apply(&network, 404, &mut backend, T1.into()),
            Err(LedgerError::RevisionNotFound { revision: 404, .. })
        ));
        assert!(matches!(
            ledger.rollback(&network, 404, &mut backend),
            Err(LedgerError::RevisionNotFound { revision: 404, .. })
        ));

        ledger.record(&network, "h1".into(), T1.into());
        assert!(matches!(
            ledger.apply(&network, 1, &mut backend, T2.into()),
            Err(LedgerError::SupersededRevision {
                revision: 1,
                latest: 2,
                ..
            })
        ));

        ledger
            .apply(
                &network,
                2,
                &mut BrokenBackend::new("apply failed", "unused"),
                T2.into(),
            )
            .unwrap();
        assert_eq!(backend.calls, 0);
        assert!(matches!(
            ledger.rollback(&network, 1, &mut backend),
            Err(LedgerError::SupersededRevision {
                revision: 1,
                latest: 2,
                ..
            })
        ));
        assert_eq!(backend.calls, 0);
    }

    #[test]
    fn reapplying_applied_revision_is_idempotent_and_skips_backend() {
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h".into(), T0.into());
        let mut backend = CountingBackend { calls: 0 };
        let first = l.apply(&id, 1, &mut backend, T1.into()).unwrap();
        assert_eq!(first.apply_status, ApplyStatus::Applied);
        // Replaying the same version: backend not called again, applied_at unchanged.
        let second = l.apply(&id, 1, &mut backend, T2.into()).unwrap();
        assert_eq!(backend.calls, 1);
        assert_eq!(second.apply_status, ApplyStatus::Applied);
        assert_eq!(second.applied_at.as_deref(), Some(T1));
    }

    #[test]
    fn reapplying_failed_revision_is_rejected_new_revision_is_the_retry_path() {
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h".into(), T0.into());
        let mut backend = BrokenBackend::new("boom", "unused");
        l.apply(&id, 1, &mut backend, T1.into()).unwrap();
        // In-place retry is rejected by the state machine...
        let err = l.apply(&id, 1, &mut backend, T2.into()).unwrap_err();
        assert!(matches!(err, LedgerError::IllegalTransition(_)));
        // ...retry = record a new revision with the same hash.
        let rev2 = l.record(&id, "h".into(), T2.into());
        assert_eq!(rev2, 2);
        assert_eq!(l.current(&id).unwrap().apply_status, ApplyStatus::Pending);
    }

    #[test]
    fn apply_of_unknown_revision_is_not_found() {
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        let err = l.apply(&id, 7, &mut OkBackend, T1.into()).unwrap_err();
        assert_eq!(
            err,
            LedgerError::RevisionNotFound {
                network_id: "net-1".into(),
                revision: 7
            }
        );
    }

    #[test]
    fn failed_revision_can_be_rolled_back_and_current_falls_back() {
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h1".into(), T0.into());
        l.record(&id, "h2".into(), T0.into());
        let mut backend = BrokenBackend::new("boom", "unused");
        l.apply(&id, 2, &mut backend, T1.into()).unwrap();
        let r = l.rollback(&id, 2, &mut OkBackend).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::RolledBack);
        // After rollback the current desired revision falls back to the earlier non-rolled-back one.
        assert_eq!(l.current(&id).unwrap().revision, 1);
        assert_eq!(l.current(&id).unwrap().apply_status, ApplyStatus::Pending);
    }

    #[test]
    fn rollback_is_restricted_to_failed_revisions() {
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h".into(), T0.into());
        // Pending may not be rolled back (undoing an Applied revision goes forward via a new version, ADR-009).
        let err = l.rollback(&id, 1, &mut OkBackend).unwrap_err();
        assert!(matches!(err, LedgerError::IllegalTransition(_)));
        // Applied is terminal; rollback is likewise disallowed.
        l.apply(&id, 1, &mut OkBackend, T1.into()).unwrap();
        let err = l.rollback(&id, 1, &mut OkBackend).unwrap_err();
        assert!(matches!(err, LedgerError::IllegalTransition(_)));
    }

    #[test]
    fn failed_rollback_stays_rollback_pending_with_combined_summary_and_can_retry() {
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h".into(), T0.into());
        let mut broken = BrokenBackend::new("apply boom", "interface meshlet0 missing");
        l.apply(&id, 1, &mut broken, T1.into()).unwrap();
        // Rollback failure: stays in RollbackPending with diagnostics merged (original failure + rollback error).
        let r = l.rollback(&id, 1, &mut broken).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::RollbackPending);
        let summary = r.error_summary.as_deref().unwrap();
        assert!(summary.contains("apply boom"));
        assert!(summary.contains("rollback failed: interface meshlet0 missing"));
        // Retrying the rollback succeeds → RolledBack.
        let r = l.rollback(&id, 1, &mut OkBackend).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::RolledBack);
    }

    #[test]
    fn rolling_back_a_rolled_back_revision_is_idempotent() {
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h".into(), T0.into());
        let mut broken = BrokenBackend::new("boom", "unused");
        l.apply(&id, 1, &mut broken, T1.into()).unwrap();
        l.rollback(&id, 1, &mut OkBackend).unwrap();
        // Idempotent: no error, status unchanged, backend not called.
        let mut backend = CountingBackend { calls: 0 };
        let r = l.rollback(&id, 1, &mut backend).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::RolledBack);
        assert_eq!(backend.calls, 0);
    }

    #[test]
    fn fully_rolled_back_network_has_no_current_revision() {
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h".into(), T0.into());
        let mut broken = BrokenBackend::new("boom", "unused");
        l.apply(&id, 1, &mut broken, T1.into()).unwrap();
        l.rollback(&id, 1, &mut OkBackend).unwrap();
        assert!(l.current(&id).is_none());
    }

    #[test]
    fn rollback_of_superseded_failed_revision_is_rejected() {
        // §10.4 cross-damage guard: a Failed revision superseded by a newer one never took effect,
        // and rolling it back by its intent would touch objects owned by the newer revision.
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h1".into(), T0.into());
        let mut broken = BrokenBackend::new("boom", "unused");
        l.apply(&id, 1, &mut broken, T1.into()).unwrap();

        // Superseder is Pending: rolling back the old failed revision is refused.
        l.record(&id, "h2".into(), T2.into());
        assert_eq!(
            l.rollback(&id, 1, &mut OkBackend).unwrap_err(),
            LedgerError::SupersededRevision {
                network_id: "net-1".into(),
                revision: 1,
                latest: 2,
            }
        );
        // Superseder is Applied: likewise refused (undoing an Applied revision goes forward via a new version).
        let mut l2 = ConfigLedger::new();
        l2.record(&id, "h1".into(), T0.into());
        l2.apply(&id, 1, &mut broken, T1.into()).unwrap();
        l2.record(&id, "h2".into(), T2.into());
        l2.apply(&id, 2, &mut OkBackend, T2.into()).unwrap();
        assert!(matches!(
            l2.rollback(&id, 1, &mut OkBackend).unwrap_err(),
            LedgerError::SupersededRevision { .. }
        ));
        // The current (latest) failed revision can still be rolled back normally — the restriction is not a blanket ban.
        let mut l3 = ConfigLedger::new();
        l3.record(&id, "h1".into(), T0.into());
        l3.apply(&id, 1, &mut broken, T1.into()).unwrap();
        l3.record(&id, "h2".into(), T2.into());
        l3.apply(&id, 2, &mut broken, T2.into()).unwrap();
        let r = l3.rollback(&id, 2, &mut OkBackend).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::RolledBack);
        // Cascade: after rolling back the latest, the earlier failed revision becomes current and can be rolled back too.
        let r = l3.rollback(&id, 1, &mut OkBackend).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::RolledBack);
    }

    /// Record every call the backend receives (revision identity), to assert the rollback boundary.
    #[derive(Default)]
    struct RecordingBackend {
        applied: Vec<(String, u64)>,
        rolled_back: Vec<(String, u64)>,
    }

    impl ConfigApplyBackend for RecordingBackend {
        fn apply(&mut self, r: &ConfigRevision) -> Result<(), String> {
            self.applied.push((r.network_id.to_string(), r.revision));
            Err("recorded failure".into())
        }
        fn rollback(&mut self, r: &ConfigRevision) -> Result<(), String> {
            self.rolled_back
                .push((r.network_id.to_string(), r.revision));
            Ok(())
        }
    }

    #[test]
    fn rollback_backend_receives_only_the_failed_revision() {
        // §10.3 / ADR-007: the rollback is bounded by **that failed revision** — the backend only
        // receives this revision's identity (network_id + revision), never other revisions or any
        // "wipe everything" instruction; the ledger layer pins down this contract.
        let mut l = ConfigLedger::new();
        let (a, b) = (net("net-a"), net("net-b"));
        l.record(&a, "ha1".into(), T0.into());
        l.record(&b, "hb1".into(), T0.into());
        l.record(&a, "ha2".into(), T1.into());
        let mut backend = RecordingBackend::default();

        // net-a rev2 fails to apply; roll it back.
        l.apply(&a, 2, &mut backend, T2.into()).unwrap();
        let r = l.rollback(&a, 2, &mut backend).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::RolledBack);

        assert_eq!(backend.applied, vec![("net-a".into(), 2)]);
        // Exactly one rollback call, targeting the failed revision itself — not rev1, not net-b.
        assert_eq!(backend.rolled_back, vec![("net-a".into(), 2)]);
    }

    #[test]
    fn interrupted_applying_can_be_rolled_back_after_restart() {
        // A converged failed revision remains a valid rollback entry (rollback retry semantics unchanged).
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        let mut r = ConfigRevision::new(id.clone(), 1, "h".into(), T0.into());
        r.apply_status = ApplyStatus::Applying;
        l.restore(vec![r]);
        l.interrupt_applying("interrupted");
        let r = l.rollback(&id, 1, &mut OkBackend).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::RolledBack);
    }
}
