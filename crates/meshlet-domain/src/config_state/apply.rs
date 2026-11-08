//! apply/rollback 语义（§10.3–§10.4）：修订的状态机跃迁与 backend 交互。
//!
//! 跃迁纪律：已 `Applied` 的修订幂等返回、不再调用 backend；`Failed` 不允许
//! 原地重试（重试 = 记录新修订）；回滚只针对**当前**修订；失败与结果不确定
//! 一律显式落 `Failed`/`RollbackPending` 并保留可诊断的 `error_summary`。

use crate::config_state::backend::ConfigApplyBackend;
use crate::config_state::ledger::{ConfigLedger, LedgerError};
use crate::entities::{ApplyStatus, ConfigRevision, NetworkId, RevisionError, Timestamp};

impl ConfigLedger {
    /// 应用一个修订：`pending → applying → applied | failed`。
    ///
    /// - 已 `Applied`：幂等返回，**不再调用 backend**（§10.3 重复应用不破坏
    ///   网络）；
    /// - backend 失败（含结果不确定）：进入 `Failed` 并记录 `error_summary`，
    ///   返回更新后的修订——调用方必须向控制台暴露该失败，不得吞掉；
    /// - 其余非法跃迁（如对 `Failed` 原地重试）返回
    ///   [`LedgerError::IllegalTransition`]，重试路径是记录新修订。
    pub fn apply(
        &mut self,
        network_id: &NetworkId,
        revision: u64,
        backend: &mut dyn ConfigApplyBackend,
        now: Timestamp,
    ) -> Result<ConfigRevision, LedgerError> {
        // 先做只读判定：未知修订 / 已生效版本的幂等重放都不需要可变借用。
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
                // 失败（含不确定结果）显式落态：error_summary 可诊断（§12.2）。
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

    /// 回滚一个 `Failed` 修订：`failed → rollback_pending → rolled_back`。
    /// 回滚动作同样交给 backend；上次回滚未确认（`RollbackPending`）允许重试，
    /// 已 `RolledBack` 的修订幂等返回。回滚成功后当前期望修订自然回落到更早
    /// 的未回滚修订（见 [`ConfigLedger::current`]）。
    ///
    /// 只允许回滚**当前**（最新未回滚的）修订：被更新修订取代的 `Failed`
    /// 修订从未生效，按其意图回滚会交叉触碰更新修订拥有的对象（§10.4），
    /// 返回 [`LedgerError::SupersededRevision`]。
    pub fn rollback(
        &mut self,
        network_id: &NetworkId,
        revision: u64,
        backend: &mut dyn ConfigApplyBackend,
    ) -> Result<ConfigRevision, LedgerError> {
        // 先做只读判定：未知修订 / 幂等重放 / 非法跃迁都不需要可变借用。
        match self.get(network_id, revision) {
            None => {
                return Err(LedgerError::RevisionNotFound {
                    network_id: network_id.to_string(),
                    revision,
                })
            }
            Some(r) => match r.apply_status {
                ApplyStatus::RolledBack => return Ok(r.clone()), // 幂等
                // Failed 正常进入回滚；RollbackPending 是上次回滚未确认的重试入口。
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
        // 取代检查（§10.4 交叉破坏）：只回滚当前修订。
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
                // 回滚失败：留在 RollbackPending（明确未完成），保留原失败
                // 诊断并追加回滚错误——状态可区分，失败可见。
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
        // §10.3：结果不确定时进入明确的失败状态，不得假装成功。
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
        // 重放同一版本：不再调用 backend，applied_at 不变。
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
        // 原地重试被状态机拒绝……
        let err = l.apply(&id, 1, &mut backend, T2.into()).unwrap_err();
        assert!(matches!(err, LedgerError::IllegalTransition(_)));
        // ……重试 = 以相同哈希记录新修订。
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
        // 回滚后当前期望回落到更早的未回滚修订。
        assert_eq!(l.current(&id).unwrap().revision, 1);
        assert_eq!(l.current(&id).unwrap().apply_status, ApplyStatus::Pending);
    }

    #[test]
    fn rollback_is_restricted_to_failed_revisions() {
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h".into(), T0.into());
        // Pending 不允许回滚（Applied 的撤销走前滚新版本，ADR-009）。
        let err = l.rollback(&id, 1, &mut OkBackend).unwrap_err();
        assert!(matches!(err, LedgerError::IllegalTransition(_)));
        // Applied 是终态，同样不允许回滚。
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
        // 回滚失败：留在 RollbackPending，诊断合并（原失败 + 回滚错误）。
        let r = l.rollback(&id, 1, &mut broken).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::RollbackPending);
        let summary = r.error_summary.as_deref().unwrap();
        assert!(summary.contains("apply boom"));
        assert!(summary.contains("rollback failed: interface meshlet0 missing"));
        // 重试回滚成功 → RolledBack。
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
        // 幂等：不报错、状态不变、不调用 backend。
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
        // §10.4 交叉破坏防线：被更新修订取代的 Failed 修订从未生效，按其
        // 意图回滚会触碰更新修订拥有的对象。
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h1".into(), T0.into());
        let mut broken = BrokenBackend::new("boom", "unused");
        l.apply(&id, 1, &mut broken, T1.into()).unwrap();

        // 取代者是 Pending：回滚旧失败修订被拒。
        l.record(&id, "h2".into(), T2.into());
        assert_eq!(
            l.rollback(&id, 1, &mut OkBackend).unwrap_err(),
            LedgerError::SupersededRevision {
                network_id: "net-1".into(),
                revision: 1,
                latest: 2,
            }
        );
        // 取代者是 Applied：同样被拒（Applied 的撤销走前滚新版本）。
        let mut l2 = ConfigLedger::new();
        l2.record(&id, "h1".into(), T0.into());
        l2.apply(&id, 1, &mut broken, T1.into()).unwrap();
        l2.record(&id, "h2".into(), T2.into());
        l2.apply(&id, 2, &mut OkBackend, T2.into()).unwrap();
        assert!(matches!(
            l2.rollback(&id, 1, &mut OkBackend).unwrap_err(),
            LedgerError::SupersededRevision { .. }
        ));
        // 当前（最新）失败修订仍可正常回滚——限制不是全禁。
        let mut l3 = ConfigLedger::new();
        l3.record(&id, "h1".into(), T0.into());
        l3.apply(&id, 1, &mut broken, T1.into()).unwrap();
        l3.record(&id, "h2".into(), T2.into());
        l3.apply(&id, 2, &mut broken, T2.into()).unwrap();
        let r = l3.rollback(&id, 2, &mut OkBackend).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::RolledBack);
        // 级联：回滚掉最新后，更早的失败修订成为当前，可继续回滚。
        let r = l3.rollback(&id, 1, &mut OkBackend).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::RolledBack);
    }

    /// 记录 backend 收到的每次调用（修订身份），用于断言回滚边界。
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
        // §10.3 / ADR-007：回滚以**该失败修订**为边界——backend 只收到这个
        // 修订的身份（network_id + revision），从不收到其他修订或任何
        // 「清空全部」指令；ledger 层钉死这条契约。
        let mut l = ConfigLedger::new();
        let (a, b) = (net("net-a"), net("net-b"));
        l.record(&a, "ha1".into(), T0.into());
        l.record(&b, "hb1".into(), T0.into());
        l.record(&a, "ha2".into(), T1.into());
        let mut backend = RecordingBackend::default();

        // net-a rev2 应用失败；回滚它。
        l.apply(&a, 2, &mut backend, T2.into()).unwrap();
        let r = l.rollback(&a, 2, &mut backend).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::RolledBack);

        assert_eq!(backend.applied, vec![("net-a".into(), 2)]);
        // 恰好一次回滚调用，目标就是失败修订本身——不是 rev1、不是 net-b。
        assert_eq!(backend.rolled_back, vec![("net-a".into(), 2)]);
    }

    #[test]
    fn interrupted_applying_can_be_rolled_back_after_restart() {
        // 收敛后的 failed 修订仍是合法回滚入口（rollback 重试语义不变）。
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
