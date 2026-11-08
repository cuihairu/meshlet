//! 每网络配置修订簿记（ADR-009）：修订的记录、查询、启动重建与中断收敛。
//! apply/rollback 语义（状态机跃迁与 backend 交互）在 `apply` 子模块。

use crate::entities::{ApplyStatus, ConfigRevision, NetworkId, RevisionError, Timestamp};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    #[error("revision {revision} not found in network {network_id}")]
    RevisionNotFound { network_id: String, revision: u64 },
    /// 回滚目标已被更新修订取代（§10.4）：被取代的失败修订从未生效，按其
    /// 意图回滚会交叉触碰更新修订所拥有的对象——重试路径是对当前修订操作
    /// 或前滚记录新修订。
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

/// 每网络配置修订簿记（ADR-009）：版本号网络内严格单调递增（§10.4 的版本
/// 顺序——同一网络的配置修改串行化即由「先记录修订、再应用修订」保证）。
#[derive(Debug, Clone, Default)]
pub struct ConfigLedger {
    revisions: HashMap<NetworkId, Vec<ConfigRevision>>,
}

impl ConfigLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// 记录一次期望配置变更：版本号 = 该网络上一版本 + 1，初始状态
    /// `Pending`（此时只完成了 DB 写入，**尚未生效**）。
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

    /// 某网络的全部修订（按版本号升序；未知网络返回空切片）。
    pub fn revisions(&self, network_id: &NetworkId) -> &[ConfigRevision] {
        self.revisions
            .get(network_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// 单个修订。
    pub fn get(&self, network_id: &NetworkId, revision: u64) -> Option<&ConfigRevision> {
        self.revisions(network_id)
            .iter()
            .find(|r| r.revision == revision)
    }

    /// 当前期望修订 = 最新一个未回滚的修订（控制台以此为准，§10.1）。
    pub fn current(&self, network_id: &NetworkId) -> Option<&ConfigRevision> {
        self.revisions(network_id)
            .iter()
            .rev()
            .find(|r| r.apply_status != ApplyStatus::RolledBack)
    }

    /// 装载持久化的修订（§17.3 启动重建）：按网络分组、版本号升序灌入，
    /// 版本序列与 DB 逐字一致——后续 [`Self::record`] 从最后一条继续递增，
    /// 不重号。调用方（boot）应保证同一网络内版本号无重复。
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

    /// §10.3 中断收敛（§17.3 重启恢复）：进程重启后，停在 `Applying` 的修订
    /// 结果不可知——一律落 `Failed` 并记录中断诊断，**不得假装成功**。
    /// `RollbackPending` 保留（回滚未确认、可重试）；`Applied`/`RolledBack`
    /// 是终态，不动。返回被收敛修订的身份，供调用方回写持久层。
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
        // 另一网络独立计数（§10.4 版本顺序按网络隔离）。
        assert_eq!(l.record(&b, "h1".into(), T0.into()), 1);
        assert_eq!(l.current(&a).unwrap().revision, 2);
        assert_eq!(l.get(&a, 1).unwrap().desired_config_hash, "h1");
        assert_eq!(l.get(&b, 1).unwrap().desired_config_hash, "h1");
    }

    #[test]
    fn recorded_revision_is_pending_without_applied_at_or_error() {
        // 验收基线：DB 写入 ≠ 显示生效——新修订不得宣称 Applied。
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
        // §17.3 启动重建：持久化的修订逐字灌回，后续 record 接续递增不重号。
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        let r1 = ConfigRevision::new(id.clone(), 1, "h1".into(), T0.into());
        let mut r2 = ConfigRevision::new(id.clone(), 2, "h2".into(), T1.into());
        r2.apply_status = ApplyStatus::Applied;
        r2.applied_at = Some(T2.into());
        l.restore(vec![r2.clone(), r1.clone()]); // 乱序输入也按版本号归位
        assert_eq!(l.revisions(&id), &[r1, r2]);
        assert_eq!(l.current(&id).unwrap().desired_config_hash, "h2");
        // 重启后新变更：版本号从 3 续起。
        assert_eq!(l.record(&id, "h3".into(), T2.into()), 3);
    }

    #[test]
    fn interrupted_applying_lands_failed_with_summary() {
        // §10.3：停在 applying 的修订结果不可知 → 落 failed + 中断诊断。
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
        // 终态与回滚未确认态不受影响。
        assert_eq!(l.get(&id, 1).unwrap().apply_status, ApplyStatus::Applied);
        assert_eq!(
            l.get(&id, 3).unwrap().apply_status,
            ApplyStatus::RollbackPending
        );
        // 幂等：再次收敛不再命中任何修订。
        assert!(l.interrupt_applying("again").is_empty());
    }

    #[test]
    fn concurrent_record_assigns_unique_contiguous_revisions() {
        // §10.4 版本顺序：并发记录（调用方持网络级互斥）下版本号唯一、
        // 连续、严格递增——不交叉、不丢号、不重号。
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
