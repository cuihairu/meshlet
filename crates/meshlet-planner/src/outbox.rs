//! R-01 执行器切片：Outbox 投递状态机与 Revision 回执（纯逻辑，零依赖）。
//! 语义：至少一次投递 + 幂等键；回执乱序到达安全；状态迁移复用 planner 迁移表。

use crate::RevisionStatus;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxStatus {
    Pending,
    Dispatched,
    Acked,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEntry {
    /// 幂等键：revision_id + 操作序号，重复入队不会产生第二条
    pub idempotency_key: String,
    pub revision_id: String,
    pub op_index: u32,
    pub status: OutboxStatus,
    /// 至少一次投递：acked 之前可被 redeliver 任意次
    pub attempts: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboxError {
    UnknownEntry(String),
    IllegalTransition {
        from: OutboxStatus,
        to: OutboxStatus,
    },
}

#[derive(Debug, Default)]
pub struct Outbox {
    entries: BTreeMap<String, OutboxEntry>,
}

impl Outbox {
    pub fn enqueue(&mut self, revision_id: &str, op_index: u32) -> String {
        let key = format!("{revision_id}#{op_index}");
        self.entries
            .entry(key.clone())
            .or_insert_with(|| OutboxEntry {
                idempotency_key: key.clone(),
                revision_id: revision_id.to_string(),
                op_index,
                status: OutboxStatus::Pending,
                attempts: 0,
            });
        key
    }

    /// 取下一条待投递（字典序确定性）；投递计数 +1。acked 之后不会再出现。
    pub fn claim_next(&mut self) -> Option<&OutboxEntry> {
        let key = self
            .entries
            .values()
            .find(|e| e.status == OutboxStatus::Pending)
            .map(|e| e.idempotency_key.clone())?;
        let e = self.entries.get_mut(&key)?;
        e.status = OutboxStatus::Dispatched;
        e.attempts += 1;
        self.entries.get(&key)
    }

    /// 至少一次语义：acked 前允许重复投递。
    pub fn redeliver(&mut self, key: &str) -> Result<&OutboxEntry, OutboxError> {
        let e = self
            .entries
            .get_mut(key)
            .ok_or_else(|| OutboxError::UnknownEntry(key.into()))?;
        if e.status != OutboxStatus::Dispatched {
            return Err(OutboxError::IllegalTransition {
                from: e.status,
                to: OutboxStatus::Dispatched,
            });
        }
        e.attempts += 1;
        self.entries
            .get(key)
            .ok_or_else(|| OutboxError::UnknownEntry(key.into()))
    }

    pub fn ack(&mut self, key: &str) -> Result<(), OutboxError> {
        let e = self
            .entries
            .get_mut(key)
            .ok_or_else(|| OutboxError::UnknownEntry(key.into()))?;
        if e.status != OutboxStatus::Dispatched {
            return Err(OutboxError::IllegalTransition {
                from: e.status,
                to: OutboxStatus::Acked,
            });
        }
        e.status = OutboxStatus::Acked;
        Ok(())
    }

    pub fn pending_count(&self) -> usize {
        self.entries
            .values()
            .filter(|e| e.status == OutboxStatus::Pending)
            .count()
    }
}

/// Revision 回执：记录终态与投递统计，迁移必须过 planner 迁移表。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionReceipt {
    pub revision_id: String,
    pub status: RevisionStatus,
    pub ops_total: u32,
    pub ops_acked: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptError {
    IllegalTransition {
        from: RevisionStatus,
        to: RevisionStatus,
    },
    OpsExceedTotal,
}

impl RevisionReceipt {
    pub fn new(revision_id: &str, ops_total: u32) -> Self {
        Self {
            revision_id: revision_id.to_string(),
            status: RevisionStatus::Pending,
            ops_total,
            ops_acked: 0,
        }
    }

    /// 逐 op 回执（乱序安全：计数即可，谁先谁后不重要）。
    pub fn record_op_ack(&mut self) -> Result<(), ReceiptError> {
        if self.ops_acked + 1 > self.ops_total {
            return Err(ReceiptError::OpsExceedTotal);
        }
        self.ops_acked += 1;
        Ok(())
    }

    pub fn transition(&mut self, next: RevisionStatus) -> Result<(), ReceiptError> {
        if !self.status.can_transition_to(next) {
            return Err(ReceiptError::IllegalTransition {
                from: self.status,
                to: next,
            });
        }
        self.status = next;
        Ok(())
    }

    /// 全部 op acked 且处于 Applying 时，可进入 Succeeded。
    pub fn try_complete(&mut self) -> Result<bool, ReceiptError> {
        if self.ops_acked == self.ops_total && self.status == RevisionStatus::Applying {
            self.transition(RevisionStatus::Succeeded)?;
            return Ok(true);
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enqueue_is_idempotent() {
        let mut ob = Outbox::default();
        let a = ob.enqueue("rev1", 0);
        let b = ob.enqueue("rev1", 0);
        assert_eq!(a, b);
        assert_eq!(ob.pending_count(), 1);
    }

    #[test]
    fn redelivery_increments_attempts_only_before_ack() {
        let mut ob = Outbox::default();
        let k = ob.enqueue("rev1", 3);
        let e = ob.claim_next().unwrap();
        assert_eq!(e.attempts, 1);
        assert_eq!(ob.redeliver(&k).unwrap().attempts, 2);
        ob.ack(&k).unwrap();
        assert!(matches!(
            ob.redeliver(&k),
            Err(OutboxError::IllegalTransition { .. })
        ));
    }

    #[test]
    fn ack_unknown_or_pending_is_rejected() {
        let mut ob = Outbox::default();
        assert!(matches!(ob.ack("nope"), Err(OutboxError::UnknownEntry(_))));
        let k = ob.enqueue("rev9", 0);
        assert!(matches!(
            ob.ack(&k),
            Err(OutboxError::IllegalTransition { .. })
        ));
    }

    #[test]
    fn receipt_out_of_order_acks_then_complete() {
        let mut r = RevisionReceipt::new("rev1", 3);
        r.transition(RevisionStatus::Preparing).unwrap();
        r.transition(RevisionStatus::Applying).unwrap();
        r.record_op_ack().unwrap();
        r.record_op_ack().unwrap();
        r.record_op_ack().unwrap();
        assert!(r.try_complete().unwrap());
        assert_eq!(r.status, RevisionStatus::Succeeded);
        // Failed 不能直通 Succeeded（迁移表）
        let mut bad = RevisionReceipt::new("rev2", 1);
        bad.transition(RevisionStatus::Preparing).unwrap();
        bad.transition(RevisionStatus::Failed).unwrap();
        assert!(matches!(
            bad.transition(RevisionStatus::Succeeded),
            Err(ReceiptError::IllegalTransition { .. })
        ));
    }

    #[test]
    fn receipt_rejects_over_ack() {
        let mut r = RevisionReceipt::new("rev1", 1);
        r.record_op_ack().unwrap();
        assert!(matches!(
            r.record_op_ack(),
            Err(ReceiptError::OpsExceedTotal)
        ));
    }
}
