//! R-01 executor slice: the Outbox delivery state machine and Revision receipts (pure logic, zero dependencies).
//! Semantics: at-least-once delivery + idempotency keys; receipts are safe to arrive out of order; transitions reuse the planner transition table.

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
    /// Idempotency key: revision_id + op index; re-enqueueing never creates a second entry
    pub idempotency_key: String,
    pub revision_id: String,
    pub op_index: u32,
    pub status: OutboxStatus,
    /// At-least-once delivery: may be redelivered any number of times before ack
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

    /// Claim the next entry to deliver (deterministic lexicographic order); attempts += 1. Never resurfaces after ack.
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

    /// At-least-once semantics: repeated delivery is allowed before ack.
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

/// Revision receipt: records the terminal state and delivery stats; transitions must pass the planner transition table.
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

    /// Per-op receipt (out-of-order safe: it is just a count, arrival order does not matter).
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

    /// Once every op is acked while in Applying, the revision may move to Succeeded.
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
        // Failed must not jump straight to Succeeded (transition table)
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
