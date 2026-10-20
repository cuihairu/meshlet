use meshlet_planner::{OutboxStatus, PlanOp, RevisionStatus};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionRecord {
    pub network_id: String,
    pub revision_id: String,
    pub plan_json: String,
    pub ops_total: u32,
    pub status: RevisionStatus,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRecord {
    pub id: i64,
    pub network_id: String,
    pub revision_id: String,
    pub op_index: u32,
    pub idempotency_key: String,
    pub plan_op: PlanOp,
    pub status: OutboxStatus,
    pub delivery_count: u32,
    pub created_at: i64,
    pub dispatched_at: Option<i64>,
    pub acked_at: Option<i64>,
}
