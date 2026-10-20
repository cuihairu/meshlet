use meshlet_planner::OutboxStatus;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database operation failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("stored data is invalid: {0}")]
    InvalidData(#[from] serde_json::Error),
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("stored plan operation is invalid: {0}")]
    InvalidPlanOp(String),
    #[error("stored revision status is invalid: {0}")]
    InvalidRevisionStatus(String),
    #[error("stored outbox status is invalid: {0}")]
    InvalidOutboxStatus(String),
    #[error("revision {0} already exists")]
    RevisionExists(String),
    #[error("outbox entry {0} is not {1:?}")]
    IllegalOutboxTransition(i64, OutboxStatus),
    #[error("unknown outbox entry {0}")]
    UnknownOutboxEntry(i64),
}
