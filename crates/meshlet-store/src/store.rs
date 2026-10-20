use std::path::Path;

use meshlet_planner::{OutboxStatus, PlanOp, RevisionStatus};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    Row, SqlitePool,
};

use crate::codec::{
    decode_outbox_status, decode_plan_op, decode_revision_status, encode_outbox_status,
    encode_plan, encode_plan_op, encode_revision_status,
};
use crate::error::StoreError;
use crate::models::{OutboxRecord, RevisionRecord};

#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
}

#[derive(Debug, Clone)]
pub struct RevisionDraft {
    pub network_id: String,
    pub revision_id: String,
    pub ops: Vec<PlanOp>,
    pub created_at: i64,
}

impl Store {
    pub async fn new(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal);
        let pool = SqlitePoolOptions::new().connect_with(options).await?;
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    async fn migrate(&self) -> Result<(), StoreError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS revisions (
               network_id TEXT NOT NULL,
               revision_id TEXT NOT NULL,
               plan_json TEXT NOT NULL,
               ops_total INTEGER NOT NULL,
               status TEXT NOT NULL,
               created_at INTEGER NOT NULL,
               PRIMARY KEY(network_id, revision_id)
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(include_str!("../../../docs/design/r01-schemas/outbox.sql"))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn append_revision(&self, draft: RevisionDraft) -> Result<(), StoreError> {
        let plan_ops = draft.ops;
        let ops_total = plan_ops.len();
        let plan_json = encode_plan(&plan_ops)?;
        let mut transaction = self.pool.begin().await?;
        let inserted = sqlx::query(
            "INSERT INTO revisions(network_id, revision_id, plan_json, ops_total, status, created_at)
             VALUES(?, ?, ?, ?, ?, ?)
             ON CONFLICT(network_id, revision_id) DO NOTHING",
        )
        .bind(&draft.network_id)
        .bind(&draft.revision_id)
        .bind(&plan_json)
        .bind(ops_total as i64)
        .bind(encode_revision_status(RevisionStatus::Pending))
        .bind(draft.created_at)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if inserted == 0 {
            return Err(StoreError::RevisionExists(draft.revision_id));
        }
        for (op_index, op) in plan_ops.iter().enumerate() {
            let op_index = op_index as u32;
            sqlx::query(
                "INSERT INTO outbox(
                   network_id, revision_id, op_index, idempotency_key, plan_op_json,
                   status, delivery_count, created_at
                 ) VALUES(?, ?, ?, ?, ?, ?, 0, ?)",
            )
            .bind(&draft.network_id)
            .bind(&draft.revision_id)
            .bind(op_index as i64)
            .bind(format!("{}#{}", draft.revision_id, op_index))
            .bind(encode_plan_op(op)?)
            .bind(encode_outbox_status(OutboxStatus::Pending))
            .bind(draft.created_at)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn get_revision(
        &self,
        network_id: &str,
        revision_id: &str,
    ) -> Result<Option<RevisionRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT network_id, revision_id, plan_json, ops_total, status, created_at
             FROM revisions WHERE network_id = ? AND revision_id = ?",
        )
        .bind(network_id)
        .bind(revision_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| map_revision(&row)).transpose()
    }

    pub async fn revision_outbox(
        &self,
        revision_id: &str,
    ) -> Result<Vec<OutboxRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, network_id, revision_id, op_index, idempotency_key, plan_op_json,
                    status, delivery_count, created_at, dispatched_at, acked_at
             FROM outbox WHERE revision_id = ? ORDER BY op_index",
        )
        .bind(revision_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(map_outbox).collect()
    }

    pub async fn claim_next(&self, now: i64) -> Result<Option<OutboxRecord>, StoreError> {
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT id, network_id, revision_id, op_index, idempotency_key, plan_op_json,
                    status, delivery_count, created_at, dispatched_at, acked_at
             FROM outbox WHERE status IN('pending', 'dispatched')
             ORDER BY id LIMIT 1",
        )
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let record = map_outbox(&row)?;
        sqlx::query(
            "UPDATE outbox
             SET status = ?, delivery_count = delivery_count + 1, dispatched_at = ?
             WHERE id = ?",
        )
        .bind(encode_outbox_status(OutboxStatus::Dispatched))
        .bind(now)
        .bind(record.id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        let mut delivered = record.clone();
        delivered.status = OutboxStatus::Dispatched;
        delivered.delivery_count += 1;
        delivered.dispatched_at = Some(now);
        Ok(Some(delivered))
    }

    pub async fn ack_entry(&self, id: i64, now: i64) -> Result<(), StoreError> {
        let result = sqlx::query(
            "UPDATE outbox
             SET status = ?, acked_at = ?
             WHERE id = ? AND status = ?",
        )
        .bind(encode_outbox_status(OutboxStatus::Acked))
        .bind(now)
        .bind(id)
        .bind(encode_outbox_status(OutboxStatus::Dispatched))
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            let status = sqlx::query("SELECT status FROM outbox WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
            return match status {
                Some(row) => Err(StoreError::IllegalOutboxTransition(
                    id,
                    decode_outbox_status(row.try_get("status")?).unwrap_or(OutboxStatus::Failed),
                )),
                None => Err(StoreError::UnknownOutboxEntry(id)),
            };
        }
        Ok(())
    }
}

fn map_revision(row: &sqlx::sqlite::SqliteRow) -> Result<RevisionRecord, StoreError> {
    let status = row.try_get::<String, _>("status")?;
    let decoded_status = decode_revision_status(&status)?;
    Ok(RevisionRecord {
        network_id: row.try_get("network_id")?,
        revision_id: row.try_get("revision_id")?,
        plan_json: row.try_get("plan_json")?,
        ops_total: row.try_get::<i64, _>("ops_total")? as u32,
        status: decoded_status,
        created_at: row.try_get("created_at")?,
    })
}

fn map_outbox(row: &sqlx::sqlite::SqliteRow) -> Result<OutboxRecord, StoreError> {
    let op_json = row.try_get::<String, _>("plan_op_json")?;
    let plan_op = serde_json::from_str::<serde_json::Value>(&op_json)
        .map_err(|error| StoreError::InvalidPlanOp(error.to_string()))?;
    let plan_op = decode_plan_op(plan_op)?;
    let status =
        decode_outbox_status(&row.try_get::<String, _>("status")?).map_err(
            |error| match error {
                StoreError::InvalidPlanOp(reason) => StoreError::InvalidOutboxStatus(reason),
                other => other,
            },
        )?;
    Ok(OutboxRecord {
        id: row.try_get("id")?,
        network_id: row.try_get("network_id")?,
        revision_id: row.try_get("revision_id")?,
        op_index: row.try_get::<i64, _>("op_index")? as u32,
        idempotency_key: row.try_get("idempotency_key")?,
        plan_op,
        status,
        delivery_count: row.try_get::<i64, _>("delivery_count")? as u32,
        created_at: row.try_get("created_at")?,
        dispatched_at: row.try_get("dispatched_at")?,
        acked_at: row.try_get("acked_at")?,
    })
}
