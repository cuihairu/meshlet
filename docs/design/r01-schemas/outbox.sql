-- R-01 outbox draft: written in the same transaction as the revision, delivered at
-- least once, and marked once the executor acks.
CREATE TABLE IF NOT EXISTS outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  network_id TEXT NOT NULL,
  revision_id TEXT NOT NULL,
  op_index INTEGER NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  plan_op_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  delivery_count INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  dispatched_at INTEGER,
  acked_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_outbox_revision ON outbox(revision_id);
