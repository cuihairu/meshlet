-- R-01 Outbox 草案：与 Revision 同事务写入，至少一次投递，执行器回执后标记。
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
