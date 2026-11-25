-- Tasks confirm/retry (MT-003): user-side acknowledgment. Confirming is a user-side
-- action - the agent only reports exit_code (done|failed); confirmed_at is writable only
-- by the console/CLI, and the agent endpoints must never confirm ("the agent must not
-- declare itself done").
-- retry (reject and rerun) keeps the original record, sets rejected_at, and dispatches a
-- new generation (parent_task_id points at the rejected task; the new generation gets a
-- new id - the agent ledger dedupes by task id, so only a fresh id triggers a rerun).
ALTER TABLE tasks ADD COLUMN confirmed_at TEXT;
ALTER TABLE tasks ADD COLUMN rejected_at TEXT;
ALTER TABLE tasks ADD COLUMN parent_task_id TEXT;
