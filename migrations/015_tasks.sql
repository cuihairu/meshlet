-- Tasks (MT-002): a general task channel. The server dispatches tasks over the existing
-- agent pull channel; the agent acks, runs, and reports back the exit code + log tail.
-- The task id is the idempotency key: re-dispatch after a disconnect never re-executes.
-- State machine: meshlet-domain TaskState (assigned->acked->running->done|failed);
-- the `state` column stores the as_str() contract field.
CREATE TABLE tasks (
    id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL,
    target_device_id TEXT NOT NULL,
    cmd TEXT NOT NULL,
    workdir TEXT,
    timeout_secs INTEGER,
    state TEXT NOT NULL,
    retry_limit INTEGER NOT NULL DEFAULT 0,
    result_ref TEXT,
    exit_code INTEGER,
    log_tail TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Pending-work lookup by target device + state (agent pulls pending; the console groups by node).
CREATE INDEX idx_tasks_target_state ON tasks (target_device_id, state);
