-- Tasks (MT-002): 通用任务通道。server 经既有 agent 拉取通道派任务，agent
-- 回 ack / 运行 / 回传 exit code + 日志尾部；task id 为幂等键，断线补派
-- 不重复执行。状态机见 meshlet-domain TaskState（assigned→acked→running→
-- done|failed），`state` 列存 as_str() 契约字段。
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

-- 按目标设备 + 状态查询待办（agent 拉取 pending、控制台按节点分列）。
CREATE INDEX idx_tasks_target_state ON tasks (target_device_id, state);
