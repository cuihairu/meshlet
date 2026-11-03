-- Tasks confirm/retry (MT-003): user-side acknowledgment. 确认是用户侧动作——
-- agent 只回执 exit_code（done|failed），confirmed_at 仅控制台/CLI 可置，
-- agent 端点绝无确认能力（「agent 不得自判 done」）。
-- retry（驳回重跑）保留原记录并置 rejected_at，派发新一代任务
-- （parent_task_id 指向被驳回任务；新代换新 id——agent 账本按 task id 去重，
-- 换新 id 才能触发重跑）。
ALTER TABLE tasks ADD COLUMN confirmed_at TEXT;
ALTER TABLE tasks ADD COLUMN rejected_at TEXT;
ALTER TABLE tasks ADD COLUMN parent_task_id TEXT;
