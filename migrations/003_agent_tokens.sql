-- Agent 心跳/上报凭证 + 设备在线证据时间戳（存档 §12.4、§14.1）。
-- Agent Token 与邀请/会话同一纪律：只存 SHA-256 摘要，原始 Token 仅在加入响应里出现一次。
-- 注：device_id 不加外键——设备记录当前存于内存 MeshState，SQLite 不做持久化。
ALTER TABLE devices ADD COLUMN last_handshake_at TEXT;
ALTER TABLE devices ADD COLUMN last_report_at TEXT;

CREATE TABLE agent_tokens (
    token_hash TEXT PRIMARY KEY,
    device_id  TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE INDEX idx_agent_tokens_device ON agent_tokens(device_id);
