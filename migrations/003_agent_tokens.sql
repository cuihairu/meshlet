-- Agent heartbeat/report credentials + device online-evidence timestamps (archive §12.4, §14.1).
-- Agent tokens follow the same discipline as invites/sessions: only the SHA-256 digest is
-- stored; the raw token appears exactly once, in the join response.
-- Note: device_id has no foreign key - device records currently live in the in-memory
-- MeshState and are not persisted in SQLite.
ALTER TABLE devices ADD COLUMN last_handshake_at TEXT;
ALTER TABLE devices ADD COLUMN last_report_at TEXT;

CREATE TABLE agent_tokens (
    token_hash TEXT PRIMARY KEY,
    device_id  TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE INDEX idx_agent_tokens_device ON agent_tokens(device_id);
