-- Machine credentials for external systems (API tokens, requested by the user 2026-10-14).
-- Same discipline as invite/session/agent credentials: only the SHA-256 digest is stored;
-- the raw token appears exactly once, in the create response (mlt_ prefix + 64 hex).
-- Revoke/list go by stable id; the digest never leaves the boundary.
-- scopes: 'read' or 'write' (write implies read).
CREATE TABLE api_tokens (
    id           TEXT PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE,
    user_id      TEXT NOT NULL REFERENCES users(id),
    name         TEXT NOT NULL,
    scopes       TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at   TEXT
);

CREATE INDEX idx_api_tokens_user ON api_tokens(user_id);
