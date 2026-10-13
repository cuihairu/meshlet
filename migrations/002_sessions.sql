-- meshlet schema v0.0.2 (console auth sessions).
-- Sources: docs/review/chatgpt-2026-10-13.md §11.4.
-- Invariant: only session token digests are stored, never raw tokens.

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE INDEX idx_sessions_user ON sessions(user_id);
