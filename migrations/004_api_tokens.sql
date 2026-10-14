-- 外部系统机器凭据（API Token，2026-10-14 用户需求）。
-- 与邀请/会话/agent 凭证同一纪律：只存 SHA-256 摘要，原始 Token 仅在创建
-- 响应中出现一次（mlt_ 前缀 + 64 hex）。撤销/列表走稳定 id，摘要不出边界。
-- scopes：'read' 或 'write'（write 隐含 read）。
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
