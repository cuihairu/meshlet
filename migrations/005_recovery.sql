-- meshlet schema v0.0.5 (Phase 5 recovery, archive §17.3).
-- Control-plane mesh state (networks/devices/lan_routes/config_revisions) is
-- persisted so a restart rebuilds the same desired state. Migrations 001-004
-- are published and untouched; device presence evidence columns already exist
-- (migration 003).
--
-- Monotonic counters that must not restart from zero live here: a deleted
-- route id must never be reused after a restart (§17.3).
CREATE TABLE mesh_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
