-- meshlet schema v0.0.6 (Phase 5 diagnostics, archive §12.7).
-- One row per diagnostics run: POST /networks/{id}/diagnostics computes the
-- 12 checks (§12.7) and stores the report as JSON; GET returns the latest run
-- for the network. Checks are a closed, read-only set rendered by the console,
-- so a JSON snapshot needs no per-check table.
CREATE TABLE diagnostics_runs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id TEXT NOT NULL REFERENCES networks(id),
    checked_at TEXT NOT NULL,
    report     TEXT NOT NULL
);

CREATE INDEX idx_diagnostics_network ON diagnostics_runs(network_id, id);
