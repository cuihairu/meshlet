-- Last successful hub plans contain public configuration only, never private keys.
CREATE TABLE hub_deployments (
    network_id TEXT PRIMARY KEY REFERENCES networks(id),
    plan_json TEXT NOT NULL,
    recovery_error TEXT,
    checked_at TEXT
);
CREATE TABLE device_apply_receipts (
    device_id TEXT PRIMARY KEY REFERENCES devices(id),
    revision INTEGER NOT NULL,
    plan_hash TEXT NOT NULL,
    applied_at TEXT NOT NULL,
    error TEXT
);
