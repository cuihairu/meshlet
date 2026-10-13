-- meshlet schema v0.0.1 (Phase 1 core entities).
-- Sources: docs/architecture/domain-model.md (ADR-003/004/006/009).
-- Invariant: no table stores private key material (ADR-010, §11.2).

PRAGMA foreign_keys = ON;

CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE networks (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    overlay_cidr  TEXT NOT NULL UNIQUE,
    status        TEXT NOT NULL DEFAULT 'active',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE devices (
    id             TEXT PRIMARY KEY,
    network_id     TEXT NOT NULL REFERENCES networks(id),
    name           TEXT NOT NULL,
    virtual_ipv4   TEXT NOT NULL,
    public_key     TEXT NOT NULL,
    platform       TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending',
    last_seen_at   TEXT,
    created_at     TEXT NOT NULL,
    revoked_at     TEXT,
    UNIQUE (network_id, name),
    UNIQUE (network_id, virtual_ipv4)
);

CREATE TABLE device_keys (
    device_id   TEXT NOT NULL PRIMARY KEY REFERENCES devices(id),
    public_key  TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    revoked_at  TEXT
);

CREATE TABLE invitations (
    id          TEXT PRIMARY KEY,
    network_id  TEXT NOT NULL REFERENCES networks(id),
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  TEXT,
    max_uses    INTEGER NOT NULL DEFAULT 1,
    used_count  INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    revoked_at  TEXT
);

CREATE TABLE lan_routes (
    id                  TEXT PRIMARY KEY,
    network_id          TEXT NOT NULL REFERENCES networks(id),
    gateway_device_id   TEXT NOT NULL REFERENCES devices(id),
    destination_cidr    TEXT NOT NULL,
    route_mode          TEXT NOT NULL,
    return_path_mode    TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending',
    created_at          TEXT NOT NULL
);

CREATE TABLE alias_mappings (
    id               TEXT PRIMARY KEY,
    network_id       TEXT NOT NULL REFERENCES networks(id),
    lan_route_id     TEXT NOT NULL REFERENCES lan_routes(id),
    alias_cidr       TEXT NOT NULL,
    target_cidr      TEXT NOT NULL,
    translation_mode TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending',
    created_at       TEXT NOT NULL
);

CREATE TABLE config_revisions (
    network_id           TEXT NOT NULL REFERENCES networks(id),
    revision             INTEGER NOT NULL,
    desired_config_hash  TEXT NOT NULL,
    apply_status         TEXT NOT NULL DEFAULT 'pending',
    created_at           TEXT NOT NULL,
    applied_at           TEXT,
    error_summary        TEXT,
    PRIMARY KEY (network_id, revision)
);

CREATE TABLE audit_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id    TEXT,
    action      TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id   TEXT,
    detail      TEXT,
    created_at  TEXT NOT NULL
);

CREATE INDEX idx_devices_network ON devices(network_id);
CREATE INDEX idx_invitations_network ON invitations(network_id);
CREATE INDEX idx_lan_routes_network ON lan_routes(network_id);
CREATE INDEX idx_alias_network ON alias_mappings(network_id);
CREATE INDEX idx_audit_created ON audit_events(created_at);
