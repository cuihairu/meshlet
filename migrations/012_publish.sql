-- meshlet schema v0.0.12 (R-06: service publishing control plane).
--
-- Four typed publish objects plus one agent-reported probe-health table.
-- Objects are network- and device-scoped: only the owning device's agent
-- binds a listener for them, so port conflicts are judged per device.
--
-- `allowed_bearer_tokens` holds ingress allowlist secrets for the published
-- service (NOT control-plane credentials). They are stored raw because the
-- data plane compares them exactly, but the read APIs never echo them (a
-- count is returned instead) and they are never written to the audit log.
-- No private key material is ever stored (ADR-010).
CREATE TABLE publish_forwards (
    id                  TEXT PRIMARY KEY,
    network_id          TEXT NOT NULL REFERENCES networks(id),
    device_id           TEXT NOT NULL REFERENCES devices(id),
    protocol            TEXT NOT NULL,
    listener_address    TEXT NOT NULL,
    backend_address     TEXT NOT NULL,
    allowed_source_cidrs TEXT NOT NULL,
    allowed_bearer_tokens TEXT NOT NULL,
    enabled             INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT NOT NULL
);

CREATE INDEX idx_publish_forwards_network ON publish_forwards(network_id);
CREATE INDEX idx_publish_forwards_device ON publish_forwards(device_id);

CREATE TABLE publish_http_routes (
    id                    TEXT PRIMARY KEY,
    network_id            TEXT NOT NULL REFERENCES networks(id),
    device_id             TEXT NOT NULL REFERENCES devices(id),
    hostname              TEXT NOT NULL,
    path_prefix           TEXT NOT NULL,
    backend_address       TEXT NOT NULL,
    listener_address      TEXT NOT NULL,
    allowed_source_cidrs  TEXT NOT NULL,
    allowed_bearer_tokens TEXT NOT NULL,
    tls_termination       INTEGER NOT NULL DEFAULT 0,
    created_at            TEXT NOT NULL
);

CREATE INDEX idx_publish_http_routes_network ON publish_http_routes(network_id);
CREATE INDEX idx_publish_http_routes_device ON publish_http_routes(device_id);

CREATE TABLE publish_probes (
    id              TEXT PRIMARY KEY,
    network_id      TEXT NOT NULL REFERENCES networks(id),
    device_id       TEXT NOT NULL REFERENCES devices(id),
    target_kind     TEXT NOT NULL,
    address         TEXT NOT NULL,
    path            TEXT,
    expected_status INTEGER,
    timeout_secs    REAL NOT NULL,
    interval_secs   INTEGER NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL
);

CREATE INDEX idx_publish_probes_network ON publish_probes(network_id);
CREATE INDEX idx_publish_probes_device ON publish_probes(device_id);

CREATE TABLE publish_dns_records (
    id               TEXT PRIMARY KEY,
    network_id       TEXT NOT NULL REFERENCES networks(id),
    device_id        TEXT NOT NULL REFERENCES devices(id),
    name             TEXT NOT NULL,
    address          TEXT NOT NULL,
    ttl              INTEGER NOT NULL,
    priority         INTEGER NOT NULL DEFAULT 100,
    bind_address     TEXT NOT NULL,
    internal_suffix  TEXT NOT NULL,
    created_at       TEXT NOT NULL
);

CREATE INDEX idx_publish_dns_network ON publish_dns_records(network_id);
CREATE INDEX idx_publish_dns_device ON publish_dns_records(device_id);

-- One row per probe: the latest report an agent sent. Reports are evidence,
-- not configuration, so they are keyed by probe and upserted rather than
-- accumulated.
CREATE TABLE publish_probe_reports (
    probe_id     TEXT PRIMARY KEY REFERENCES publish_probes(id),
    network_id   TEXT NOT NULL REFERENCES networks(id),
    device_id    TEXT NOT NULL REFERENCES devices(id),
    state        TEXT NOT NULL,
    checked_at   TEXT NOT NULL,
    detail       TEXT,
    updated_at   TEXT NOT NULL
);
