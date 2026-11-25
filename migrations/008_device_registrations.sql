-- meshlet schema v0.0.8 (device self-registration, ZeroTier-style).
-- A device bootstraps with a bootstrap code -> lands in device_registrations (Pending)
-- -> the control center approves or rejects.
--
-- Key trade-off: **Pending applications never enter the `devices` table**. Three reasons:
--   1. `devices.virtual_ipv4` is NOT NULL and the virtual IP is only allocated at
--      **approval time** (reserving an address earlier would inflate the apparent free
--      capacity admins see, and a rejection would then need a reclaim);
--   2. no address reserved = not in the desired config / not in Peer AllowedIPs
--      (device_plan only reads `devices`), so a Pending device is fully invisible to
--      the dataplane;
--   3. the device id is assigned at registration time (`dev-reg-N`, a monotonic
--      sequence kept in mesh_meta); after approval the **same id carries over** into
--      `devices`, so references like `agent_tokens.device_id` need no migration.
--
-- `devices.approved_at`: approval time. On the self-registration path `created_at` is
-- the "application time" (start of Pending) while `approved_at` lands at approval -
-- the console uses the pair to tell "just approved" from "running for a week". On the
-- legacy invite path both hold the same value and the column stays NULL.
ALTER TABLE devices ADD COLUMN approved_at TEXT;

CREATE TABLE bootstrap_tokens (
    id         TEXT PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(id),
    -- Only the SHA-256 digest is stored (§11.3): the raw bootstrap code appears exactly once, in the create response.
    token_hash TEXT NOT NULL,
    -- NULL allowed = unlimited uses by default (this is a long-lived registration entry, not a one-shot invite).
    max_uses   INTEGER,
    used_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE INDEX idx_bootstrap_tokens_network ON bootstrap_tokens(network_id);
CREATE INDEX idx_bootstrap_tokens_hash ON bootstrap_tokens(token_hash);

CREATE TABLE device_registrations (
    id                 TEXT PRIMARY KEY,
    network_id         TEXT NOT NULL REFERENCES networks(id),
    name               TEXT NOT NULL,
    public_key         TEXT NOT NULL,
    platform           TEXT NOT NULL,
    requested_at       TEXT NOT NULL,
    -- A Pending device has no devices row yet, so agent heartbeat evidence lands only in these two columns (§7.5/§12.4).
    last_report_at     TEXT,
    dataplane_evidence TEXT
);
CREATE INDEX idx_device_registrations_network ON device_registrations(network_id);
-- Device names are unique within a network across both stages (the approval path checks conflicts here).
CREATE UNIQUE INDEX uniq_device_registrations_network_name
    ON device_registrations(network_id, name);
