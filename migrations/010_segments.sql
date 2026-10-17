-- meshlet schema v0.0.10 (ADR-012: network segments are trust groups).
-- A Segment is a Network-scoped address prefix. A device belongs to at most
-- one segment and its overlay address must fall inside that segment. Grants
-- are one-way: source -> destination only opens traffic in that direction.
--
-- Existing networks keep today's all-pass behavior by receiving one default
-- segment whose CIDR equals the network overlay; every Active device is then
-- attached to it. Plan compilation and kernel execution deliberately remain
-- unchanged in this first slice.
CREATE TABLE segments (
    id         TEXT PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(id),
    name       TEXT NOT NULL,
    cidr       TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    UNIQUE (network_id, name)
);

CREATE TABLE segment_grants (
    id                     TEXT PRIMARY KEY,
    network_id             TEXT NOT NULL REFERENCES networks(id),
    source_segment_id      TEXT NOT NULL REFERENCES segments(id),
    destination_segment_id TEXT NOT NULL REFERENCES segments(id),
    status                 TEXT NOT NULL DEFAULT 'pending',
    created_at             TEXT NOT NULL,
    revoked_at             TEXT
);

ALTER TABLE devices ADD COLUMN segment_id TEXT REFERENCES segments(id);

INSERT INTO segments (id, network_id, name, cidr, status, created_at)
SELECT 'seg-' || n.id, n.id, 'default', n.overlay_cidr, 'active', n.created_at
FROM networks AS n
WHERE NOT EXISTS (
    SELECT 1 FROM segments AS s
    WHERE s.network_id = n.id AND s.name = 'default'
);

UPDATE devices
SET segment_id = (
    SELECT s.id
    FROM segments AS s
    WHERE s.network_id = devices.network_id
      AND s.name = 'default'
      AND s.cidr = (
          SELECT n.overlay_cidr
          FROM networks AS n
          WHERE n.id = devices.network_id
      )
)
WHERE status = 'active'
  AND segment_id IS NULL;
