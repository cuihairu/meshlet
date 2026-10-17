-- Keep one canonical default segment per existing network. The id format is
-- shared with meshlet_domain::default_segment_id: "seg-" + network id.
INSERT INTO segments (id, network_id, name, cidr, status, created_at)
SELECT 'seg-' || n.id, n.id, 'default', n.overlay_cidr, 'active', n.created_at
FROM networks AS n
WHERE NOT EXISTS (
    SELECT 1 FROM segments AS s
    WHERE s.network_id = n.id AND s.name = 'default'
);

-- Migration 010 assigned existing active devices; fill any remaining rows too
-- (including revoked devices) so every persisted device has a valid segment.
UPDATE devices
SET segment_id = (
    SELECT s.id FROM segments AS s
    WHERE s.network_id = devices.network_id AND s.name = 'default'
)
WHERE segment_id IS NULL;
