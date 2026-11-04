-- Device labels (MT-005): operator-assigned node tags (role/capability etc.)
-- used to route task dispatch. JSON object of string pairs; DEFAULT '{}' keeps
-- existing rows (and enroll-time inserts that omit the column) at "no tags".
-- Labels are set post-creation via the operator endpoint (PATCH semantics),
-- so device INSERT paths rely on this default rather than carrying the column.
ALTER TABLE devices ADD COLUMN labels TEXT NOT NULL DEFAULT '{}';

-- Task payload label constraint (MT-005): persisted so a task's routing
-- requirement survives restart (payload round-trips, not just dispatch-time).
-- JSON object of string pairs; DEFAULT '{}' = no label constraint.
ALTER TABLE tasks ADD COLUMN required_labels TEXT NOT NULL DEFAULT '{}';
