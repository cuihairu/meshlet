-- Device-side dataplane measurements (agent heartbeat reports, §7.5/§12.4): kernel
-- readings + large-packet probes, carried as JSON (serialized
-- meshlet_domain::DataplaneEvidence; NULL = not reported yet).
ALTER TABLE devices ADD COLUMN dataplane_evidence TEXT;
