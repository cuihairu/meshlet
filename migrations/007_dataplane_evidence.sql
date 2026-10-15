-- 设备侧数据面实测证据（agent 心跳回传，§7.5/§12.4）：内核读数 + 大包探测，
-- 以 JSON 承载（meshlet_domain::DataplaneEvidence 序列化；NULL = 尚无上报）。
ALTER TABLE devices ADD COLUMN dataplane_evidence TEXT;
