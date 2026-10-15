-- meshlet schema v0.0.8 (device self-registration, ZeroTier-style).
-- 设备持自举码自举 → 落 device_registrations（Pending）→ 控制中心审批/拒绝。
--
-- 关键取舍：**Pending 申请不进 `devices` 表**。理由三条：
--   1. `devices.virtual_ipv4` 为 NOT NULL，而虚拟 IP 在**批准时刻**才分配（批准前
--      占用地址会让管理员看到的可用容量虚低，拒绝后还得回收）；
--   2. 不占地址 = 不进期望配置 / 不进 Peer AllowedIPs（device_plan 只读
--      `devices`），Pending 设备对数据面完全不可见；
--   3. 设备 id 在注册时即分配（`dev-reg-N`，单调序列见 mesh_meta），批准后
--      **沿用同一 id** 转入 `devices`，`agent_tokens.device_id` 等引用无需迁移。
--
-- `devices.approved_at`：批准时刻。自举注册路径下 `created_at` 是「申请时刻」
-- （Pending 起始），批准后 `approved_at` 落审批时刻——控制台据此区分
-- 「刚批准」与「已运行一周」。老邀请入会路径两者同值，该列为 NULL。
ALTER TABLE devices ADD COLUMN approved_at TEXT;

CREATE TABLE bootstrap_tokens (
    id         TEXT PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(id),
    -- 只存 SHA-256 摘要（§11.3）：原始自举码只在创建响应里出现一次。
    token_hash TEXT NOT NULL,
    -- 允许 NULL = 默认不限次（它是长期注册入口，不是一次性邀请）。
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
    -- Pending 设备尚无 devices 行，agent 心跳证据只落这两列（§7.5/§12.4）。
    last_report_at     TEXT,
    dataplane_evidence TEXT
);
CREATE INDEX idx_device_registrations_network ON device_registrations(network_id);
-- 同网络内设备名跨阶段唯一（批准路径按此判冲突）。
CREATE UNIQUE INDEX uniq_device_registrations_network_name
    ON device_registrations(network_id, name);
