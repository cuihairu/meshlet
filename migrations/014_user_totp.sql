-- 014_user_totp.sql
--
-- 控制台 TOTP 二次认证（RFC 6238，SHA-1，6 位，30s 步长，±1 步窗口）。
--
-- `totp_secret`：base32 密钥（服务端唯一持有，任何出站响应不含其原文；
-- 只在扫码导入用的 otpauth:// URI 内出现——认证器导入的标准材料）。
--    NULL  = 未发起绑定；
--    非空  = 已生成待激活（`totp_enabled`=0）或已激活（`totp_enabled`=1）。
-- `totp_enabled`：0/1，仅在 `totp_secret` 非空且用户以验证码确认后置 1；
--   置 1 后登录需第二步校验。存量用户默认 0（未绑定，首登引导绑定）。

ALTER TABLE users ADD COLUMN totp_secret TEXT;
ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
