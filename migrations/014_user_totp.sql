-- 014_user_totp.sql
--
-- Console TOTP second factor (RFC 6238, SHA-1, 6 digits, 30s step, +/-1
-- step window).
--
-- `totp_secret`: base32 secret, held only by the server; no outbound response
-- ever carries it in clear text, and it only appears inside the otpauth://
-- URI used for the QR scan (the standard material for authenticator import).
--    NULL   = binding not started;
--    non-null = generated awaiting activation (`totp_enabled`=0), or already
--               activated (`totp_enabled`=1).
-- `totp_enabled`: 0/1, set to 1 only once `totp_secret` is non-null and the
--   user confirmed with a verification code; login then requires the second
--   step. Existing users default to 0 (unbound, guided to bind on first login).

ALTER TABLE users ADD COLUMN totp_secret TEXT;
ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
