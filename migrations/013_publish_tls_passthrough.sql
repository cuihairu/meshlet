-- 013_publish_tls_passthrough.sql
--
-- M1 field rename: `tls_termination` was a misnomer. What this column records is SNI
-- sniffing + raw TLS byte passthrough; meshlet holds no certificates, decrypts nothing,
-- and never terminates TLS. The column and the API field are both renamed to
-- `tls_passthrough` (a generic term, as used by Envoy and the like); the values and
-- semantics carry over unchanged and existing rows need no rewrite.
--
-- True TLS termination is not supported today: options that cannot execute on a
-- passthrough route (bearer token, a path prefix other than `/`) are rejected with 409
-- at creation time, never silently ignored.

ALTER TABLE publish_http_routes RENAME COLUMN tls_termination TO tls_passthrough;
