-- 013_publish_tls_passthrough.sql
--
-- M1 字段更名：`tls_termination` 名不副实。该列记录的是 SNI 嗅探 + TLS
-- 原始字节直通，meshlet 没有证书、不解密，从来不做 TLS 终结。列名与
-- API 字段统一改为 `tls_passthrough`（沿用 Envoy/Luban 一类通用术语），
-- 取值与语义原样沿用，存量行无需改写。
--
-- 真正的 TLS 终结当前不支持：passthrough 路由上配置无法执行的项
-- （bearer token、非 `/` 路径前缀）在创建期 409 拒绝，不静默忽略。

ALTER TABLE publish_http_routes RENAME COLUMN tls_termination TO tls_passthrough;
