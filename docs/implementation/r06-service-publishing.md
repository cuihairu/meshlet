# R-06: Service Publishing Progress

R-06 remains open. Service forwarding, web publishing, authorization, health checks, and the internal service directory are implemented in the current codebase — but **`meshlet-publish` is not wired into the agent runtime path yet**, so the real VPS / real-device end-to-end acceptance cannot be closed (see the gap list below).

## Implemented

- TCP and UDP PortForward publish local services through the mesh and preserve the selected transport protocol.
- HTTP and HTTPS publishing routes external traffic to mesh services.
- Authorization control is exposed through `POST /api/v1/publish/routes/check`; the server route is wired at `apps/server/src/lib.rs:1014` through the `meshlet-publish` service adapter.
- Health probes validate that a published target is reachable before traffic is admitted.
- The internal DNS service directory supports split-horizon service discovery without overriding public DNS resolution.
- Automated coverage currently reports `cargo test -p meshlet-publish` as 8 passed and `cargo test -p meshlet-server --test publish_check` as 2 passed.

## Live VPS Acceptance Record (2026-10-23)

Acceptance host `106.14.216.177` (Aliyun ECS, Ubuntu, kernel 7.0.0-34-generic, 2 vCPU / 1.6 GiB RAM, `/proc/cpuinfo` model string `Intel(R) Xeon(R) Platinum`). Every command and output below is verbatim from that host and unmodified. This document contains no passwords, tokens, or private-key material.

### Server status snapshot

```text
$ systemctl is-active meshlet-server
active

$ sha256sum /usr/local/bin/meshlet-server
75327714caf46018e72acb7cfafc60a19b65b7781bcbde5df26825bb780e15ff

$ df -h /
/dev/vda3        40G   21G   17G  55% /

$ docker ps --format "{{.Names}} {{.Status}}"
oddsmaker-demo-control Up 3 days (healthy)
oddsmaker-demo-postgres Up 2 weeks (healthy)
oddsmaker-demo-redis Up 2 weeks (healthy)
```

Deployment evidence: the packages were built on the VPS with the pinned 1.99.0 toolchain. The previous `ce36e81` binary has sha256 `514e076d7cacc448321087abf7fde4b3a3912115a4c32f653c8b79a3abd454a3` (13705376 bytes); the new `ef97f0d` binary has sha256 `75327714caf46018e72acb7cfafc60a19b65b7781bcbde5df26825bb780e15ff` (12734632 bytes). They were swapped with an atomic `install` + `mv`, followed by `systemctl restart`; the service came back `active` and the journal recorded `mesh state rebuilt from database networks=1 devices=0 revisions=1`. At the end of the acceptance the server was still running `ef97f0d` (sha256 matches the value above).

### Control-plane benchmark (real VPS, not the CI machine)

`cargo run --release -p meshlet-server --example bench`. The driver is an in-process axum `oneshot`, so **TCP/TLS stack cost is excluded** — the numbers are for before/after comparison only.

```text
$ ./target/release/examples/bench --db file --secs 8 --sweep 1,8,32
环境：CPU = : Intel(R) Xeon(R) Platinum；db = file；时长/档 = 8s
注：进程内 oneshot 驱动，不含 TCP/TLS 栈成本；数字用于前后对照。

| 目标 | 并发 | req/s | p50 µs | p90 µs | p99 µs | max µs | 错误 |
|---|---|---|---|---|---|---|---|
| GET /system/status（公开，无 DB） | 1 | 442556 | 1 | 2 | 3 | 5448 | 0 |
| GET /networks（会话校验 = 1 次 DB 读） | 1 | 8611 | 89 | 165 | 460 | 16244 | 0 |
| GET /auth/tokens（会话 + token 列表 = 2 次 DB 读） | 1 | 4445 | 186 | 309 | 806 | 8228 | 0 |

| 目标 | 并发 | req/s | p50 µs | p90 µs | p99 µs | max µs | 错误 |
|---|---|---|---|---|---|---|---|
| GET /system/status（公开，无 DB） | 8 | 485127 | 3 | 3 | 14 | 61457 | 0 |
| GET /networks（会话校验 = 1 次 DB 读） | 8 | 18333 | 358 | 707 | 1619 | 17424 | 0 |
| GET /auth/tokens（会话 + token 列表 = 2 次 DB 读） | 8 | 9015 | 775 | 1296 | 2808 | 32439 | 0 |

| 目标 | 并发 | req/s | p50 µs | p90 µs | p99 µs | max µs | 错误 |
|---|---|---|---|---|---|---|---|
| GET /system/status（公开，无 DB） | 32 | 486822 | 3 | 3 | 14 | 32783 | 0 |
| GET /networks（会话校验 = 1 次 DB 读） | 32 | 18739 | 1569 | 2257 | 4916 | 21028 | 0 |
| GET /auth/tokens（会话 + token 列表 = 2 次 DB 读） | 32 | 8814 | 3222 | 4642 | 11665 | 47047 | 0 |

RSS：11012 KiB → 48492 KiB（含驱动与运行时）
```

Memory footprint, run separately with `--footprint` (500 networks + 500 tokens provisioned in bulk):

```text
| 批量操作 | 数量 | RSS 增量 | 均摊 |
|---|---|---|---|
| 500 网络（内存态 + 各 1 修订） | 500 | 1908 KiB | 3.8 KiB/网络 |
| 再 500 API Token（SQLite 行） | 500 | 132 KiB | 0.3 KiB/token |
```

How to read it: DB-touching paths are bounded by 2 vCPUs plus the serial SQLite pool. Throughput for `/networks` and `/auth/tokens` is essentially flat from 8 to 32 concurrent workers (18333 → 18739, 9015 → 8814) while p50 latency rises from 358 µs to 1569 µs — that is queueing, not degradation. Error counts are 0 across all three concurrency levels. The external-path baseline, measured from the local machine to the VPS on `GET /api/v1/system/status` over 10 samples, was min 20.9 ms / max 25.4 ms / mean ~23.2 ms.

### Authorization control, measured live (the only wired-in surface)

`POST /api/v1/publish/routes/check`, exercised path by path on the real instance:

```text
$ curl -s -X POST http://127.0.0.1:8080/api/v1/publish/routes/check \
    -H 'X-Requested-With: XMLHttpRequest' -H 'content-type: application/json' \
    -d '{"remote":"10.240.4.9:40000","policy":{"allowed_source_cidrs":["10.240.0.0/16"],"allowed_bearer_tokens":[]}}'
{"allowed":true,"reason":"authorized"}

$ curl -s -X POST http://127.0.0.1:8080/api/v1/publish/routes/check \
    -H 'X-Requested-With: XMLHttpRequest' -H 'content-type: application/json' \
    -d '{"remote":"192.168.9.9:40000","auth_header":"Bearer wrong","policy":{"allowed_source_cidrs":["10.240.0.0/16"],"allowed_bearer_tokens":["secret"]}}'
{"allowed":false,"reason":"source or bearer token not authorized"}

$ curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8080/api/v1/publish/routes/check
403
```

A missing CSRF header `X-Requested-With: XMLHttpRequest` returns 403, consistent with `publish/routes/check 4xx = 1` in `meshlet_http_requests_total`. Authorization is enforced before the service connection is opened (`crates/meshlet-publish/src/forwarding.rs:66`, `forwarding.rs:115`, `http.rs:165`, `http.rs:191`). `AuthorizationPolicy::authorize` (`crates/meshlet-publish/src/authorization.rs:45`) has OR semantics: a CIDR match returns `Allowed` immediately without checking the token; an IPv6 source can never match a CIDR because `Ipv4Cidr` only expresses IPv4, so it can only be admitted via a bearer token.

### Wiring closed on 2026-10-24 (wiring plus tests, not a real-device acceptance)

Every gap listed above is now closed in code and covered by tests. This is control-plane wiring
plus crate/server integration tests — **no real agent process has served real published traffic yet.**

| Surface | Where | Test |
|---|---|---|
| Control-plane CRUD, four object kinds | `apps/server/src/publish.rs` — `POST/GET /api/v1/networks/{network_id}/publish/{forwards,http-routes,probes,dns-records}` plus `GET/DELETE /publish/{kind}/{id}` | `apps/server/tests/publish.rs` (10 tests) |
| Agent probe-health endpoint | `POST /api/v1/agent/publish-health` — one upserted row per probe in `publish_probe_reports`; a report for a probe the presenting device does not own is 400, an unknown probe id is 404 | `probe_health_report_is_guarded_by_device_id` |
| DevicePlan carries publish config | `crates/meshlet-network/src/lib.rs` — `publish: Option<PublishPlan>`, folded into `desired_config_hash` | `device_plan_carries_the_publish_segment` |
| Agent runs the publish layer | `apps/agent/src/agent.rs` — `PublishRuntime` owns a dedicated single-worker tokio runtime; `tick` reconciles the plan even when the kernel apply failed, then uploads buffered reports (256 per batch, front-trimmed) | `meshlet-publish` runtime tests, `apps/agent` tests |
| Publish tables | `migrations/012_publish.sql` — five tables (`publish_forwards`, `publish_http_routes`, `publish_probes`, `publish_dns_records`, `publish_probe_reports`) | `tests/publish.rs`, `tests/migrations.rs`, `tests/backup.rs` |

Behaviour the new tests pin down: create/list/get/delete round-trips for all four kinds; port
conflicts judged **per (device, protocol, listener)** — same device and same port is 409, while a
different protocol on the same port and a different device on the same port are both legal;
`allowed_bearer_tokens` are never echoed by any read path (a count is returned instead) and are
never written to `audit_events`; a publish object with neither a source CIDR nor a bearer token is
rejected; one DNS socket per device (a second suffix for the same device is 409); every publish
write leaves exactly one `audit_events` row and one `config_revisions` row; a restart restores all
objects and the global publish sequence keeps counting (no id reuse).

Two real defects surfaced while writing these tests and were fixed:

- `upsert_probe_reports` bound six values into a seven-column `INSERT` (the SELECT list omitted
  `p.id`), so every probe-health upload returned 500.
- `apps/agent` owned a `tokio::runtime::Runtime` that panicked when dropped from an async context.
  The runtime is now shut down on a dedicated thread so any caller is safe.

`tls_termination` is no longer an unread field: `runtime.rs` reads it and `RouteMode::TlsPassThrough`
sniffs the SNI, applies the route policy, and forwards the TLS bytes to the backend. **There is still
no TLS termination** — no certificate, no decryption.

### What is still not accepted

- **No real-device end-to-end run.** No real agent has bound a forwarding port, an HTTP listener or a
  DNS socket from a server-delivered plan. The forwarding, DNS and probe paths are verified on
  loopback with high ports (`meshlet-publish` runtime tests); `0.0.0.0:53` still needs root and has
  not been exercised on a real device.
- **No console UI** for creating publish objects — CRUD is reachable over the REST API only.

## Outstanding

- Run and archive the real VPS / real-device end-to-end acceptance for published services: a real
  agent binds a forwarding port, an HTTP listener and a DNS socket from a server-delivered plan,
  with external traffic in and out. Until then the TODO record stays pending live verification.
