# R-06: Service Publishing Progress

R-06 is wired end to end and has been run on a real device: a real `meshlet-agent` binds forwarding ports, an HTTP listener and a DNS socket from a server-delivered plan, and external traffic reaches the published backends. The full real-device record is in [Live VPS acceptance run, 2026-10-24](#live-vps-acceptance-run-2026-10-24); the surfaces that remain unverified on a real device are listed in [What is still not accepted](#what-is-still-not-accepted).

## Implemented

- TCP and UDP PortForward publish local services through the mesh and preserve the selected transport protocol.
- HTTP and HTTPS publishing routes external traffic to mesh services.
- Authorization control is exposed through `POST /api/v1/publish/routes/check`; the server route is wired at `apps/server/src/lib.rs:1017` through the `meshlet-publish` service adapter.
- Health probes validate that a published target is reachable before traffic is admitted.
- The internal DNS service directory supports split-horizon service discovery without overriding public DNS resolution.
- Automated coverage is `cargo test -p meshlet-publish` = 35 passed (21 lib, 1 dns_catalog, 3 forwarding, 4 health_probe, 6 http_publishing), `cargo test -p meshlet-server` = 213 passed across 24 suites including `publish.rs` 12 and `publish_check.rs` 2 (the per-suite count re-verified 2026-10-27; the 213/24 totals are the 2026-10-24 acceptance snapshot and have since grown with new suites), `cargo clippy --workspace --all-targets -- -D warnings` clean, `cargo fmt --check` clean, and the console at 17 passed tests plus a clean build.

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

### Wiring closed on 2026-10-24 (wiring plus tests)

Every gap listed above was closed in code and covered by tests. This section records that wiring
round: control-plane CRUD, the probe-health endpoint and the agent runtime hook, plus the crate and
server integration tests. The real-device run it was waiting for is recorded in
[Live VPS acceptance run](#live-vps-acceptance-run-2026-10-24).

| Surface | Where | Test |
|---|---|---|
| Control-plane CRUD, four object kinds | `apps/server/src/publish.rs` — `POST/GET /api/v1/networks/{network_id}/publish/{forwards,http-routes,probes,dns-records}` plus `GET/DELETE /publish/{kind}/{id}` | `apps/server/tests/publish.rs` (12 tests) |
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

`tls_passthrough` is no longer an unread field: `runtime.rs` reads it and `RouteMode::TlsPassThrough`
sniffs the SNI, applies the route policy, and forwards the TLS bytes to the backend. **There is still
no TLS termination** — no certificate, no decryption.

### Field rename and explicit capability refusal (M1, implemented on 2026-10-26)

The field was called `tls_termination`, which the implementation never did. It is now
`tls_passthrough` everywhere — the API field, the in-memory model (`HttpRoute`), the request and
view structs, the console types and wording, and the database column
(`migrations/013_publish_tls_passthrough.sql` renames it in place; value and semantics unchanged).
Requests may still send the old name: it is accepted as a serde alias so existing callers keep
working, and responses always emit the new name. Sending both names in one request is rejected
as a duplicate field, so the alias cannot be used to contradict itself.

The rename also makes the unsupported combinations fail loudly at create time, with the same 409
idiom as the mixed-termination guard, instead of being silently ignored:

- `tls_passthrough: true` plus `allowed_bearer_tokens` → 409. The router never sees HTTP headers
  (the TLS bytes are opaque to it), so a bearer token would never have been checked.
- `tls_passthrough: true` plus a `path_prefix` other than `/` → 409. SNI sniffing selects by host
  name only and always matches `/`, so the prefix could never have taken part in routing.

Want either capability? Use a plain HTTP route — both work there. True TLS termination is not
supported; refusing it at create time is the honest answer, not a name that implies it.

### Console UI entry point (implemented on 2026-10-24)

Creating publish objects was previously REST-only. The network view now has a **Service
publishing** section (`console/src/App.tsx`, `PublishSection`), driven by four methods in
`console/src/api.ts` and covered by `console/src/publish.test.tsx`.

Borrowing, recorded so the provenance is auditable:

- **Portainer's service "Port publishing" editor** — the row vocabulary. Each L4 row reads
  `protocol | published host:port → target host:port`, with the listener and backend split into
  separate host and port fields exactly as Portainer does; the same vocabulary is reused by
  Dokploy's per-app port table, which is what makes the port-forward row readable to a reader of
  either product.
- **The meshlet host-forwarding conflict card** — how a failure is shown. A refused create renders
  the same `Publishing conflict — nothing was published.` card the host-forwarding editor uses, so
  a failure is never a raw error string and never looks like a partial publish.
- **Portainer's two-step inline delete** — `Delete` turns into `Confirm delete` + `Cancel` in the
  row, instead of a modal; the shared `DeleteButton` is also used by the other publish tables.
- Deliberately **not** copied: Tailscale's app dashboard is a read-only status surface with no
  port-publishing editor, so there was nothing to copy from it beyond the read-only health column.

Bearer tokens appear only on the create forms; every read view keeps a count, so a listing never
echoes a secret. One device selector drives all four create forms.

Walked through in a real browser against the live console: the section renders the four tables with
the live rows (two forwards, one route, three probes with `healthy` / `healthy` / `unreachable`
states from the control plane, one DNS record), `Create` posts the object and the row appears,
`Delete` requires the second confirmation click, and `API errors` stays empty on every step.
Creating and deleting a route from the UI produced the corresponding agent reconciliation
(`started=1 stopped=0`, then `started=0 stopped=1`).

### Live VPS acceptance run (2026-10-24)

Same host as the record above (`ali`, eth0 `172.19.169.82`, public `106.14.216.177`). All outputs
below are verbatim from the host and unmodified. The device is `dev-reg-2` in `net-1`.

```text
$ systemctl is-active meshlet-server
active

$ sha256sum /usr/local/bin/meshlet-server /usr/local/bin/meshlet-agent   # first 16 chars
9adc19a90092bca7  meshlet-server
8025b5e3f2ec831a  meshlet-agent

$ ps -eo pid,args | grep meshlet
2363888 /usr/local/bin/meshlet-server /etc/meshlet/meshlet.toml
2379033 /usr/local/bin/meshlet-agent /etc/meshlet/agent.toml

$ grep -c panicked /root/agent-publish.log
1
```

The one panic line is from the **pre-fix** binary, `2026-10-23T19:02:08Z`. Nothing after the fixed
binaries were installed at `19:40:54Z` added to it, so the count stays at 1 for the rest of the run.

#### Defect 1: the SNI sniffer panicked on a real ClientHello

The first TLS pass-through attempt crashed the publish worker:

```text
thread 'meshlet-publish' (2322840) panicked at crates/meshlet-publish/src/http.rs:238:54:
index out of bounds: the len is 1554 but the index is 7157
```

Three separate defects behind that one trace:

1. `sniff_sni` indexed into the record with no bounds checks, so a truncated or malformed
   ClientHello panicked instead of returning `invalid`.
2. It never stripped the 4-byte handshake header (type + 3-byte length), so even a well-formed
   ClientHello parsed wrong — the body offset was off by 4.
3. It consumed the ClientHello and never replayed it, so the backend never received the handshake.
   This one hid behind the other two and was only found when an integration test hung on
   `Elapsed` and the backend reported `0` of `N` bytes received.

The fix is a bounds-checked `Cursor` (`take` / `u8` / `u16`, the same idiom as `dns.rs`) and a new
contract: `sniff_sni` returns `(sni, consumed_record_bytes)` and the caller replays the record with
`backend.write_all(&hello)` before `copy_bidirectional`.

Real-device proof that the trigger no longer panics — a plain HTTP request to a TLS listener is
exactly the old crash path:

```text
$ curl -s -m 5 -H 'Host: tls.mesh.internal' http://127.0.0.1:18090/ -w 'status=%{http_code} bytes=%{size_download}
'
status=000 bytes=0
$ grep -c panicked /root/agent-publish.log
1
```

The connection is refused with a reset and the panic count does not move. Regression coverage: 11
unit tests in `http.rs` (well-formed SNI, extension skipping, plain HTTP rejection, non-ClientHello
records, truncated cipher block, extension length lying, server-name list lying, name entry lying,
missing host_name entry, no extensions at all, truncated record body) plus 3 integration tests in
`tests/http_publishing.rs`.

#### Defect 2: a second listener and a mixed termination mode were silently accepted

The plan has exactly one `http_listener` and one `RouteMode` per device. A second route on another
port never bound, and one TLS route flipped the whole device into SNI mode. Both failures were
silent, and the old binary accepted `hr-9` (`tls.mesh.internal` on `18091`) next to a plain route on
`18090` — the resulting router reset every plain request:

```text
$ curl -v -m 5 -H "Host: app.mesh.internal" http://127.0.0.1:18090/
* Request completely sent off
* Recv failure: Connection reset by peer
curl: (56) Recv failure: Connection reset by peer
```

The fix rejects the mismatch at create time (`check_http_socket_consistent` in
`apps/server/src/publish.rs`, mirroring the existing one-DNS-socket-per-device guard):

```text
$ # TLS route on a device that already has a plain route
status=409
{"error":{"code":"conflict","message":"device dev-reg-2 already serves route hr-3 with tls_passthrough=false; one termination mode per device"}}

$ # second listener on the same device
status=409
{"error":{"code":"conflict","message":"device dev-reg-2 already listens for http on 0.0.0.0:18090 (route hr-3); one http listener per device"}}
```

Dropping the stale route reconciles cleanly and the phantom listener disappears:

```text
$ curl -s -X DELETE .../publish/http-routes/hr-9 -w 'status=%{http_code}
'
status=204
applied rev 13 applied
reconciled the publish plan started=1 stopped=1 failed=[]
18091 listeners after delete: 0
```

#### Defect 3: each probe ran once and never again

Probe reports were frozen in `publish_probe_reports` at `checked_at 2026-10-23T18:53:07Z` for hours
while the process was alive. Reading the scheduler found the cause — `spawn_probe_loop` refreshed
the due-table for **every** schedule on every 1-second tick, not just the ones it had scheduled:

```rust
for schedule in &schedules {          // wrong: all of them, every tick
    last_run.insert(schedule.id.clone(), now);
}
```

`duration_since(last_run)` therefore stayed at ~1 second, so any probe with an interval above the
tick length was never due again. The fix records `last_run` only for the schedules that actually ran.
Note this is also the true root cause of the frozen `checked_at` observed before the crash fix — the
worker had not died; the earlier "worker not accepting" reading was Defect 2 resetting plain
requests.

Continuous reporting, two snapshots 35 seconds apart on the real device:

```text
== t0 19:58:51Z ==
pb-5|healthy|2026-10-23T19:58:44Z|2026-10-23T19:58:44Z
pb-6|healthy|2026-10-23T19:58:34Z|2026-10-23T19:58:44Z
pb-7|unreachable|2026-10-23T19:58:44Z|2026-10-23T19:58:44Z
== t+35s 19:59:26Z ==
pb-5|healthy|2026-10-23T19:59:24Z|2026-10-23T19:59:24Z
pb-6|healthy|2026-10-23T19:59:14Z|2026-10-23T19:59:14Z
pb-7|unreachable|2026-10-23T19:59:24Z|2026-10-23T19:59:24Z
```

And again 65 seconds later: `pb-5`/`pb-7` `20:01:24Z`, `pb-6` `20:01:24Z` (interval 20s). The
server-side rows advance, which is what `checked_at` in `publish_probe_reports` means. Regression
test: `the_probe_loop_re_runs_a_due_schedule` in `tests/health_probe.rs`.

#### Accepted surfaces, measured live

Agent bound from the server-delivered plan — `ss -tlnup`:

```text
udp 0.0.0.0:15353   tcp 0.0.0.0:18090   tcp 0.0.0.0:18083   tcp 0.0.0.0:18080
```

```text
$ curl -s -m 6 http://127.0.0.1:18080/                 # forward, allow 0.0.0.0/0
L4-FORWARD-BACKEND-OK

$ curl -s -m 6 -o /dev/null -w 'status=%{http_code} bytes=%{size_download}
' http://127.0.0.1:18083/
                                                        # forward, only 10.9.9.9/32 may in
status=000 bytes=0                                       # reset, zero bytes

$ curl -s -m 6 -H 'Host: app.mesh.internal' http://127.0.0.1:18090/
HTTP-ROUTE-BACKEND-OK

$ dig @127.0.0.1 -p 15353 app.mesh.internal +short +time=3 +tries=1
10.240.0.5

$ dig @127.0.0.1 -p 15353 github.com +short +time=3 +tries=1
;; no servers could be reached       # a public name is not in the catalog and is not answered
```

TLS pass-through — the client sees the **backend** certificate, because the agent holds none:

```text
$ curl -sk -m 8 --resolve tls.mesh.internal:18090:127.0.0.1 https://tls.mesh.internal:18090/ -w 'status=%{http_code} remote=%{remote_ip}
'
TLS-PASSTHROUGH-BACKEND-OK
status=200 remote=127.0.0.1
$ echo | openssl s_client -connect 127.0.0.1:18090 -servername tls.mesh.internal 2>/dev/null | openssl x509 -noout -subject
subject=CN=tls.mesh.internal

$ curl -sk -m 8 --resolve tls.mesh.internal:18090:172.19.169.82 https://tls.mesh.internal:18090/ -w 'status=%{http_code} remote=%{remote_ip}
'
TLS-PASSTHROUGH-BACKEND-OK
status=200 remote=172.19.169.82
subject=CN=tls.mesh.internal

$ curl -sk -m 8 --resolve other.mesh.internal:18090:172.19.169.82 https://other.mesh.internal:18090/ -o /tmp/n.out -w 'status=%{http_code} bytes=%{size_download}
'
status=000 bytes=0                    # unknown SNI: reset, backend never connected
```

One defect was found on the console side of this test and is worth recording: the first script
pinned `--resolve tls.mesh.internal:18090` against `https://tls.mesh.internal/`, which defaults to
port 443, so curl never resolved the host (`curl: exit 6`, `remote_ip` empty). That was a script bug,
not a product bug — `openssl s_client` had already returned the backend certificate through the same
port. Corrected by putting the port in the URL.

Reconciliation events, all from the agent log:

```text
reconciled the publish plan started=7 stopped=0 failed=[]      # cold start: 2 forwards, 1 router, 1 dns, 3 probes
reconciled the publish plan started=1 stopped=1 failed=[]      # route swapped plain -> TLS
reconciled the publish plan started=1 stopped=1 failed=[]      # route restored TLS -> plain
reconciled the publish plan started=0 stopped=1 failed=[]      # last route dropped, listener released
```

#### External reach, measured from a host outside the box

```text
$ for p in 22 80 443 8080 18080 18090; do timeout 10 bash -c "echo > /dev/tcp/106.14.216.177/$p" && echo OPEN || echo BLOCKED; done
tcp 22    OPEN
tcp 80    OPEN
tcp 443   OPEN
tcp 8080  OPEN
tcp 18080 BLOCKED
tcp 18090 BLOCKED

$ curl -s -m 8 -o /dev/null -w '%{http_code}
' http://106.14.216.177:8080/api/v1/networks
401
$ curl -s -m 8 -o /dev/null -w '%{http_code}
' http://106.14.216.177:18090/
000
```

The control plane is reachable from outside behind its auth gate. The published ports are **not**
reachable from outside: the cloud security group opens 22, 80, 443 and 8080 only, and the published
listeners sit on 15353, 18080, 18083 and 18090. Everything in the "Accepted surfaces" table above
was therefore exercised over loopback or the private IP.

The one public-path proof that did succeed ran through port 80: with a **temporary** nginx vhost
proxying `app.mesh.internal` to `127.0.0.1:18090`, the published name resolved to the published
backend from outside —

```text
$ curl -s -m 8 --resolve app.mesh.internal:80:106.14.216.177 http://app.mesh.internal/
HTTP-ROUTE-BACKEND-OK
```

That vhost was removed at the end of the acceptance (reversibility), which is why the same request
now returns nginx's default page:

```text
$ curl -s -m 8 --resolve app.mesh.internal:80:106.14.216.177 http://app.mesh.internal/
<!DOCTYPE html><html><head><title>Welcome to nginx!</title>...

$ ls /etc/nginx/sites-enabled/
cockpit.cuihairu.site  coding.cuihairu.site  default  oddsmaker.cuihairu.site  wingman.cuihairu.site

$ nginx -t
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
```

So: traffic in through a published name over an open port is proven as a capability, but it is not
part of the box's permanent configuration and is not verified as such.

### What is still not accepted

- **`0.0.0.0:53` has not been bound.** The DNS socket is bound on `0.0.0.0:15353`, which needs no
  root. Port 53 would need root and no root bind was attempted, so the internal suffix is accepted
  on a high port only.
- **No off-box ingress to a published port.** 15353 / 18080 / 18083 / 18090 are all blocked by the
  cloud security group from any outside host. Verified from outside as `BLOCKED` / `000`.
- **No off-box TLS ingress.** Port 443 is held by the `cockpit.cuihairu.site` business vhost, so
  adding an nginx stream pass-through on 443 would conflict with a live business service, and 18090
  is not exposed by the security group. TLS pass-through is therefore verified via loopback and the
  private IP only.
- **No TLS termination.** There is no certificate and no decryption anywhere in this path —
  `tls_passthrough` means SNI pass-through.
- **Public HTTP ingress for a published name is not permanently configured.** It worked only while a
  temporary nginx vhost was present, and that vhost was removed.
- **The device-global limit is a design limit, not a bug to fix silently.** One HTTP listener and
  one termination mode per device, now enforced at create time with 409 instead of silently
  dropping the second value. A device that needs both a plain and a TLS hostname needs two
  listeners, which this plan shape cannot express.

## Outstanding

- Express two HTTP listeners (or mixed termination modes) on one device so a plain and a TLS
  hostname can be published side by side. The plan currently carries one `http_listener` and one
  `RouteMode`; the 409 guard makes that limit visible at create time instead of silently dropping
  the second value.
- Bind and accept on `0.0.0.0:53` on a device where the agent runs as root. Only port 15353 has
  been accepted on a real device.
- Wire a published hostname into the box's real ingress (an nginx host header on 80, or a stream
  pass-through on 443 that coexists with `cockpit.cuihairu.site`) so off-box traffic reaches a
  published service without a throwaway vhost.
- Open the published ports in the cloud security group, or accept that on this box only 80 and 443
  are usable ingress and the published listeners serve a LAN peer.
- Real TLS termination (certificate, decrypt, re-encrypt) if SNI pass-through stops being enough.
