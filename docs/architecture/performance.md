# Performance Plan and Baselines

The benchmark record measures representative control-plane requests against SQLite and records the environment, commands, and repeated observations. Results are useful only when the workload and host conditions are stated.

## Method

Measure throughput and latency for network and device operations, compare file-backed and in-memory databases, and report memory per server process. Run the same workload before and after a change, use multiple trials, and avoid presenting a single best run as a guarantee.

## Interpretation

A single-connection SQLite pool serializes writes by design. That choice simplifies state ordering for a small self-hosted deployment but can limit concurrency. Any optimization must preserve transaction order and recovery semantics before it is accepted.

## Reproduction

The source record includes the exact commands, baseline environment, and post-change measurements. Re-run those commands on the target class of machine before drawing conclusions about production capacity. Relay throughput is also bounded by the endpoint links and VPS network path, not by control-plane benchmarks.

## Baseline 2026-10-24 (R-07 performance acceptance)

Environment: Intel Core i9-10880H @ 2.30GHz (dev laptop), rustc 1.99.0 release build, 10 s per concurrency level. Driven by the in-process oneshot bench (`apps/server/examples/bench.rs`) — **no TCP/TLS stack cost is included**; the numbers are for before/after comparison of handler + SQLite work, not a capacity promise. Zero errors at every point.

`db = file` (SQLite on disk):

| Target | Concurrency | req/s | p50 µs | p90 µs | p99 µs | max µs |
|---|---|---|---|---|---|---|
| GET /system/status (public, no DB) | 1 | 206484 | 3 | 4 | 13 | 34704 |
| GET /networks (session check = 1 DB read) | 1 | 5744 | 138 | 208 | 1120 | 34093 |
| GET /auth/tokens (session + list = 2 DB reads) | 1 | 3743 | 228 | 319 | 1240 | 8118 |
| GET /system/status | 16 | 859491 | 3 | 4 | 23 | 21509 |
| GET /networks | 16 | 28221 | 537 | 685 | 1091 | 17890 |
| GET /auth/tokens | 16 | 12851 | 1052 | 1818 | 3991 | 14941 |
| GET /system/status | 64 | 893484 | 3 | 4 | 21 | 13305 |
| GET /networks | 64 | 30450 | 2043 | 2415 | 3449 | 9387 |
| GET /auth/tokens | 64 | 16911 | 3706 | 4328 | 5432 | 8581 |
| GET /system/status | 256 | 916522 | 3 | 4 | 18 | 12435 |
| GET /networks | 256 | 16800 | 14067 | 21989 | 36856 | 81476 |
| GET /auth/tokens | 256 | 6579 | 35716 | 56977 | 89101 | 112371 |

`db = memory` (same handlers, SQLite in-memory — isolates disk sync from handler cost):

| Target | Concurrency | req/s | p50 µs | p90 µs | p99 µs |
|---|---|---|---|---|---|
| GET /system/status | 1 | 324673 | 2 | 3 | 7 |
| GET /networks | 1 | 4559 | 151 | 289 | 2154 |
| GET /auth/tokens | 1 | 2784 | 332 | 438 | 962 |
| GET /system/status | 64 | 835102 | 3 | 4 | 19 |
| GET /networks | 64 | 7607 | 8248 | 10029 | 12034 |
| GET /auth/tokens | 64 | 3878 | 16332 | 19495 | 21982 |
| GET /system/status | 256 | 987914 | 2 | 4 | 19 |
| GET /networks | 256 | 7272 | 34899 | 41759 | 49037 |
| GET /auth/tokens | 256 | 3712 | 68393 | 80337 | 94844 |

Memory footprint: RSS 11300 KiB → 66496 KiB across the file sweep (includes the load driver and runtime); the footprint run then measured 3.5 KiB/network (500 networks with one revision each: +1740 KiB) and 0.2 KiB/token (500 API tokens: +112 KiB).

Reading: the public status path scales to ~0.9 M req/s because it touches no lock; every authenticated path funnels through the single SQLite connection and saturates in the tens of thousands of req/s, with queueing (not disk) dominating at c=256 — the memory table shows the same collapse, so the bottleneck is the serialized pool, matching the interpretation above. At a realistic self-hosted load (a few agents polling every 30 s plus one console session) these paths sit idle; the numbers exist so future changes can be compared.

Commands: `cargo run --release -p meshlet-server --example bench -- --db file --secs 10 --sweep 1,16,64,256`, then `--db memory`, then `--db file --footprint`. Full raw output: `docs/implementation/r07-deployment-acceptance.md`.
