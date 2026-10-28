# TODO Completion Status Audit — 2026-10-27

**Scope:** M5 in `todo.md` — verify, item by item, every **checked** box: implementation
path, test coverage, and real acceptance evidence. This report is also the required
upstream input to the still-pending **TODO #52 SystemBackend wiring decision**
(`crates/meshlet-network/src/lib.rs:44-49`).

**Conditions:** audited 2026-10-27 on `/home/cui/workspaces/meshlet` at `ebcd9e7`
(post-M4), read-only inspection of code, tests, and acceptance docs, plus one live
`cargo test --workspace` run at that revision (exit 0; `single_instance` 8 tests in
71.14 s parallel — corroborating the 71.43 s figure M4 records).

## Verdict scale

| Label | Meaning |
| --- | --- |
| **有证据** (evidenced) | A real machine or real kernel run produced measured numbers, recorded in an implementation doc. |
| **证据弱** (weak) | Implementation and tests exist and are genuine, but there is no measured acceptance record — or the tested code is not on the product path. |
| **仅代码存在** (code only) | Code exists and compiles; it has never been executed under test. |

Only one sub-surface lands in **仅代码存在**: the Windows elevation **execution** layer
(`crates/meshlet-network/src/windows_elevation.rs:194`, the `#[cfg(windows)]` module) —
its 11 tests at `:282` all sit outside the gated module and exercise the plan layer only.

## Summary

| TODO item | Verdict | Basis |
| --- | --- | --- |
| R-01 architecture rebuild | 证据弱 | Real code + 15 ungated unit tests, but no acceptance doc and the dependency gate is not wired into CI. |
| R-02 Linux dataplane | 证据弱 | Isolation/recovery/revoke are proven by real-kernel netns tests, but the doc carries no numbers and the TODO names the wrong engine (§Discrepancies 1). |
| R-03 unified netplan | 证据弱 | 12 tests including order-independence shuffles, but the crate is not consumed by the server. |
| R-04 Linux agent E2E | **有证据** | Real PVE lab run 2026-10-24, two devices, DF/MTU/drift numbers. |
| R-04 sub: registration/recovery/receipts/retry/upgrade | **有证据** | Code + real empty-DB bootstrap walk. |
| R-04 sub: connectivity diagnostics | **有证据** | Packet-size probe validated through a real tunnel, twice. |
| R-05 sub: elevation | 证据弱 (exec layer 仅代码存在) | Plan layer + 11 tests; the `#[cfg(windows)]` exec layer has zero tests and was never run on a machine. |
| R-05 sub: dataplane real-machine | **有证据** | zh-CN Server 2022 real-machine 2026-10-25/26, CP936 fix with byte-level regressions. |
| R-06 PortForward / HTTP-TLS / authz / probes / DNS | **有证据** | Real VPS 2026-10-24 with verbatim host logs; ingress gaps recorded honestly. |
| R-06 real VPS E2E | **有证据** | Same run; all measured numbers in TODO's R-06 real-machine acceptance entry match the doc. |
| R-07 blank container install | **有证据** | sha256 match against published `SHA256SUMS`, 107 MB image leak fixed. |
| R-07 key rotation | **有证据** | 45 s convergence for 3 devices; negative-case detection is an open gap. |
| R-07 backup/restore | **有证据** | 11 integration tests + real run; the acceptance rests on a prose-only "stop first". |
| R-07 performance baseline | 证据弱 | Numbers are real but self-labelled floors, ungated and un-trended. |
| R-07 multi-device | **有证据** | Third device, `max_uses=1` token, bookkeeping `bt-1 2/5`. |
| R-07 upgrade/rollback | **有证据** | Real binary hashes both directions; rollback-to-tag not achievable. |
| M1 `tls_passthrough` | **有证据** | Every claimed test count verified exactly (12/9/12/17, 11+3). |
| M2 identity-level drift | **有证据** | All 8 cited unit tests found at the cited lines; gated injection tests exist. |
| M3 fault matrix | **有证据** | All nine scenarios at cited lines; assertions spot-checked; runtimes corroborated. |
| M4 rollback must not re-grant | **有证据** | Filter point + all four call sites at exact lines; no bypass found. |

Unchecked items are out of scope here and deliberately untouched: R-05 parent,
R-07 parent and soak, M5's own gate, and #52 — all blocked on external conditions
(§Blocked).

## Focus area 1 — Permission revocation and rollback

The security-critical chain is real and has no gap in the paths I swept.

- **Revocation itself** (`apps/server/src/service.rs:2417` `revoke_device`) deletes the
  revoked device's LAN routes and the aliases bound to those orphaned route ids **before**
  recording the revision. Priority order revoke > delete-route > clear-NAT holds.
- **Single filter point** (`apps/server/src/revision.rs:165` `enforce_authorization`):
  drop revoked peers → drop routes whose gateway is inactive → drop orphaned aliases →
  drop hub forward routes lacking a peer allowed-ips basis.
- **All four consumer boundaries verified** — `revision.rs:208` (kernel target for
  apply/rollback/recover `last_good_plan`), `revision.rs:915` (rollback settlement before
  the in-memory journal write), `apps/server/src/persist.rs:1562` (`load`, filtering every
  row read from `hub_deployments`), `persist.rs:2225` (rollback persistence).
- **Bypass sweep.** Every `hub_deployments` write and every in-memory `deployments` insert
  was enumerated: `persist.rs:2163` (apply), `persist.rs:2225` (rollback),
  `revision.rs:760` (apply success), `revision.rs:922` (rollback),
  `convergence.rs:267` (legacy recovery), `convergence.rs:305` (error column only).
  The three fresh-plan writers recompute the plan and filter
  `DeviceStatus::Active`, so a revoked device cannot enter a fresh plan.
  **No bypass found.**
- **Test** `single_instance.rs:2008`
  `rolling_back_a_failed_revoke_does_not_reopen_access` asserts every claimed property:
  revoked key absent from the peer list after rollback, `!ping`, empty routes, journal
  peers/routes excluding the revoked key, surviving device handshake and rx counters
  still advancing, and the same result after `persist::load` + `recover_once`.
- **Verdict: 有证据.** One honest caveat: the negative control at `:2123` — "remove the
  filter and this test fails" — is a self-reported counterfactual run, not reproducible by
  inspection. Only the assertion location is verifiable.

## Focus area 2 — Multi-network isolation

- `single_instance.rs:212` `two_networks_isolate_reconcile_and_rollback_on_one_hub` is the
  load-bearing test: seven netns, two disjoint overlays, and it asserts **both** that
  network B is alive (`ping(ns[1], 10.240.0.3)`) **and** that A cannot reach B
  (`!ping(ns[1], 10.242.0.3)` / `10.242.0.1`) at `:335-353`, then confirms B survives
  reapply + reboot (`:355-367`, `:388`) and that rollback restores the plan rather than
  sweeping B (`:395-409`).
- `dual_site_end_to_end.rs` (1675 lines) covers the same property through the production
  boot path with a second server instance.
- **Verdict: 有证据** — but note this is netns-level evidence on one host, not WAN/NAT
  traversal, and it lives under M3 rather than R-02, which is why R-02 alone is 证据弱.

## Focus area 3 — Windows backend (the #52 input)

**Windows cannot be wired as `SystemBackend` today, and the blocker is not a missing
`cfg` line.**

- **The decision site** is a single alias (`lib.rs:44-49`): Linux →
  `linux::LinuxNetworkBackend`, non-Linux → `unsupported::UnsupportedBackend`. Its
  `refuse()` returns `NetworkError::Unsupported` naming the operation, with the text
  `"(windows backend pending, ADR-008)"`, and `mtu_probe_sync` returns `false`
  (unverified, never green). Locking test: `every_operation_refuses_naming_the_operation`.
- **Zero tunnel implementation.** A grep for `wireguardnt|wintun|tun2socks|OpenAdapter`
  over `crates/` and `apps/` returns exactly two hits, both doc comments in
  `windows_routes.rs:13,207`. No driver load, no adapter creation, no adapter-name
  discovery. Windows today is **routes + firewall + service + elevation + cleanup only** —
  and `apply_tunnel` is the first call the agent makes
  (`apps/agent/src/agent.rs:124`). Wiring requires building the tunnel subsystem
  (driver install, tunnel service, config persistence, interface discovery, MTU), which
  ADR-008 defers.
- **What does exist is solid.** Routes, firewall, service, and cleanup execution layers
  passed real full-lifecycle tests on a zh-CN Windows Server 2022 machine (2026-10-25/26),
  and the CP936/GBK redirection bug was found and fixed with byte-level regression tests
  (`windows_console.rs:43` `MultiByteToWideChar(CP_ACP)`; `Win32_Globalization` present in
  `[target.'cfg(windows)'.dependencies]`).
- **The remaining gaps**, matching TODO's R-05 entry: tunnel full lifecycle, elevation exec
  layer (never run on a machine, zero tests), and boot-recovery **restart** verification
  (skipped because the acceptance host was a resident worker that could not be restarted —
  design check only).
- One internal inconsistency: the `windows_firewall.rs` module header (`:3-7`) still says
  the exec layer "未在 Windows 上实测", while its own exec doc (`:261-263`) records the
  2026-10-26 real-machine run. The header is stale.

## Per-item findings

### R-01 — 证据弱
`crates/meshlet-planner` (dependency-free, `Cargo.toml` `[dependencies]` genuinely empty),
`crates/meshlet-store` (revision + outbox in one transaction via
`include_str!("docs/design/r01-schemas/outbox.sql")`), `crates/meshlet-executor`
(`trait Executor { prepare, verify, recover }`). Tests: 3 planner + 5 outbox + 3 store +
4 executor, all ungated. Design docs present. **No acceptance record of any kind** —
`docs/implementation/` has no R-01 file. `scripts/check-planner-deps.sh` is correct but
**not referenced by any CI job or Makefile**, so the dependency boundary is unenforced.

### R-02 — 证据弱
Wired backend: `meshlet-network` `LinuxNetworkBackend`
(`lib.rs:45`, consumed by both apps), using **iptables** (49 references in
`linux.rs`). Peer management `linux.rs:215-298`, routes `:744`, isolation `:484`,
rollback `:1158`, drift detection `:819/1388/1435`. Revoke ordering covered by
`apps/server/tests/device_revoke.rs` (8 tests). Last-good recovery at
`apps/agent/src/agent.rs:502`. `docs/implementation/r02-linux-dataplane.md` is nine lines
of prose with **no dates, hashes, or numbers** — it describes
`crates/meshlet-net-linux/`, which **no app depends on** (nftables implementation,
effectively dead code). **Deleted 2026-10-27**; the doc now carries a superseded note.

### R-03 — 证据弱
**`crates/meshlet-netplan` was deleted 2026-10-27** (follow-up #2), so the symbol:line
references below are historical, kept for the record:
`crates/meshlet-netplan` (`canonical_conflicts:18`, `analyze_network_conflicts:103`,
`validate_network:131`, `plan_hub_peers:330`, `plan_network:411`). 12 tests / 23 fns,
ungated, including the order-independence claims: `stable_ipam_allocates_lowest_free_addresses_independent_of_input_order:248`,
`overlapping_alias_space_is_rejected_without_favoring_input_order:321`,
`hub_plan_is_identical_after_shuffling_creation_order:366`,
`global_conflict_set_and_plan_error_are_order_independent:519`. But
`meshlet-netplan` appears in **no** `apps/*/Cargo.toml` and **no** server source file;
the server does its own conflict handling (`apps/server/src/alias.rs:63`,
`lib.rs:282/360`).

### R-04 — 有证据
Bootstrap tokens stored as SHA-256 only (`meshlet-domain/src/entities.rs:141`), agent
token `0600` (`apps/agent/src/bootstrap.rs:17/67/146`), startup recovery
(`apps/agent/src/reconcile.rs:68/86`), receipts flushed before the next tick with cap 16
(`apps/agent/src/agent.rs:222-239`, `:236`), exponential backoff (`:163-177`), self-update
hash verification (`apps/agent/src/self_update.rs:219-262`), exactly 13 diagnostic checks
(`apps/server/src/diagnostics.rs:161-174`), real `ping -M do` probe
(`meshlet-network/src/linux.rs:672`).

Acceptance `docs/implementation/r04-linux-agent-e2e.md`: PVE lab, **two** device CTs
(TODO's "两台设备" is accurate, and the doc notes the external review's 3-device claim was
the error). Baseline 20×64 B bidirectional 20/20, avg 0.47–0.94 ms; DF 1392 5/5 both ways;
1419/1472 → `0 received, +2 errors, 100% loss`; MTU drift 1480→1420 healed in one tick
(`KernelDrift`, 22:24:53Z); explicit `tunnel_mtu=1480` → probe 1452.

### R-05 sub-items — 证据弱 / 有证据
**Elevation:** plan layer validated (managed `.exe` path check, `runas` escaping, error
classification) with 11 Linux tests; the `#[cfg(windows)]` exec layer
(`windows_elevation.rs:194`) has **no tests inside it** and its own doc at `:196` states
it was never tested on a machine. Sub-item honest as labelled, but "权限提升" covers the
compile gate only.
**Dataplane real-machine:** two `#![cfg(target_os = "windows")]` integration files
(`tests/windows_netsh.rs`, `tests/windows_cleanup_e2e.rs`) run natively in CI on
windows-latest (`.github/workflows/ci.yml` matrix `os: [ubuntu-latest, windows-latest]`
with `cargo test --workspace`). Real zh-CN bytes are embedded as assertions
(`GBK_ELEMENT_ABSENT` = `D5 D2 B2 BB B5 BD D4 AA CB D8 A1 A3` → `找不到元素。`), including
sc 1060/1062 idempotency. Note the decoder is `#[cfg(windows)]` with a Linux
`utf8_lossy` stub, so CP936 decoding is only verified on real Windows. Also: `docs/implementation/r05-windows-acceptance.md` **does not exist** and was never committed —
`dispatch/` is untracked scratch. (后补见本次提交新增的
`docs/implementation/r05-windows-acceptance.md` —— R-05 数据面真机验收记录。)

### R-06 — 有证据 (six sub-items)
`forwarding.rs` (TCP `:53/59`, UDP `:95/101/128`), `http.rs` (route selection `:75`,
TLS branch `:165`, plain `:187`, bounds-checked SNI sniff `:227`), `authorization.rs`
(OR semantics, IPv4-only), `health.rs:35`, `dns.rs:85/108/134/159`.

Claimed counts verified exactly: publish integration **12**, backup **9**
(`assert_eq!(migrations, 13)` at `:361`), migrations **12**, console **17**; SNI fixes
**11 unit + 3 integration**.

Acceptance `docs/implementation/r06-service-publishing.md` is a verbatim host log from
`106.14.216.177`: `18080` → `L4-FORWARD-BACKEND-OK`, `18083` (`10.9.9.9/32`) → reset zero
bytes, `18090` → `HTTP-ROUTE-BACKEND-OK`, `dig @127.0.0.1 -p 15353` → `10.240.0.5` with
public names unanswered, TLS passthrough returning the **backend** cert
`CN=tls.mesh.internal` via `openssl s_client` from both `127.0.0.1` and `172.19.169.82`,
probe `checked_at` advancing across two 35 s snapshots. Three real defects found and fixed
with regressions.

**Explicitly not verified**, and TODO's R-06 real-machine acceptance entry discloses all of
it accurately: `0.0.0.0:53`
was never bound (root binding needs privileges); `15353/18080/18083/18090` are blocked by
the cloud security group, so all data-plane evidence is loopback/private-IP only; no
off-box TLS ingress (443 held by a cockpit vhost); public HTTP ingress worked only via a
temporary nginx vhost that was then deleted. The gaps are **ingress-side, not
evidence-side**.

### R-07 sub-items — 有证据 with caveats
All six ran 2026-10-24 on a local PVE host with hub + 3 containers — real hardware and
real published artifacts, but a lab, not a rented VPS.

- **Blank install:** `install.sh` `--no-install-recommends` fixed the 107 MB kernel image
  leak; asset sha256 matched published `SHA256SUMS`; files `0600`. No test covers install;
  only one stock template exercised.
- **Key rotation:** pub key changed, 45 s to full 3/3 peer convergence
  (`reason=DesiredConfigChanged`); deleting `hub.key` left the service `active` with
  `hub recovery failed` ERROR. That ERROR line is exactly the case `systemctl` cannot show,
  and nothing automates detecting it.
- **Backup/restore:** 11 integration tests (the strongest of the six) plus the real run
  (`385024 B`, `networks=1 devices=2 revisions=3`, plaintext SQLite `0600`). **Residual
  risk:** restoring while the service runs renames a file over `meshlet.db` while the
  process holds the old inode — every later write, including a token mint returning **201**,
  lands on a detached inode and never reaches disk. The stop-first order is now mandatory
  in two docs but enforced only by prose; no code guard or test.
- **Performance:** real socket numbers (`/system/status` 126 serial / 261 at 8 workers,
  `/networks` 130, backup 63 req/s; footprint 3.5 KiB per network, 0.2 KiB per token) —
  but the doc calls them floors twice, the bench is an ungated example, and nothing is
  trended or regression-gated. Recorded baseline, not proven capacity.
- **Multi-device:** third device via `max_uses=1` token, `dev-reg-3` → `10.240.0.4`,
  `bt-1 2/5`, `bt-2 1/1`, three peers fresh. Single network, single host L2 bridge — no
  WAN/NAT traversal.
- **Upgrade/rollback:** real binary hashes both directions
  (`4845343087249b66…` → `089893187da04786…` and back), three state hashes byte-identical,
  no re-registration, 1472 B pings 3/3 lossless. **Rollback to a published older tag is not
  achievable** — only one rolling `nightly` exists, so rollback is offline-archive only and
  requires having saved the previous artifact.

### M1 — 有证据
`http.rs:18-21` `tls_passthrough` with `#[serde(alias = "tls_termination")]`; request
struct keeps the alias under `deny_unknown_fields`; `publish.rs:736`
`check_publish_mode_supported` returns 409 for `allowed_bearer_tokens` on a passthrough
route and for `path_prefix != "/"`; `migrations/013` is a single `ALTER TABLE … RENAME
COLUMN`; console updated. The one test
`tls_passthrough_rejects_capabilities_it_cannot_enforce` asserts the legacy alias is still
readable, `tls_termination` no longer appears in responses, and both 409s name the reason.
**No test in `meshlet-publish` is gated** — all always run.

### M2 — 有证据
Every cited line resolves to in-range content. One off-by-a-few-lines case found and
corrected on re-check (2026-10-27): `NetworkSnapshot`/`PeerObserved` was cited as
`lib.rs:160/177`, but the `peers` field and the struct are at `:169`/`:182` — todo.md and
`r04-linux-agent-e2e.md` now cite those. Everything else verified exactly as cited: peer
parsing from `wg show` (`linux.rs:238`, 44-char base64 ending `=`), `proto 198` marker
(`linux.rs:40`), NAT fingerprint `chain|dest|action|owner|source|interface` (`nat.rs:79`,
POSTROUTING→`none` at `:87`), kernel-side parser (`linux.rs:941`), set comparisons
(`reconcile.rs:165/179/209`), stale-rule cleanup that skips unparseable shapes rather than
deleting (`linux.rs:913`, called at `:1142`). All **8 cited unit tests found at the cited
lines**. Gated injection tests exist in `backend_wiring.rs` and `agent_reconcile.rs`.

### M3 — 有证据
All nine scenarios exist at the cited locations and the load-bearing assertions were
spot-checked, including scenario 5's dual positive+negative pair and scenario 7's
post-restart kernel assertion (`recovered_peers == 1`, ping fails). The gate exists in 40+
sites; without `MESHLET_REQUIRE_DATAPLANE` a missing sudo/`wg` prints `SKIP:` and returns —
a green exit code alone proves nothing. The dataplane CI job sets the variable, installs
wireguard-tools, and fails the run if `SKIP:` appears. `docs/implementation/m3-fault-matrix.md`
(201 lines) records per-scenario solo runtimes and states both non-defect observations
prominently: the ~180 s `REJECT_AFTER_TIME` session-key limit after an interface rebuild
(stock WireGuard behaviour), and the fact that a manual apply after a restore does not
re-converge because `ConfigLedger::apply` is idempotent for `Applied`
(`config_state.rs:230`) — recovery via `recover_once` at boot is the supported path.

### M4 — 有证据
See Focus area 1. Test runtimes corroborate the record: `105.89 s` for 7 tests plus
`8.44 s` solo ≈ the claimed `116.83 s` serial total, and the parallel figure matches my own
run.

## Discrepancies found (TODO wording vs reality)

1. **R-02 says "nftables"; the wired backend uses iptables.** The nftables
   implementation lives only in `crates/meshlet-net-linux`, which no app depends on, and
   `r02-linux-dataplane.md` describes that unwired crate.
2. **`crates/meshlet-netplan` is not on the product path.** The server implements conflict
   handling itself. R-03's checked claim implies otherwise.
3. **The planner dependency gate is unenforced.** `scripts/check-planner-deps.sh` is
   correct but referenced by no CI job and no Makefile.
4. **R-02 and R-03 acceptance docs contain no measured values** — nine lines of prose each,
   restating what unit tests cover. That is why both are 证据弱.
5. **R-04's 真实连接诊断 sub-item is self-contradictory**: "真实 VPS 到设备的端到端连通验收仍留下轮"
   followed by "(2026-10-24 完成，见父行…)". The implementation doc marks it done.
6. **Stale test count in TODO's R-06 授权控制 entry**: 11 integration tests is the pre-M1
   number; M1's added test makes 12. `r06-service-publishing.md` also disagreed with itself
   (11 in the coverage bullet, 12 in the surface table).
7. **`backup.rs` "migration hard count" is not in source.** There is no count constant in
   `apps/server/src/backup.rs`; the migration count comes from
   `sqlx::migrate!("../../migrations")` at `store.rs:17`, and 13 is asserted in the tests
   (`backup.rs:368`, `:1086`). Claim true, wording implies a source constant.
8. **"crate 实现与单测" overstates unit-test placement** for DNS, health probes, and
   forwarding (TODO's R-06 DNS, 健康探测, and PortForward entries): those source files contain no in-file unit tests —
   coverage is integration tests plus lib tests in `runtime.rs`.
9. **Line ranges drifted in the M2 TODO text**: `backend_wiring.rs:977-1182` is scenario 11
   — the block actually spans `:1035` (marker) through `:1245`, with the three injections
   starting at `:1048`; `agent_reconcile.rs:878-992` actually ends at `:1003`. All claimed
   content exists, at different lines. The R-04 doc's citations also drifted after the M2
   commit: receipts `:136/:140` → `enqueue_receipt :235` / `flush_pending_receipts :222`;
   cap `:701` → `:236` (test at `:842`); heartbeat `:422` → `collect_evidence :555` with
   the probe at `:567`; update-manifest `lib.rs:941` → `:945`; self-update test span
   `:219-259` → `:227-275`. All corrected on 2026-10-27.
10. **`windows_firewall.rs` module header is stale** — see Focus area 3.
11. **"真实 VPS" is imprecise for R-04 and R-07** — both ran on a local PVE lab host with
    containers. R-06's run was on a real cloud VPS. Not false, but the terms are used
    loosely.
12. **M4's test does not explicitly assert `journal["aliases"]` is empty**; empty aliases
    hold only transitively. TODO's "peer/路由/alias 均不含它" over-claims slightly.

## Blocked — external conditions required

| Item | Missing |
| --- | --- |
| R-05 parent | WireGuardNT/wintun tunnel subsystem (no code at all), elevation exec-layer real-machine run, boot-recovery restart on a host that may be restarted. |
| R-07 parent + soak | Weeks of soak data. Collector started 2026-10-24; day-1 review showed 16.85 h of `status=OK` with `NRestarts=0` and zero new registrations — healthy but nowhere near the stated bar. |
| #52 SystemBackend wiring | The R-05 prerequisites above, plus the design check for a tunnel-only Windows v1 (ADR-008: Overlay client, no gateway/NAT). |

None of these can be advanced locally. Nothing was changed in those TODO lines.

## What this audit does not establish

- Counterfactual claims (e.g. M4's "remove the filter and the test fails") are the author's
  record; only assertion locations are verifiable by inspection.
- Test **counts** were verified by reading source; **pass results** were verified only once,
  by the single `cargo test --workspace` run at `ebcd9e7`.
- Performance numbers are floors on a curl-forked client and were not re-measured.
- Windows exec-layer behaviour was not executed here (Linux host); its evidence is CI on
  windows-latest plus the 2026-10-25/26 local runs recorded in the file headers.

## Follow-ups that are locally actionable

**Status (2026-10-27, same day): all four landed.** #1 in `ee1cf12`, #2 in `eb6ce1b`,
#3 in `2fe3fd5` (flock-based instance lock, not just a probe), #4 in the line-number sweep
across `todo.md`, `r04-linux-agent-e2e.md`, `r06-service-publishing.md` and the two
`windows_*.rs` headers (this report's own TODO references were made line-independent so
they cannot rot the same way).

1. Wire `scripts/check-planner-deps.sh` into CI (or delete it) so the R-01 dependency
   boundary is actually enforced.
2. Correct the two factual errors in `todo.md` (nftables → iptables; `meshlet-netplan`
   not on the product path) or delete the unwired crates.
3. Decide the backup-restore guard: either a code-level refusal of a restore while the
   service holds an open database, or an automated check that would have caught the
   detached-inode write loss.
4. Update the stale line ranges and test counts in `todo.md` and
   `r04-linux-agent-e2e.md`, and fix the stale `windows_firewall.rs` header.
