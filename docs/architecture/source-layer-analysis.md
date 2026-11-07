---
outline: deep
---

# Source Layer Analysis

This page records the runtime layers that exist in the code on 2026-11-07, not the repository directory names. The [glossary](./source-layer-glossary) defines the shared vocabulary; the Chinese page is its synchronized counterpart.

## Layers

### Configuration Contract Layer

Typed TOML inputs separate operator intent from runtime behavior. `ServerConfig` owns the hub's listener, SQLite path, overlay, presence windows, backup, tunnel MTU, hub dataplane, trusted proxies, and SSH distribution fields (`crates/meshlet-config/src/lib.rs:134`); `AgentConfig` owns the server URL, state directory, credentials, tray, upgrade, and device dataplane fields (`crates/meshlet-config/src/lib.rs:386`). Both schemas are decoded through explicit raw-TOML structs with unknown fields rejected (`crates/meshlet-config/src/lib.rs:38`), and defaults are fixed in code (`crates/meshlet-config/src/lib.rs:181`).

The implementations live in `apps/server`, `apps/agent`, and platform applications. There is no single protocol file for all configuration: agent TOML is parsed from `apps/agent/src/main.rs:62`, while the Windows tray application edits a deliberately simple flat TOML projection (`apps/tray-app/src-tauri/src/main.rs:57`). The server unit hardens the default unprivileged control-plane deployment (`deploy/systemd/meshlet-server.service:17`), and the dataplane drop-in adds only `CAP_NET_ADMIN` and `CAP_NET_RAW` (`deploy/systemd/meshlet-server.service.d/dataplane.conf:1`).

### Policy and Planning Layer

This layer makes decisions before any external effect. The domain entities and `DeviceRegistry` define networks, devices, keys, and lifecycle fields without runtime I/O (`crates/meshlet-domain/src/entities.rs:9` and `:291`); IPAM assigns and frees overlay addresses (`crates/meshlet-domain/src/ipam.rs:58`); segment trust and one-way grants decide route visibility (`crates/meshlet-domain/src/segments.rs:25` and `crates/meshlet-domain/src/segments.rs:146`); conflict checking validates LAN routes and alias prefixes (`crates/meshlet-domain/src/conflict.rs:180`); and route helpers derive hub and client AllowedIPs (`crates/meshlet-domain/src/peer_routes.rs:47` and `:100`). Direct-path decisions are also policy: the state machine classifies probes and hysteresis (`crates/meshlet-domain/src/p2p.rs:171` and `:472`).

The server-owned `MeshState` is the aggregate that composes these decisions. Its collections cover networks, IPAM, registrations, devices, routes, aliases, segments, revisions, tasks, diagnostics, and publishing (`apps/server/src/service.rs:485`). Device planning translates that policy aggregate into a typed `DevicePlan` (`apps/server/src/device_plan.rs:89`).

### Revision and State Reconciliation Layer

The revision ledger separates recording from effect. `desired_config_hash` deterministically hashes the authorized snapshot (`crates/meshlet-domain/src/config_state.rs:36`); `ConfigLedger` allocates monotonically increasing network revisions and applies only the current revision through a backend (`crates/meshlet-domain/src/config_state.rs:156` and `:215`). `ConfigApplyBackend` is the boundary for effects, while failures are explicit (`crates/meshlet-domain/src/config_state.rs:119`).

The application wrapper preserves this distinction. `UnconfiguredBackend` refuses to report success (`apps/server/src/revision.rs:73`); the backend factory serializes apply and rollback per network (`apps/server/src/revision.rs:100`); `HubDataPlaneBackend` builds a hub snapshot, enforces current authorization, and applies tunnel plus routes as one all-or-fail operation (`apps/server/src/revision.rs:150`, `:166`, and `:197`). Startup recovery compares persisted state and hub deployment journaling, and a background loop recovers interrupted revisions (`apps/server/src/convergence.rs:20` and `:88`).

### Persistence Layer

The control plane uses a dual-form state model. In-memory `MeshState` is authoritative for transactional policy work, while SQLite is the restartable mirror. `store::connect` applies migrations and configures WAL plus synchronous `NORMAL` (`apps/server/src/store.rs:20`); `persist::load` rebuilds the in-memory aggregate from tables (`apps/server/src/persist.rs:1307`); and write paths use the shared `state.persist` mutex so the in-memory change and SQLite commit remain ordered (`apps/server/src/auth.rs:65` and `apps/server/src/service.rs:100`). Backups use SQLite VACUUM INTO and restores validate schema, row counts, and content before a guarded rename (`apps/server/src/persist.rs:2013` and `:2124`).

SQLite is the only relational storage. There is no Redis, MySQL, server-side key/value cache, or durable process-wide memory contract. The agent and local UIs use atomic JSON ledgers instead.

### Device Reconciliation and OS Execution Layer

The agent consumes a structured plan, records the last successful plan, and reconciles the kernel. Its core loop pulls plans, applies changes, reports receipts and heartbeats, and drives local task, direct-path, probe, tray, upgrade, and publish subsystems (`apps/agent/src/agent.rs:43`). Reconciliation compares the desired hash with the `applied.json` ledger (`apps/agent/src/reconcile.rs:20`) and persists that ledger atomically (`apps/agent/src/reconcile.rs:54`).

The platform boundary is `SystemBackend`, a type alias selecting Linux, Windows, or explicit unsupported behavior (`crates/meshlet-network/src/lib.rs:89` and `:95`). The `NetworkBackend` trait exposes inspect, tunnel, route, NAT, and rollback operations (`crates/meshlet-network/src/lib.rs:707`). Linux execution applies tunnel, routes, host firewall, direct-port firewall, NAT, and stale-NAT cleanup through one synchronized method (`crates/meshlet-network/src/linux.rs:1606`).

### Service Publishing Layer

Publishing is a typed child plan rather than shell fragments. `PublishPlan` carries forwards, HTTP routes and listener, DNS, and probes (`crates/meshlet-publish/src/plan.rs:14`). The control plane stores CRUD records, validates them, allocates revisions, and projects enabled objects for one device (`apps/server/src/publish.rs:1214` and `:1294`). `Publisher` owns local tokio tasks and reconciles those objects (`crates/meshlet-publish/src/runtime.rs:86` and `:128`). L4 authorization checks source CIDRs or bearer tokens before backend connection (`crates/meshlet-publish/src/authorization.rs:45`).

### Task and Messaging Layer

The task layer deliberately extends the no-server-shell-command rule with an explicit operator exception. Domain state transitions are strict (`crates/meshlet-domain/src/task.rs:54` and `:157`); server dispatch and recovery are serialized by the shared persist mutex (`apps/server/src/task.rs:628` and `:709`); agent execution is an acknowledged, idempotent worker (`apps/agent/src/tasks.rs:254` and `:270`), and the command process runs locally under timeout and log-tail capture (`apps/agent/src/tasks.rs:90` and `:412`).

### Interface Layer

The Axum router exposes public, management, and agent API surfaces under one process. Management requests authenticate as users, and mutating requests require `WriteUser` plus CSRF (`apps/server/src/auth.rs:504` and `:521`); agent requests use a separate Bearer extractor (`apps/server/src/agent.rs:223`). The router composition and static console fallback are explicit (`apps/server/src/lib.rs:979` and `:1113`). There is no standalone generic schema file beyond the API contracts in `crates/meshlet-api-types/src/lib.rs:8`, `docs/architecture/api-contract.md`, and `docs/public/api/openapi.yaml`.

The CLI and local UIs are separate consumers of state. The CLI reads agent-produced files and calls only the task API (`apps/cli/src/main.rs:78` and `:896`); the Tauri tray reads and writes local config and status JSON (`apps/tray-app/src-tauri/src/main.rs:57`); the Windows tray host listens to no agent channel and polls status files while rebuilding menus (`apps/tray-host/src/main.rs:106` and `:430`).

### Observability and Diagnostics Layer

Telemetry is emitted as structured JSON through `op_log!` and middleware (`apps/server/src/telemetry.rs:41`). Metrics keep bounded in-process counters and expose Prometheus at scrape time (`apps/server/src/metrics.rs:31` and `:67`). Diagnostics form a closed 13-check vocabulary with per-check layers and statuses (`apps/server/src/diagnostics.rs:33` and `:43`); a run is persisted and audited (`apps/server/src/diagnostics.rs:852`). Runtime evidence remains separate from desired configuration.

### Platform Packaging and Lifecycle Layer

Systemd units define two server modes: control-plane-only and dataplane-enabled. The base unit keeps an empty capability set (`deploy/systemd/meshlet-server.service:17`); the drop-in grants network capabilities and enables forwarding only for dataplane mode (`deploy/systemd/meshlet-server.service.d/dataplane.conf:1`). The agent unit requires the dataplane, device token, and private key before start and grants only the two network capabilities (`deploy/systemd/meshlet-agent.service:18`). Windows MSI/ZIP installation has a separate script pipeline (`scripts/package-release.sh:13`).

## Rationale

1. **Configuration and runtime stay separate** because raw TOML is decoded into typed runtime structs and unknown fields fail (`crates/meshlet-config/src/lib.rs:38`, `:201`, and `:347`).
2. **Policy precedes state mutation** because IPAM, segments, conflicts, and direct-path decisions are pure domain functions (`crates/meshlet-domain/src/ipam.rs:58`, `crates/meshlet-domain/src/segments.rs:146`, `crates/meshlet-domain/src/conflict.rs:180`, and `crates/meshlet-domain/src/p2p.rs:171`).
3. **Desired state and actual state are not conflated** because recording creates `Pending`, backend application is required for `Applied`, and uncertainty becomes `Failed` (`crates/meshlet-domain/src/config_state.rs:1`).
4. **Plan production and execution are separated** because the server builds a private-key-free `DevicePlan` (`apps/server/src/device_plan.rs:84`), while the agent injects a local key (`apps/agent/src/agent.rs:637`).
5. **OS backends are isolated behind one boundary** because all callers use the platform `SystemBackend` alias (`crates/meshlet-network/src/lib.rs:89`) and the trait owns inspect/apply/rollback semantics (`crates/meshlet-network/src/lib.rs:707`).
6. **Publishing remains its own bounded subsystem** because it has typed validation and an independent local task runtime (`crates/meshlet-publish/src/plan.rs:43` and `crates/meshlet-publish/src/runtime.rs:128`).
7. **Tasks are explicit exception traffic** because the task module itself documents the operator-issued command exception to the normal structured-plan discipline (`apps/server/src/task.rs:13`).
8. **API and local-interface channels are separated** because management auth, agent auth, and file-based local UI inputs use distinct boundaries (`apps/server/src/auth.rs:504`, `apps/server/src/agent.rs:223`, and `apps/tray-host/src/main.rs:106`).
9. **Evidence is append-only and runtime-derived** because metrics, diagnostics, heartbeats, receipts, and probe reports update separately from desired state (`apps/server/src/metrics.rs:31`, `apps/server/src/diagnostics.rs:60`, and `apps/server/src/publish.rs:1320`).
10. **Lifecycle security is deployment-scoped** because the base server unit intentionally has no capabilities while the dataplane drop-in and agent unit add only the required network capabilities (`deploy/systemd/meshlet-server.service:28`, `deploy/systemd/meshlet-server.service.d/dataplane.conf:2`, and `deploy/systemd/meshlet-agent.service:35`).

## Call Channels

- Management UI/API → Axum `Router` → cookie/API-token extractor → service functions → SQLite mirror.
- Agent → HTTP Bearer endpoints → `DevicePlan` pull, receipt, heartbeat, direct candidates, publish health, and task acknowledgment/result.
- Hub revisions → `ConfigApplyBackend` → `SystemBackend` → host WireGuard, routes, firewall, and forwarding.
- Device revisions → agent reconciliation → `SystemBackend` → local WireGuard, routes, firewall, NAT, forwarding, and `applied.json`.
- CLI/local tray → local JSON and TOML files, plus HTTP only for explicitly issued tasks.

## Lifecycle

1. Load and validate configuration.
2. Acquire the database file lock, connect SQLite, apply migrations, and rebuild `MeshState`.
3. Install factories, recovery loops, scheduled backup, routes, and optional static console.
4. The agent resolves credentials, injects the local private key, and enters reconciliation.
5. Revisions record intent, apply through a configured backend, persist receipts, and recover interrupted work.
6. Publishing and task runtimes run independently, report evidence, and stop with plan removal or process exit.

## Storage Inventory

| Component | Storage | Key evidence |
|---|---|---|
| Control plane | SQLite `meshlet.db` + WAL/SHM | `crates/meshlet-config/src/lib.rs:136`, `apps/server/src/store.rs:20`, `migrations/001_init.sql:1` |
| Agent reconciliation | `applied.json` | `apps/agent/src/reconcile.rs:20`, `:54` |
| Direct path | `direct.json`, `direct-peers.json`, `direct-switch-events.json` | `apps/agent/src/agent.rs:1154`, `apps/agent/src/direct.rs:143` |
| Task worker | `tasks.json` | `apps/agent/src/agent.rs:1159`, `apps/agent/src/tasks.rs:90` |
| Tray/status | `tray/status.json`, `tray/icon-*.png`, `tray/lang`, SSH sync state | `apps/agent/src/tray.rs:344`, `apps/agent/src/ssh_sync.rs:415` |
| Server backup | timestamped SQLite snapshots | `apps/server/src/persist.rs:2013` |

No Redis or MySQL storage is used.
