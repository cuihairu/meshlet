# Process Topology

<picture>
  <source media="(max-width: 767px)" srcset="../public/architecture/system-en-mobile.svg">
  <img src="../public/architecture/system-en.svg" alt="Meshlet processes and data flow" style="max-width:100%;height:auto">
</picture>

Solid lines carry business data: console traffic, desired plans and receipts, hub tunnel plans, kernel changes. Dashed lines carry registration and recovery.

## Three zones, four binaries

**Control plane, on the hub host.** `meshlet-server` serves the console and the agent HTTP/TLS API, and owns authentication, bootstrap tokens, approval, the planner, revisions and the audit log. It persists everything in one `meshlet.db` SQLite file (0600, single file). The server also owns the hub's `wg0` and rebuilds that tunnel from the database on boot.

**Kernel dataplane.** The `10.240.0.0/16` WireGuard overlay on UDP 51820, MTU 1420. The hub relay
is always on — device pairs relay through the hub by default; when direct connect is enabled, the
agent promotes same-LAN peers or dialed candidates (`decide_direct_path` in
`crates/meshlet-domain/src/p2p.rs`: SameLan/HolePunch) to direct `/32` peers via
`apps/agent/src/direct.rs`, and falls back to the hub relay through a hysteresis gate when a
direct link degrades.

**Devices.** One `meshlet-agent` binary per host. It polls the desired plan, applies it with `ip`, `wg`, iptables or nftables, posts the receipt and a heartbeat, and keeps a local ledger (`applied.json`) for drift read-back. A gateway agent additionally publishes LAN routes with owner and metric, does SNAT/DNAT on the device, and runs service publishing for forwarding, HTTP and DNS.

**`meshlet-cli`** ships info, status, peers, peer dial, agent diag, networks, config and task
assign/ls/confirm/retry commands (single source of truth: the command catalog in
`crates/meshlet-commands`; reconciliation tests pin `--help`, the catalog and dispatch together).

## Source of truth

The diagram follows the code as it stands, not the earlier documents. Two places where the documents and the source disagree: `apps/agent/src/server.rs` is a client of the hub API, not a local listener, and the hub's `wg0` lives in the server process (`hub_public_key`, `hub_backend_factory`, `hub_deployments`), not in the agent. Where a document and the source disagree, the source wins.

<details>
<summary>SVG variants</summary>

- [`system-en.svg`](./system-en.svg) — 1280 × 900, desktop
- [`system-en-mobile.svg`](./system-en-mobile.svg) — 480 × 1480, vertical re-layout, not a proportional shrink
</details>
