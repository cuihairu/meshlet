# R-04: Linux Agent End-to-End Progress

R-04 remains open. The registration, startup recovery, receipt persistence, retry, and self-update portions are implemented; live connection diagnostics still require a real deployment acceptance pass.

## Implemented

- Bootstrap registration reuses a saved agent token before registering, writes the agent token as a `0600` secret, and generates or reuses the local private key without transmitting it. The flow and permissions are covered by `apps/agent/src/bootstrap.rs:17`, `apps/agent/src/bootstrap.rs:67`, and `apps/agent/src/bootstrap.rs:146`.
- The server stores only the Bootstrap Token SHA-256 digest (`crates/meshlet-domain/src/entities.rs:141`). Registration stores the hashed token alongside use and revocation state, and registration reports omit the digest (`apps/server/tests/device_registration.rs:278`).
- Startup reconciliation loads the applied-plan journal, detects drift and corrupt state, and replays only after comparing the desired hash with kernel state. Evidence is in `apps/agent/src/reconcile.rs:68` and `apps/agent/src/reconcile.rs:86`.
- Every plan application reports an exact revision receipt; failures are retained in memory and flushed before the next tick. Evidence is in `apps/agent/src/agent.rs:136` and `apps/agent/src/agent.rs:140`. The queue is capped at 16 and dropping the oldest entry is locked by `apps/agent/src/agent.rs:701`.
- Self-update fetches a public manifest, verifies the artifact SHA-256 before staging, atomically replaces the binary, preserves a backup, and writes a restart marker. Coverage spans version selection, hash mismatch, current-version behavior, and installation at `apps/agent/src/self_update.rs:219` through `apps/agent/src/self_update.rs:259`. The server exposes `/api/v1/update-manifest` at `apps/server/src/lib.rs:941`.
- Heartbeats collect real kernel evidence and a do-not-fragment MTU probe against the hub, with absent values explicitly represented as unverified rather than synthesized. Evidence is in `apps/agent/src/agent.rs:422` and `crates/meshlet-domain/src/entities.rs:156`.

## Outstanding

- Run the real VPS-to-device connection diagnostic acceptance and archive its evidence. The TODO record explicitly leaves this split item open for the next round.
