# R-01 Domain Model (Draft)

> Based on `docs/architecture/target-architecture.md`; for implementation, this document plus the code in `crates/meshlet-planner` are authoritative.

## Five resource types (distinct, per Decision 4)

- **Network**: the virtual network itself (ID, name, Overlay CIDR, default Segment).
- **Segment**: a trust group within a Network (policy template, member authorization).
- **Route**: a published LAN route (prefix, owner, gateway, metric, health conditions, failover).
- **Alias**: a mapping for overlapping address space (translation rules between a local LAN and a remote site).
- **PortForward**: an L4 entry point (TCP/UDP, listener binding, target service, authorization, health probe).
- **HttpExposure**: domain/path to service (including TLS termination policy).

## Device and NetworkAttachment are separate

- **Device**: device identity (public key, platform, registration/revocation state).
- **NetworkAttachment**: a device's membership in one Network (Overlay address, Segments, enabled state).

## Revision state machine (no single `Applied` state)

`Pending` → `Preparing` → `Applying` → `Succeeded`; failure path: `Failed` → `RollingBack` → `RolledBack`.

Valid transitions are defined by `can_transition_to` in `crates/meshlet-planner/src/lib.rs`; rollback creates a new revision (Decision 6).

## Four state categories are never mixed

1. **DesiredState** — desired state; the single source of truth.
2. **Revision/Plan/Receipt** — execution records; immutable.
3. **ObservedState** — actual kernel state; input for drift detection.
4. **Audit** — audit history with a hash chain.
