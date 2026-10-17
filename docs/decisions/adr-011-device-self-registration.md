# ADR-011: Device Self-Registration and Central Approval

**Status:** Accepted

## Context

A user needs to install an agent before an operator can add its device record. Directly trusting every registration would let an unreviewed endpoint enter the network.

## Decision

A device presents a one-time bootstrap token and its public identity. The server creates a pending registration, issues a device-bound agent credential, and keeps the request outside the active registry. An operator approves or denies it. Approval reuses the request's device ID, allocates an Overlay address, creates a revision, and makes the device eligible for a plan.

## Rationale and trade-offs

Approval provides a clear trust boundary without requiring the administrator to deliver a second secret after approving. Pending credentials can report enrollment status but cannot fetch desired network configuration. The credential is revoked when a request is denied.

## Revisit when

Bulk enrollment, hardware attestation, delegated approvers, or richer expiry and recovery workflows are required.
