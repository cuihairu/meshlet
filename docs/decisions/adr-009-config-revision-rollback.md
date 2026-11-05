# ADR-009: Configuration Revisions, Application State, and Rollback

Status: Accepted

## Context

Control-plane writes and kernel changes happen at different times and can fail independently. Operators need a history that distinguishes desired state from applied state.

## Decision

Every desired configuration change creates a monotonically numbered network revision with a deterministic hash. Revisions track pending, applying, applied, failed, and rollback states. A backend result and required device receipts determine whether a revision is effective.

## Rollback and recovery

Rollback targets a specific eligible failed revision and must not overwrite newer work. If the process restarts during application, the outcome is unknown. Mark it failed with a diagnostic rather than assuming success. Recovery replays persisted intent and reconciles the backend.

## Trade-offs

The ledger adds state and operational detail. It prevents a database commit from being mistaken for network convergence. Revisit the state machine only if a simpler model can retain the same evidence and failure guarantees.
