# ADR-003: SQLite for the Initial Control Plane

**Status:** Accepted

## Context

The initial deployment is a single self-hosted server with modest expected write volume. It needs durable state, transactions, migrations, backup, and recovery without operating a separate database service.

## Decision

Use SQLite as the control-plane database. Run migrations at startup and serialize writes through a single-connection pool.

## Rationale and trade-offs

SQLite keeps installation and backup simple and supports transactional state changes. A single writer fits the initial scale and makes ordering easier to reason about. It limits concurrent writes and does not provide multi-host coordination.

## Revisit when

A measured deployment requirement exceeds the single-instance model, or high availability and multi-writer operation become explicit product requirements. Such a change must preserve transaction, backup, and recovery guarantees.
