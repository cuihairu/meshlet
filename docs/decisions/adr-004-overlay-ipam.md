# ADR-004: Overlay IPAM and Address Allocation

**Status:** Accepted

## Context

Devices need stable virtual IPv4 addresses that do not collide within a private network. The hub needs a predictable address, and client addresses must survive restart and revocation.

## Decision

Each network has an immutable Overlay CIDR. The first usable address is reserved for the hub; client addresses are allocated from the remaining usable range. Persisted assignments remain reserved, including revoked devices, unless an explicit lifecycle rule releases them.

## Rationale and trade-offs

A small deterministic allocator is easy to inspect and test. Immutable CIDRs avoid silently invalidating existing routes and peers. Exhaustion is reported rather than handled by reusing an occupied address.

## Revisit when

IPv6, subnet resizing, or large-scale allocation becomes a concrete requirement. Any migration must preserve uniqueness and address ownership across restart.
