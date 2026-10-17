# ADR-001: WireGuard as the Tunnel Foundation

**Status:** Accepted

## Context

Meshlet needs encrypted IP connectivity between user-controlled devices and a self-hosted coordination point. The first version should remain small, auditable, and suitable for a VPS relay.

## Decision

Use WireGuard for the encrypted tunnel. Meshlet manages peer identity, addressing, and desired configuration around it rather than inventing a transport protocol.

## Rationale and trade-offs

WireGuard provides a compact, well-understood cryptographic data plane and is available on the initial target platform. The application still owns key lifecycle, peer configuration, route derivation, and operational recovery. Using WireGuard does not provide coordination, NAT traversal, authorization, or multi-network isolation by itself.

## Revisit when

Reconsider only if a supported platform cannot meet the required lifecycle or if a measured product requirement cannot be met with WireGuard and its existing platform implementations.
