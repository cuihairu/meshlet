# ADR-002: Use a VPS Hub Relay for the First Version

**Status:** Accepted

## Context

A personal networking product needs a reachable coordination and traffic path even when endpoints are behind restrictive NATs. Direct peer connectivity adds discovery, traversal, and fallback complexity.

## Decision

The first topology uses a user-operated VPS as the hub. Devices establish WireGuard connections to it, and the hub relays traffic between peers.

## Rationale and trade-offs

The hub gives the operator one stable public endpoint and a central place to coordinate policy. It also introduces a bandwidth and availability dependency: client-to-client traffic traverses the VPS, and hub capacity bounds throughput.

## Revisit when

Measure the actual relay bottleneck first. A direct peer path may be prototyped later, but it must retain hub fallback, preserve network isolation, and define behavior when connectivity changes.
