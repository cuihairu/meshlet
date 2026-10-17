# ADR-005: LAN Routes and Return-Path Modes

**Status:** Accepted

## Context

A remote device may need to reach a real LAN behind another Meshlet device. The gateway must forward traffic, and the LAN must know how to return it.

## Decision

A LAN route names an active gateway device, destination CIDR, and explicit return-path mode. The initial modes distinguish routed return traffic from controlled source NAT.

## Rationale and trade-offs

Explicit modes make route behavior reviewable and prevent the server from assuming that a LAN router has a return route. Source NAT can work where route changes are unavailable, but it reduces source-address visibility. Route publication is network-scoped and subject to conflict checks.

## Revisit when

Additional gateway selection, failover, or policy-routing requirements arise. Those features must specify duplicate publication, gateway health, and deterministic return behavior.
