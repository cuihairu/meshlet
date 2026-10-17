# Product Scope

## Positioning

Meshlet is a self-hosted private network for a person or small trusted group. The operator controls the server, network membership, and deployment environment rather than relying on a hosted coordination service.

## Design principles

Prefer a small, inspectable system; keep private keys on endpoint devices; make desired state and applied state distinct; and require explicit evidence before calling a feature complete. Addressing and routing behavior should remain predictable across restart and recovery.

## First-version boundaries

The first version centers on IPv4 Overlay connectivity through a VPS hub, device enrollment, LAN route publication, Alias mappings for overlapping prefixes, a management console, backups, and diagnostics. It does not claim a production-ready Windows client, mobile clients, peer-to-peer NAT traversal, multi-tenant identity, or application-level access control.

## Deployment shape

A user runs one server and one or more agents. The VPS is the coordination point and traffic relay. Real deployment acceptance, especially on a clean VPS and across physical devices, remains separate from automated tests.
