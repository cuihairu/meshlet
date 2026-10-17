# Modularity and Library Reuse

## Goals

Keep the domain model independent of the HTTP server and operating-system effects. Make network planning deterministic and testable, then pass an explicit plan to a backend that reconciles host state.

## Suggested layers

- **Domain:** identities, CIDR rules, IPAM, desired configuration, and revision transitions.
- **Planning:** translate domain state into device and hub plans without performing privileged operations.
- **Platform backends:** apply WireGuard, routes, and NAT through narrow operating-system interfaces.
- **Applications:** the server coordinates users and persistence; the agent owns local reconciliation and reporting.

## Public interfaces

Reusable libraries should expose stable data types and errors while leaving process lifecycle, configuration loading, logging, and privilege decisions to the host application. A coordinator can be injected into an application without taking over its runtime.

## Virtual network interface

The normal product remains a virtual-network client. A no-virtual-interface mode is a constrained access path for specific use cases, not a replacement for the Overlay. Keep an extension boundary available, but do not build a second networking architecture before there is a validated need.

## Migration

Extract modules gradually with compatibility tests around existing APIs. Document ownership, side effects, platform requirements, and versioning before publishing a library.
