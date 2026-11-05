# Routing Optimization

## Current design

The first release uses a VPS hub relay. The server derives peer routes and AllowedIPs from active network state. This is simple to inspect, but traffic between two clients consumes both client-to-hub links and the hub's bandwidth.

## Bottlenecks to measure

Record peer count, each peer's AllowedIPs, relay throughput, round-trip time, MTU behavior, and controlled-SNAT connection tracking. Compare client-to-hub and client-to-client paths on the same environment. Do not attribute a result to a protocol change when the route or host differs.

## Candidate changes

Potential optimizations include narrowing peer routes, reducing unnecessary entries, and improving relay capacity. They also include eventually adding direct peer paths. P2P traversal changes topology, firewall assumptions, and failure modes. It is the project's core goal and is in active development (`lane/nat-punch`). The hub relay remains the always-available fallback.

## Decision

Keep the hub relay for v1. Optimize only after a reproducible bottleneck is measured. Preserve the existing plan derivation as the baseline. Verify that any performance change keeps network isolation, route visibility, and recovery behavior intact.
