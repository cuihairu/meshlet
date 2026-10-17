# Routing Optimization

## Current design

The first release uses a VPS hub relay. The server derives peer routes and AllowedIPs from active network state. This is simple to inspect, but traffic between two clients consumes both client-to-hub links and the hub's bandwidth.

## Bottlenecks to measure

Record peer count, each peer's AllowedIPs, relay throughput, round-trip time, MTU behavior, and controlled-SNAT connection tracking. Compare client-to-hub and client-to-client paths on the same environment. Do not attribute a result to a protocol change when the route or host differs.

## Candidate changes

Potential optimizations include narrowing peer routes, reducing unnecessary entries, improving relay capacity, and eventually adding direct peer paths. P2P traversal changes topology, firewall assumptions, and failure modes; it needs a prototype before it becomes a default.

## Decision

Keep the hub relay for v1. Optimize only after a reproducible bottleneck is measured. Preserve the existing plan derivation as the baseline and verify that any performance change keeps network isolation, route visibility, and recovery behavior intact.
