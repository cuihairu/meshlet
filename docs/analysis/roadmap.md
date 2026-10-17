# Roadmap, Decisions, and Acceptance

## Phased delivery

The project progresses from architecture and prototype work through the minimal Overlay, console, LAN routing, Alias support, and stability. Later work should close evidence-backed P0 gaps before adding broad platform or product scope.

## Decision records

ADRs record durable choices such as WireGuard transport, VPS relay topology, SQLite, Overlay IPAM, return paths, Alias NAT, operating-system backends, configuration revisions, authentication, enrollment, and segment trust groups. New implementation should follow accepted decisions or explicitly revise them.

## Acceptance discipline

A feature is complete only when its acceptance criteria and the relevant evidence pass. Tests must identify whether they cover domain logic, API integration, privileged networking, or real deployment. Build success is necessary but does not substitute for operational verification.

## Collaboration

Keep tasks small enough to review, link implementation to requirements and ADRs, and record meaningful deviations. The current TODO is the active queue; historical records preserve earlier evidence without claiming that every old checkbox represents current product completeness.
