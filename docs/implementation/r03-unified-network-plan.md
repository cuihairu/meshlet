# R-03: Unified Network Planning and Conflict Analysis

> **Crate removed (2026-10-27).** `meshlet-netplan` was never consumed by the
> server and has been **deleted**. Conflict analysis and plan determinism now
> live in the product path inside `apps/server`: route and Alias conflict
> rejection is integration-tested (`apps/server/tests/routes.rs:239`,
> `apps/server/tests/aliases.rs:288`), and plan-hash stability across route
> reordering is covered at `apps/server/src/device_plan.rs:590`. What is not
> carried over is the crate's device/segment/grant shuffle-independence suite —
> those inputs have no equivalent exercise in the product path. This file is
> retained as the design record for that lost coverage. See `todo.md` R-03.

R-03 introduces `meshlet-netplan`, a pure cross-platform planning library. It validates the complete desired state first, then compiles one canonical HubPlan containing hub peers, gateway assignments, and device routes. The planner performs no persistence or platform execution.

Conflict analysis covers Overlay and server-known routes, segment containment and pairwise policy overlaps, Direct-route ownership, Alias uniqueness and target equality, orphan or ambiguous Alias bindings, duplicate device addresses, unknown gateways, and active device membership. The server-known conflict set is sorted and deduplicated before it is returned, so different persistence order produces the same conflict set.

Gateway selection follows centralized IPAM and peer-route allocation semantics used by Tailscale and NetBird: ownership and overlap are coordinated against the complete state, then every gateway is selected by its stable device identity. Plans use ordered maps and final lexicographic sorting, never unordered iteration. Dedicated tests shuffle the same devices, segments, grants, routes, and aliases and assert identical HubPlans; conflicting inputs assert identical conflict sets and errors.

Direct routes publish one real prefix per gateway. Alias routes require a one-to-one mapping, equal target and alias prefix length, and distinct virtual space; overlapping real prefixes are permitted only across different gateways, preserving the two-site Alias design. Segment grants narrow which destinations a device receives, while Hub peers retain the forwarding topology. The implementation remains pure IPv4 planning; API migration and platform backend integration are deferred to R-04 and R-05.
