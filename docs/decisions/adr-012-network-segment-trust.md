# ADR-012: Network Segments as Trust Groups

**Status:** Accepted as a design contract; policy enforcement has separate acceptance criteria.

## Context

A network may need device groups with different trust boundaries. A single Overlay-wide peer set makes every active device mutually reachable by default.

## Decision

A Segment is a network-scoped address prefix and trust group. Each device belongs to one segment and its address must fall within that prefix. Devices in the same segment trust one another by default. Cross-segment traffic is denied unless an applied, directional grant allows source-to-destination traffic.

LAN routes and Alias visibility follow the segment of their publishing gateway. Existing networks migrate to one default segment with behavior equivalent to the prior single-group network.

## Enforcement and trade-offs

The intended policy has both peer-plan and hub-forwarding layers. The current model and persistence work do not alone prove that both layers enforce the contract. Segment changes may require address reassignment, and rule count grows with segments and grants.
