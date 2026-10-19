# Network Segment Trust Groups

This design treats a segment as both an address prefix and a trust boundary inside one Meshlet network. The control-plane model, persistence, CRUD/apply/revoke API, revisions, audit, backup accounting, and plan hashing are implemented; the accepted design must not be confused with complete data-plane policy enforcement.

## Membership and addressing

Each network starts with a `default` segment whose CIDR equals the Overlay. That preserves the behavior of existing single-group networks. A device belongs to exactly one segment, and its Overlay address must be inside that segment. Creating a child segment requires a non-overlapping prefix contained by the Overlay. Moving a device changes its address assignment and must be handled as a controlled revision.

## Trust rules

Devices in the same active segment may communicate. Cross-segment communication is denied by default. A `SegmentGrant` permits traffic in one direction from a source segment to a destination segment; the reverse direction requires a separate grant. Pending or revoked grants do not open traffic.

## Two enforcement layers

1. Device plans narrow peer AllowedIPs to the hub, the device's own segment, and destinations authorized for that source segment.
2. The hub forwarding policy isolates peers, permits same-segment traffic, applies directional grants, and denies the remainder.

Both layers are required. Peer routes alone are not a sufficient security boundary, and a hub firewall without correct device plans can still expose unintended routes.

## Route visibility and revisions

LAN routes and Alias mappings are visible according to the segment of their publishing gateway. A segment change, route change, or grant change must create a desired-state revision and wait for the required application evidence. Revocation and recovery must not re-open traffic accidentally.

## Console behavior

The console lists network segments and grants together, shows source-to-destination direction and grant status, offers an explicit Apply only for Pending grants, and offers Revoke for Pending or Applied grants. Client and server validation errors are displayed inline; a rejected create never turns an existing list into an empty list. Because grant Apply is a desired-state transition, the console may still show the enclosing config revision as Pending after that operation.

## Migration and open work

Existing networks receive one default segment and their device assignments are backfilled. Segment ID generation, creation, and persistence are defined by the current migrations and server code. Prefix containment, all boundary cases, policy compilation, kernel execution, and real traffic tests remain separate acceptance work.
