# Domain Model

## Core entities

A **User** manages the console. A **Network** owns an immutable Overlay CIDR, devices, invitations, routes, segments, and configuration revisions. A **Device** has a network-scoped identity, public key, allocated IPv4 address, platform, status, and presence evidence. Private keys never enter the server model.

## Enrollment

Devices join through an invitation or a bootstrap registration. Invite enrollment creates an active device with an allocated address. Bootstrap registration first creates a pending request; approval reuses its identity, allocates an address, and records the approval time. Pending devices do not enter the active device set.

## Routing entities

A **LAN Route** publishes a real prefix through a gateway device. An **Alias Mapping** maps an equal-sized virtual prefix to an overlapping real prefix and is bound to a route. Peer AllowedIPs are derived from active devices and published configuration.

## Revisions and recovery

Each configuration change creates a monotonic network-scoped **Config Revision** with a desired-state hash and an application status. The ledger distinguishes recorded intent from confirmed application and supports constrained rollback.

## Segment trust

A **Segment** is a network-scoped prefix and trust group. Each device has one segment assignment. A **Segment Grant** opens one directed path from a source segment to a destination segment and starts as `pending`; an explicit apply changes it to `applied`, while revoke changes it to `revoked`. Segment, grant, revision, audit, and SQLite records are committed atomically.

Only `applied` grants participate in plan visibility and the desired-config hash. `pending` and `revoked` grants still produce revisions but do not change the serialized desired state. This is a control-plane state transition, not a claim that the hub or endpoints have already enforced the new policy. See the segment design for the remaining data-plane acceptance gate.
