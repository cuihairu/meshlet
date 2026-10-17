# Network Design: Overlay, Relay, LAN Routes, and Aliases

## Overlay addressing

Each private network has an IPv4 CIDR and an IPAM allocator. The hub reserves its address; client addresses are allocated without duplication and remain reserved after revocation so that restart does not silently reassign an identity.

## WireGuard relay

The initial topology sends each device through a VPS hub. The hub coordinates peers and relays traffic. Endpoint AllowedIPs are derived from the network's desired state rather than accepted as arbitrary client input.

## LAN routes

An active device can publish a real LAN prefix through a route. The server checks conflicts and the selected return-path mode. The gateway agent installs the route and NAT behavior, while peer plans advertise only routes that have reached the required applied state.

## Alias mappings

An Alias gives an overlapping remote LAN a virtual prefix. Address translation is tied to a published route and uses equal-length prefixes, preserving one-to-one host mapping. Exact execution and return-path behavior are specified in the relevant ADR and architecture pages.
