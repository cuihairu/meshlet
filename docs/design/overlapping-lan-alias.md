# RG-02: Independent Aliases for Overlapping LANs

Date: 2026-10-18. Status: detailed design draft; implementation and acceptance remain incomplete.

This design refines accepted [ADR-006](../decisions/adr-006-alias-prefix-nat.md). RG-03 owns complete conflict checks, ADR-012 / PN-02 own authorization, and AR-02 owns application acknowledgements.

## Scenario and choice

The home LAN, office LAN, and client's local LAN all use `192.168.1.0/24`. Keep their real addresses and assign a distinct, equal-length Alias prefix to each remote site.

| Destination | Real address | Address used by the client | Gateway |
|---|---|---|---|
| Local host | `192.168.1.50` | `192.168.1.50` | Existing local route |
| Home host | `192.168.1.50` | `10.241.1.50` | G1: `10.240.0.2` |
| Office host | `192.168.1.50` | `10.241.2.50` | G2: `10.240.0.3` |

Client C is `10.240.0.4` in Overlay `10.240.0.0/16`. All addresses are examples requiring conflict checks. Alias translation preserves host bits. Each mapping references one Alias-mode LAN Route, which supplies the target prefix. The gateways represent separate sites. Reject overlapping real destinations behind the same gateway's ordinary routing context; independent VRF/netns support needs a separate design.

## Packet path and plan contract

```text
C → 10.241.1.50 → hub → G1 → 192.168.1.50 at home
C → 10.241.2.50 → hub → G2 → 192.168.1.50 at the office
C → 192.168.1.50 → existing local LAN
```

The hub chooses the gateway by Alias prefix and performs no LAN translation. The destination gateway applies DNAT/NETMAP; connection tracking reverses the translation for replies. Gateway failure must never redirect an Alias to another site.

The following sets describe approved publication within one default Segment. With multiple Segments, apply ADR-012 visibility first; AllowedIPs do not replace complete authorization.

| Location | Routes and Peer AllowedIPs |
|---|---|
| C's hub Peer | Overlay plus both Alias prefixes |
| C's routes | Each Alias through its gateway's Overlay address on the managed tunnel; the actual WireGuard Peer remains the hub |
| Hub's G1 Peer | G1 Overlay `/32` plus home Alias |
| Hub's G2 Peer | G2 Overlay `/32` plus office Alias |
| Hub's routes | Home Alias to G1; office Alias to G2 |
| G1's hub Peer and routes | Overlay plus office Alias; no publication of its own home Alias or real LAN back into the tunnel |
| G2's hub Peer and routes | Overlay plus home Alias; no publication of its own office Alias or real LAN back into the tunnel |

Neither repeated real LAN prefix enters C's or the hub's tunnel routes or AllowedIPs. Do not install more-specific real-host routes that override C's local LAN. Publish actual Alias prefixes rather than an aggregate containing unpublished destinations.

An Alias-mode route without a mapping publishes nothing and must never fall back to its real prefix. Reject orphan mappings, cross-network references, and mismatched targets before compilation. Candidate plans can contain pending resources for the selected revision; compilation must not mark resources or acknowledgements successful.

## Return paths and supported boundaries

Controlled SNAT is the compatibility mode: the target sees its gateway's LAN address and needs no added Overlay return route. Explicit source preservation uses DNAT only: the target sees C's Overlay address and requires a return route through the corresponding gateway.

Retain existing `return_path_mode` and `translation_mode` fields. This draft recommends rejecting explicit contradictions: `controlled_snat` corresponds to `dnat_snat`, and `dual_route` to `dnat_only`. Audit inconsistent stored records and require an explicit migration choice rather than silently changing NAT on upgrade. This compatibility work remains unimplemented.

Acceptance covers tested IPv4 unicast protocols. Broadcast discovery, embedded-address rewriting, unsolicited LAN-originated cross-site connections, gateway access through its own Alias, and cross-network connections require separate designs and tests.

## Lifecycle and failures

1. Register valid gateways, then create Alias-mode routes and equal-length mappings. Different gateways may publish overlapping real LANs; visible Alias prefixes remain independent.
2. RG-03 checks the shared forwarding domain and known local routes. An offline client's local occupancy stays unknown until application preflight. Conflicts block the affected device's application without overwriting foreign routes.
3. Compile hub forwarding, gateway NAT, and client routing separately. Show desired revision, device acknowledgements, and business probes separately; hub success alone is insufficient.
4. Keep the site binding when a gateway is offline and report degradation. Application failure follows AR-04 recovery rules and cannot publish a failed plan as successful.
5. Deleting one mapping removes only its owned routes, Peer prefixes, and NAT. Preserve the other site and local LAN. Existing-session cleanup and prevention of stale replay depend on IM-06/07/08.
6. A deleted Alias is no longer reachable by contract. RG-03 must define retained discard routes or firewall protection against default-egress leakage; ordinary route deletion is insufficient evidence for that guarantee.

## Current source evidence and remaining work

| Source | Current finding | Missing acceptance |
|---|---|---|
| `crates/meshlet-domain/src/peer_routes.rs` | Real LANs are published only for Direct routes; Aliases publish mapping prefixes; own publications are excluded | Two-site set equality and rejection of malformed/orphan inputs |
| `apps/server/src/device_plan.rs`, `revision.rs` | RouteMode selects real versus Alias destinations; gateways receive NAT | Client/hub/gateway consistency for one snapshot |
| `apps/server/src/service.rs` | Alias routes can overlap in real space; mappings require a same-network Alias route, one-to-one binding, and equal prefix length | Same-gateway ambiguity rejection, return-mode compatibility, RG-03 checks |
| `crates/meshlet-network/tests/alias_nat.rs` | Existing topology covers two overlapping remote LANs, site identity, SNAT, and source preservation | Formal API/Agent entry points plus a matching client-local LAN |
| `apps/server/tests/agent_plan.rs` | Gateway NAT and exclusion of its own LAN have coverage | Combined topology, single-site deletion, restart, failure recovery |
| `apps/server/tests/dual_site_end_to_end.rs` | Formal API/Agent flow covers two remote LANs plus the client-local same-prefix LAN. UDP probes return local/site1/site2, the kernel keeps the client-local route, and the repeated real prefix is absent from tunnel routes | TCP identity, return-mode variation, deletion, restart, failure recovery, and RG-03 preflight remain open |

These findings include a local Linux netns run of `dual_same_prefix_lans_published_via_the_control_plane_reach_their_sites`. This remains integration acceptance, not VPS deployment or full RG-02 acceptance.

## Acceptance matrix

| Case | Required result |
|---|---|
| RG02-01: two remote LANs and local LAN overlap | UDP returns local/site1/site2 in the available netns test; TCP identity remains open |
| RG02-02: plan consistency | Alias prefixes belong to the correct hub Peers and client routes/AllowedIPs; no repeated real or unpublished aggregate prefixes enter the tunnel |
| RG02-03: return modes | SNAT exposes the correct gateway LAN address; preserved-source mode exposes Overlay source, fails without a return route, and succeeds when it is added |
| RG02-04: missing or invalid mapping | No real-prefix fallback; reject orphan, cross-network, mismatched-target, or ambiguous same-gateway input without partial writes |
| RG02-05: delete home Alias | Home entry fails; office and local access remain; remove only home-owned objects and its NAT |
| RG02-06: G1 offline or application fails | No redirection to G2 or false success; deterministic failure/recovery |
| RG02-07: restart and restore | Keep route/mapping/gateway references and actual NAT mode; do not resurrect deleted mappings |
| RG02-08: conflicts and unknown occupancy | Reject occupied Alias space; display unknown offline-client checks; preflight preserves foreign routes, jointly with RG-03 |

Implementation gates are domain peer-route tests, server plan/API regressions, and strict dataplane tests. Set `MESHLET_REQUIRE_DATAPLANE=1`: missing prerequisites fail rather than count a skip as success. Mark RG-02 accepted only after the combined scenario passes.

## Alternatives and next item

Metrics cannot distinguish sites sharing one destination IP. Hub-side NAT introduces repeated real space into a shared forwarding context. IPv6 site encoding is unnecessary for this increment; retain ADR-006's equal-length IPv4 Alias model.

Next, RG-03 defines the complete conflict matrix, shared validation entry point, device preflight, and protection against default-egress leakage after deletion. RG-02 completion does not complete RG-03 or PN-02.
