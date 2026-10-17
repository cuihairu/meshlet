# ADR-006: Alias Prefix Mapping and NAT

**Status:** Accepted

## Context

Two remote LANs can use the same IPv4 prefix. A client cannot route both real prefixes unambiguously, so one side needs a virtual address range.

## Decision

An Alias maps a virtual CIDR to a real CIDR with the same prefix length and binds to a published LAN route. Translation is one-to-one. The selected translation mode determines whether return traffic is source-NATed.

## Rationale and trade-offs

Equal-length prefixes preserve host bits and make the mapping predictable. Binding an Alias to a route keeps gateway ownership and route lifecycle explicit. The design does not solve overlap with a client's own local LAN automatically.

## Execution correction

The implementation must apply and verify NAT using the same ownership model, including host-specific `/32` cases. A successful plan assertion is not proof that the kernel accepted or retained the rules.

## Revisit when

Requirements demand non-bijective translation, port-level service publishing, or richer conflict resolution.
