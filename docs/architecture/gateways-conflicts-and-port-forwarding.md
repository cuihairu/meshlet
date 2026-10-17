# Gateways, Prefix Conflicts, and Port Forwarding

This proposal treats three capabilities separately: choosing a gateway for a destination, detecting overlapping address spaces, and publishing a service through a host or port forward.

## Gateway selection

A route identifies its gateway device and return-path mode. If more than one gateway can publish the same destination, the system needs explicit priority, health, and failover rules; it must not choose a gateway unpredictably. Route visibility should follow the network and trust rules of its publishing gateway.

## Conflict classes

A remote LAN may overlap another remote LAN, a local device LAN, an Overlay, or an Alias. These cases have different remedies. Alias translation can address some remote overlap, while a local collision may require a different virtual prefix or an explicit routing choice. Validation must be consistent regardless of which API creates the resource first.

## Service forwarding

A host forward maps a virtual host address to a real LAN host, while a port forward exposes selected TCP or UDP ports. These are distinct from a general route and need clear ownership, translation mode, gateway, and failure behavior.

## Acceptance

The proposed matrix covers creation order, duplicate routes, gateway loss, return paths, NAT behavior, and rejection without partial state. The proposal does not claim that every item is implemented.
