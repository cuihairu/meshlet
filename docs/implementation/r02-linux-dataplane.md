# R-02: Reliable Linux Dataplane

R-02 now provides the Linux hub main line as a reusable crate. Desired hub state is validated and deterministically compiled into immutable plans. The plan owns one isolated WireGuard interface, UDP port, IPv4 overlay, peer set, route set, and explicit firewall rules per network.

The Linux backend observes real state through `defguard_wireguard_rs`, netlink, `/proc/sys/net/ipv4/ip_forward`, and the nftables JSON ruleset. The reconciler classifies drift and chooses between desired application, security-preserving recovery, or no-op. Recovery is selected only when sanitized last-good state compiles and matches observed state. Revocations are retained from both last-good and desired state, removed peers are never resurrected, and routes survive only when a surviving peer still covers them.

The nftables compiler emits an owned `meshlet` table, a forward base chain with default-drop policy, explicit revoked-address drops before same-network accept rules, cross-network isolation drops, and network-scoped rule comments. The first apply creates the owned table in one transaction; later applies atomically delete and recreate it. IPv4-only forwarding and routes remain the scope of this milestone.

Automated tests cover deterministic planning, route/AllowedIP conflict rejection, drift reporting, last-good file persistence, revoked-peer recovery, firewall transaction compilation, and reconcile decisions.
