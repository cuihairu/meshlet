# Performance Baseline

Measured dataplane throughput baseline for the WireGuard data plane, with the
tuning knobs that move it. Every number below comes from a real run of the
reproducible netns harness (`scripts/bench-dataplane.sh`) — no extrapolated or
hand-written figures. Re-run it any time on any Linux host with passwordless
sudo, `wg`, `iperf3` and `ethtool`; it builds throwaway network namespaces,
measures, and cleans up after itself.

## Environment

| Item | Value |
| --- | --- |
| Date | 2026-11-04 |
| Kernel | 7.0.0-38-generic |
| CPU | Intel Core i9-10880H @ 2.30 GHz, 14 vCPU (KVM VM, shared host) |
| Memory | 45 GiB |
| Underlay | veth pairs on an L2 bridge (jumbo variant: veth MTU 9000) |
| Tunnel MTU | 1420 (default) / 8920 (jumbo variant) |
| Offloads | gro/gso/tso/rx/tx/sg **on** unless stated |
| Tool | iperf 3.20, 8 s per run, 1 s warm-up skipped |
| MTU probe payload | 1392 (= 1420 − 28), adaptive since this lane |

Honest caveats: all paths run inside one kernel (veth + netns), so this is a
shape-accurate but not wire-accurate baseline — no NIC rings, no real RTT.
`host_busy` counts every core of the **shared VM**, not the benchmark alone;
run-to-run variance on this host is roughly ±10 %, so treat small deltas as
noise. The load CPU usage during the recorded run was 52–90 % whole-host.

## Three paths

1. **Relay** — client A → hub → client B. Kernel forwarding (`ip_forward`) in
   the hub netns, both clients hold the hub as their only peer with
   `allowed-ips 10.240.0.0/16`. This is the shape of Meshlet's default path
   (per `docs/architecture/overview.md`, every device pair relays through the
   hub unless a direct link is promoted).
2. **Direct** — client A → client B as a direct `/32` WireGuard peer over the
   same LAN underlay. This is exactly what `apps/agent/src/direct.rs`
   (`DirectManager::Promote`) installs for same-LAN peers.
3. **Bare** — plain WireGuard pair over a back-to-back veth (no bridge, no
   hub, nothing Meshlet-specific). Control: since Meshlet only writes kernel
   `wg` state, the relay/direct numbers minus this number bound Meshlet's own
   data-plane overhead (expected ≈ 0; observed costs come from topology).

## Results (single run, 2026-11-04)

Bitrate in Gbit/s (iperf3 receiver unless noted); UDP offered at 1 Gbit/s.

**Defaults: underlay MTU 1500, tunnel MTU 1420, offloads on**

| Path | TCP 1 stream | TCP 4 streams (retrans) | UDP 1 Gbit/s received | UDP loss |
| --- | --- | --- | --- | --- |
| Relay | 1.32 | 1.36 (279) | 858 Mbit/s | 9.8 % |
| Direct | 1.20 | 1.21 (0) | 975 Mbit/s | 2.6 % |
| Bare | 1.47 | 1.56 (1509) | 951 Mbit/s | 8.7 % |

**Jumbo underlay: underlay MTU 9000, tunnel MTU 8920, offloads on**

| Path | TCP 1 stream | TCP 4 streams (retrans) | UDP 1 Gbit/s received | UDP loss |
| --- | --- | --- | --- | --- |
| Relay | 5.33 | 5.45 (338) | 940 Mbit/s | 6.0 % |
| Direct | 8.06 | 5.26 (0) | 973 Mbit/s | 2.7 % |
| Bare | 8.42 | 5.87 (1) | 984 Mbit/s | 1.6 % |

**Offloads off: underlay MTU 1500, tunnel MTU 1420, gro/gso/tso/rx/tx/sg off**

| Path | TCP 1 stream | TCP 4 streams (retrans) | UDP 1 Gbit/s received | UDP loss |
| --- | --- | --- | --- | --- |
| Relay | 1.18 | 1.17 (0) | 936 Mbit/s | 6.4 % |
| Direct | 1.22 | 1.17 (0) | 977 Mbit/s | 2.4 % |
| Bare | 1.47 | 1.50 (0) | 973 Mbit/s | 2.7 % |

## What the numbers say

- **MTU 1420 is not conservative — it is exactly right for a 1500-byte
  underlay** (1500 − 80 B WireGuard overhead). The size to challenge is the
  *underlay*, not the tunnel: on a jumbo-capable underlay, raising the tunnel
  MTU is the single biggest lever (see below).
- **Jumbo underlay is a 4–6.7× lever.** Relay TCP 4-stream 1.36 → 5.45 Gbit/s;
  direct TCP 1-stream 1.20 → 8.06 Gbit/s. At 8920 B per packet the packet rate
  drops ~6× at the same bitrate, which also shows up as lower UDP loss
  everywhere.
- **Meshlet's relay shape costs ~13 % vs bare** (TCP 4-stream 1.36 vs 1.56),
  from double encryption at the hub plus the bridge hop — kernel, not agent:
  there is no userspace data plane. Direct (same LAN) lands between relay and
  bare and shows **zero TCP retransmits** in every run at default MTU, while
  relay retransmits whenever the path is loaded. If both devices sit on the
  same LAN, the promoted direct link is measurably the better path.
- **Multi-stream does not help.** 4 streams ≈ 1 stream at every MTU (the
  bottleneck is per-packet crypto/segmentation, not a single flow's window).
  Don't spin up parallel flows expecting more.
- **Offloads on vs off is within noise on this kernel** except relay
  multi-stream TCP (1.36 → 1.17, −14 % with them off). Note:
  `crates/meshlet-network/tests/wg_forwarding.rs` disables all veth offloads
  because a handshake once failed silently with them on; on kernel
  7.0.0-38 that failure does not reproduce (handshakes and throughput both
  work with offloads on). Keep the test's workaround, but do not carry the
  "offloads break WG" assumption into production guidance.

## Tuning checklist

| # | Knob | Action | Before → after (measured) |
| --- | --- | --- | --- |
| 1 | Tunnel MTU on jumbo underlay | set `tunnel_mtu = 8920` (underlay MTU − 80) in the server config; every hop of the underlay (including bridge ports) must carry the jumbo MTU — a single 1500-byte bridge port silently blackholes every big frame (hit for real while building this harness) | relay TCP4 1.36 → 5.45 Gbit/s; direct TCP1 1.20 → 8.06 Gbit/s |
| 2 | MTU-adaptive probe (shipped in this lane) | agent reads its default-route interface MTU and sizes the DF probe accordingly (`derive_tunnel_mtu`, §7.5 evidence); plan-pinned MTU always wins; Windows/others fall back to the 1392 default | evidence-only change; no data-plane effect by design |
| 3 | Direct link when peers share a LAN | keep §12 direct promotion enabled | 0 retransmits vs relay's 279 on a loaded path (default MTU) |
| 4 | Offloads | leave GRO/GSO/TSO on (kernel default) | −14 % relay multi-stream TCP with them off; otherwise within noise |
| 5 | qdisc on hub underlay | not measured in this environment — WG interfaces use `noqueue` and the veth underlay default `noqueue`/`pfifo_fast`; an `fq` A/B on a real NIC underlay is still open | environment did not support a meaningful A/B |
| 6 | UDP-heavy workloads over relay | prefer jumbo MTU (6× fewer packets per bit) | relay UDP loss 9.8 % → 6.0 % at the same 1 Gbit/s offer |

## Windows (advice only, no code in this lane)

- Check the physical adapter MTU: `Get-NetIPInterface -AddressFamily IPv4`.
- The WireGuard interface MTU is planned by the server (`tunnel_mtu`); the
  agent enforces it. On a jumbo underlay, set the adapter MTU and the server
  `tunnel_mtu` to `underlay − 80` and record a new revision so the hub applies
  it too (the hub's own interface follows the applied revision — see
  [R-04](/implementation/r04-linux-agent-e2e) for the convergence caveat).
- Keep adapter offloads (Large Send / Receive Side Scaling) at their Windows
  defaults; the wireguard-windows driver handles segmentation itself.
- Verify the path from a device after any MTU change:
  `ping -f -l <planned_mtu - 28> <overlay-peer-ip>` (Windows `-l` is payload,
  `-f` is DF — the same probe the agent reports as `mtu_probe_payload`).

## Reproduce

```bash
sudo scripts/bench-dataplane.sh            # defaults only
sudo scripts/bench-dataplane.sh 8 1 1      # + jumbo and offloads-off matrices
```

The script prints the environment header, then for each mode × path a
TCP 1-stream, TCP 4-stream (with retransmits) and UDP 1 Gbit/s block, each
with a whole-host CPU busy sample taken during the run. Requires: passwordless
sudo, `wg`, `iperf3`, `ethtool`; skips cleanly without them.
