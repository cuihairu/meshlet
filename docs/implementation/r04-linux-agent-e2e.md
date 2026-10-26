# R-04: Linux Agent End-to-End Progress

R-04 is complete: the registration, startup recovery, receipt persistence, retry, and self-update portions are implemented, and the real cross-host connection diagnostic acceptance ran on 2026-10-24 (evidence in **Outstanding**, closed items listed first).

## Implemented

- Bootstrap registration reuses a saved agent token before registering, writes the agent token as a `0600` secret, and generates or reuses the local private key without transmitting it. The flow and permissions are covered by `apps/agent/src/bootstrap.rs:17`, `apps/agent/src/bootstrap.rs:67`, and `apps/agent/src/bootstrap.rs:146`.
- The server stores only the Bootstrap Token SHA-256 digest (`crates/meshlet-domain/src/entities.rs:141`). Registration stores the hashed token alongside use and revocation state, and registration reports omit the digest (`apps/server/tests/device_registration.rs:278`).
- Startup reconciliation loads the applied-plan journal, detects drift and corrupt state, and replays only after comparing the desired hash with kernel state. Evidence is in `apps/agent/src/reconcile.rs:68` and `apps/agent/src/reconcile.rs:86`.
- Every plan application reports an exact revision receipt; failures are retained in memory and flushed before the next tick. Evidence is in `apps/agent/src/agent.rs:235` (`enqueue_receipt`) and `apps/agent/src/agent.rs:222` (`flush_pending_receipts`). The queue is capped at 16 at `apps/agent/src/agent.rs:236`, and the drop-oldest behavior is locked by the test at `apps/agent/src/agent.rs:842`.
- Self-update fetches a public manifest, verifies the artifact SHA-256 before staging, atomically replaces the binary, preserves a backup, and writes a restart marker. Coverage spans version selection, hash mismatch, current-version behavior, and installation at `apps/agent/src/self_update.rs:227` through `apps/agent/src/self_update.rs:275`. The server exposes `/api/v1/update-manifest` at `apps/server/src/lib.rs:945`.
- Heartbeats collect real kernel evidence and a do-not-fragment MTU probe against the hub, with absent values explicitly represented as unverified rather than synthesized. Evidence is in `apps/agent/src/agent.rs:555` (`collect_evidence`, with the MTU probe payload at `:567`) and `crates/meshlet-domain/src/entities.rs:156`.

## Acceptance 2026-10-24 (real cross-host run)

- ~~Run the real VPS-to-device connection diagnostic acceptance and archive its evidence.~~ **Done 2026-10-24** (PVE lab: hub CT 192.168.5.150, two device CTs; UTC timestamps from the lab clock are 2026-10-23T22:xxZ). Full control-plane walk with real session auth on an empty database: `POST /api/v1/auth/bootstrap` (201), login, second bootstrap → 409 `admin user already exists; bootstrap is closed`; `POST /networks` → `net-1` 10.240.0.0/16; bootstrap token `max_uses=5` returned raw once, list shows metadata only (`bt-1`, `used_count` 2 after both devices enrolled, SHA-256 digest 64 chars, no raw value anywhere in the store); two devices self-registered presenting the bootstrap token and received agent tokens saved `0600` (store keeps only 64-char digests); `POST .../devices/{id}/approve` ×2 booked revisions; the hub revision was then applied through `POST .../config-revisions/3/apply` (200, `applied` 22:16:37Z) — until that call the desired endpoint answers 503 `dataplane_not_configured` and agents back off exponentially (observed `retry_in_secs=256`), which converges by itself once the revision is applied.
- Real cross-host connectivity (hub ⇄ each device, `wg0` overlay): baseline 20×64 B 20/20 both ways (avg 0.47–0.94 ms); DF boundary with `ping -M do`: payload 1392 (1420 − 28) carried 5/5 both ways; negatives 1419 and 1472 → `0 received, +2 errors, 100% packet loss` from the hub side. While one device was still mid-convergence at 1480, its own DF 1419 to the hub carried and its twin at 1420 failed — the boundary tracked each side's own interface, confirming the probe measures the real path, not a stub.
- Connection diagnostics (the 13-check report) ran clean after convergence: `api_reachable` pass, `server_peer_configured` pass (2 devices with hub-side peers), `recent_handshake` pass (`2/2 … inside the 120s window`), `config_revision_consistent` pass (`latest revision #3 is applied at 2026-10-23T22:16:37Z`), `mtu_planned` pass (`device evidence confirms the plan: pve-dev-1 reading 1420 probe 1392; pve-dev-2 reading 1420 probe 1392`), LAN/alias/NAT rows correctly `not_applicable`/`unavailable` for a no-LAN-route network. Device heartbeats carried the verbatim evidence `{"tunnel_mtu":1420,"nat_rules_present":false,"nat_snat_rules_present":false,"mtu_probe_payload":1392}` per device.
- MTU convergence, the defect this round fixed (agent enforced an unset plan as "leave the interface alone", so drift never healed): with the fixed agent (`sha256/16 2114bd9e…`), a device interface manually raised to 1480 returned to 1420 on its next tick (`applied the desired device plan … reason=KernelDrift`, 22:24:53Z); a hub config with explicit `tunnel_mtu = 1480` (root table) moved both devices to 1480 within one tick with `reason=DesiredConfigChanged`, device probes then report `probe 1452` and the diagnostic says `tunnel_mtu = 1480 is explicitly configured; device evidence confirms the plan: pve-dev-1 reading 1480 probe 1452`; removing the key healed both devices back to 1420 (`reason=DesiredConfigChanged`, 22:33:43/22:33:53Z) and the DF boundary followed (1392 carries, 1452 fails).
- Recorded as observed behavior, not fixed here: the hub's own `wg0` MTU follows the *applied revision* (booked when approved), while device plans read the live server config, so immediately after a config MTU change the hub stays at 1420 while devices sit at 1480 — DF probes from the hub side then fail even though the diagnostic passes on device evidence. Tunnel capacity is bounded by the hub's send path until a new revision is booked/applied. A follow-up could fold the live MTU into the hub plan or make the diagnostic compare the hub interface as well.
- First acceptance attempt appended `tunnel_mtu` below the `[backup]` table in the hub TOML and the server correctly kept the default — recorded because it is the negative proof that the key is root-table-only.

## Identity-level drift detection (M2, implemented 2026-10-27)

`drifted()` compared kernel state against the plan by **counts**, not identities — its own
comment at the former `apps/agent/src/reconcile.rs:139` admitted "a count is not an
identity". Three shapes of drift were therefore invisible: a planned peer swapped for a
stranger at equal total, a surviving peer's `allowed-ips` widened, and a NAT rule planted
by hand under a Meshlet ownership comment.

The snapshot now carries identities (`NetworkSnapshot` at `crates/meshlet-network/src/lib.rs:169`,
`PeerObserved` at `:182`) and the decision compares identity sets:

| Item | Observed side | Comparison |
| --- | --- | --- |
| Tunnel | existence, address, MTU (MTU only when the plan sets one) | unchanged |
| Peers | `wg show <if> dump` parsed line by line, `parse_peer_dump_line` at `crates/meshlet-network/src/linux.rs:238` — a public key must be 44 base64 chars ending in `=`, so header lines and `(none)` never become peers | `BTreeSet<(pubkey, {allowed-ips})>` at `apps/agent/src/reconcile.rs:165` |
| Routes | only routes carrying the Meshlet marker `proto 198` (`MESHLET_ROUTE_PROTO` at `crates/meshlet-network/src/linux.rs:40`) | missing or extra → drift, at `apps/agent/src/reconcile.rs:179` |
| NAT | `iptables -S` parsed into the same fingerprint as the plan, `nat_rule_signature_from_iptables` at `crates/meshlet-network/src/linux.rs:941` | `BTreeSet<fingerprint>` at `apps/agent/src/reconcile.rs:209` |

Ownership is what makes an object visible at all: unmarked routes and NAT rules without a
Meshlet comment never enter the observed set, so they are structurally incapable of being
judged as drift or deleted.

The fingerprint is `chain|dest|action|owner|source|interface` (`NatRule::signature` at
`crates/meshlet-network/src/nat.rs:79`). It reflects only what the kernel actually renders:
`-i` exists on PREROUTING rules only, so `POSTROUTING` signatures always carry `none`
(`:87`). Absent optional fields render as `none`, not `{:?}`, which would print struct
internals and never match. The ledger's `nat_rules` is compared plan-vs-plan only, so this
wording change costs at most one idempotent re-apply.

### Three real bugs the real-kernel harness found

1. **`NETMAP --to` was never parsed.** `iptables -S` renders `--to` and its value as
   separate tokens; the parser read one, so every DNAT fingerprint came back `net_map:` with
   an empty target and nothing matched the plan.
2. **Plan and kernel fingerprints differed in shape.** The plan side printed `{:?}`, giving
   `Some(Ipv4Cidr { network: …, prefix: … })` against the kernel's bare CIDR string — no
   rule could ever round-trip.
3. **The new cleanup deleted a planned SNAT rule.** `POSTROUTING` rules had been given
   `incoming_interface` metadata that `iptables_args` never renders, so the plan fingerprint
   said `…|wg0` while the kernel's said `…|none`. The rule was treated as unplanned and
   removed, and the next readback failed with "applied plan did not match kernel readback".
   Both sides now canonicalize: the signature ignores the field for POSTROUTING
   (`crates/meshlet-network/src/nat.rs:87`), and `incoming_interface` is only set on
   PREROUTING rules (`apps/server/src/device_plan.rs:189`, `apps/agent/src/agent.rs:409`).

Unplanned meshlet-owned NAT rules are now removed rather than merely never added:
`remove_stale_nat_rules_sync` (`crates/meshlet-network/src/linux.rs:913`) deletes every
meshlet-commented rule whose fingerprint is absent from the plan, and skips unparseable
shapes instead of deleting them. `apply_device_plan_sync` calls it after adding
(`:1142`).

### Evidence

Unit tests, no kernel — `missing_route_peer_or_nat_counts_as_drift`,
`a_substituted_or_extra_peer_is_drift_with_an_equal_count`,
`peer_allowed_ips_widened_is_drift_and_order_is_ignored`,
`missing_or_extra_nat_fingerprint_is_drift`, `orphan_nat_rules_on_a_demoted_gateway_are_drift`
(`apps/agent/src/reconcile.rs:419`–`:544`); `peer_dump_line_yields_identity_not_a_count`,
`nat_signature_round_trips_through_kernel_rendering`,
`nat_signature_rejects_shapes_the_renderer_never_emits`
(`crates/meshlet-network/src/linux.rs:1470`–`:1551`).

Real kernel under `MESHLET_REQUIRE_DATAPLANE` (two network namespaces, a real `wg0`, real
`iptables -t nat`, running as root):

- `crates/meshlet-network/tests/backend_wiring.rs:1048`–`:1245` — a stranger peer is
  detected and removed while the planned peer survives; an unmarked `10.245.0.0/24 dev wg0`
  is **not** drift, stays out of the owned set, and survives the repair on its exact line;
  an extra meshlet-commented SNAT is detected and removed while the planned SNAT and a
  foreign "user rule" both survive.
- `apps/agent/tests/agent_reconcile.rs:878`–`:1003` — the same three injections through the
  real agent decision path, asserting `reason=KernelDrift` on each and `!needs_apply` at the
  end.
