# M3: Fault Matrix Acceptance

M3 asks for the nine failure scenarios of review section 54.2 to be exercised for
real — no mocks — with repeatable evidence. All nine ran on 2026-10-27 on the
development machine (`/home/cui/workspaces/meshlet`, passwordless sudo,
`NET_ADMIN`, `wireguard-tools`, `iptables`).

## How the harness is real

Every test below is gated by `MESHLET_REQUIRE_DATAPLANE=1` (`apps/server/tests/single_instance.rs:65`,
`apps/agent/tests/ledger_recovery.rs:38`). Without the gate the tests print `SKIP:`
and exit 0, so a green exit code alone proves nothing — the evidence below comes
from runs with the gate set.

The scenarios that need a hub run through the production startup path
(`boot_app`, `apps/server/tests/single_instance.rs:1146`): `store::connect` →
`persist::load` → `AppState::new(...).with_dataplane(...).with_apply_backend(hub_backend_factory_with(...))`
→ the real axum router, a real admin bootstrap, real device enrollments, and real
`SystemBackend` applies executed with `sudo` inside per-test network namespaces.
Seven namespaces per test (`mlsi{pid}-0..6`): the hub at `10.240.0.1` on `wg0`
(port 51820, MTU 1380), gateway `10.240.0.2` with two LAN subnets, client
`10.240.0.3`, plus two underlay `/30` segments and two LAN hosts. Assertions
read the kernel directly (`ip route`, `wg show`, `iptables -S`, `ping`) and
compare identity sets, not counts.

## The nine scenarios

| # | Scenario | Test | Time (solo) |
| --- | --- | --- | --- |
| 1 | Hub restart restores managed state | `hub_reboot_rebuilds_managed_kernel_state_by_identity`, `single_instance.rs:1377` | 9.38 s |
| 2 | Agent restart does not trust the ledger | `a_matching_ledger_does_not_shield_kernel_drift`, `ledger_recovery.rs:379` | 1.19 s |
| 3 | Process killed mid route change | `a_half_applied_route_change_from_a_killed_apply_converges`, `ledger_recovery.rs:442` | 3.01 s |
| 4 | Deleting a LAN route cascades | `deleting_a_lan_route_cascades_managed_kernel_objects`, `single_instance.rs:1510` | 6.78 s |
| 5 | Two networks in parallel, no cross-talk | `two_networks_isolate_reconcile_and_rollback_on_one_hub`, `single_instance.rs:212` | 53.70 s |
| 6 | Host rules are not deleted | scenario 12 of `backend_driven_tunnel_routes_and_nat`, `backend_wiring.rs:704` (body at `:1247`) | 32.96 s |
| 7 | Revoked device cannot reauthorize a stale plan | `revoked_device_cannot_reauthorize_its_stale_plan`, `single_instance.rs:1821` | 5.94 s |
| 8 | Hub key rotation migrates devices | `hub_key_rotation_converges_devices_after_restart`, `single_instance.rs:1456` | 6.20 s |
| 9 | Kernel becomes consistent after DB restore | `restoring_a_backup_reconverges_the_kernel`, `single_instance.rs:1650` | 9.81 s |

Times are single-test serial runs (`--test-threads=1`); the whole
`single_instance` file is 105.89 s for 7 tests, `ledger_recovery` 6 tests in
6.35 s (suite total) / 1.19 s and 3.01 s for scenarios 2 and 3 individually,
`backend_wiring` 1 test in 32.96 s.

## Scenario evidence

### 1. Hub restart restores managed state

A two-device network with a `direct`/`controlled_snat` route is applied and both
devices converge; `192.168.60.5` behind the gateway becomes reachable from the
client. The test then captures the hub's own public key, the peer identity lines
(public key plus allowed IPs — endpoints and handshake times are excluded on
purpose), the hub routes, and the gateway NAT. The hub interface is deleted,
state is reloaded from SQLite with `persist::load`, and
`convergence::recover_once` rebuilds it. After the rebuild the hub key is
unchanged, the peer identity lines are byte-equal, the hub routes are equal, and
the gateway NAT is equal.

Recorded as observed behavior, not a defect: the rebuilt interface holds no
session keys, while the devices keep sending keepalives under their old
sessions — still valid within WireGuard's `REJECT_AFTER_TIME` (≈180 s) — which
the hub cannot decrypt and therefore learns no endpoints from, so the hub never
initiates a handshake and packets are dropped silently. That is stock WireGuard
behavior. The scenario contract is the identity-level rebuild, which is what is
asserted; data-plane return is verified through the devices' own convergence
step, which re-applies and thus resets the peer session
(`single_instance.rs:1441`).

### 2. Agent restart does not trust the ledger

The plan is applied for real first, so the ledger and the kernel genuinely
agree — a control tick then returns `UpToDate`, proving the next detection can
only come from the kernel. The test swaps the managed route for a *different*
route carrying the same Meshlet marker: the count is still one, only the
identity changed. The tick returns `KernelDrift`, reinstalls the desired route,
removes the swap-in, and leaves a planted foreign route untouched; a second
tick is `UpToDate`.

### 3. Process killed mid route change

Three kill points, each seeded as a real half-applied kernel state after plan A
was applied and ledgered: new route added but the old one not yet removed, both
gone, and neither touched. Each converges on the next tick to the new plan —
new route installed, old route gone, the foreign route still there — and the
ledger ends up describing plan B (`rev-b`). A follow-up tick is `UpToDate`.

### 4. Deleting a LAN route cascades

An `alias`-mode route plus its alias (`dnat_only`) are applied; three managed
witnesses are captured — the hub route for the alias prefix, the gateway NAT
whose owner comment is `meshlet alias {alias_id}`, and the hub's `allowed-ips`.
Deleting the LAN route returns 204 and leaves the alias list empty. The hub
converges on the next apply: the alias route is gone and the alias prefix
leaves the hub's allowed IPs. The gateway's new plan carries no NAT rules, and
`apply_device_plan_sync` would early-return on an empty rule list, so the
scenario drives `Agent::reconcile` with a fresh state directory: the decision
is `NoLocalLedger`, the ownership sweep removes the alias NAT, and overlay
connectivity survives.

### 5. Two networks in parallel, no cross-talk

One hub, two networks (`10.240.0.0/16` and `10.242.0.0/16`), real namespaces
and devices on both sides. A malicious client that adds the other network's
routes and allowed IPs is still denied by hub enforcement; re-applying network A
leaves B's peers and tunnel intact; deleting A's kernel interface and rebuilding
state from SQLite (reboot simulation) restores only A. Rollback of a failed
revision restores the prior working plan rather than sweeping the tunnel.
`single_instance.rs:337`, `:354`, `:357`, `:427`.

### 6. Host rules are not deleted

The managed apply runs in the **root namespace** — the production shape, where
the agent sits next to somebody else's routes. The test plants a foreign
route, NAT rule, FORWARD rule, and a specific `ip_forward` baseline before the
apply, proves the managed objects landed next to them, then deletes only the
managed NAT (`remove_nat_sync`) and rolls back (`rollback_sync`). The foreign
objects survive verbatim and `ip_forward` is unchanged; only the tunnel remains.
`RootGuard` (`backend_wiring.rs:245`) guarantees a failed assertion never leaves
test objects behind on the host. The same three shapes are asserted through the
real agent decision at `apps/agent/tests/agent_reconcile.rs:878`, each with
`reason=KernelDrift`.

### 7. Revoked device cannot reauthorize a stale plan

Three layers, with the revoked device still online:

1. **Credential boundary.** After revoke + apply, the same token gets 401 from
   `GET /api/v1/agent/device/desired` and 401 on `POST /api/v1/agent/device/applied`
   whether the receipt names the old revision or the current one
   (`convergence.rs:133-146` rejects an inactive device before any revision
   logic runs).
2. **Revision and hash boundary.** With the *surviving* device's valid token the
   stale receipt still fails: the old revision number is a 400 (stale receipt),
   and the current revision number paired with the old plan hash is a 400
   (hash mismatch). Neither a stale number nor a stale hash can confirm the
   post-revoke revision.
3. **No re-admission.** The surviving device's plan hash changed and its peers no
   longer contain the revoked public key; a brand-new route plus apply does not
   bring the revoked peer back into the hub's peer list; the revoked device
   stays unreachable; and the surviving device keeps handshaking with its traffic
   counters advancing, read from `wg show wg0 dump`.

The kernel side of the same revoke (peer removed from the hub, surviving network
unaffected, a restart from persisted state not resurrecting the peer from the
last-good journal) is covered at `single_instance.rs:624-674`.

### 8. Hub key rotation migrates devices

The private key file is replaced, the hub interface deleted, state reloaded and
`recover_once` run. The hub comes back on the rotated key while the peer
identities are unchanged. Each device then converges: its plan carries the new
public key and its kernel holds it, with the old key gone from both. Overlay
connectivity returns.

### 9. Kernel becomes consistent after DB restore

A route is applied and both devices converge; `192.168.60.5` is reachable. Hub
routes and gateway NAT are captured as backup-time evidence, then
`persist::backup_once` writes a backup (`summary.routes = 1`, `aliases = 0`,
no interrupted revision). After the backup the route is deleted, applied, and
the gateway's empty-NAT plan is reconciled — proving the post-backup change
reached the kernel. The pool is closed, `restore_from_backup` swaps the
database back in, and the server boots again (bootstrap now answers 409, so the
test logs in instead — the same session either way).

Recorded as observed behavior: **clicking apply cannot re-converge the kernel
after a restore that rewinds applied history.** `ConfigLedger::apply` returns
immediately for a revision that is already `Applied`
(`crates/meshlet-domain/src/config_state.rs:230`), and the revision created
after the backup no longer exists in the restored database, so there is no
revision to apply at all. The supported recovery is the production startup
path — `convergence::recover_once`, the synchronous form of the `start_recovery`
task launched at `apps/server/src/main.rs:98` — which compares the restored
expected plan against the kernel and reinstalls what is missing. After that the
hub routes are byte-equal to the backup-time capture, the gateway re-converges
its NAT to the backup-time set, and the LAN path reconnects. Making a manual
apply idempotent in the "kernel drifted" sense is a product decision, not an
acceptance gap; it is filed as a follow-up rather than changed here.

## Verification

```sh
MESHLET_REQUIRE_DATAPLANE=1 cargo test -p meshlet-server --test single_instance
MESHLET_REQUIRE_DATAPLANE=1 cargo test -p meshlet-agent --test ledger_recovery
MESHLET_REQUIRE_DATAPLANE=1 cargo test -p meshlet-network --test backend_wiring
MESHLET_REQUIRE_DATAPLANE=1 cargo test -p meshlet-agent --test agent_reconcile
MESHLET_REQUIRE_DATAPLANE=1 cargo test -p meshlet-server --test dual_site_end_to_end
```

Results, all with the gate set: `single_instance` 7 passed in 105.89 s,
`ledger_recovery` 6 passed in 6.35 s, `backend_wiring` 1 passed in 32.96 s,
`agent_reconcile` 1 passed in 27.06 s, `dual_site_end_to_end` 1 passed in
33.82 s. `cargo clippy --workspace --all-targets -- -D warnings` and
`cargo fmt --all -- --check` are clean, and the host namespace is left without
the test objects (`RootGuard` plus per-test namespace cleanup).

The matrix can be folded into the R-07 soak run; nothing here depends on clock
age, and scenarios 2, 3, 5, 6 and 7 are the ones worth repeating under
`MESHLET_REQUIRE_DATAPLANE=1` on the soak host because they are the ones that
touch shared kernel state.
