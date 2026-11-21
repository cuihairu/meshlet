# Multi-Instance Failure and Userspace WireGuard — Analysis

Date: 2026-11-20. Status: analysis and design recommendation only. No production
code was changed by this document. The spike in §4 lives on the `scratch/userspace-wg-poc`
branch and is not wired into `backend.rs` or any other production path.

User decision 2026-11-20: the multi-network model is **Option A** (one agent process,
many networks). The three questions asked together — "installing a second meshlet
instance stops working", "can WireGuard be implemented in userspace the way
Tailscale/ZeroTier do it", and "how should multiple networks be modelled" — turn out
to be the same question. Every collision that breaks a second instance is a collision
over a *kernel-owned, machine-global* resource, and the userspace question is what
makes it stop colliding.

## 1. Why a second instance breaks

The failures are not a missing lock. They are four machine-global resource pools that
all key off one value — the tunnel/interface name — plus one port constant shared
across instances, plus one platform idiom that converts a name collision into silent
takeover.

### 1.1 The interface name is the single collision key

One `String` in the agent config fans out to four machine-global namespaces at once:

| Resource pool | Keyed by | Where the key is produced |
|---|---|---|
| Windows tunnel service (`WireGuardTunnel$<name>`) | tunnel name | `crates/meshlet-network/src/windows_tunnel.rs:192` |
| Windows tunnel conf file (`%ProgramData%\meshlet\<name>.conf`) | tunnel name | `crates/meshlet-network/src/windows_tunnel.rs:130` |
| Linux wireguard netdev (`ip link add <name>`) | interface name | `crates/meshlet-network/src/linux/operations.rs:540` |
| Linux iptables chain (`MLT_<name>`) | interface name | `crates/meshlet-network/src/linux/operations.rs:282` |

All four are namespace-global on the machine — the SCM name space, the
`%ProgramData%` directory, the kernel netdev table, the iptables chain table. None is
scoped by `state_dir`, so a second agent with its own `state_dir` lands in the same
four tables under the same key.

The key is not per-instance by construction. The config default is a literal —
`interface: "wg0"` (`crates/meshlet-config/src/agent.rs:369`) — and the agent threads
it straight into the backend (`apps/agent/src/agent/mod.rs:137`,
`SystemBackend::new().with_interface(config.dataplane.interface.clone())`). The
backend's own defaults are equally constant: `"meshlet"` on Windows
(`crates/meshlet-network/src/windows/backend.rs:28`) and `"wg0"` on Linux
(`crates/meshlet-network/src/linux/backend.rs:28`). Either way the value does not vary
with the instance.

### 1.2 Windows: the later install tears down the earlier tunnel

This is not "the second install fails". The second install **succeeds**, and that is
what destroys the first one.

The conf is written to a machine-global directory that never involves `state_dir`:
`tunnel_conf_dir()` returns `program_data_root().join("meshlet")`
(`crates/meshlet-network/src/windows_tunnel.rs:125`) and `tunnel_conf_path_under`
appends `<name>.conf` (`crates/meshlet-network/src/windows_tunnel.rs:130`). Two
agents, two `state_dir`s, one identical conf path.

The install path is deliberately destructive of any pre-existing tunnel, because
`wireguard.exe` has no `setconf`-equivalent CLI:

- `crates/meshlet-network/src/windows/wireguard.rs:18` —
  `let existing = self.tunnel_service_exists(&self.interface);`
- `crates/meshlet-network/src/windows/wireguard.rs:19` —
  `install_plan(existing, &self.interface, conf_path)`
- `crates/meshlet-network/src/windows_tunnel.rs:176` —
  `existing_service == true` yields `[UninstallService, InstallService]`
- `crates/meshlet-network/src/windows/wireguard.rs:22-35` — the uninstall branch runs,
  waits for the old service to exit, then installs the new conf over the same service
  name

Instance B arriving second with the same default name therefore uninstalls A's tunnel
service, overwrites the conf both read, and installs its own peer table under A's
service name. A's peers are gone and the shared conf now holds B's keys. Both agents
report "applied"; both are dead. The peer-table clobber in the original hypothesis is
exactly this code path — not a race, but the intended re-apply semantics
(`install_plan` calls it 「重配路径」).

Service-name uniqueness *is* checked, but only against itself:
`crates/meshlet-network/src/windows/process_cmds.rs:6-12` formats
`WireGuardTunnel${tunnel_name}` and `sc query`s it. Nothing asks "is another meshlet
owning this name?".

### 1.3 The listen port is never unique per instance

`DirectConnectConfig::default()` pins `listen_port: 51820`
(`crates/meshlet-config/src/agent.rs:253`), so two instances render
`ListenPort = 51820` into two confs that both want the same UDP port.

The existing mitigation is real but scoped to one platform and one direction:

- `apps/agent/src/agent/direct_port.rs:59-60` —
  `if !is_windows { return PortResolution::Port(configured); }`. Linux and everything
  else unconditionally take the configured port; there is no probe at all.
- The Windows fallback window (`FALLBACK_PORT_BASE = 52900`,
  `apps/agent/src/agent/direct_port.rs:28`) is documented against the
  `netsh` UDP *excluded-port-range* case (`0xc0000022`,
  `Could not bind socket to 0.0.0.0:51820`) — against the OS refusing the bind, not
  against a sibling meshlet holding the port. It also runs *after* the failure, so the
  sequence is: A binds 51820 → B's probe fails → B falls back to 52900 → both tunnels
  come up on different ports and B's peers cannot reach B at the address their endpoint
  table names. Coexistence happens by accident, Windows only, and only when the two
  agents do not start in the same instant.
- Linux has no escape: `wg set <if> listen-port` is issued unconditionally at
  `crates/meshlet-network/src/linux/operations.rs:560-563`, and both instances target
  the same port on the same — hijacked, see §1.4 — interface.

### 1.4 Linux: the second instance hijacks the first interface, silently

On Linux the failure is worse than "collides and fails", because the code is written to
*reuse* an existing link rather than refuse one:

- `crates/meshlet-network/src/linux/operations.rs:537-541` —
  `if self.run(&["ip", "link", "show", &ifname]).is_err() { ip link add … }`. The
  comment reads 「接口存在则复用，不存在则创建（幂等）」. Instance B finds A's `wg0`
  up, so it skips creation and proceeds to *reuse* it.
- `crates/meshlet-network/src/linux/operations.rs:542-549` —
  `ip address replace <vip>/<prefix> dev wg0` overwrites A's overlay address.
- `crates/meshlet-network/src/linux/operations.rs:555-560` —
  `wg set wg0 private-key <(cat)` replaces A's keypair entirely.
- `crates/meshlet-network/src/linux/operations.rs:560-563` —
  `wg set wg0 listen-port` changes A's listening port.

Nothing fails. B takes over A's netdev, A's handshake state is invalidated by the key
swap, and A's next reconcile re-asserts its own key over B's. The two agents then flap
one kernel object against each other — indistinguishable from a device that keeps
dropping off the mesh.

### 1.5 The single-instance lock does not intervene

`apps/agent/src/instance_lock.rs:11-12` states the boundary explicitly:
「不同 `state_dir`（不同设备）互不干涉——这是刻意的」, and `try_acquire`
(`apps/agent/src/instance_lock.rs:56`) only ever locks `<state_dir>/agent.lock`
(`apps/agent/src/instance_lock.rs:47-48`). That is the right call for two *devices* and
exactly wrong for two instances on *one machine*: the lock is keyed on the per-instance
directory while every resource it protects is machine-global. It was never asked to see
across `state_dir`s, so it sees nothing.

### 1.6 The design gap is already documented

`docs/design/meshlet-identity-network-id.md:181-189` names the missing layer and defers
it:

> What does not exist is agent-side coexistence: one agent process manages one overlay
> interface, one ledger, one `applied.json`. Multi-network on the agent means multiple
> tunnels, per-network ledgers, routing-table policy and panel UI — it is a separate
> phase.

The hub side already models multiple networks (`apps/server/src/service.rs:487`,
`networks: HashMap<String, Network>`; `crates/meshlet-domain/src/entities.rs:96`, device
rows carry `network_id`). The agent side has no multiplexing layer: one process, one
interface, one ledger at `{state_dir}/applied.json` (`apps/agent/src/reconcile.rs:54-55`).
So "run a second instance" is not a configuration the product contemplates; it is two
agents each assuming they own the whole machine.

ADR-014 (`docs/decisions/adr-014-coexistence-personal-positioning.md`) anticipates exactly
this stress test: 「If a user deployment shows Meshlet and a commercial mesh cannot
coexist on one host, reopen the coexistence contract」.

**Root cause, in one sentence.** One interface-name value fans out into four
machine-global namespaces, one port constant is shared across instances, the
platform-specific "reuse if present" idiom turns a name collision into silent takeover
instead of a refusal, and the only mutual-exclusion mechanism is keyed on a per-instance
directory. None of this is a bug in the reconciliation logic; it is the consequence of
the data plane being kernel-owned and machine-global.

## 2. Userspace WireGuard: three routes, verified against crates.io

Every version, license and download count below was read from
`https://crates.io/api/v1/crates/<name>` and `.../versions` on 2026-11-20 (the
`<version>` endpoints were queried separately because the crate-level `license` field
came back null). Nothing here is from memory.

### 2.1 Corrections to the working assumptions

The research brief for this analysis carried three premises that the registry
contradicts. They matter because two of them would have sent the selection the wrong way.

| Brief premise | Verified truth | Consequence |
|---|---|---|
| "wireguard-nt 0.5.x, the mainline candidate" | wireguard-nt's newest release is **0.5.0**, published **2024-08-10**. There is no 0.5.x minor series — 7 releases from 0.1.0 (2021-09-30) to 0.5.0, none yanked | Treat as "0.5.0, quiet since 2024-08", not "actively maintained 0.5.x" |
| "official WireGuardNT C library safe bindings" | **Correct.** `nulldotblack` is Troy Neubauer / null.black Inc., the WireGuardNT maintainer, and `src/lib.rs` says "Safe rust idiomatic bindings for the WireGuard NT C library" | This is the *official* binding, not a third-party clone |
| "无外部 wireguard.exe 服务、无受限 token bind — 51820 deny 根因直接消失" | **Partly wrong.** The 51820 `0xc0000022` came from the `netsh` UDP excluded-port-range, which rejects *any* process, not the service token specifically (`apps/agent/src/agent/direct_port.rs:3-9` models the same rejection for any probe) | The in-process adapter still needs the probe fallback; the service removal is the win, not the port fix |
| "`Adapter::create` / `set_config`" | **Correct**, with the actual type names being `SetInterface` and `SetPeer`, not `Configuration` / `Peer` | Spike code must use `SetInterface` / `SetPeer` |
| "`listen_port: None` lets the OS pick the port" | **False.** `None` skips setting the `HAS_LISTEN_PORT` flag, so the field is left zeroed — and zeroed means the WireGuard default **51820** (`src/adapter.rs:76-77,241-244`) | Ports must be **assigned per network**, never left to `None`. The crate's own example comment ("let the OS pick a port") is contradicted by its own field doc and code path — see §2.5 |
| "wintun-rs + wirefeather" as a pure-Rust userspace route | **Both unusable in 2026-11** (§2.3) | Route 2 collapses; see §2.6 |
| "netstack 方向（Tailscale 形态）" | **The crate by that name is not Tailscale's** (§2.4) | The netstack route needs a real name before it can be evaluated |

### 2.2 Crate truth table

| crate | max stable | released | license | total dl | repo | notes |
|---|---|---|---|---|---|---|
| `wireguard-nt` | 0.5.0 | 2024-08-10 | MIT | 144,731 | nulldotblack/wireguard-nt | 7 releases, none yanked |
| `wintun-rs` | 0.0.6 | 2026-10-05 | MIT | 82 | abc15018045126/wintun-rs | 3 versions in 3 days |
| `wirefeather` | 0.3.0 | 2026-11-03 | MIT OR Apache-2.0 | 152 | no-std-rs/tailfeather | 0.0.1 was yanked |
| `netstack` | 0.3.0 | 2020-04-05 | MIT | 5,732 | Vengarioth/netstack | **Unrelated — game netcode** |
| `netstack-smoltcp` | 0.2.5 | 2026-11-05 | MIT OR Apache-2.0 | 253,085 | cavivie/netstack-smoltcp | The real Rust userspace TCP/IP stack |
| `tun` | 0.8.15 | 2026-11-18 | WTFPL | 3,037,629 | meh/rust-tun | 56 versions, only 0.7.12 yanked |
| `boringtun` | 0.7.1 | 2026-05-01 | BSD-3-Clause | 2,199,008 | — | Cloudflare userspace WG port |
| `gotatun` | 0.10.3 | 2026-11-09 | MPL-2.0 | 535,830 | defguard | Active userspace WG impl |
| `wireguard` | 0.2.0 | 2025-09-21 | MIT | 532 | conduition/wireguard-rs | Deps frozen at ~2020 |
| `wireguard-rs` | 0.0.0 | 2022-07-30 | AGPL-3.0-or-later | 1,812 | (none) | Placeholder |
| `wireguard-go` | **404** | — | — | — | — | No Rust crate exists |
| `ts_netstack` / `tailscale_netstack` | **null** | 2026-01-06 / 2026-01-05 | — | 29 / 27 | — | `description: "placeholder"` — name-squatting |

`wireguard-go` is not a Rust crate: it is a Go module (`golang.zx2c4.com/wireguard` /
`github.com/tailscale/wireguard-go`). Its honest Rust counterparts are `boringtun`
(2.2M downloads), `gotatun` (535k, active) and `defguard_boringtun`.

### 2.3 Route 2 — wintun-rs + wirefeather: not a production dependency in 2026-11

- `wintun-rs` 0.0.6: 82 total downloads, 3 versions published inside 2026-10-03 to
  2026-10-05. `0.0.4` was `GPL-2.0-only`; `0.0.5`/`0.0.6` are `MIT`. A three-week-old
  `0.0.x` with 82 downloads cannot carry a data plane.
- `wirefeather` 0.3.0: 152 total downloads, 4 versions in ~3 months, and 0.0.1 already
  yanked. It is the `no-std-rs` **embedded** project — `no_std`, sans-io,
  allocation-free WireGuard protocol core, README says "not audited and is not a
  general-purpose Tailscale client", builds under Bazel, needs Rust 1.88 / edition 2024.
  It has no TUN layer and no device management.
- The *direction* is complementary (it embeds the signed wintun driver rather than
  loading an external DLL), but the ecosystem is the dealbreaker, not the architecture.

### 2.4 Route 3 — the netstack direction: the name does not exist as such

crates.io `netstack` is `Vengarioth/netstack`, "A batteries included networking crate
for games", last released **2020-04-05**, edition 2018, depending on the abandoned
`failure`, `bitvec ^0.17` and `sha2 ^0.8`. It is UDP game netcode and has nothing to do
with Tailscale.

Tailscale's netstack is a Go package (`tailscale.com`); there is no usable Rust crate
for it. `ts_netstack` and `tailscale_netstack` are name-squatting placeholders with
`max_stable_version: null` and `description: "placeholder"`.

The real Rust candidates for "userspace TCP/IP stack on a TUN device" are
`netstack-smoltcp` 0.2.5 (253,085 downloads, active) built on `smoltcp`, plus `tun`
0.8.15 for TUN device creation. Combined with `boringtun`/`gotatun` for the userspace
WireGuard crypto, that *is* a buildable Tailscale-shaped stack in Rust — and it is a
multi-hundred-hour project, not a dependency swap.

### 2.5 Route 1 — wireguard-nt 0.5.0

The verified API surface (read from `src/lib.rs` and `src/adapter.rs` at 0.5.0):

| Item | Where | Notes |
|---|---|---|
| `Wireguard(Arc<Sys>)` | `src/lib.rs:125` | One handle, loaded once, shared by all adapters |
| `unsafe fn load_from_path(path)` | `src/lib.rs:170` | Loads `wireguard.dll` at runtime via `libloading` |
| `Adapter::create(wireguard, pool, name, guid)` | `src/adapter.rs:124` | In-process; returns `Err(Error::Driver)` if the name is taken |
| `Adapter::open(wireguard, name)` | `src/adapter.rs:170` | The idempotent path |
| `Adapter::set_config(&SetInterface)` | `src/adapter.rs:188` | Applies key + peers in-process |
| `SetInterface { listen_port: Option<u16>, public_key: Option<[u8; 32]>, private_key: Option<[u8; 32]>, peers: Vec<SetPeer> }` | `src/adapter.rs:73-87` | `None` port → **51820, not OS-chosen** (see below) |
| `Adapter::get_config() -> WireguardInterface` | `src/adapter.rs:514` | Reads back `listen_port: u16` — the effective port |

**The port question, settled from the code.** `src/adapter.rs:76-77` documents the
field as 「The port this interface should listen on. The default **51820** is used if
this is set to `None`」. The code path confirms it: `set_config` only writes the port
behind the `HAS_LISTEN_PORT` flag
(`src/adapter.rs:241-244`, `if let Some(listen_port) = config.listen_port`), and the
buffer is zero-initialised, so `None` submits a zeroed `ListenPort` — which in WireGuard
configuration semantics means the default 51820.

This matters because the crate's own example contradicts it: the `lib.rs` doc comment at
the `listen_port: None` line says `//Let the OS pick a port for us`. The field doc is
authoritative and is what the code does, so the example comment is wrong. The
consequence is not cosmetic — Option A's per-network ports must be **assigned by the
agent**, and `None` is not a shortcut for "random". See §3.1.
| `MAX_NAME = 256` | `src/lib.rs` | Contrast with Linux's 15-char netdev cap |
| `set_default_route(&routes, &interface)` | `src/adapter.rs:336` | Routing table setup, also in-process |

Crate doc: ``// Must be run as Administrator because we create network adapters``
(`src/lib.rs:33`). WireGuardNT driver floor: versions 0.10 and above
(`src/lib.rs:38-40`). Windows-only target metadata (`*-pc-windows-msvc`), so this does
not help Linux at all.

What it removes: the `WireGuardTunnel$<name>` Windows service, the `wireguard.exe`
process, and every per-network service-install round trip. That is the root of §1.2 —
the singleton is not "one WireGuard" but "one *service per tunnel name*", and going
in-process makes the adapter a Rust object whose name is a caller-chosen parameter.

What it does not remove: the WireGuardNT driver itself. The DLL is loaded at runtime
through `libloading`, the crate ships none of it (the four DLLs in the repo live under
`examples/wireguard_nt/bin/`), and the README says to download it. Elevation is still
required. And the 51820 excluded-port-range refusal still applies to the in-process
bind — the existing probe fallback remains necessary.

### 2.6 What Tailscale and ZeroTier actually do (verified, because the brief misstated it)

The brief framed the reference architectures with a `userspace-tunnel` build tag. That
tag does not exist — no hits in `tailscale/tailscale` across main, v1.38, v1.24, v1.20,
v1.0.0, and none in GitHub code search. The real mechanisms are:

- **Runtime flag** `--tun=userspace-networking`
  (`cmd/tailscaled/tailscaled.go:126`, help text: 「the string
  "userspace-networking", "tap:TAPNAME[:BRIDGENAME]" or comma-separated list thereof」).
- **Compile-time feature tag** `ts_omit_netstack`, described as "gVisor netstack
  (userspace networking) support" (`cmd/tailscaled/netstack.go`,
  `feature/featuretags`).

Verified composition in that mode, and the three privilege tiers that matter:

| Tier | Shape | Privileges |
|---|---|---|
| Default | kernel TUN (`tailscale0`) + userspace WG engine | root — `tailscaled requires root; … (or use --tun=userspace-networking)` |
| `--tun=userspace-networking` | gVisor netstack + wireguard-go + **fake TUN**, no kernel TUN | no root, no `/dev/net/tun` |
| `tsnet` (library) | same stack embedded per-process | README: 「No root privileges required. No system daemons to install or manage」 |

Two facts that matter more than the taxonomy:

- **WireGuard is userspace in *every* Tailscale mode, including default.** The kernel
  contributes only a TUN interface; the protocol is `wireguard-go` with userspace
  `chacha20poly1305`/`blake2s`. meshlet's current design is the opposite — the protocol
  lives in the kernel (Linux `wireguard` module, WireGuardNT driver) and the agent only
  configures it. That inversion is why §1's collisions are kernel-owned and unbindable
  from userspace.
- **ZeroTier is a userspace daemon, not a kernel module** (Linux). One `zerotier-one`
  process, one home directory, one JSON API, and **one TAP per network** created inside
  that process from `/dev/net/tun` with `IFF_TAP | IFF_NO_PI`
  (`osdep/LinuxEthernetTap.cpp`). The device name is `zt` + base32 of the network ID
  (`_base32_5_to_8`, same file). One detail is directly relevant to Option A:
  the constructor takes a **global mutex** with the comment 「Create only one tap at a
  time globally」 — a single owner process serialises device creation, which is exactly
  the property a multi-process-per-network design (Option B) cannot have without an
  external lock.

So the reference interval is bounded: at one end netstack-style pure userspace (no
privilege, no kernel object, performance given up), at the other TAP-style single
process with one device per network (privilege needed for the TAP, but one owner for
all devices). meshlet's Option A is the TAP-style end of that interval.

On performance, the official position is qualitative only: wireguard-go's README says
「you should instead use the kernel module, which is faster and better integrated into
the OS」, and wireguard.com/xplatform says userspace is for portability 「for maximum
performance」 the kernel is used. No official userspace-vs-kernel benchmark numbers
exist (`wireguard.com/performance` compares kernel WG against IPsec/OpenVPN and is
self-described as 「old, crusty」). A userspace meshlet should therefore claim
"acceptable", never "equal".

### 2.7 Route comparison and recommendation

| | wireguard-nt 0.5.0 | wintun-rs + wirefeather | netstack direction |
|---|---|---|---|
| Fix for the reported multi-instance bug | Yes — no service, adapter name is a parameter | Yes in principle | Yes, total |
| Fix for the Windows service dependency | Partial — driver still required | Yes — embeds the signed driver | Yes |
| Fix for the 51820 port collision | No — probe fallback still needed | No | Yes |
| Kernel crypto retained | Yes (WireGuardNT driver) | Yes (wintun.sys) | **No — userspace crypto** |
| Needs elevation | Yes | Yes (signed driver load) | **No — this is the real prize** |
| Removes the fliploop root cause | No | No | **Yes — the whole problem disappears** |
| Usable crate in 2026-11 | Yes — official binding, MIT, 144k dl | **No** — 82 + 152 dl | Only as `netstack-smoltcp` + `boringtun` |
| Engineering size | M — new backend, no service, no `wireguard.exe` | M+L | **XL — a userspace TCP/IP stack in Rust** |
| Windows-only | Yes | Yes | No |

**Recommendation.**

1. **Mainline: wireguard-nt 0.5.0.** It is the official WireGuardNT binding, MIT, and it
   removes the `WireGuardTunnel$` service that is the root of §1.2. It also fits Option
   A naturally: one elevated agent process creates *N* adapters in-process, so the cost
   of a second network becomes a Rust object instead of a second Windows service.
2. **Parked as phase two: the netstack route.** Tailscale's stack in that mode is
   **gVisor netstack** — a Go codebase with no Rust equivalent; the nearest Rust
   analogue is `netstack-smoltcp` 0.2.5 (on `smoltcp`) with `boringtun`/`gotatun` for the
   protocol and `tun` 0.8.15 for the device. This is the only route that makes the
   fliploop problem structurally impossible — when the TCP/IP stack is a userspace
   library rather than the kernel's, roaming stops being a kernel-owned event the agent
   cannot control (`docs/acceptance-evidence/fliploop-fix-acceptance.md:7-10` records
   64 flips/hour at baseline and a promote face pinned to `10.147.19.97:51821`). It is
   XL and is not a near-term route.
3. **Rejected: wintun-rs + wirefeather.** Zero production track record in 2026-11.

Note that for the *reported* bug specifically, Option A (§3) fixes it without any of
this — the collision is a naming problem, and unique per-network names remove it.
wireguard-nt is the right call for the data-plane architecture, not for the reported
symptom.

## 3. Multi-network model: **Option A**, decided

Option A — one agent process, many networks — is the chosen model. Option B is kept
here as a comparison column because it is the cheaper change and the reader will
otherwise re-litigate it.

### 3.1 Option A, concretely

The agent config becomes an array of network entries. Each entry gets its own
tunnel interface, its own listen port, and its own state subdirectory:

```
<state_dir>/
  agent.lock                    # single lock, at the state_dir root — one lock per agent
  networks/<net>/
    applied.json                # per-network ledger
    direct-port.json            # per-network port ledger
    device_token                # per-network credentials
```

One `agent.lock` at the `state_dir` root is correct here, and it is the fix for §1.5:
today's lock is scoped to a per-instance directory while the resources it protects are
machine-global, so it sees nothing. Under Option A one agent owns all networks, so the
lock's scope and the resources' scope finally match — and the second-instance problem
becomes "second network" instead of "second agent".

Naming is derived from the network's own handle, not from a literal: `wg-mlt-<net>`,
where `<net>` is a stable ≤8-character discriminator. `wg-mlt-` is 7 characters and
Linux rejects interface names over 15 (`crates/meshlet-network/src/linux/operations.rs:525`),
leaving exactly 8 for the handle — so a prefix of the 16-character `nwid` from
`docs/design/meshlet-identity-network-id.md` §4, not the whole ID.

This has a working precedent. ZeroTier names each per-network TAP `zt` + base32 of the
network ID — a device name derived from the joined network's own ID, not from a
constant (`osdep/LinuxEthernetTap.cpp`, `_base32_5_to_8`). The scheme proposed here is
the same idea under meshlet's naming.

Two consequences that the design must carry, not paper over:

- **The port can no longer be a constant, and `None` will not save us.** Each network
  needs a distinct effective listen port, but `listen_port: None` yields the WireGuard
  default **51820** — so two networks left at `None` collide exactly as §1.3 describes.
  The agent must assign a port per network (the existing probe-bind fallback,
  `apps/agent/src/agent/direct_port.rs`, becomes per-network rather than per-agent),
  and then read the *effective* port back from `Adapter::get_config()`
  (`src/adapter.rs:514`) to publish it in the candidate-endpoint report. Never publish
  the configured constant. This is the direct answer to §5 of this document.
- **The backend becomes N instances.** Each per-network backend is constructed with
  `.with_interface("wg-mlt-<net>")`, which the existing assertion already expects:
  `apply_tunnel_sync` refuses a tunnel name that is not its own interface
  (`crates/meshlet-network/src/linux/operations.rs:532`). That is a contained change —
  the data plane needs N objects, not a rewrite.

### 3.2 What Option A resolves

| Collision (§1) | Before | Under Option A |
|---|---|---|
| §1.1 interface name | constant `wg0` / `meshlet` | per-network `wg-mlt-<net>`, derived from the network |
| §1.2 Windows service | later install uninstalls earlier | distinct `WireGuardTunnel$wg-mlt-<net>` per network — or, with wireguard-nt, no service at all |
| §1.3 listen port | both want 51820 | distinct per network, read back from the adapter |
| §1.4 Linux hijack | B finds A's `wg0` up and reuses it | B creates `wg-mlt-<net2>`; A's link is untouched |
| §1.5 instance lock | keyed on the wrong directory | one lock at `state_dir` root, matching the resource scope |

### 3.3 Option B (rejected, kept as a column)

Option B keeps one instance per network and makes collisions impossible by deriving
names and ports: `interface = meshlet-<net>`, `listen_port = 0` for kernel-chosen. It
fixes the reported bug with the smallest possible change and no new agent loop.

It is rejected because it buys nothing that Option A does not, while keeping N agent
processes to upgrade, restart and self-update, N lock files, N panel instances and no
way to express a route that crosses networks. Given that the hub already stores
multiple networks and the identity design (`docs/design/meshlet-identity-network-id.md`
§4) already reserves a future multi-join consumer, building a second agent instead of a
multiplexed one is the expensive wrong direction. B is recorded here because it is the
correct *fallback* if the Option A multiplexing proves larger than the spike suggests.

## 4. Spike plan (scratch branch `scratch/userspace-wg-poc`, not executed)

Specified so it can be run without touching production. Nothing below has been
executed: there is no Windows host reachable from the analysis machine, no spike code
exists yet, and the `scratch/userspace-wg-poc` branch is not yet created — it should be
cut from `main` when the spike starts, so this document alone carries no spike changes.

**Step 0 — Linux two-interface PoC.** Cheapest possible proof of the Option A data-plane
shape and needs no new crate and no elevation. One process, two
`LinuxNetworkBackend` instances with `.with_interface("wg-mlt-a")` and
`.with_interface("wg-mlt-b")`, two `ip link add … type wireguard`, two
`wg set <if> listen-port 0` each, one `ip address replace` per interface. Acceptance: two
netdevs coexist, two independent peer sets, two independent routes, no cross-talk. This
validates the naming scheme and the per-network backend construction before any Windows
work.

**Step 1 — reproduce the collision on Windows** (no spike code, current binary). Two
agents, two `state_dir`s, default config, same machine. Record: both write the same
`%ProgramData%\meshlet\wg0.conf`; one `sc query WireGuardTunnel$wg0` service; the peer
table in `wg show wg0 dump` belongs to the later installer. This re-establishes §1.2
against the current binary rather than the 2026-11 record.

**Step 2 — reproduce the port refusal.** Point two instances at 51820 and capture
`wireguard.exe /dumplog` showing `Could not bind socket to 0.0.0.0:51820`
(`0xc0000022`), confirming that the probe fallback is still needed in-process.

**Step 3 — wireguard-nt dual-adapter PoC.** The load-bearing one. New crate on the
scratch branch, dependencies `wireguard-nt = "0.5.0"` plus a staged `wireguard.dll`.
Windows-only target, run elevated, with WireGuardNT present on the host.

1. `let wireguard = unsafe { wireguard_nt::load_from_path("…/wireguard.dll") }?` — once,
   shared by both adapters.
2. `Adapter::create(&wireguard, "WireGuard", "wg-mlt-a", None)` then
   `Adapter::create(&wireguard, "WireGuard", "wg-mlt-b", None)`.
3. `SetInterface { listen_port: Some(port_a), public_key: Some(pubA), private_key: Some(kA), peers: vec![SetPeer { … }] }`
   and `adapter.set_config(&interface)`; the same for `b` with `kB`, `pubB` and
   `port_b`. `port_a` and `port_b` are **explicitly distinct assigned ports** — deliberately
   not `None`, which would resolve both to 51820 (§2.5).
4. `set_default_route(&routes_a, &adapter)` for each.
5. Read back both effective ports from `Adapter::get_config()`.

Acceptance criteria, in order:

- `sc query WireGuardTunnel$wg-mlt-a` → **1060 ERROR_SERVICE_DOES_NOT_EXIST**. That is
  the assertion that the service singleton is gone.
- `netstat -an -p udp` shows two distinct bound ports, and each matches the value read
  back from `get_config().listen_port`. That is the assertion that the port collision is
  gone — and that the report must be fed from `get_config()`, since neither a configured
  constant nor `None` is trustworthy.
- **Negative control on the port:** configure a third adapter with
  `listen_port: None` and confirm `get_config().listen_port == 51820`. This cheaply
  re-proves the §2.5 finding against the actual driver rather than from source, and pins
  down that per-network port assignment is mandatory rather than optional.
- `Adapter::get_config()` on A still holds A's peer table after B was configured. That
  is the assertion that the two adapters do not clobber each other — the exact
  failure in §1.2, which must not be reproducible.
- Each overlay exchanges packets independently.

Gate before opening a real task: steps 1 and 2 confirmed on hardware, and step 3's
clobber assertion passing. If step 3 fails, the fallback is Option B, not a deeper
investigation.

## 5. Open questions

- Whether wireguard-nt's runtime DLL loading means the agent ships `wireguard.dll` or
  depends on a WireGuardNT install. The crate provides neither. **Resolved (ships)**:
  the dll is vendored at `packaging/windows/wireguard-nt/` (amd64 1.1, SHA256
  `b1b85e07…`) and delivered in all three Windows forms (MSI, nightly zip,
  `install.ps1` deploy) — the official WireGuard for Windows install does not
  carry it (its tunnel service static-links it into `wireguard.exe`).
- Whether a per-network name derived from the hub's `nwid` survives a hub migration —
  `nwid` embeds the hub's own node ID (`docs/design/meshlet-identity-network-id.md` §4),
  so a renamed hub renames every tunnel on that machine and churns them.
- Whether the direct-connect candidate table can absorb an effective port that changes
  per boot. Under Option A the port is OS-chosen, so the report must carry the value
  read back from the adapter rather than a configured constant, and peers must re-learn
  it.
- Whether the wireguard-nt 0.5.0 quiet period since 2024-08-10 is a maintenance gap or
  a sign the driver API is stable. It is the official binding, but a 17-month-old
  release should be checked against the WireGuardNT release notes before it carries
  production traffic.
- Whether Option A's per-network ledgers can be introduced without a migration: today's
  `{state_dir}/applied.json` (`apps/agent/src/reconcile.rs:54`) is the single ledger, and
  a per-network layout changes the on-disk shape.

## 附：中文摘要

**一、多实例失效根因（已逐条核实 file:line）**

失效不是缺锁。四条机器级全局资源全部以「接口名」为键，加上一个跨实例共享的端口常量，再加上一个把重名从「报错」变成「静默接管」的平台惯用法：

1. **Windows 单例服务顶掉 peer 表**：conf 落在机器级全局目录 `%ProgramData%\meshlet\<name>.conf`（`windows_tunnel.rs:130`），与安装路径 `wireguard.exe /installtunnelservice` 的服务名 `WireGuardTunnel$<name>`（`windows_tunnel.rs:192`）同源。后装实例走「停/卸载/装」重配路径（`windows/wireguard.rs:18-19`、`windows_tunnel.rs:176`），**先拆掉先装者的服务并覆盖同一份 conf** —— 两边都报 applied，两边都断。
2. **端口冲突**：`listen_port` 默认恒 51820（`config/src/agent.rs:253`）。Windows 的 probe 回退只针对 UDP 排除端口段的 `0xc0000022`（`agent/direct_port.rs:59-60`），且发生在失败之后；Linux 完全不探测，直接 `wg set … listen-port`（`linux/operations.rs:560-563`）。
3. **Linux wg0 撞名**：`if ip link show <if> is err 才 add`（`linux/operations.rs:537-541`）—— 第二个实例发现 wg0 已存在就**复用**，随后 `ip address replace`（542-549）、`wg set private-key`（555-560）、`wg set listen-port`（560-563）逐条覆盖第一个实例的内核对象，静默接管。
4. **设计缺位**：agent 侧没有多路复用层，一进程一网口一账本（`identity-network-id.md:181-189` 已明写）。

单实例锁（`instance_lock.rs:11-12`、56）按 `state_dir` 锚定，而它保护的资源是机器级全局的 —— 锁与被锁对象的作用域错配，所以它永远拦不到。

**二、用户空间 WireGuard 选型（crates.io 真值，2026-11-20 查证）**

- **主线：wireguard-nt 0.5.0**（MIT，144,731 dl，`nulldotblack` = WireGuardNT 维护者本人）。已核实安全 API：`Adapter::create`（`adapter.rs:124`）、`Adapter::open`（170）、`set_config`（188）、`SetInterface`/`SetPeer`（73/50）、`get_config()`（514）回读生效端口。**四点必须写清**：① 仍通过 `libloading` 运行时加载 `wireguard.dll`，crate 不自带（DLL 在 examples/ 下），仍需 WireGuardNT 驱动在场；② 仍要求管理员提权（`src/lib.rs:33` 注释）；③ 51820 排除端口段拒绑对任意进程生效，probe 回退不能省；④ **`listen_port: None` 不是「OS 选口」而是 51820**——字段文档明写（`adapter.rs:76-77`），代码路径也证实（`None` 不置 `HAS_LISTEN_PORT` 标志，字段保持零值 = WG 默认 51820；`adapter.rs:241-244`）。crate 自带示例注释「Let the OS pick a port」与其自身字段文档矛盾，以字段文档+代码为准。**端口必须由 agent 逐网络分配，不能用 `None` 偷懒**。它消灭的是 `WireGuardTunnel$` 服务单例（§1.2 的根），不是端口问题。
- **netstack 方向列为二期**：crates.io 的 `netstack` 是 2020 年废弃的游戏 netcode（Vengarioth），**不是 Tailscale 的那个**；Tailscale netstack 是 Go 包，`ts_netstack`/`tailscale_netstack` 只是占位（`description: "placeholder"`，max_stable null）。真名是 `netstack-smoltcp` 0.2.5（253,085 dl）+ `boringtun`/`gotatun`。这是唯一能让 fliploop 问题**结构性消失**的路线（栈在用户态，内核漫游不再不可控），代价是 XL 级工程量。
- **wintun-rs + wirefeather 排除**：82 dl / 152 dl，分别 3 个版本 3 天内、4 个版本 3 个月；wirefeather 是 ESP32 no_std 嵌入式协议核、自述「not audited」。生产环境零跟踪记录。

**三、多网络模型：方案 A 拍板**

A（一 agent 多网，配置数组化，每网络独立 iface `wg-mlt-<net>` + 每网络独立 listen_port + 每网络独立状态子目录，单实例锁仍按 state_dir 根锚定一个）。命名约束：Linux iface ≤15 字符（`linux/operations.rs:525`），`wg-mlt-` 占 7 字符，留给网络句柄 8 字符 —— 取 `nwid` 前缀而非全 ID。这个命名有先例：ZeroTier 每个网络的 TAP 名就是 `zt` + 网络 ID 的 base32（`LinuxEthernetTap.cpp`）。端口注意：不是「OS 随机」，而是 **agent 逐网络分配**（现有 probe-bind 回退从按 agent 改为按网络），再用 `get_config()` 回读生效端口上报 —— 因为 `None` 会落到 51820。B（一实例一网络靠自动分配避撞）作对比备栏，被否：同样修掉 reported bug，但保留 N 个 agent 进程/升级/重启，且无法表达跨网路由。

**参照系（已核实，且题面有一处误记）**：Tailscale 没有 `userspace-tunnel` build tag（main/v1.38/v1.24/v1.20/v1.0.0 全量 grep 零命中）；真机制是运行时 `--tun=userspace-networking`（`tailscaled.go:126`）+ 编译期 `ts_omit_netstack`。其用户态栈是 **gVisor netstack**（Go，无 Rust 对应物）。三层特权：默认=内核 TUN+root；`--tun=userspace-networking`=gVisor netstack+wireguard-go+假 TUN，无需 root；`tsnet`=进程内库形态，「No root privileges required」。**关键洞察**：Tailscale 连默认模式下的 WireGuard 协议都是用户态（wireguard-go + 用户态 ChaCha20Poly1305），内核只出 TUN 接口 —— meshlet 现状正好相反（协议在内核里），这正是 §1 冲突「内核持有、用户态解不开」的原因。ZeroTier Linux 侧是用户态 daemon 非内核模块，单进程每网络一个 TAP（`IFF_TAP|IFF_NO_PI`），且构造函数用全局互斥锁「Create only one tap at a time globally」—— 单属主串行化设备创建，正是多进程方案（B）没有的能力。性能方面官方只给定性结论「内核更快」，无量化数字，故用户态路线只能宣称「可用」不能宣称「同级」。

**四、spike（scratch 分支，未执行）**

Step 0 Linux 双 iface PoC（无新 crate、无提权）→ Step 1 复现 Windows 冲突 → Step 2 复现端口拒绑 → Step 3 wireguard-nt 双 adapter PoC，验收断言四：`sc query` → 1060（服务单例消失）、`netstat` 两端口（51820 冲突消失）、A 的 peer 表在 B 配置后不变（§1.2 不可复现）、两 overlay 独立通包。Step 3 失败则回退方案 B，不做深挖。

## 附：证据索引

| 主张 | 证据 |
|---|---|
| conf 路径机器级全局 | `crates/meshlet-network/src/windows_tunnel.rs:125,130` |
| 服务名按 tunnel 名 | `crates/meshlet-network/src/windows_tunnel.rs:192` |
| 后装拆前装 | `crates/meshlet-network/src/windows/wireguard.rs:18-19,22-35`；`windows_tunnel.rs:176` |
| 端口默认 51820 | `crates/meshlet-config/src/agent.rs:253` |
| 端口探测仅 Windows | `apps/agent/src/agent/direct_port.rs:59-60` |
| 51820 排除端口段根因 | `apps/agent/src/agent/direct_port.rs:3-9,28` |
| Linux 复用已存在 iface | `crates/meshlet-network/src/linux/operations.rs:537-541` |
| Linux 覆盖地址/私钥/端口 | `crates/meshlet-network/src/linux/operations.rs:542-563` |
| iface 名 ≤15 校验 | `crates/meshlet-network/src/linux/operations.rs:525` |
| 后端按自身 iface 名断言 | `crates/meshlet-network/src/linux/operations.rs:532` |
| iface 默认 wg0 / meshlet | `crates/meshlet-config/src/agent.rs:369`；`windows/backend.rs:28`；`linux/backend.rs:28` |
| 后端接线 | `apps/agent/src/agent/mod.rs:137` |
| 单实例锁按 state_dir | `apps/agent/src/instance_lock.rs:11-12,47,56` |
| 账本单文件 | `apps/agent/src/reconcile.rs:54-55` |
| 多网缺位设计缺口 | `docs/design/meshlet-identity-network-id.md:181-189` |
| ADR-014 共存契约 | `docs/decisions/adr-014-coexistence-personal-positioning.md:24` |
| fliploop 基线 | `docs/acceptance-evidence/fliploop-fix-acceptance.md:7-10` |
| wireguard-nt 安全 API | `src/adapter.rs:124,170,188,514`；`src/lib.rs:125,154,170,187` |
| wireguard-nt 需提权 | `src/lib.rs:33` |
| wireguard-nt 不自带 DLL | `src/lib.rs:153-170`（libloading）；仓库 examples/ 下的 DLL |
| `listen_port: None` = 51820，非 OS 选口 | `src/adapter.rs:76-77`（字段文档）、`241-244`（代码路径） |
| Tailscale 用户态开关 | `cmd/tailscaled/tailscaled.go:126`（`userspace-networking`）、`cmd/tailscaled/netstack.go`（`ts_omit_netstack`） |
| 用户态栈 = gVisor netstack | `wgengine/netstack/netstack.go`；`wgengine/userspace.go`「Starting userspace WireGuard engine (with fake TUN device)」 |
| tsnet 免 root | `tsnet/README.md`「No root privileges required」 |
| ZeroTier 单进程每网 TAP + 名从 nwid 派生 | `osdep/LinuxEthernetTap.cpp`（`_base32_5_to_8`、`IFF_TAP \| IFF_NO_PI`、全局 tapCreateLock） |
| 版本真值 | `crates.io/api/v1/crates/<name>` 与 `/versions`，2026-11-20 |