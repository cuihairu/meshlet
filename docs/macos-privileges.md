# macOS Privileges — sudo Whitelist, Resolver Files, and the Helper Follow-up

Date: 2026-11-22. Status: wiring of the privilege model for the macOS boringtun
data plane (task batch ③-A/③-B of the `WG-MAC-BT` item). What is wired here is
the **pure plan layer plus the executor hook**; the macOS executor itself is
`#[cfg(target_os = "macos")]`, cross-checked for `x86_64-apple-darwin` but not
executed in host CI. Real-machine acceptance (Intel mac, task ⑤) is still
BLOCKED pending SSH access to that machine.

## 1. Why the data plane needs root

macOS's `utun` interface is a kernel-managed dumb device. The meshlet agent
runs as an ordinary user, but addressing and routing that dumb device needs
root:

| operation | command |
|---|---|
| interface address / MTU | `/sbin/ifconfig` |
| point-to-point routes for peer allowed-ips | `/sbin/route` |
| resolver inspection (`--dns`, read only) | `/usr/sbin/scutil` |

Key and peer configuration does **not** need root: the WireGuard UAPI socket
(`/var/run/wireguard/*.sock`) is opened by the `wg` tool as the agent user,
and `boringtun-cli` runs under that same user. That is why `wg` and
`boringtun-cli` are deliberately **absent** from the whitelist below.

## 2. The sudo whitelist

The agent elevates with `sudo -n` (non-interactive) and **only** for a closed
set of programs. The set is data:

`SUDO_WHITELIST = ["ifconfig", "route", "scutil"]`

(`crates/meshlet-network/src/macos_privileges.rs`)

Behaviour:

- `argv[0]` is matched by **basename**, so both `ifconfig` and
  `/sbin/ifconfig` are accepted; every other program is rejected before it
  is spawned.
- A rejected command is refused as an apply error naming
  `docs/macos-privileges.md`. The executor never silently falls back to
  running the command *without* elevation — that would just fail again on
  permissions and mislead the operator.
- If `sudo -n` itself reports that a password is required (or that the user
  "may not run sudo"), the error is `InsufficientPrivileges` and points at
  this document, so the missing sudoers entry is the first thing an operator
  sees.

## 3. Suggested sudoers entry

Drop in `/etc/sudoers.d/meshlet` (validate with `sudo visudo -cf` first):

```
cui ALL=(root) NOPASSWD: /sbin/ifconfig, /sbin/route, /usr/sbin/scutil
```

Notes:

- No shell, no wildcards, no argument globbing. The three programs are the
  data-plane surface and nothing else.
- The agent's own user name goes in the `cui` position; keep the list to one
  line per agent user.
- The entry grants elevation for the *whole* program. macOS `ifconfig`
  accepts interface arguments, so this is broader than "only `utun5`" — it
  is the same scope the `wg-quick` and `wireguard-go` installers assume.

## 4. Resolver file elevation

Per-domain resolvers are written as files, which is the standard macOS
mechanism and needs no `scutil` state change: the plan layer emits
`/etc/resolver/<domain>` with `nameserver` lines and mode `0644`.
Validation is path-safe — the domain is rejected if it would escape
`/etc/resolver/` (`..`, absolute paths, separators, empty names).

Writing under `/etc/resolver/` needs root. Today the executor writes the file
directly when the process is privileged and otherwise returns
`InsufficientPrivileges` — a visible, non-fabricated failure. Elevating that
write is the `launchd` helper follow-up in §5; it is not wired.

## 5. `launchd` privileged helper — later enhancement, not implemented

Recorded as a follow-up rather than a decision against it:

- A privileged XPC helper installed with `SMAppService` (macOS 13+) would let
  the agent run with no `sudo` at all: one helper owns `utun`, resolver
  files, and route changes.
- Cost: a signed helper bundle, a launchd provisioning step, and a helper
  protocol — meaningful surface that cannot be exercised without the Intel
  mac. The sudo route covers the same capability with one sudoers line.
- Trigger to revisit: a fleet with more than one macOS node, or a node where
  granting the three root programs is unacceptable.

## 6. Pending

Real-machine acceptance (task ⑤) still owes:

- installing the sudoers drop-in and observing a real apply cycle,
- the source of the kernel-assigned `utun` name when the configured interface
  is the bare `utun` placeholder,
- end-to-end resolver writes through the privileged path.
