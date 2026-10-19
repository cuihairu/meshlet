# Agent Local API and Authorization · 2026-10-19

## Finding

The agent is currently a background pull client, not a local API server. It reads configuration, resolves its device credential, fetches a typed desired plan from the Meshlet server, applies/reconciles it locally and reports an apply receipt/heartbeat. It does not execute server-supplied shell commands. No local TCP listener or Unix socket is present in the agent entry point. This proposal concerns a new local control surface for scripts, CLI and a future desktop console on the same machine.

## Current behavior and security evidence

| Evidence | Repository location |
|---|---|
| Agent executable loads a config path, resolves device token, reads local private key, then enters `Agent::run`; dataplane-disabled mode exits without touching the kernel | [`apps/agent/src/main.rs:20`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/main.rs#L20), [`:37`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/main.rs#L37), [`:42`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/main.rs#L42), [`:51`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/main.rs#L51), [`:59`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/main.rs#L59) |
| `Agent::run` is a loop over `tick`, and `tick` is the worker lifecycle | [`apps/agent/src/agent.rs:85`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/agent.rs#L85) |
| Agent fetches `/api/v1/agent/device/desired` with device Bearer token; sends `/applied` and `/heartbeat` with that credential | [`apps/agent/src/server.rs:17`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/server.rs#L17), [`:71`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/server.rs#L71), [`:91`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/server.rs#L91) |
| Agent API contract is desired-plan pull plus heartbeat/evidence; server does not issue commands | [`apps/agent/src/server.rs:1`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/server.rs#L1), [`apps/agent/src/main.rs:7`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/main.rs#L7) |
| Agent reconcile inspects kernel, applies typed plan, checks readback and saves a private-key-free last-good plan; failure restores last-good | [`apps/agent/src/agent.rs:184`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/agent.rs#L184), [`:253`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/agent.rs#L253), [`:276`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/agent.rs#L276), [`:289`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/agent.rs#L289) |
| Server currently binds one configured TCP address; no agent-local listener is wired into this startup | [`apps/server/src/main.rs:46`](https://github.com/cuihairu/meshlet/blob/main/apps/server/src/main.rs#L46) |
| Server routes expose agent desired/applied/heartbeat endpoints as server-side routes | [`apps/server/src/lib.rs:981`](https://github.com/cuihairu/meshlet/blob/main/apps/server/src/lib.rs#L981) |
| Management auth accepts a session or management API token; invalid session does not fall back to Bearer; agent tokens are a separate credential boundary | [`apps/server/src/auth.rs:411`](https://github.com/cuihairu/meshlet/blob/main/apps/server/src/auth.rs#L411) |
| Management writes require `WriteUser`; session-authenticated writes also require CSRF header | [`apps/server/src/auth.rs:464`](https://github.com/cuihairu/meshlet/blob/main/apps/server/src/auth.rs#L464), [`:483`](https://github.com/cuihairu/meshlet/blob/main/apps/server/src/auth.rs#L483) |
| API tokens are read/write scoped, stored by digest, revocable, and have last-used tracking | [`apps/server/src/api_token.rs:38`](https://github.com/cuihairu/meshlet/blob/main/apps/server/src/api_token.rs#L38), [`:76`](https://github.com/cuihairu/meshlet/blob/main/apps/server/src/api_token.rs#L76), [`:100`](https://github.com/cuihairu/meshlet/blob/main/apps/server/src/api_token.rs#L100) |
| Registration requests remain pending until operator approval; only approved devices enter the active registry and receive a plan | [`apps/server/src/agent.rs:303`](https://github.com/cuihairu/meshlet/blob/main/apps/server/src/agent.rs#L303), [ADR-011](../decisions/adr-011-device-self-registration.md) |
| Sensitive management actions go to audit; raw credential material cannot enter the audit record API | [`apps/server/src/audit.rs:1`](https://github.com/cuihairu/meshlet/blob/main/apps/server/src/audit.rs#L1), [`:45`](https://github.com/cuihairu/meshlet/blob/main/apps/server/src/audit.rs#L45) |

Server auth/audit are materially present: one-time administrator bootstrap, sessions, CSRF, separate scoped management API tokens, separate device-bound agent credentials, approval gate and audited writes. Audit writes are fail-closed for sensitive operations. Gaps relevant to a local API: there is no local caller identity, local permission policy, local operation audit actor, listener lifecycle, or documented status/apply/log IPC contract. Current API token scopes are only broad `read` and `write`; the browser session is a user identity and should not become an agent-local secret.

## Local API scope

**Callers:** (1) same-user scripts and automation, (2) a Meshlet CLI on the host, and later (3) a desktop/tray console. A root/system service may need a separate explicit caller policy when network configuration requires privilege. Remote callers are out of scope; this API must not become another network administration listener.

**First capability set, inferred from existing behavior:**

| Capability | Initial semantics | Authorization class |
|---|---|---|
| Read status | Agent running/version, last successful reconcile, desired revision/hash, last error and connectivity evidence; no secrets | Read |
| Trigger reconcile/apply | Ask the existing worker to fetch the latest server plan and reconcile now; never accept arbitrary shell, raw kernel commands, private keys or caller-authored `DevicePlan` | Write / control |
| Read recent logs/diagnostics | Bounded, structured agent events and current diagnostic snapshot; redact credentials and private key material | Read |
| Shutdown/restart (later) | Coordinate with service manager, not an agent self-escalation path | Admin / platform-specific |

Apply is a request to reconcile the server's current approved desired state, not a local override. Device approval and the server revision/apply receipt remain authoritative. A local caller cannot create server-side approval by invoking the local API.

## Authorization options

Research date for all external references: **2026-10-19**.

| Option | Security model | Complexity | Windows fit | Integration with current auth/audit | Main risks |
|---|---|---|---|---|---|
| **Unix domain socket + owner/group/mode + `SO_PEERCRED`** | Kernel supplies connected peer PID/UID/GID; socket directory and socket mode constrain who can connect. Authorize the effective UID (and optionally an explicit group); check peer credentials on each accepted connection. Linux documents `SO_PEERCRED` for connected AF_UNIX streams. [Linux `unix(7)`](https://www.man7.org/linux/man-pages/man7/unix.7.html) (2026-10-19) | Low–medium on Linux; requires a small framed protocol, socket lifecycle/cleanup and UID policy | Not a Windows transport; implement Windows named pipe separately | Map the local principal to an internal actor such as `local:uid:1000`; reuse the same operation policy and audit action names, without minting a server session or exposing the device token | Any process running as the authorized user can call it; permissive parent-directory/socket modes, stale socket path, confused deputy if privileged agent accepts arbitrary operations |
| **Loopback HTTP + random bearer token** | Bind explicitly to `127.0.0.1` (and separately decide IPv6 loopback); possession of high-entropy token authorizes requests. Store only a digest if validating server-side; create a random local secret in a mode-0600/ACL-restricted file, never argv/env/logs. Rotate by atomic replacement/revoke old immediately; optional short-lived token minted by local CLI. Bearer tokens require protecting storage and transport; loopback alone is not authentication. [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) (2026-10-19) | Low–medium; can reuse HTTP/JSON patterns, but token provisioning, rotation, CSRF/origin policy and local listener lifecycle add work | High; same HTTP client/server shape, but bind and firewall assumptions need Windows validation | Could use a dedicated local token table and audit actor; do not reuse management `mlt_` tokens or device token. Existing server read/write scope shape is a precedent, though likely needs status/control/logs scopes | Other local processes can steal token from file/process/debug surface; DNS rebinding/origin mistakes if hostname accepted; browser CSRF; local malware; token copied onto host backup |
| **Mutual TLS / local client certificates** | Local service trusts an explicit CA or pinned client cert; client proves private-key possession in TLS. Certificate can encode identity and be revoked/rotated; TLS 1.3 defines client Certificate/CertificateVerify authentication. [RFC 8446](https://www.rfc-editor.org/info/rfc8446/) (2026-10-19) | High for a single-host agent: CA/provisioning, cert issuance, storage, renewal, revocation, trust migration | Possible on Windows; system certificate stores help, but cross-platform provisioning is substantial | Map certificate fingerprint/SAN to local principal, then use shared local authorization and audit. It does not provide current web-session semantics by itself | More key lifecycle than this local boundary warrants; certificate copy and root compromise; local TLS listener is still reachable by other processes and must authorize identity |
| **OS authorization/service credentials (`polkit`, systemd credentials, Windows pipe ACL)** | Delegate authorization to OS policy and protected IPC/credential stores. polkit evaluates subject/action for privileged operations; systemd `LoadCredential=` exposes a read-only per-unit credential only to its service UID; Windows named-pipe DACL controls client access. [polkit reference](https://polkit.pages.freedesktop.org/polkit/), [systemd `systemd.exec`](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec), [Microsoft named-pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights) (2026-10-19) | Medium–high; Linux policy/D-Bus integration and systemd packaging; Windows security descriptor and impersonation checks | Strong Windows option via named-pipe ACL; Linux polkit/systemd is Linux-specific, so adapters needed | Best fit for “who may control this host”; translate OS identity/action result to common local principal, then use Meshlet audit. systemd credentials suit agent secret delivery, not interactive per-request authorization | Policy/package drift; unexpected default ACLs; polkit agents absent in headless hosts; broad administrator grants; OS policy is less portable and can be difficult to explain/debug |

## Recommendation

**Recommend a local IPC boundary with OS peer identity: Unix domain socket and `SO_PEERCRED` on Linux first, with a Windows named-pipe adapter using an explicit restrictive DACL when Windows agent control is implemented.** Keep the protocol and authorization layer transport-neutral. This is one recommendation: native local IPC authenticated by the host, with a platform-specific equivalent. Do not make loopback bearer tokens the primary identity mechanism.

Reasons: no secret has to be copied into scripts or desktop preferences; the kernel identifies the caller; Linux aligns with the current server/agent deployment; a Windows named pipe has a documented access-control model rather than forcing a local HTTP token exception. The existing server credentials remain independent: local OS identity authorizes local operations, while the device credential continues to authenticate the agent to the server. Audit records should add an explicit local actor and operation outcome; local identity does not silently become a Meshlet administrator account.

### Phased path

1. **Specify the contract and threat boundary:** read status, request reconcile, bounded logs; forbid arbitrary commands, caller-supplied plans, private-key reads and management/server writes. Define request size/time limits and audit fields.
2. **Linux MVP:** one AF_UNIX socket under the agent runtime directory; restrictive parent and socket ownership/mode; verify peer credentials after accept; default to the service owner UID, with optional configured group only if justified. Return structured status and enqueue reconcile into the existing worker rather than running a second apply concurrently.
3. **CLI integration:** CLI connects to the local socket; it does not read the agent's device token or private key. Add local audit events with peer UID, operation, result, desired revision/hash, timestamp; never record credential material.
4. **Windows adapter:** named pipe with explicit DACL for the intended user/admin group, remote-client rejection and peer identity validation; preserve the same protocol/authorization semantics. This is separate from PN-03's full dataplane completion.
5. **Desktop/UI and policy refinement:** add only after CLI behavior is stable; consider polkit confirmation for privileged actions if the UX needs per-action elevation. Add narrower scopes only when real consumers demonstrate the need.

### MOD-05 relationship and ADR

This is an agent-local control protocol, not the management SDK/Public API described by MOD-05. It can become a separate local client interface consumed by CLI/desktop. MOD-05 still covers server management API DTOs, stable consumer documentation and an independently consumable SDK; do not publish or promise compatibility for this local protocol as a side effect. A shared authorization vocabulary may be extracted under MOD-02 only after the local API contract exists.

Suggested decision record: **ADR-013 — Agent Local Control API and OS-Principal Authorization**. It should decide socket/pipe transport contract, caller identity mapping, default user/group policy, permitted operations, audit schema, privileged-operation boundary and protocol compatibility/versioning. If Windows implementation is deferred, record Linux-first scope explicitly and require the Windows adapter to preserve policy.

## Explicit scope limit

This is research and a recommendation only. No implementation code is written here, no schedule is promised, and no existing authentication contract is changed.

