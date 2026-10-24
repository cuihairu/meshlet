# R-07: Deployment and Long-Run Acceptance

Acceptance run of 2026-10-24 on a local Proxmox VE 9.2.4 host (`pve-manager/9.2.4`, kernel 7.0.14-4-pve, 1.82 TiB LVM thin pool): hub container at 192.168.5.150 with `wg0` 10.240.0.1/16 listening on :51820, and three device containers at 192.168.5.151/.152/.153 with 10.240.0.2/3/4. Lab clock is UTC, so timestamps read `2026-10-23T22:xxZ`. Binaries under test were built locally for this run (agent `sha256/16 2114bd9e16de2045`, server `92318893987ae2e0`); the blank-container install in **Blank container install** used the *published* nightly asset instead. The console password and all tokens are generated per run and are never printed.

## Blank container install

The third container was created from the stock `debian-12-standard_12.12-1` template with no preparation: 2 cores, 1 GiB RAM, unprivileged, `nesting=1`, a 10 GiB thin rootfs, one veth to the management bridge. `install.sh` was fetched and piped straight from the published release.

Two things the documentation got wrong, both found by this install:

- The README one-liner is `curl -fsSL … | sudo bash -s -- agent`. A stock Debian 12 container has **neither `curl` nor `sudo`**: the run ends with `curl: command not found`, `sudo: command not found`, exit 127, and leaves nothing on disk. The container does have `wget`, so `wget -qO- … | bash -s -- agent …` works. The README now states the prerequisite (`apt-get update && apt-get install -y curl sudo`) and the wget form.
- install.sh's apt line pulled a **107 MB kernel image** into the container (`linux-image-6.12.113+deb12-rt-amd64` plus `initramfs-tools`, `linux-base`, `klibc-utils`, 17 new packages, "Need to get 111 MB of archives") through the Recommends chain of `wireguard-tools`. A container shares its host's kernel, so the image is dead weight and the setup took over two extra minutes to download at 755 kB/s. `scripts/install.sh` now passes `--no-install-recommends`; the `for tool in …` check still fails loudly if a recommended package was actually required.

The wget run then completed end to end: dependencies installed (wireguard-tools 1.0.20210914-1+b1, iptables 1.8.9-2, iproute2 6.1.0-3, iputils-ping, ca-certificates, curl), the archive downloaded and verified, and the service left in this state — `active`; unit hardening `User=meshlet-agent`, `Group=meshlet-agent`, `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW`, `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW`, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/meshlet-agent`, `ExecStartPre=+sysctl -w net.ipv4.ip_forward=1`; files `/etc/meshlet/agent.toml`, `/etc/meshlet/agent.key` and `/var/lib/meshlet-agent/device_token` all `0600 meshlet-agent:meshlet-agent`; `agent.toml` written with `device_name = "pve-dev-3"`, `hub_endpoint = "192.168.5.150:51820"`, `poll_interval_secs = 30`, and the bootstrap token left in place (recorded only in the CT config, redacted from the log).

Release-artifact integrity was checked directly on the fresh container: the downloaded `meshlet-linux-x86_64.tar.gz` hashes to `39852830b3d38e7e16a0ddcf706f0a0812329427b5fe0891056d85ce7f0c3fcd`, matching the published `SHA256SUMS` exactly (`sha256sum -c` → `OK`). The archive carries `install.sh`, `meshlet-agent`, `meshlet-cli`, `console/`, `systemd/` and `BUILD_INFO`.

The published nightly agent hashes to `4845343087249b66`, i.e. the pre-fix build — the acceptance binaries are newer, which is why the upgrade step below exists.

## Three real devices

Registration ran through the real bootstrap path: `POST /networks/{net-1}/bootstrap-tokens` with `max_uses=1` returned token `bt-2`, used exactly once. The device self-registered as `dev-reg-3` (name `pve-dev-3`, platform `linux`) and its agent logged `self-registered: waiting for approval in the control center`, then `registration pending approval: heartbeat sent, plan withheld`. Approval returned `virtual_ipv4 10.240.0.4`, `revision_id 4`, `apply_status pending`; the revision was then applied through `POST …/config-revisions/4/apply` (200, `applied` 22:52:40Z), after which the agent applied the plan with `reason=NoLocalLedger` on its first post-apply tick. The intervening 503 `dataplane_not_configured` shows in the log with `retry_in_secs=2`, the start of the exponential backoff.

The hub then holds three peers with `/32` allowed-ips and fresh handshakes, and the diagnostics report reads `3/3 device(s) with a handshake inside the 120s window`. All three devices report identical kernel evidence: `{"tunnel_mtu":1420,"nat_rules_present":false,"nat_snat_rules_present":false,"mtu_probe_payload":1392}`. Token accounting in the database: `bt-1` at 2 of 5 uses (shared), `bt-2` at 1 of 1 (exhausted), digests only — no raw token in the store.

## Backup and restore

`POST /api/v1/system/backup` produced a 385024-byte artifact reporting `networks=1 devices=2 routes=0 invites=0 revisions=3`. The artifact is a **plaintext SQLite database**, `0600 meshlet:meshlet`, inside a `750` directory. That is the deliberate stance, stated in [backup-restore](/architecture/backup-restore.md): the file is not encrypted, it is equivalent to the database itself, and it is `0600` until it leaves the machine; the hub WireGuard key lives at `/etc/meshlet/hub.key` (`0600`, 45 bytes) *outside* the database, so a database restore does not restore the transport key and an independent copy of the key file is required.

The documented sequence was executed and is now correct: stop the service, run `meshlet-server restore <backup> <config>`, start again. The restore reported `networks=1 devices=2 routes=0 invites=0 revisions=3` and `system.restore recorded`; the restored `meshlet.db` is `0600 meshlet:meshlet` — before this round's fix a root-run restore left the file `root:root` and the service crash-looped on `unable to open database file`. After the fix the service comes up `active` with `NRestarts=0` and `{"status":"ok"}`. Business state survived (devices, revisions, bootstrap tokens), the `system.restore` audit row carries the source path, the pre-restore session cookie still authenticates (`GET /auth/me` 200) because live sessions ride along in the database, and the hub reconciled its two peers from the restored records. No `restore-tmp` staging files were left behind.

A negative check: the same backup request without `x-requested-with` is rejected `403 {"error":{"code":"forbidden","message":"mutating console requests must set X-Requested-With"}}`.

**Restore while the server is running is not safe, and this round proved the mechanism.** A restore performed with the service up renamed a fresh file over `meshlet.db` while the server still held its old inode; the service stayed `active`, but every write after that — including a bootstrap token mint that returned HTTP 201 — went to the detached inode and never appeared in the on-disk database. A service restart adopted the restored file. The documented sequence stops the service first, and that order must be kept.

## Key rotation and key loss

The hub key is the only transport secret the server owns; device keys stay on the devices (ADR-010), and a device rotation is just the re-enroll path already exercised above.

Independent key backup: the hub key (`0600 meshlet:meshlet`, 45 bytes) was copied to `/root/meshlet-key-backup/hub.key.20261023T225729Z` in a `700` directory *before* rotation. A rotation is then `wg genkey` into the same path, permissions re-applied, service restarted: the hub public key went from `S7HIikdT8Xvkb78fDOi5HlP6f5RAC7m0QcCkw6R9XQs=` to `mUEmAMp/yLpIgquw1px7OVLcVkS1sWzbFr0D6+ie7Vg=`.

Zero-touch on the devices: **45 seconds after the restart all three containers were already peered at the new hub key with fresh handshakes (25–40 s ago)**. The server serves the hub public key in each device's desired plan, so each agent updated its peer on its next 30 s tick and logged `applied the desired device plan … reason=DesiredConfigChanged`. No device-side action was taken. Diagnostics then read `3/3 device(s) with a handshake inside the 120s window`, and pings to all three overlay addresses were lossless.

Key loss, and the documented stance: deleting `hub.key` and restarting did **not** stop the service — the server stayed `active` and kept answering the control plane, and logged `{"level":"ERROR","message":"hub recovery failed","network_id":"net-1","error":"read private_key_file /etc/meshlet/hub.key: No such file or directory (os error 2)"}`. The tunnel side is dead while the console still works, which is quiet enough to deserve watching for that error line. Restoring the key from the independent backup and restarting brought the tunnel back with no device-side action (three lossless pings). Note what that backup actually restores: it held the **pre-rotation** key `S7HIikdT8Xvkb78fDOi5HlP6f5RAC7m0QcCkw6R9XQs=`, so restoring it *undid* the rotation and the devices followed it back to the old key — a good rotation should be treated as a change to back up, not a fact.

One recorded gap: a lost hub key does not make the service unhealthy; a deployment that only watches `systemctl` will not notice.

## Upgrade and rollback

Rolling back to a *published older tag* is not possible on this seat right now: the release page holds a single rolling `nightly`, because the nightly build was broken by the toolchain mismatch fixed in this round, so no dated release was ever published. Upgrade and rollback were therefore measured as **re-run the same role = in-place upgrade** and **offline/staged install (`MESHLET_INSTALL_ARCHIVE` + `MESHLET_INSTALL_SHA256SUMS`) = rollback**, on CT 113 with real release assets. Before dispatching the fixed nightly, the currently published 2026-10-17 assets were saved to the PVE host (`sha256sum -c` against the published sums → `OK`) so the rollback target is the true previous archive.

**Upgrade (23:25Z).** `wget -qO- …/install.sh | bash -s -- agent` re-run on the installed device: installer exit 0, binary `4845343087249b66…bcd644` → `089893187da04786…85192552`, `agent-build-info` now `commit=cefd5ef5ac26e723d9526e71a50255f4995dde6b, built_at=2026-10-23T23:23:14Z, source_dirty=false`. State survived byte-for-byte — `sha256sum` of `/etc/meshlet/agent.toml`, `/etc/meshlet/agent.key` and `/var/lib/meshlet-agent/device_token` identical before and after (`8e631408…` / `17b2da52…` / `d8bc6393…`); the agent log shows `using the saved agent token`, no re-registration. First tick after the restart: the hub sees three peers with handshakes 11/12/32 s old, and the upgraded device passes DF 1472-byte pings to `10.240.0.2` (3/3, 0% loss, avg 0.684 ms).

**Rollback (23:26Z).** The saved 2026-10-17 archive, `SHA256SUMS` and `install.sh` were pushed into the container and installed via `MESHLET_INSTALL_ARCHIVE=… MESHLET_INSTALL_SHA256SUMS=… bash install.sh agent`: the installer prints `Verifying staged Meshlet nightly (x86_64)…`, exits 0, and the binary is back to `4845343087249b66…bcd644` with the same three state hashes unchanged. No re-enrollment: first tick pings `10.240.0.2` 3/3, 0% loss, avg 0.640 ms, hub handshakes fresh (95/96/116 s). A final re-run moves the device back onto the fixed build (`089893187da04786…`), where the hub keeps answering its heartbeats and applied receipts.

One cosmetic wart recorded, not fixed: the installer's closing hint tells an *upgrading* agent device to "approve this device in the console, then apply the current network revision" — misleading when the device is already approved; the device itself never needed any console action in either direction.

## Performance baseline

The in-process handler baseline (file-backed and in-memory SQLite, concurrency 1/16/64/256, footprint) is in [performance](/architecture/performance.md); it is an internal driver with no TCP/TLS, so it is not a capacity claim. Against the *running* service on the hub container, with real sockets:

| Path | Shape | Result |
|---|---|---|
| `GET /system/status` (public, no DB) | 200 serial | 126 req/s |
| `GET /system/status` | 8 workers × 100 | 261 req/s |
| `GET /networks` (session + 1 DB read) | 100 serial | 130 req/s |
| `POST /system/backup` (session + `VACUUM INTO`) | 20 serial | 63 req/s |

Each iteration forks a fresh `curl` process, so these are floors set by client process startup, not the server's ceiling; the backup path is dominated by the real `VACUUM INTO` on every call (23 artifacts accumulated). The server on this box is idle next to the load it can carry.

## Defects found and fixed in this round

- Agent MTU reconciliation treated an unset plan MTU as "leave the interface alone", so an interface left at a higher MTU never converged. Enforced like an explicit value and read back against the same default; evidence in [R-04](/implementation/r04-linux-agent-e2e.md).
- Root-run restore left the database owned by root, crash-looping the non-privileged service; the restore now restores the prior owner (replaced file, else the data directory) and clears stale `-wal`/`-shm` sidecars.
- install.sh's apt line pulled a 100+ MB kernel image into containers; now `--no-install-recommends`.
- README one-liner assumed `curl` and `sudo`, neither present on a stock minimal Debian container; prerequisite now documented.
- The nightly workflow's build step pinned the toolchain to `stable` while `rust-toolchain.toml` pins 1.99.0, failing every build with E0463 after the pin was introduced; the workflow now requests the pinned version. That is why the release page still shows a 2026-10-17 nightly and no dated releases exist.

## Not accepted

- Windows client: no Windows machine on this seat, so R-05 stays open. The `x86_64-pc-windows-msvc` check/clippy gate is green, nothing more.
- Long-run soak: the run is hours, not weeks. No sustained traffic over a multi-day window.
- LAN routes, alias mappings, NAT and gateway agents are exercised as absent (`not_applicable`/`unavailable` in diagnostics), not positively tested on a gateway.
- The hub MTU follows the applied revision while device MTU follows live config, so an MTU change leaves the hub capped at 1420 until a new revision is booked; recorded in [R-04](/implementation/r04-linux-agent-e2e.md).
