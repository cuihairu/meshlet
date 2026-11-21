# wireguard-nt runtime DLL (amd64, 1.1)

Vendored **prebuilt** `wireguard.dll` for the wireguard-nt 0.5.0 binding used
by the WG-NT-SWITCH data-plane path (see `docs/design/userspace-wireguard-analysis.md`
and `docs/decisions/2026-11-21-adr-008-wireguard-nt-poc-verdict.md`).

## Provenance

- Source: official release `https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip`
  (zip SHA256 `dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace`).
- `wireguard.dll` = `bin/amd64/wireguard.dll` from that zip;
  SHA256 **`b1b85e072c45d81358be29d94c599dc76652f912be8c0f0a41e2d5d89a6461d3`**
  (recorded in `SHA256SUMS`).
- Driver version 65537 (wireguard-nt 1.1), verified on real hardware
  (imac, privileged PoC, 8/8 PASS — `docs/acceptance-evidence/wgnt-step12-2026-11-21.md`).
- License: `wireguard-nt-LICENSE.txt` (WireGuard LLC Prebuilt Binaries License;
  must ship alongside the dll).

## Why vendored, not CI-downloaded

Official WireGuard for Windows **does not install this dll** — its tunnel
service statically links it into `wireguard.exe`. The dll therefore **must
ship with meshlet** in all three delivery forms (MSI, nightly zip, and the
`install.ps1` deploy path) or the nt backend cannot load.

Vendoring keeps the nightly build deterministic and offline-safe: the repo's
history shows the GitHub release/CDN fetch path is flaky, and a dll download
at build time would turn a working build into a network-dependent one.

## Refresh procedure

1. Download a newer `wireguard-nt-<ver>.zip` from `download.wireguard.com/wireguard-nt/`.
2. Replace `wireguard.dll` (amd64) and `wireguard-nt-LICENSE.txt`.
3. Update `SHA256SUMS` and this file; re-verify the driver version on a
   real machine (privileged PoC) before shipping.
