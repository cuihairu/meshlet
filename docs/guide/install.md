# Linux VPS Installation Guide

This guide describes the server and agent deployment shape. Automated checks and development-host runs do not replace a clean-VPS acceptance test; confirm the current TODO and walkthrough before treating deployment as production-ready.

## Requirements

Use a supported Linux x86_64 host with systemd and a Rust stable build environment. Install Node.js and pnpm only if building the console. Expose HTTPS through a reverse proxy and allow the configured WireGuard UDP port when the data plane is enabled.

## Build

```sh
git clone https://github.com/cuihairu/meshlet.git
cd meshlet
cargo build --release --bin meshlet-server --bin meshlet-agent
cd console
corepack enable
pnpm install
pnpm run build
```

The server listens on loopback by default. Put it behind an HTTPS reverse proxy; set the secure-cookie option when serving over HTTPS. Keep the SQLite database and configuration in the service's state directory and restrict them to the dedicated system account.

## Service setup

Install the server binary, console assets, configuration, and systemd unit. Verify the unit with `systemd-analyze verify`, then inspect the effective user, writable state paths, listening address, and hardening settings before enabling it. Bootstrap the first administrator once, log in, create a network, and issue a device join credential.

## Backups and network access

Backups are disabled until an explicit directory is configured. Store them with restrictive permissions on independent storage and test restoration. The hub needs its WireGuard UDP port reachable; the management UI should be reachable only through HTTPS.

## Acceptance boundary

A complete deployment check includes a real agent joining, establishing WireGuard, applying routes, exchanging traffic, restarting both sides, and restoring a backup. The repository's test evidence should be read alongside the real-host status; do not infer a clean-VPS pass from compilation alone.
