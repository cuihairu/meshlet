//! Windows platform data plane backend
//! ([ADR-008](../../../docs/decisions/adr-008-windows-network-backend.md)).
//!
//! Dual-model dispatch (`[dataplane] tunnel_backend`, see
//! [crate::windows_wireguard_nt]):
//!
//! - **service** (default): the tunnel service model based on WireGuardNT
//!   (official WireGuard for Windows) — `wireguard.exe /installtunnelservice`
//!   creates the managed service `WireGuardTunnel$<name>`, and routes are
//!   managed via `netsh interface ipv4 add route`;
//! - **nt**: wireguard-nt 0.5.0 embedded adapter bindings (one process holds the
//!   handle persistently), with no wireguard.exe dependency — routes are wired up
//!   by the adapter's `set_default_route`.
//!
//! This module wires the plan-layer functions of [windows_tunnel] /
//! [windows_service] / [windows_routes] into a [crate::NetworkBackend]
//! implementation, letting the Windows agent:
//! - inspect: check WireGuard installation state, tunnel existence, peers,
//!   routes, MTU
//! - apply_tunnel: render the conf and call
//!   `wireguard.exe /installtunnelservice`
//! - apply_routes: add/remove routes through netsh
//!
//! Same discipline as the Linux backend: every operation touching the kernel
//! returns an explicit result and never fails silently; unsupported operations
//! return [`NetworkError::Unsupported`].

mod backend;
pub use backend::WindowsNetworkBackend;
mod diagnostics;
mod nat;
mod netsh;
mod parsing;
mod process_cmds;
mod route;
mod wireguard;

#[cfg(test)]
mod tests;
