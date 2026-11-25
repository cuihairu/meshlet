//! Real-machine integration tests for the Linux `NetworkBackend` implementation
//! ([ADR-007](../../docs/decisions/adr-007-linux-network-backend.md)).
//!
//! How it differs from `wg_forwarding.rs` / `alias_nat.rs`: **every kernel operation goes through
//! `LinuxNetworkBackend`** (netns + sudo test hooks) instead of configuring the dataplane with raw
//! `wg` / `ip` commands -- the same code sits between the control-plane apply path and the kernel.
//! Raw commands are used only to build the underlay (bridge/veth/netns itself, which is not the
//! backend's job) and for "external viewpoint" probes.
//!
//! The scenario modules share the same `mltb` prefix; an in-process serialization lock keeps that
//! underlay from being rewritten concurrently. The pre-existing acceptance semantics, SKIP
//! discipline and external-object protection are unchanged.

#![cfg(target_os = "linux")]

#[path = "backend_wiring/alias.rs"]
mod alias;
#[path = "backend_wiring/common.rs"]
mod common;
#[path = "backend_wiring/connectivity.rs"]
mod connectivity;
#[path = "backend_wiring/host_isolation.rs"]
mod host_isolation;
#[path = "backend_wiring/recovery.rs"]
mod recovery;
