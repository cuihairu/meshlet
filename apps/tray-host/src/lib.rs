//! Library target of `meshlet-tray-host`: exposes the **cross-platform** part (the local panel) on its own.
//!
//! The binary (Win32 tray host) and `examples/local_panel` (the local curl smoke-test entry point)
//! share this single code base, so panel logic is written once and both sides stay in sync.

pub mod panel;
