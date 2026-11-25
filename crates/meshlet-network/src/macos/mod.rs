//! macOS boringtun backend module (see [crate::macos_wireguard_bt] for the
//! plan layer).
//!
//! The command plan in [backend] ([backend::BtCommand] /
//! [backend::bt_apply_commands] / [backend::bt_apply]) is a **pure function on
//! every platform** — running its unit tests on a Linux host means asserting
//! the command sequence without actually executing it; the `exec` submodule is
//! the `#[cfg(target_os = "macos")]` executor (the host CI does not run macOS
//! tests; compilation is only verified via an `x86_64-apple-darwin` cross
//! check). [system] is macOS's dual-mode dispatch for `SystemBackend` (③-C
//! wiring), compiled under `cfg(target_os = "macos")`.

pub mod backend;
#[cfg(target_os = "macos")]
pub mod system;
