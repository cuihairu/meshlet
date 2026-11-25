//! Runtime system-tray status display (user 2026-10-16: "the runtime needs to show the matching icon", "the
//! system-tray icon should ideally reflect state changes").
//!
//! ## Discipline one: no new state names
//!
//! The four states of [`TrayState`] each correspond **one-to-one to an existing in-repo enum**; the mapping
//! rationale is written on each variant:
//!
//! | User words | Tray state | Existing in-repo enum |
//! |---|---|---|
//! | online, direct | [`TrayState::Online`] | [`meshlet_domain::presence::PresenceState::Online`] + [`crate::reconcile::Reason::UpToDate`] |
//! | relaying | ditto | v1 is a VPS central relay (ADR-002) and the repo has **no binary "direct / relay" signal**, with P2P direct connect explicitly deferred to v2 - so "online, direct" and "relaying" are **the same real state** in v1, and this module expresses them with one state rather than fabricating a second |
//! | disconnected | [`TrayState::Offline`] | `PresenceState::Offline` (no fresh evidence for either the control channel or the tunnel) |
//! | tunnel fault | [`TrayState::TunnelDrift`] | [`crate::reconcile::Reason::KernelDrift`] + [`meshlet_domain::entities::ApplyStatus::Failed`] |
//!
//! There is one state in between: [`TrayState::TunnelOnly`] <- `PresenceState::TunnelOnly` (fresh handshake but a
//! stale agent report) - one of the three states that **really exist** in the repo, with the agent-side counterpart
//! "a handshake is readable locally but heartbeat reporting fails", see [`TrayState::derive`].
//!
//! ## Disciplines two/three: not static, text equivalents, never color alone
//!
//! A state change swaps the icons ([`TraySink::publish_with`] only writes when the content differs); every state has
//! a `tooltip` (a full-sentence explanation) and an `accessible_name` (an accessibility short name). The four
//! states' **silhouettes are pairwise distinct** (the November 2026 tray redesign, the four-state plan the user
//! approved, design source [apps/tray-app/src-tauri/icons](../../tray-app/src-tauri/icons/), commit `e9d67d4`):
//! hex-nut / right-chamfered nut / hollow hex ring / hollowed-out exclamation hex - color is only the second channel,
//! and [`tray_state_silhouettes_are_pairwise_distinct`] pins this down with pixel probes.
//!
//! ## Discipline four: headless / CI must be a no-op
//!
//! [`EnvProbe::from_env`] reads the desktop-session environment, and when [`EnvProbe::has_desktop_session`] is
//! false (CI, headless VPS) [`TraySink::publish_with`] returns [`TrayWrite::Skipped`] outright - writing no file,
//! panicking never, and never keeping the agent from starting. The desktop probe is **injected** pure data, so tests
//! need not touch process environment variables.
//!
//! ## Materials and dependencies discipline
//!
//! Icons are **simple self-drawn shapes**, with their geometry and color values aligned item-by-item with the
//! approved four-state PNG designs (the 32px masters' hex glyphs in `icon-{online,degraded,offline,error}.png` plus
//! `gen_icons.py`'s 16px legibility tweaks: the offline inner hole enlarged, feathers tightened to 0.5px), with no
//! brand-logo stand-ins: the main form of the in-repo [logo.svg](../../../logo.svg) is a layered lens polygon
//! (`viewBox="0 0 1024 1024"`), whose detail turns to mush at 16px. State information is carried by shape + color
//! in two channels, rendered natively 1:1 at 16/24px (without scaling, avoiding the "32px downscaled to 16px fills the
//! inner hole with antialiasing residue" defect recorded in gen_icons.py).
//!
//! No GUI / tray crates are pulled in (`tray-icon`/`tao`/`winit` all absent): the tray host wires itself up on the
//! desktop shell's side from the PNGs that [TraySink] writes (panel plugins, `notify-send` scripts, etc.). PNGs are
//! produced by the built-in encoder (stored deflate blocks), adding zero dependencies; [`png_roundtrip_decodes_the_same_pixels`]
//! "decodes the stream it wrote itself" to verify a generic inflater can restore the output.
//!
//! ## Module division (LAY-017)
//!
//! - [`state`]: the four-state machine (mapping, text equivalents) - pure semantics, no rendering;
//! - [`icon`]: icon rendering (outline geometry + palette + sizes);
//! - [`png`]: PNG encoding (stored deflate blocks, zero-dependency codec);
//! - [`env`]: desktop-session probing (injected pure data);
//! - [`sink`]: writing tray artifacts to disk (status.json + icon PNGs, idempotent publishing).

pub mod env;
pub mod icon;
pub mod png;
pub mod sink;
pub mod state;

pub use env::EnvProbe;
pub use icon::IconSize;
pub use png::png_encode;
pub use sink::{TraySink, TrayStatus, TrayWrite};
pub use state::TrayState;
