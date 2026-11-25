//! meshlet-agent library: device-side dataplane reconciliation ([ADR-007](../../docs/decisions/adr-007-linux-network-backend.md)).
//!
//! The agent only consumes a **structured configuration object** delivered by the server
//! (§16.4): it fetches its own dataplane plan with enrollment credentials, applies
//! tunnel/routing/NAT via [`meshlet_network::SystemBackend`] when it changes, and
//! periodically heartbeats local handshake evidence.
//!
//! Hard disciplines:
//! - **Never execute shell commands issued by the server** - only the typed
//!   [`meshlet_network::DevicePlan`] is consumed;
//! - **Reconcile on startup** ("the process is alive" != "the kernel still looks the way it did"):
//!   compare the actual objects against the `desired_config_hash` recorded in the ledger, and
//!   replay on missing/drifted state - this covers "the tunnel vanished after a host reboot but
//!   the ledger still says applied" (TODO #32);
//! - **The private key never leaves the device** (ADR-010): plans never carry a private key; the
//!   agent injects it locally from `[dataplane] private_key_file`.

pub mod agent;
pub mod backoff;
pub mod bootstrap;
pub mod candidates;
#[cfg(target_os = "linux")]
pub mod dbus;
pub mod desktop;
#[cfg(not(target_os = "linux"))]
pub mod desktop_unsupported;
pub mod direct;
pub mod direct_rtt;
pub mod instance_lock;
pub mod mcp;
pub mod net_event;
pub mod probe;
pub mod reconcile;
pub mod self_update;
pub mod server;
pub mod ssh_sync;
pub mod tasks;
pub mod tray;

pub use agent::{read_private_key, Agent};
pub use bootstrap::resolve_device_token;
pub use desktop::{DesktopPublish, NotifyCall, StatusNotifierProperties};
pub use reconcile::{needs_apply, stale_owners, AgentState, Decision, Reason};
pub use tray::{IconSize, TraySink, TrayState, TrayStatus, TrayWrite};
