//! meshlet-network: the unified `NetworkBackend` abstraction ([archive §15.1](../../docs/review/chatgpt-2026-10-13.md),
//! [ADR-007](../../docs/decisions/adr-007-linux-network-backend.md)).
//!
//! The Linux implementation lives in the [linux](linux) module (running `ip` / `wg` / `iptables`
//! commands under control; ADR-007's degraded path landed first, and the path has been verified on
//! real machines via netns integration tests);
//! the Windows implementation joins later per ADR-008 — until then, non-Linux platforms get
//! the **explicit placeholder** of the [unsupported] module (every dataplane operation explicitly
//! reports [NetworkError::Unsupported] and never silently pretends to work).
//!
//! Note: native `async fn` traits are used (Rust 1.75+). Native async traits do not yet support
//! `dyn` dispatch; if object safety is needed later, evaluate `async-trait` (the archive §15.1 reserves this decision point).
//!
//! The [nat](nat) module is a pure **planning** layer (§9.4–§9.5): it deterministically derives the
//! gateway-side NAT rules from Alias mappings; execution follows dataplane wiring (ADR-007).
//!
//! [windows_routes](windows_routes) / [windows_firewall](windows_firewall) / [windows_service](windows_service) /
//! [windows_tunnel](windows_tunnel) are the **planning layer** of the Windows dataplane (ADR-008):
//! command argument construction, parsing, and failure-text classification, unit-tested green on
//! Linux; the `#[cfg(windows)]` execution layer only calls the planning layer. The route/firewall/
//! service execution layers are verified on real machines (2026-10-16 CI runner en-US;
//! 2026-10-26 Chinese Windows Server); tunnel execution primitives are delivered, but the full
//! lifecycle after WireGuardNT driver install is still unverified on real machines (see the
//! [windows_tunnel] module docs). Windows is not wired in as [SystemBackend] until full acceptance.
//!
//! Pre-audit of wiring-decision completion status (M5, 2026-10-27): see "Focus area 3 / Windows
//! backend" in [docs/analysis/todo-completion-audit-2026-10-27.md](../../docs/analysis/todo-completion-audit-2026-10-27.md).
//! Conclusion: the tunnel implementation was entirely absent, so wiring meant a new subsystem
//! rather than flipping one `cfg`. The `windows_tunnel` planning layer + `#[cfg(windows)]` execution
//! primitives landed 2026-10-27; `apply_tunnel` wiring and the real-machine full lifecycle remain missing.
//!
//! [DevicePlan] is the **structured configuration object** from server → agent (§16.4): the agent only
//! consumes typed tunnel/route/NAT plans and never executes arbitrary shell commands handed down by the server.

// Grouped by responsibility: plan types (plan) / errors (error) / pure parsing and
// reconciliation (reconcile) / diagnostics carriers (types) / SSH alias (ssh_alias);
// this file keeps the module declarations, the full re-exports, the platform default
// backend alias, and the NetworkBackend trait.
mod error;
mod plan;
mod reconcile;
mod types;

pub use error::NetworkError;
pub use plan::{
    derive_tunnel_mtu, ApplyResult, ConfigRevisionRef, DevicePlan, NetworkSnapshot, PeerConfig,
    PeerObserved, RouteConfig, SshConfigPlan, SshHostConfig, TunnelConfig, DEFAULT_TUNNEL_MTU,
    HUB_KEEPALIVE_SECS, WG_TUNNEL_OVERHEAD_BYTES,
};
#[cfg(target_os = "windows")]
pub(crate) use reconcile::device_plan_matches;
pub(crate) use reconcile::parse_handshake_ages;
pub use reconcile::{parse_wg_dump_listen_port, parse_wg_dump_local_public_key};
pub use types::{InterfaceDiagnostic, NetworkDiagnostics, WgPeerDiagnostic};

pub mod diag;
pub mod dial;
pub mod doctor;
pub mod keys;
pub mod nat;
pub mod probe;
pub mod ssh_alias;
pub mod windows_cleanup;
pub mod windows_console;
pub mod windows_elevation;
pub mod windows_firewall;
pub mod windows_probe;
pub mod windows_routes;
pub mod windows_service;
pub mod windows_tunnel;
pub mod windows_wireguard_nt;

/// boringtun planning layer (compiles and unit-tests on every platform) and the macOS
/// backend modules (command plans on every platform, `cfg(macos)` executors). See the
/// [crate::macos_wireguard_bt] module docs (②-3 path decision: spawn boringtun-cli + wg.sock UAPI).
pub mod macos;
pub mod macos_dns;
pub mod macos_privileges;
pub mod macos_wireguard_bt;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub mod unsupported;

/// Platform default backend: on Linux this is the real kernel backend ([linux] module, ADR-007).
///
/// Callers always construct through this alias (`SystemBackend::new()` + `with_*` assembly); platform
/// differences converge here — on Linux it really executes.
#[cfg(target_os = "linux")]
pub type SystemBackend = linux::LinuxNetworkBackend;

/// Platform default backend (Windows): the real Windows backend ([windows] module; ADR-008
/// tunnel-only v1 wired in; NAT-bearing plans are explicitly rejected, never silently pretended to work).
#[cfg(target_os = "windows")]
pub type SystemBackend = windows::WindowsNetworkBackend;

/// Platform default backend (macOS): [macos::system::MacSystemBackend] — a placeholder by
/// default (behavior identical to the old [unsupported] placeholder) + `mac-boringtun`
/// dataplane dispatch (③-C wiring; zero behavior change when `tunnel_backend` is not selected).
#[cfg(target_os = "macos")]
pub type SystemBackend = macos::system::MacSystemBackend;

/// Platform default backend (all other platforms): the [unsupported] module's explicit placeholder;
/// every dataplane operation fails visibly (`NetworkError::Unsupported`), never silently pretending to work.
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub type SystemBackend = unsupported::UnsupportedBackend;

/// The unified network backend abstraction: inspect → apply → rollback.
///
/// A native async fn inside a trait cannot declare `Send` bounds; here we use RPITIT + `Send`
/// (Rust 1.75+) so the futures can later be passed safely between axum handlers and
/// `spawn_blocking`, without pulling in the `async-trait` macro dependency.
pub trait NetworkBackend {
    fn inspect<'s>(
        &'s self,
    ) -> impl std::future::Future<Output = Result<NetworkSnapshot, NetworkError>> + Send + 's;

    fn apply_tunnel<'s>(
        &'s self,
        config: TunnelConfig,
    ) -> impl std::future::Future<Output = Result<ApplyResult, NetworkError>> + Send + 's;

    fn apply_routes<'s>(
        &'s mut self,
        routes: Vec<RouteConfig>,
    ) -> impl std::future::Future<Output = Result<ApplyResult, NetworkError>> + Send + 's;

    /// Push NAT rules at the gateway side (planning-layer [nat::NatRule] rendered and executed).
    /// Rules carry the `meshlet alias {id}` ownership comment (§12.6), and [NetworkBackend::remove_nat]
    /// removes them exactly by that comment.
    fn apply_nat<'s>(
        &'s self,
        rules: Vec<nat::NatRule>,
        gateway_lan_addr: std::net::Ipv4Addr,
    ) -> impl std::future::Future<Output = Result<ApplyResult, NetworkError>> + Send + 's;

    /// Remove the NAT rules owned by `owner` (e.g. `meshlet alias al-1`) by their ownership comment;
    /// only rules carrying that comment are touched, and the user's own rules are never rewritten (ADR-007).
    fn remove_nat<'s>(
        &'s self,
        owner: &'s str,
    ) -> impl std::future::Future<Output = Result<ApplyResult, NetworkError>> + Send + 's;

    /// Rollback may only touch Meshlet-owned objects (§10.3).
    fn rollback<'s>(
        &'s self,
        revision: ConfigRevisionRef,
    ) -> impl std::future::Future<Output = Result<ApplyResult, NetworkError>> + Send + 's;

    /// AGENT-ISO-1: **self-healing** isolation of foreign overlays (ZeroTier-like).
    ///
    /// Unlike interfaces such as [`NetworkBackend::apply_tunnel`] that only run when something
    /// changed, this method **must run on every reconcile round**: isolation rules can be flushed
    /// externally, and there is a startup race between the managed tunnel and a foreign overlay
    /// (measured on 2026-11-23: zerotier's ExecStartPost ran 0.7s before wg-mlt came up and the
    /// whole rule batch was lost → the two tunnels became each other's path with 185:1 recursive
    /// encapsulation). Hooking only into apply misses the rounds with no plan change, and lost
    /// rules never come back.
    ///
    /// Default is a no-op (platforms with no foreign overlay to isolate); the Linux implementation
    /// idempotently re-adds the iptables rules. Failures are logged by the caller — isolation is
    /// hardening, not a dataplane prerequisite, and tunnels must not be interrupted over it
    /// ([`crate::diag`] / the `doctor` surface report it as FAIL).
    fn ensure_overlay_isolation(&self) -> Result<(), NetworkError> {
        Ok(())
    }

    /// AGENT-DOC-1: coexistence health check for foreign overlays (see [crate::doctor]).
    ///
    /// By default returns [crate::doctor::unsupported_report] — on unimplemented platforms every
    /// item is `not_assessed` and it **never returns PASS** (§7.5: "not implemented" ≠ "checked and fine").
    /// The Linux backend overrides this with real collection.
    fn doctor(&self) -> crate::doctor::DoctorReport {
        crate::doctor::unsupported_report()
    }
}

/// Probe the local WireGuard-type interface name (first hit of `ip -o link show type wireguard`).
///
/// Neither the CLI nor MCP has a hardcoded source for the "managed interface name" — when the
/// config says `wg0` but the real machine named it `wg-mlt`, reading by the default name comes up
/// empty (this is how the `diag` wg section stayed `(not collected)` for so long). Probe by link
/// type at runtime; return `None` when it cannot be read and let the caller fall back to the default.
#[cfg(target_os = "linux")]
pub fn detect_wireguard_interface() -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["-o", "link", "show", "type", "wireguard"])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let name = fields.get(1)?.trim_end_matches(':');
            (!name.is_empty()).then(|| name.to_string())
        })
        .next()
}

/// Non-Linux platforms have no equivalent probe for now (wireguard-nt / boringtun enumerate interfaces through their own backend).
#[cfg(not(target_os = "linux"))]
pub fn detect_wireguard_interface() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Proves the trait can be implemented and dispatched generically (the §15.1 concept interface, realized).
    struct DummyBackend;

    impl NetworkBackend for DummyBackend {
        async fn inspect(&self) -> Result<NetworkSnapshot, NetworkError> {
            Ok(NetworkSnapshot {
                tunnel_exists: true,
                forwarding_enabled: Some(true),
                peers: vec![
                    PeerObserved {
                        public_key: format!("{}=", "A".repeat(43)),
                        allowed_ips: vec!["10.240.0.2/32".parse().unwrap()],
                    },
                    PeerObserved {
                        public_key: format!("{}=", "B".repeat(43)),
                        allowed_ips: vec!["10.240.0.0/16".parse().unwrap()],
                    },
                ],
                installed_routes: vec!["10.240.0.0/16".parse().unwrap()],
                nat_rules: Vec::new(),
                tunnel_mtu: Some(1420),
                local_public_key: None,
                tunnel_address: None,
                tunnel_listen_port: None,
                routes_from_peers: false,
            })
        }

        async fn apply_tunnel(&self, _config: TunnelConfig) -> Result<ApplyResult, NetworkError> {
            Ok(ApplyResult::ok())
        }

        async fn apply_routes(
            &mut self,
            routes: Vec<RouteConfig>,
        ) -> Result<ApplyResult, NetworkError> {
            assert_eq!(routes.len(), 1);
            Ok(ApplyResult::ok())
        }

        async fn apply_nat(
            &self,
            rules: Vec<nat::NatRule>,
            _gateway_lan_addr: std::net::Ipv4Addr,
        ) -> Result<ApplyResult, NetworkError> {
            assert_eq!(rules.len(), 1);
            Ok(ApplyResult::ok())
        }

        async fn remove_nat(&self, _owner: &str) -> Result<ApplyResult, NetworkError> {
            Ok(ApplyResult::ok())
        }

        async fn rollback(
            &self,
            _revision: ConfigRevisionRef,
        ) -> Result<ApplyResult, NetworkError> {
            Ok(ApplyResult::failed("nothing to roll back"))
        }
    }

    #[tokio::test]
    async fn backend_contract_via_generic_dispatch() {
        async fn use_backend<B: NetworkBackend>(b: &B) -> NetworkSnapshot {
            b.inspect().await.unwrap()
        }
        let snap = use_backend(&DummyBackend).await;
        assert!(snap.tunnel_exists);
        assert_eq!(snap.peers.len(), 2);

        let mut mutable_backend = DummyBackend;
        mutable_backend
            .apply_routes(vec![RouteConfig {
                destination: "10.241.1.0/24".parse().unwrap(),
                interface: "wg0".into(),
                gateway: None,
            }])
            .await
            .unwrap();
        mutable_backend
            .apply_nat(
                vec![nat::NatRule {
                    source_cidr: None,
                    incoming_interface: None,
                    chain: nat::NatChain::Prerouting,
                    match_dest: "10.241.1.0/24".parse().unwrap(),
                    action: nat::NatAction::NetMap {
                        to: "192.168.1.0/24".parse().unwrap(),
                    },
                    owner: "meshlet alias test".into(),
                }],
                "192.168.1.1".parse().unwrap(),
            )
            .await
            .unwrap();
        mutable_backend
            .remove_nat("meshlet alias test")
            .await
            .unwrap();

        let result = DummyBackend
            .rollback(ConfigRevisionRef {
                network_id: "n".into(),
                revision: 1,
            })
            .await
            .unwrap();
        assert!(!result.applied);
        assert!(result.error.is_some());
    }
}
