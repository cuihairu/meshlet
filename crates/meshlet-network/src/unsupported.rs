//! Explicit placeholder backend for non-Linux platforms
//! ([ADR-008](../../../docs/decisions/adr-008-windows-network-backend.md)).
//!
//! Construction and assembly (`new` / `with_*`) work as usual, so
//! platform-agnostic caller code compiles and runs on any platform; but
//! **every operation that would touch the kernel** returns
//! [`NetworkError::Unsupported`] and names the operation and the interface —
//! the Windows network backend (WireGuard tunnel service + system routing
//! API) is ADR-008's follow-up implementation item. The point of the
//! placeholder is an **error surface** rather than a false green: apply
//! failures are visible and readings are treated as "unverified"; it never
//! silently pretends to have taken effect (§10.3, §12.2).

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::nat::NatRule;
use crate::{
    ApplyResult, ConfigRevisionRef, DevicePlan, NetworkBackend, NetworkError, NetworkSnapshot,
    RouteConfig, TunnelConfig,
};
use meshlet_domain::Ipv4Cidr;

/// Placeholder backend for non-Linux platforms: every data-plane operation is
/// explicitly refused (ADR-008 pending integration).
#[derive(Clone, Default)]
pub struct UnsupportedBackend {
    interface: String,
}

impl UnsupportedBackend {
    pub fn new() -> Self {
        Self {
            interface: "meshlet".to_string(),
        }
    }

    /// Test-hook parity (the same-named assembly method on the Linux backend):
    /// the placeholder backend ignores netns and the `sudo -n` prefix — every
    /// operation is going to be refused anyway.
    pub fn with_netns(self, _netns: impl Into<String>) -> Self {
        self
    }

    /// Same as [`UnsupportedBackend::with_netns`].
    pub fn with_sudo(self) -> Self {
        self
    }

    /// Record the managed interface name so the refusal message can name it
    /// (same shape as the Linux backend).
    pub fn with_interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = interface.into();
        self
    }

    fn refuse(&self, operation: &str) -> NetworkError {
        NetworkError::Unsupported(format!(
            "operation `{operation}` on interface `{}` needs a platform dataplane backend \
             (windows backend pending, ADR-008)",
            self.interface
        ))
    }

    pub fn clear_hub_sync(&self) -> Result<(), NetworkError> {
        Err(self.refuse("clear_hub"))
    }

    pub fn isolate_hub_sync(&self, _address: Ipv4Addr) -> Result<(), NetworkError> {
        Err(self.refuse("isolate_hub"))
    }

    pub fn device_plan_matches_sync(
        &self,
        _plan: &DevicePlan,
        _extra_peer_keys: &BTreeSet<String>,
    ) -> Result<bool, NetworkError> {
        Err(self.refuse("device_plan_matches"))
    }

    pub fn diagnostics_sync(&self) -> Result<crate::NetworkDiagnostics, NetworkError> {
        Err(self.refuse("network diagnostics"))
    }

    /// RTT probe is unavailable on this platform; absence is visible, not fake.
    pub fn ping_rtt_ms(&self, _target: Ipv4Addr) -> Option<u128> {
        None
    }

    pub fn inspect_sync(&self) -> Result<NetworkSnapshot, NetworkError> {
        Err(self.refuse("inspect"))
    }

    pub fn apply_tunnel_sync(
        &self,
        _config: &TunnelConfig,
        _keep_keys: &BTreeSet<String>,
    ) -> Result<ApplyResult, NetworkError> {
        Err(self.refuse("apply_tunnel"))
    }

    pub fn apply_routes_sync(&self, _routes: &[RouteConfig]) -> Result<ApplyResult, NetworkError> {
        Err(self.refuse("apply_routes"))
    }

    pub fn apply_nat_sync(
        &self,
        _rules: &[NatRule],
        _gateway_lan_addr: Ipv4Addr,
    ) -> Result<ApplyResult, NetworkError> {
        Err(self.refuse("apply_nat"))
    }

    /// Combined device-plan application (same signature as the Linux backend):
    /// refuse first, without touching tunnel/routes/NAT.
    pub fn apply_device_plan_sync(
        &self,
        _plan: &DevicePlan,
        _private_key: Option<String>,
        _gateway_lan_addr: Option<Ipv4Addr>,
        _keep_keys: &BTreeSet<String>,
    ) -> Result<(), NetworkError> {
        Err(self.refuse("apply_device_plan"))
    }

    pub fn remove_nat_sync(&self, _owner: &str) -> Result<ApplyResult, NetworkError> {
        Err(self.refuse("remove_nat"))
    }

    pub fn meshlet_nat_owners_sync(&self) -> Result<Vec<String>, NetworkError> {
        Err(self.refuse("enumerate meshlet nat owners"))
    }

    pub fn lan_addresses_sync(&self) -> Result<Vec<Ipv4Addr>, NetworkError> {
        Err(self.refuse("enumerate lan addresses"))
    }

    pub fn lan_subnets_sync(&self) -> Result<Vec<Ipv4Cidr>, NetworkError> {
        Err(self.refuse("enumerate lan subnets"))
    }

    /// No implementation of the P2P direct-connect execution layer on this
    /// platform: explicitly refused (never pretend the direct connection
    /// succeeded).
    pub fn handshake_ages_sync(&self) -> Result<BTreeMap<String, u64>, NetworkError> {
        Err(self.refuse("handshake_ages"))
    }

    /// No implementation of P2P direct peer application on this platform:
    /// explicitly refused.
    pub fn set_direct_peer_sync(
        &self,
        _public_key: &str,
        _allowed_ips: &[Ipv4Cidr],
        _endpoint: SocketAddrV4,
        _persistent_keepalive_secs: u32,
    ) -> Result<(), NetworkError> {
        Err(self.refuse("set_direct_peer"))
    }

    /// No implementation of P2P direct peer removal on this platform:
    /// explicitly refused.
    pub fn remove_peer_sync(&self, _public_key: &str) -> Result<(), NetworkError> {
        Err(self.refuse("remove_peer"))
    }

    /// SEL-002 direct endpoint roaming has no implementation on this platform:
    /// explicitly refused.
    pub fn set_direct_endpoint_sync(
        &self,
        _public_key: &str,
        _endpoint: SocketAddrV4,
    ) -> Result<(), NetworkError> {
        Err(self.refuse("set_direct_endpoint"))
    }

    pub fn remove_stale_meshlet_routes_sync(
        &self,
        _routes: &[RouteConfig],
    ) -> Result<ApplyResult, NetworkError> {
        Err(self.refuse("remove stale meshlet routes"))
    }

    pub fn rollback_sync(&self) -> Result<ApplyResult, NetworkError> {
        Err(self.refuse("rollback"))
    }

    /// The `wg pubkey` equivalent has no implementation on this platform: hub
    /// public-key derivation fails explicitly (the server returns it as a
    /// visible error, and never dispatches an empty plan pretending a hub
    /// exists).
    pub fn public_key_from_private(&self, _private_key: &str) -> Result<String, NetworkError> {
        Err(self.refuse("public_key_from_private"))
    }

    /// Large-packet probing has no data plane on this platform: `false` means
    /// "unverified", not green (§7.5/§12.2 no false green — a failed probe
    /// never pretends the path can carry it).
    pub fn mtu_probe_sync(&self, _target: Ipv4Addr, _payload: u32) -> bool {
        false
    }

    /// The default route's underlay MTU has no reading source on this platform:
    /// `None` means "reading unavailable", and the caller falls back to the
    /// default probe size (§7.5, no guessing).
    pub fn underlay_path_mtu_sync(&self) -> Option<u32> {
        None
    }
}

impl NetworkBackend for UnsupportedBackend {
    async fn inspect(&self) -> Result<NetworkSnapshot, NetworkError> {
        self.inspect_sync()
    }

    async fn apply_tunnel(&self, config: TunnelConfig) -> Result<ApplyResult, NetworkError> {
        self.apply_tunnel_sync(&config, &BTreeSet::new())
    }

    async fn apply_routes(
        &mut self,
        routes: Vec<RouteConfig>,
    ) -> Result<ApplyResult, NetworkError> {
        self.apply_routes_sync(&routes)
    }

    async fn apply_nat(
        &self,
        rules: Vec<NatRule>,
        gateway_lan_addr: Ipv4Addr,
    ) -> Result<ApplyResult, NetworkError> {
        self.apply_nat_sync(&rules, gateway_lan_addr)
    }

    async fn remove_nat(&self, owner: &str) -> Result<ApplyResult, NetworkError> {
        self.remove_nat_sync(owner)
    }

    async fn rollback(&self, _revision: ConfigRevisionRef) -> Result<ApplyResult, NetworkError> {
        self.rollback_sync()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::{NatAction, NatChain};

    fn rule() -> NatRule {
        NatRule {
            source_cidr: None,
            incoming_interface: None,
            chain: NatChain::Prerouting,
            match_dest: "10.241.1.0/24".parse().unwrap(),
            action: NatAction::NetMap {
                to: "192.168.1.0/24".parse().unwrap(),
            },
            owner: "meshlet alias al-1".into(),
        }
    }

    /// Every data-plane operation is explicitly refused, and the refusal names
    /// the operation and the interface (an error surface, not a silent swallow
    /// that pretends it passed).
    #[test]
    fn every_operation_refuses_naming_the_operation() {
        let backend = UnsupportedBackend::new().with_interface("wg0");
        let tunnel = TunnelConfig {
            name: "wg0".into(),
            address: "10.240.0.1".parse().unwrap(),
            address_prefix: 24,
            listen_port: None,
            peers: vec![],
            mtu: None,
            private_key: None,
        };
        let route = RouteConfig {
            destination: "10.241.1.0/24".parse().unwrap(),
            interface: "wg0".into(),
            gateway: Some("10.240.0.4".parse().unwrap()),
        };
        for (operation, error) in [
            ("inspect", backend.inspect_sync().unwrap_err()),
            (
                "apply_tunnel",
                backend
                    .apply_tunnel_sync(&tunnel, &BTreeSet::new())
                    .unwrap_err(),
            ),
            (
                "apply_routes",
                backend.apply_routes_sync(&[route]).unwrap_err(),
            ),
            (
                "apply_nat",
                backend
                    .apply_nat_sync(&[rule()], "192.168.1.1".parse().unwrap())
                    .unwrap_err(),
            ),
            (
                "remove_nat",
                backend.remove_nat_sync("meshlet alias al-1").unwrap_err(),
            ),
            (
                "apply_device_plan",
                backend
                    .apply_device_plan_sync(
                        &DevicePlan {
                            desired_revision: 0,
                            hub_port: None,
                            tunnel: tunnel.clone(),
                            routes: vec![],
                            nat_rules: vec![],
                            hub_address: None,
                            publish: None,
                            ssh_config: None,
                            desired_config_hash: "hash".into(),
                        },
                        None,
                        None,
                        &BTreeSet::new(),
                    )
                    .unwrap_err(),
            ),
            ("rollback", backend.rollback_sync().unwrap_err()),
            (
                "public_key_from_private",
                backend.public_key_from_private("key").unwrap_err(),
            ),
        ] {
            match error {
                NetworkError::Unsupported(detail) => {
                    assert!(detail.contains(operation), "{operation}: {detail}");
                    assert!(detail.contains("wg0"), "{operation}: {detail}");
                }
                other => panic!("{operation} must refuse as Unsupported, got {other:?}"),
            }
        }
    }

    /// The trait surface (async) refuses with the same semantics as the sync
    /// surface: the placeholder is not honest on only one path.
    #[tokio::test]
    async fn the_trait_surface_refuses_the_same_way() {
        let backend = UnsupportedBackend::new();
        assert!(matches!(
            backend.inspect().await,
            Err(NetworkError::Unsupported(_))
        ));
    }

    /// Large-packet probing is always false: under the placeholder backend
    /// "unverified" never poses as green (§7.5).
    #[test]
    fn mtu_probe_reports_unverified() {
        assert!(!UnsupportedBackend::new().mtu_probe_sync("10.240.0.2".parse().unwrap(), 1392));
    }
}
