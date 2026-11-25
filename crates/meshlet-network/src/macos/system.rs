//! macOS platform SystemBackend (③-C wiring): default placeholder + boringtun
//! data-plane dispatch.
//!
//! On macOS, `SystemBackend` used to fall through to the [crate::unsupported]
//! placeholder (every operation explicitly refused). This module swaps the
//! macOS default backend for a **dual-mode** structure:
//!
//! - **Default (Service semantics)**: delegates each operation to
//!   [crate::unsupported::UnsupportedBackend] — preserving the existing
//!   behavior (`Unsupported` per operation, never silently faking success).
//!   This is what runs when `mac-boringtun` is not selected: **zero behavior
//!   change**.
//! - **boringtun mode** ([MacSystemBackend::with_mac_boringtun]): the tunnel
//!   apply surface goes through the [crate::macos::backend::bt_apply] command
//!   plan -> executor [crate::macos::backend::MacNetworkBackend] (the sudo
//!   whitelist is guarded by the hook in [crate::macos::backend]); every other
//!   operation stays placeholder-refused (mac has no NAT / peer direct-connect
//!   surface).
//!
//! On the tunnel configuration surface, **the wg key/peer UAPI and the
//! kernel-assigned utun name (`WG_TUN_NAME_FILE`) are ⑤ real-machine
//! acceptance items** — this file invents no paths; in boringtun mode an
//! explicitly named error calling out ⑤ is raised when the planned name is
//! `utun` (kernel-chosen), and `utun` is never silently applied as a real
//! interface name.
//!
//! Compiled only under `#[cfg(target_os = "macos")]` (the host CI does not run
//! macOS tests; compilation is verified via an `x86_64-apple-darwin` cross
//! check, and command-plan semantics are covered by the cross-platform unit
//! tests).

use super::backend::{bt_apply, MacNetworkBackend};
use crate::unsupported::UnsupportedBackend;
use crate::{
    ApplyResult, ConfigRevisionRef, NetworkBackend, NetworkError, NetworkSnapshot, RouteConfig,
    TunnelConfig,
};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddrV4};

/// macOS platform backend: placeholder base + optional boringtun tunnel surface.
#[derive(Clone)]
pub struct MacSystemBackend {
    /// Placeholder base (every operation in default mode + the non-tunnel
    /// operations in boringtun mode).
    base: UnsupportedBackend,
    /// Managed utun name (`utun` lets the kernel choose / `utun<N>` is explicit).
    interface: String,
    /// boringtun data plane: `None` = default placeholder; `Some` = tunnel
    /// application goes through the command plan.
    boringtun: Option<MacNetworkBackend>,
}

impl MacSystemBackend {
    pub fn new() -> Self {
        Self {
            base: UnsupportedBackend::new(),
            interface: "utun".to_string(),
            boringtun: None,
        }
    }

    /// Record the managed utun name (mirrors each backend's `with_interface`
    /// assembly).
    pub fn with_interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = interface.into();
        self
    }

    /// Test hook (mirrors each backend's assembly surface): boringtun commands
    /// are prefixed with `sudo -n`.
    pub fn with_sudo(mut self) -> Self {
        if let Some(backend) = self.boringtun.take() {
            self.boringtun = Some(backend.with_sudo());
        }
        self
    }

    /// Test hook (mirrors each backend's assembly surface): mac has no netns,
    /// so this is ignored (placeholder semantics unchanged).
    pub fn with_netns(self, _netns: impl Into<String>) -> Self {
        self
    }

    /// ③-C wiring: select the boringtun data plane (tunnel application goes
    /// through the command plan).
    pub fn with_mac_boringtun(mut self) -> Self {
        self.boringtun = Some(MacNetworkBackend::new());
        self
    }

    /// Tunnel apply surface: in boringtun mode this goes through the bt command
    /// plan, otherwise the placeholder refuses.
    fn apply_tunnel_sync(&self, config: &TunnelConfig) -> Result<ApplyResult, NetworkError> {
        let backend = match self.boringtun.as_ref() {
            Some(backend) => backend,
            None => return self.base.apply_tunnel_sync(config, &BTreeSet::new()),
        };
        // A planned name of `utun` (kernel-chosen) can only yield the real name
        // via `WG_TUN_NAME_FILE` — that is a ⑤ real-machine item and this batch
        // invents no paths: raise an explicit error rather than treating `utun`
        // as a real interface.
        if self.interface == "utun" {
            return Err(NetworkError::ApplyRejected(
                "mac-boringtun with kernel-assigned utun name needs WG_TUN_NAME_FILE \
                 resolution (real-machine acceptance item)"
                    .into(),
            ));
        }
        let commands = bt_apply(config, &self.interface, &self.interface)?;
        backend.apply(&commands)?;
        Ok(ApplyResult::ok())
    }

    // ---- Placeholder delegation surface (identical in default and boringtun
    //      mode: mac has none of these surfaces) ----

    pub fn inspect_sync(&self) -> Result<NetworkSnapshot, NetworkError> {
        self.base.inspect_sync()
    }

    pub fn apply_routes_sync(&self, routes: &[RouteConfig]) -> Result<ApplyResult, NetworkError> {
        self.base.apply_routes_sync(routes)
    }

    pub fn apply_nat_sync(
        &self,
        rules: &[crate::nat::NatRule],
        gateway_lan_addr: Ipv4Addr,
    ) -> Result<ApplyResult, NetworkError> {
        self.base.apply_nat_sync(rules, gateway_lan_addr)
    }

    pub fn remove_nat_sync(&self, owner: &str) -> Result<ApplyResult, NetworkError> {
        self.base.remove_nat_sync(owner)
    }

    pub fn rollback_sync(&self) -> Result<ApplyResult, NetworkError> {
        self.base.rollback_sync()
    }

    pub fn diagnostics_sync(&self) -> Result<crate::NetworkDiagnostics, NetworkError> {
        self.base.diagnostics_sync()
    }

    pub fn ping_rtt_ms(&self, target: Ipv4Addr) -> Option<u128> {
        self.base.ping_rtt_ms(target)
    }

    pub fn lan_addresses_sync(&self) -> Result<Vec<Ipv4Addr>, NetworkError> {
        self.base.lan_addresses_sync()
    }

    pub fn lan_subnets_sync(&self) -> Result<Vec<meshlet_domain::Ipv4Cidr>, NetworkError> {
        self.base.lan_subnets_sync()
    }

    pub fn handshake_ages_sync(&self) -> Result<BTreeMap<String, u64>, NetworkError> {
        self.base.handshake_ages_sync()
    }

    pub fn set_direct_peer_sync(
        &self,
        public_key: &str,
        allowed_ips: &[meshlet_domain::Ipv4Cidr],
        endpoint: SocketAddrV4,
        persistent_keepalive_secs: u32,
    ) -> Result<(), NetworkError> {
        self.base
            .set_direct_peer_sync(public_key, allowed_ips, endpoint, persistent_keepalive_secs)
    }

    pub fn remove_peer_sync(&self, public_key: &str) -> Result<(), NetworkError> {
        self.base.remove_peer_sync(public_key)
    }

    pub fn set_direct_endpoint_sync(
        &self,
        public_key: &str,
        endpoint: SocketAddrV4,
    ) -> Result<(), NetworkError> {
        self.base.set_direct_endpoint_sync(public_key, endpoint)
    }

    pub fn remove_stale_meshlet_routes_sync(
        &self,
        routes: &[RouteConfig],
    ) -> Result<ApplyResult, NetworkError> {
        self.base.remove_stale_meshlet_routes_sync(routes)
    }

    pub fn public_key_from_private(&self, private_key: &str) -> Result<String, NetworkError> {
        self.base.public_key_from_private(private_key)
    }

    pub fn mtu_probe_sync(&self, target: Ipv4Addr, payload: u32) -> bool {
        self.base.mtu_probe_sync(target, payload)
    }

    pub fn underlay_path_mtu_sync(&self) -> Option<u32> {
        self.base.underlay_path_mtu_sync()
    }

    pub fn clear_hub_sync(&self) -> Result<(), NetworkError> {
        self.base.clear_hub_sync()
    }

    pub fn isolate_hub_sync(&self, address: Ipv4Addr) -> Result<(), NetworkError> {
        self.base.isolate_hub_sync(address)
    }

    pub fn device_plan_matches_sync(
        &self,
        plan: &crate::DevicePlan,
        extra_peer_keys: &BTreeSet<String>,
    ) -> Result<bool, NetworkError> {
        self.base.device_plan_matches_sync(plan, extra_peer_keys)
    }

    pub fn meshlet_nat_owners_sync(&self) -> Result<Vec<String>, NetworkError> {
        self.base.meshlet_nat_owners_sync()
    }

    /// Combined device-plan application: the tunnel surface goes through
    /// boringtun (if selected), the remaining components are placeholder-refused.
    /// The signature mirrors [UnsupportedBackend::apply_device_plan_sync]
    /// (&self).
    pub fn apply_device_plan_sync(
        &self,
        plan: &crate::DevicePlan,
        private_key: Option<String>,
        _gateway_lan_addr: Option<Ipv4Addr>,
        keep_keys: &BTreeSet<String>,
    ) -> Result<(), NetworkError> {
        let mut tunnel = plan.tunnel.clone();
        tunnel.private_key = private_key;
        let tunnel_result = self.apply_tunnel_sync(&tunnel)?;
        if !tunnel_result.applied {
            return Err(NetworkError::ApplyRejected(
                tunnel_result.error.unwrap_or_default(),
            ));
        }
        // The remaining components (routes/nat) go through the placeholder:
        // mac has no independent route/NAT surface. boringtun's routes are
        // already included in the command plan (peer allowed_ips), so there is
        // no separate routing-table component.
        let routes = self.apply_routes_sync(&plan.routes)?;
        if !routes.applied {
            return Err(NetworkError::ApplyRejected(
                routes.error.unwrap_or_default(),
            ));
        }
        if !plan.nat_rules.is_empty() {
            let nat = self.apply_nat_sync(&plan.nat_rules, Ipv4Addr::UNSPECIFIED)?;
            if !nat.applied {
                return Err(NetworkError::ApplyRejected(nat.error.unwrap_or_default()));
            }
        }
        let _ = keep_keys;
        Ok(())
    }
}

impl Default for MacSystemBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkBackend for MacSystemBackend {
    async fn inspect(&self) -> Result<NetworkSnapshot, NetworkError> {
        self.inspect_sync()
    }

    async fn apply_tunnel(&self, config: TunnelConfig) -> Result<ApplyResult, NetworkError> {
        self.apply_tunnel_sync(&config)
    }

    async fn apply_routes(
        &mut self,
        routes: Vec<RouteConfig>,
    ) -> Result<ApplyResult, NetworkError> {
        self.apply_routes_sync(&routes)
    }

    async fn apply_nat(
        &self,
        rules: Vec<crate::nat::NatRule>,
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

    /// ③-C pin: in default mode (mac-boringtun not selected) behavior matches
    /// the placeholder — tunnel application is explicitly refused and never
    /// silently faked as applied.
    #[test]
    fn default_mode_refuses_tunnel_apply() {
        let backend = MacSystemBackend::new().with_interface("utun5");
        let err = backend.apply_tunnel_sync(&crate::TunnelConfig {
            name: "net-a".into(),
            address: "10.240.0.7".parse().unwrap(),
            address_prefix: 16,
            listen_port: Some(51821),
            peers: Vec::new(),
            mtu: Some(1420),
            private_key: None,
        });
        assert!(matches!(err, Err(NetworkError::Unsupported(_))));
    }

    /// ③-C pin: boringtun mode with a planned name of `utun` (kernel-chosen)
    /// -> explicitly refused (WG_TUN_NAME_FILE is a ⑤ real-machine item, and
    /// `utun` is never applied as a real interface name).
    #[test]
    fn boringtun_bare_utun_fails_closed() {
        let backend = MacSystemBackend::new()
            .with_interface("utun")
            .with_mac_boringtun();
        let err = backend.apply_tunnel_sync(&crate::TunnelConfig {
            name: "net-a".into(),
            address: "10.240.0.7".parse().unwrap(),
            address_prefix: 16,
            listen_port: Some(51821),
            peers: Vec::new(),
            mtu: Some(1420),
            private_key: None,
        });
        assert!(matches!(err, Err(NetworkError::ApplyRejected(_))));
    }

    /// ③-C pin: boringtun mode with an explicit `utun<N>` name goes through
    /// the command plan (it is not refused just because the kernel name is
    /// unavailable — an explicit name does not need WG_TUN_NAME_FILE).
    #[test]
    fn boringtun_explicit_utun_reaches_command_plan() {
        let backend = MacSystemBackend::new()
            .with_interface("utun5")
            .with_mac_boringtun();
        // The command-plan layer (bt_apply) succeeds for an explicit name —
        // the execution layer fails with Io because no real utun exists, but
        // that is an execution error, not a plan rejection; this asserts the
        // plan surface does not refuse.
        let plan = crate::macos_wireguard_bt::bt_interface_plan(
            &crate::TunnelConfig {
                name: "net-a".into(),
                address: "10.240.0.7".parse().unwrap(),
                address_prefix: 16,
                listen_port: Some(51821),
                peers: Vec::new(),
                mtu: Some(1420),
                private_key: None,
            },
            "utun5",
        );
        assert!(plan.is_ok());
    }
}
