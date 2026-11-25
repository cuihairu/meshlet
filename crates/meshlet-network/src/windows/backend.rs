use super::parsing::{is_windows_lan_interface, parse_lan_ip_json};
use crate::nat::NatRule;
use crate::windows_console::NoWindowCommand;
use crate::windows_routes::exec::run_route_command;
use crate::windows_tunnel::exec::run_wireguard_command;
use crate::windows_tunnel::exec::{ensure_conf_dir_acl, ensure_conf_file_acl, write_tunnel_conf};
use crate::windows_tunnel::render_wireguard_conf;
use crate::windows_tunnel::wireguard_exe;
use crate::windows_tunnel::WireGuardCommand;
use crate::windows_wireguard_nt::{
    nt_adapter_handle, nt_adapter_name, NtRuntime, NT_INTERFACE_MTU,
};
use crate::{
    ApplyResult, ConfigRevisionRef, DevicePlan, NetworkBackend, NetworkError, NetworkSnapshot,
    RouteConfig, TunnelConfig,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
/// The Windows network backend: a WireGuardNT tunnel (the service model or the
/// wireguard-nt model) plus netsh routes.
#[derive(Clone)]
pub struct WindowsNetworkBackend {
    /// The managed WireGuard interface name (the tunnel service name in the
    /// service model; the source the nt model derives the adapter handle
    /// from).
    pub(super) interface: String,
    /// An explicit `wireguard.exe` override path (`None` = resolve through the
    /// environment variable/PATH).
    pub(super) wireguard_exe_override: Option<PathBuf>,
    pub(super) hub_endpoint: Option<String>,
    /// The wireguard-nt runtime (Some when `tunnel_backend = "nt"`; `None` =
    /// the service model). Shared via Arc: when the backend is cloned into
    /// background threads such as [crate::direct_rtt], the adapter handle is held
    /// persistently by the same runtime.
    pub(super) nt: Option<Arc<NtRuntime>>,
}

impl WindowsNetworkBackend {
    pub fn new() -> Self {
        Self {
            interface: "meshlet".to_string(),
            wireguard_exe_override: None,
            hub_endpoint: None,
            nt: None,
        }
    }

    pub fn with_interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = interface.into();
        self
    }

    /// Assemble the wireguard-nt runtime (`tunnel_backend = "nt"`): the runtime
    /// holds the adapter handle persistently, and every data-plane operation of
    /// this backend switches to the nt model ([Self::nt]).
    pub fn with_nt_runtime(mut self, runtime: NtRuntime) -> Self {
        self.nt = Some(Arc::new(runtime));
        self
    }

    pub fn with_wireguard_exe(mut self, path: impl Into<PathBuf>) -> Self {
        self.wireguard_exe_override = Some(path.into());
        self
    }

    pub fn with_hub_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.hub_endpoint = Some(endpoint.into());
        self
    }

    pub(super) fn find_wireguard_exe(&self) -> Option<PathBuf> {
        let exe = wireguard_exe(self.wireguard_exe_override.as_deref());
        if exe.is_absolute() && exe.exists() {
            return Some(exe);
        }
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                let candidate = dir.join("wireguard.exe");
                if candidate.exists() {
                    return Some(candidate);
                }
            }
        }
        let default_paths = [
            r"C:\Program Files\WireGuard\wireguard.exe",
            r"C:\Program Files (x86)\WireGuard\wireguard.exe",
        ];
        for p in default_paths {
            let path = PathBuf::from(p);
            if path.exists() {
                return Some(path);
            }
        }
        None
    }

    pub fn device_plan_matches_sync(
        &self,
        plan: &DevicePlan,
        extra_peer_keys: &BTreeSet<String>,
    ) -> Result<bool, NetworkError> {
        // Reconcile item by item (peer public keys / routes / MTU) instead of
        // "only checking that the tunnel exists" — a tunnel that exists but whose
        // configuration has drifted is no longer misjudged as consistent
        // (todo.md:241).
        let snapshot = self.inspect_sync()?;
        Ok(crate::device_plan_matches(plan, extra_peer_keys, &snapshot))
    }

    pub fn inspect_sync(&self) -> Result<NetworkSnapshot, NetworkError> {
        if let Some(nt) = &self.nt {
            return self.nt_inspect_sync(nt);
        }
        let _exe = self.find_wireguard_exe().ok_or_else(|| {
            NetworkError::Unsupported(
                "WireGuard for Windows is not installed.                  Install from https://www.wireguard.com/install/                  or set MESHLET_WIREGUARD_EXE to the wireguard.exe path."
                    .to_string(),
            )
        })?;
        let tunnel_exists = self.tunnel_service_exists(&self.interface);
        let forwarding_enabled = self.forwarding_enabled();
        let peers = if tunnel_exists {
            self.read_tunnel_peers(&self.interface)
        } else {
            Vec::new()
        };
        let installed_routes = if tunnel_exists {
            self.routes_on_interface()
        } else {
            Vec::new()
        };
        let tunnel_mtu = if tunnel_exists {
            self.interface_mtu()
        } else {
            None
        };
        // The local identity reading (a drift-verdict input from the BUG② fix):
        // column 2 of the dump interface line is the local public key
        // (unreadable -> None; missing evidence is never judged); the adapter
        // address is read from netsh.
        let local_public_key = if tunnel_exists {
            self.read_tunnel_dump(&self.interface)
                .as_deref()
                .and_then(crate::parse_wg_dump_local_public_key)
        } else {
            None
        };
        let tunnel_address = if tunnel_exists {
            self.interface_address()
        } else {
            None
        };
        // The actual listen port (a drift-verdict input for the direct-connect
        // pinned port): column 3 of the same dump interface line
        // (unreadable -> None; missing evidence is never judged).
        let tunnel_listen_port = if tunnel_exists {
            self.read_tunnel_dump(&self.interface)
                .as_deref()
                .and_then(crate::parse_wg_dump_listen_port)
        } else {
            None
        };
        Ok(NetworkSnapshot {
            tunnel_exists,
            forwarding_enabled,
            peers,
            installed_routes,
            nat_rules: Vec::new(),
            tunnel_mtu,
            local_public_key,
            tunnel_address,
            tunnel_listen_port,
            // Service model: routes are issued independently through netsh
            // (plan.routes -> the kernel), unrelated to peer allowed-ips; drift
            // is compared against plan.routes.
            routes_from_peers: false,
        })
    }

    /// The nt model's inspect: the source of truth is the `get_config` read-back
    /// from the adapter the runtime already holds ([NtRuntime::inspect]), with
    /// the address read from `Get-NetIPAddress` (locale-independent, the same as
    /// [Self::lan_addresses_sync]). Without the adapter (it dies with the handle
    /// after a process restart) -> an empty snapshot with `tunnel_exists=false`,
    /// and the reconcile replays from that.
    fn nt_inspect_sync(&self, nt: &NtRuntime) -> Result<NetworkSnapshot, NetworkError> {
        let adapter_name = nt_adapter_name(&nt_adapter_handle(&self.interface))?;
        let forwarding_enabled = self.forwarding_enabled();
        let readback = nt.inspect(&adapter_name);
        let tunnel_exists = readback.is_some();
        let (
            peers,
            installed_routes,
            local_public_key,
            tunnel_listen_port,
            tunnel_mtu,
            tunnel_address,
        ) = match readback {
            None => (Vec::new(), Vec::new(), None, None, None, None),
            Some(snapshot) => {
                let peers = snapshot
                    .peers
                    .iter()
                    .map(|peer| crate::PeerObserved {
                        public_key: BASE64.encode(peer.public_key),
                        allowed_ips: peer.allowed_ips.clone(),
                    })
                    .collect();
                // installed_routes = the allowed_ips assembled by the driver's
                // set_default_route (the union over peers), the very same set
                // used by the plan-routes reconciliation.
                let mut installed_routes: Vec<meshlet_domain::Ipv4Cidr> = snapshot
                    .peers
                    .iter()
                    .flat_map(|peer| peer.allowed_ips.iter().copied())
                    .collect();
                installed_routes.sort();
                installed_routes.dedup();
                let local_public_key = Some(BASE64.encode(snapshot.public_key));
                let tunnel_listen_port = Some(snapshot.listen_port);
                // The crate's set_default_route hardcodes NlMtu to 1420
                // ([NT_INTERFACE_MTU]): if the adapter is present the MTU is
                // necessarily this.
                let tunnel_mtu = Some(NT_INTERFACE_MTU);
                let tunnel_address = self.nt_adapter_address(&adapter_name);
                (
                    peers,
                    installed_routes,
                    local_public_key,
                    tunnel_listen_port,
                    tunnel_mtu,
                    tunnel_address,
                )
            }
        };
        Ok(NetworkSnapshot {
            tunnel_exists,
            forwarding_enabled,
            peers,
            installed_routes,
            nat_rules: Vec::new(),
            tunnel_mtu,
            local_public_key,
            tunnel_address,
            tunnel_listen_port,
            // nt model: routes are assembled by the adapter's set_default_route
            // from the peer allowed-ips (see the installed_routes comment above);
            // plan.routes are not issued through netsh.
            // The drift verdict therefore skips the plan.routes comparison (the
            // peer identity-level comparison already fully determines the
            // routes).
            routes_from_peers: true,
        })
    }

    /// The managed interface's usable alias at the OS layer: in the service
    /// model it is `self.interface`; in the nt model it is the OS Name looked up
    /// from the adapter name (`wg-mlt-<handle>`) through
    /// [crate::windows_wireguard_nt::resolve_nt_os_alias].
    ///
    /// Seven-item acceptance item 1 evidence (wgnt-seven-item-2026-11-21.md):
    /// the nt adapter's OS InterfaceAlias is the driver's default name
    /// `WireGuard`, and the tunnel name appears only in the
    /// InterfaceDescription — never pass `wg-mlt-<handle>` or `wg-meshlet`
    /// directly to `Set-NetConnectionProfile`/`Get-NetIPAddress` as the OS
    /// alias.
    /// A resolution failure fails closed (apply is refused); never continue with
    /// a wrong name.
    pub(super) fn effective_interface_alias(&self) -> Result<String, NetworkError> {
        if self.nt.is_some() {
            let adapter_name = nt_adapter_name(&nt_adapter_handle(&self.interface))?;
            crate::windows_wireguard_nt::resolve_nt_os_alias(&adapter_name)
        } else {
            Ok(self.interface.clone())
        }
    }

    /// The nt adapter's address reading: the `Get-NetIPAddress` entries whose
    /// InterfaceAlias equals the OS alias (looked up by InterfaceDescription
    /// through [crate::windows_wireguard_nt::resolve_nt_os_alias] — the tunnel
    /// name `wg-mlt-<handle>` is not the OS alias; see the seven-item acceptance
    /// item 1 evidence). Unreadable -> `None` (missing evidence is never judged;
    /// the same convention as [Self::lan_addresses_sync]).
    fn nt_adapter_address(&self, adapter_name: &str) -> Option<Ipv4Addr> {
        let os_alias = crate::windows_wireguard_nt::resolve_nt_os_alias(adapter_name).ok()?;
        self.lan_ip_entries()
            .ok()?
            .into_iter()
            .find(|(alias, _, _)| alias.eq_ignore_ascii_case(&os_alias))
            .map(|(_, addr, _)| addr)
    }

    /// The nt model's apply entry: [TunnelConfig] -> the adapter plan (the
    /// handle is derived from the interface name,
    /// [crate::windows_wireguard_nt::nt_adapter_handle]) -> runtime assembly.
    /// Returns the effective listen port read back from the driver (used by the
    /// firewall linkage). Plan-layer guard rejections (a missing listen_port, an
    /// MTU other than 1420, a missing peer endpoint, etc.) pass through fail
    /// closed unchanged — the nt model cannot let the driver "pick its own
    /// port" the way the service model can.
    fn nt_apply_tunnel_config(
        &self,
        nt: &NtRuntime,
        tunnel: &TunnelConfig,
    ) -> Result<u16, NetworkError> {
        let handle = nt_adapter_handle(&self.interface);
        let plan = crate::windows_wireguard_nt::nt_interface_plan(tunnel, &handle)?;
        nt.apply(&plan)
    }

    /// The cleanup of the gray-release/rollback surface before the nt model
    /// takes over the data plane: uninstall the old `WireGuardTunnel$<interface>`
    /// service on the same interface (a service-model leftover). Two data planes
    /// (service + nt adapter) on the same address and routes must conflict and
    /// must never coexist — the uninstall stops and deletes it, leaving nothing
    /// beyond the traffic interruption. Idempotent: no service (including never
    /// installed) is skipped; wireguard.exe missing while the service exists
    /// (cannot uninstall) -> an explicit error, fail closed — never switch over
    /// in a broken state.
    pub(super) fn uninstall_stale_service_tunnel_sync(&self) -> Result<(), NetworkError> {
        if !self.tunnel_service_exists(&self.interface) {
            return Ok(());
        }
        let Some(exe) = self.find_wireguard_exe() else {
            return Err(NetworkError::ApplyRejected(format!(
                "stale tunnel service WireGuardTunnel${} must be uninstalled to switch to the \
                 nt model, but wireguard.exe is not available",
                self.interface
            )));
        };
        let command = WireGuardCommand::UninstallService {
            name: self.interface.clone(),
        };
        run_wireguard_command(&command, Some(&exe))?;
        // Logging is the agent layer's job (this crate does not depend on
        // tracing, keeping the data-plane layer silent).
        Ok(())
    }

    /// This host's RFC1918 LAN addresses (reported as the §12 P2P candidate
    /// endpoints). Windows readings go through the `Get-NetIPAddress` JSON
    /// (English field names, locale-independent; netsh output is localized to the
    /// active code page and fragile to parse). Excludes this managed interface /
    /// loopback / Hyper-V vEthernet / Tailscale / other wg interfaces; the
    /// RFC1918 filter drops APIPA (169.254) and CGNAT (100.64/10, Tailscale
    /// addresses), while private segments such as ZeroTier are **kept** (the same
    /// convention as Linux's `is_lan_interface`: every routable private segment is
    /// a candidate).
    pub fn lan_addresses_sync(&self) -> Result<Vec<Ipv4Addr>, NetworkError> {
        let mut addrs: Vec<Ipv4Addr> = self
            .lan_ip_entries()?
            .into_iter()
            .filter(|(alias, _, _)| is_windows_lan_interface(alias, &self.interface))
            .map(|(_, addr, _)| addr)
            .filter(|addr| meshlet_domain::is_private_ip(*addr))
            .collect();
        addrs.sort_unstable();
        addrs.dedup();
        Ok(addrs)
    }

    /// Enumerate this host's RFC1918 LAN **subnets**: the same source as
    /// [`Self::lan_addresses_sync`], but keeping the prefix length (same-segment
    /// detection needs the segment).
    pub fn lan_subnets_sync(&self) -> Result<Vec<meshlet_domain::Ipv4Cidr>, NetworkError> {
        let mut subnets: Vec<meshlet_domain::Ipv4Cidr> = self
            .lan_ip_entries()?
            .into_iter()
            .filter(|(alias, _, _)| is_windows_lan_interface(alias, &self.interface))
            .filter(|(_, addr, _)| meshlet_domain::is_private_ip(*addr))
            // Interface address + prefix -> the owning segment
            // (from_host_address masks off the host bits); an out-of-range prefix
            // (a malformed JSON reading) counts as no subnet and does not swallow
            // the other readings.
            .filter_map(|(_, addr, prefix)| {
                meshlet_domain::Ipv4Cidr::from_host_address(addr, prefix).ok()
            })
            .collect();
        subnets.sort();
        subnets.dedup();
        Ok(subnets)
    }

    /// The `Get-NetIPAddress` JSON reading (locale-independent): a list of
    /// `(alias, address, prefix)`. PowerShell outputs an object for a single
    /// result and an array for many — normalized uniformly as a `Value`.
    fn lan_ip_entries(&self) -> Result<Vec<(String, Ipv4Addr, u8)>, NetworkError> {
        let output = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-NetIPAddress -AddressFamily IPv4 | \
                 Select-Object IPAddress,InterfaceAlias,PrefixLength | \
                 ConvertTo-Json -Compress",
            ])
            .no_window()
            .output()
            .map_err(|error| NetworkError::Io(format!("spawn powershell: {error}")))?;
        if !output.status.success() {
            return Err(NetworkError::ApplyRejected(format!(
                "Get-NetIPAddress failed: {}",
                crate::windows_console::decode_output(&output.stderr)
            )));
        }
        parse_lan_ip_json(&crate::windows_console::decode_output(&output.stdout))
    }

    // The server side's revision.rs / device_plan.rs calls this set of
    // identically-shaped sync methods uniformly through SystemBackend (the
    // Linux/unsupported backends share the signatures); if the Windows backend
    // misses one, it does not compile. Operations whose data plane is not yet
    // wired up always fail closed, never pretending to succeed.
    pub fn clear_hub_sync(&self) -> Result<(), NetworkError> {
        Err(NetworkError::Unsupported(
            "hub isolation clear on Windows is not yet implemented".to_string(),
        ))
    }

    pub fn isolate_hub_sync(&self, _address: Ipv4Addr) -> Result<(), NetworkError> {
        Err(NetworkError::Unsupported(
            "hub isolation on Windows is not yet implemented".to_string(),
        ))
    }

    pub fn apply_tunnel_sync(
        &self,
        _config: &TunnelConfig,
        _keep_keys: &BTreeSet<String>,
    ) -> Result<ApplyResult, NetworkError> {
        Err(NetworkError::Unsupported(
            "tunnel apply (sync entry) on Windows is not yet implemented".to_string(),
        ))
    }

    pub fn apply_routes_sync(&self, _routes: &[RouteConfig]) -> Result<ApplyResult, NetworkError> {
        Err(NetworkError::Unsupported(
            "route apply (sync entry) on Windows is not yet implemented".to_string(),
        ))
    }

    pub fn apply_device_plan_sync(
        &mut self,
        plan: &DevicePlan,
        private_key: Option<String>,
        _gateway_lan_addr: Option<std::net::Ipv4Addr>,
        _keep_keys: &BTreeSet<String>,
    ) -> Result<(), NetworkError> {
        // §kernel drift: IP forwarding is the convergence precondition of
        // drifted() (mirroring Linux's ip_forward=1). It runs before any tunnel
        // change — a failure fails closed, never leaving a half-applied state
        // after touching the tunnel.
        self.ensure_ip_forwarding_sync()?;
        // The shared tunnel config: the service model renders the conf, the nt
        // model goes straight to adapter assembly — both models share the same
        // plan, the same hub_endpoint fallback, and the same private key
        // semantics.
        let tunnel_config = TunnelConfig {
            name: self.interface.clone(),
            address: plan.tunnel.address,
            address_prefix: plan.tunnel.address_prefix,
            listen_port: plan.tunnel.listen_port,
            peers: plan
                .tunnel
                .peers
                .iter()
                .map(|p| {
                    let mut peer = p.clone();
                    if peer.endpoint.is_none() {
                        peer.endpoint = self.hub_endpoint.clone();
                    }
                    peer
                })
                .collect(),
            mtu: plan.tunnel.mtu,
            private_key,
        };
        // nt model (tunnel_backend="nt"): no wireguard.exe — the dll-embedded
        // bindings. The firewall linkage uses the effective port read back from
        // the adapter (module discipline: the read-back is authoritative, not the
        // requested value).
        if let Some(nt) = &self.nt {
            // Uninstall the service-model leftover tunnel before taking over
            // (the two data planes must never coexist; see the method doc).
            self.uninstall_stale_service_tunnel_sync()?;
            let listen_port = self.nt_apply_tunnel_config(nt, &tunnel_config)?;
            self.ensure_mesh_reachability_sync(tunnel_config.address)?;
            self.ensure_direct_udp_firewall_sync(listen_port)?;
            return Ok(());
        }
        let exe = self.find_wireguard_exe().ok_or_else(|| {
            NetworkError::Unsupported("WireGuard for Windows is not installed".to_string())
        })?;
        let conf = render_wireguard_conf(&tunnel_config);
        // WIN-PORT-1 defect ②: the conf goes to ProgramData (a restricted-token
        // tunnel service cannot read the user session's temp). The directory's ACL
        // is tightened before writing the file — a new file inherits the tightened
        // ACL from creation on, so the private key never sits in a wide-inheritance
        // window; after writing, the file itself is tightened once more as a
        // backstop.
        let conf_path = crate::windows_tunnel::tunnel_conf_path(&self.interface);
        ensure_conf_dir_acl(&crate::windows_tunnel::tunnel_conf_dir())?;
        write_tunnel_conf(&conf_path, &conf)?;
        ensure_conf_file_acl(&conf_path)?;
        self.install_tunnel_reconfigured(&exe, &conf_path)?;
        for route in &plan.routes {
            let netsh_cmd = crate::windows_routes::NetshRouteCommand::Add {
                route: route.clone(),
            };
            run_route_command(&netsh_cmd)?;
        }
        // AGENT-FW-1: the mesh reachability firewall (the Private profile plus an
        // ICMPv4 allowance, idempotent).
        // It runs after the tunnel and the routes (the profile command needs the
        // interface to exist); a failure reports an explicit error instead of
        // pretending it took effect — on a real machine "ping just works" belongs
        // to the acceptance walkthrough, see todo.md AGENT-FW-1.
        self.ensure_mesh_reachability_sync(plan.tunnel.address)?;
        // P2P batch ④ Windows wiring: when direct connect is on, the plan pins
        // the data-plane tunnel to a fixed listen port
        // (plan.tunnel.listen_port = Some(port)), and the firewall linkage allows
        // that UDP port — without the rule, the peer's inbound handshake packets
        // are dropped by the Public profile's default policy. Same conditions and
        // the same idempotency discipline as Linux's
        // ensure_direct_udp_firewall_sync.
        if let Some(port) = plan.tunnel.listen_port {
            self.ensure_direct_udp_firewall_sync(port)?;
        }
        Ok(())
    }
}

impl Default for WindowsNetworkBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkBackend for WindowsNetworkBackend {
    async fn inspect(&self) -> Result<NetworkSnapshot, NetworkError> {
        self.inspect_sync()
    }

    async fn apply_tunnel(&self, config: TunnelConfig) -> Result<ApplyResult, NetworkError> {
        if let Some(nt) = &self.nt {
            self.uninstall_stale_service_tunnel_sync()?;
            self.nt_apply_tunnel_config(nt, &config)?;
            return Ok(ApplyResult::ok());
        }
        let exe = self.find_wireguard_exe().ok_or_else(|| {
            NetworkError::Unsupported("WireGuard for Windows is not installed".to_string())
        })?;
        let conf = render_wireguard_conf(&config);
        // The same convention as apply_device_plan_sync (WIN-PORT-1 defect ②):
        // the conf goes to ProgramData plus tightened directory/file ACLs —
        // readable by the restricted-token service, unreadable by ordinary
        // users.
        let conf_path = crate::windows_tunnel::tunnel_conf_path(&config.name);
        ensure_conf_dir_acl(&crate::windows_tunnel::tunnel_conf_dir())?;
        write_tunnel_conf(&conf_path, &conf)?;
        ensure_conf_file_acl(&conf_path)?;
        // The same path as apply_device_plan_sync: an existing service must be
        // stopped/uninstalled/fitted with the new conf — never treat
        // "already installed" as success (that would silently keep the old
        // key/address).
        self.install_tunnel_reconfigured(&exe, &conf_path)?;
        Ok(ApplyResult::ok())
    }

    async fn apply_routes(
        &mut self,
        routes: Vec<RouteConfig>,
    ) -> Result<ApplyResult, NetworkError> {
        // In the nt model, routes are assembled by the adapter's
        // set_default_route (the peer allowed_ips) and never through netsh —
        // calling this method standalone would duplicate or misalign with the
        // driver routes, so it is explicitly refused rather than pretending to
        // succeed (the production path goes through apply_device_plan_sync and
        // never reaches here).
        if self.nt.is_some() {
            return Err(NetworkError::Unsupported(
                "route apply via netsh is not used with the wireguard-nt backend; \
                 routes are applied by the adapter allowed_ips"
                    .to_string(),
            ));
        }
        let mut errors = Vec::new();
        for route in routes {
            let netsh_cmd = crate::windows_routes::NetshRouteCommand::Add {
                route: route.clone(),
            };
            match run_route_command(&netsh_cmd) {
                Ok(result) => {
                    if let Some(err) = result.error {
                        errors.push(err);
                    }
                }
                Err(e) => errors.push(e.to_string()),
            }
        }
        if errors.is_empty() {
            Ok(ApplyResult::ok())
        } else {
            Ok(ApplyResult::failed(errors.join("; ")))
        }
    }

    async fn apply_nat(
        &self,
        _rules: Vec<NatRule>,
        _gateway_lan_addr: Ipv4Addr,
    ) -> Result<ApplyResult, NetworkError> {
        Err(NetworkError::Unsupported(
            "NAT rule management on Windows is not yet implemented".to_string(),
        ))
    }

    async fn remove_nat<'s>(&'s self, _owner: &'s str) -> Result<ApplyResult, NetworkError> {
        Err(NetworkError::Unsupported(
            "NAT rule removal on Windows is not yet implemented".to_string(),
        ))
    }

    async fn rollback(&self, _revision: ConfigRevisionRef) -> Result<ApplyResult, NetworkError> {
        // nt model: the adapter dies with the handle — taking it out of the
        // runtime and dropping it is the rollback; holding none (already rolled
        // back / never applied) counts as an idempotent success.
        if let Some(nt) = &self.nt {
            let adapter_name = nt_adapter_name(&nt_adapter_handle(&self.interface))?;
            nt.remove(&adapter_name);
            return Ok(ApplyResult::ok());
        }
        let command = WireGuardCommand::UninstallService {
            name: self.interface.clone(),
        };
        match self.find_wireguard_exe() {
            Some(exe) => run_wireguard_command(&command, Some(&exe)),
            None => Err(NetworkError::Unsupported(
                "WireGuard for Windows is not installed".to_string(),
            )),
        }
    }
}
