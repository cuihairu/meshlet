use super::backend::WindowsNetworkBackend;
use super::parsing::parse_netsh_interface_ipv4_address;
use crate::windows_console::NoWindowCommand;
use crate::windows_tunnel::exec::run_wireguard_command;
use crate::windows_wireguard_nt::{nt_adapter_handle, nt_adapter_name};
use crate::{NetworkError, PeerObserved};
use meshlet_domain::Ipv4Cidr;
use std::path::PathBuf;

impl WindowsNetworkBackend {
    /// Tunnel service install (reconfiguration correctness, BUG fix): existing →
    /// stop/uninstall/install new conf; absent → install directly. After install, poll
    /// `sc query` until the service is RUNNING (error out when no running evidence can
    /// be read, never pretend it took effect — apply_device_plan_sync does a kernel
    /// read-back afterwards; this only guarantees "the service is really up").
    pub(super) fn install_tunnel_reconfigured(
        &self,
        exe: &std::path::Path,
        conf_path: &std::path::Path,
    ) -> Result<(), NetworkError> {
        let existing = self.tunnel_service_exists(&self.interface);
        for command in crate::windows_tunnel::install_plan(existing, &self.interface, conf_path) {
            if matches!(
                command,
                crate::windows_tunnel::WireGuardCommand::UninstallService { .. }
            ) {
                run_wireguard_command(&command, Some(exe))?;
                // Uninstall only sends a stop signal: the old service process takes
                // time to exit and still holds the conf file until it does. If the
                // new service starts right away and reads the same conf, it fails to
                // come up with "The process cannot access the file because it is
                // being used by another process" (real-machine imac 2026-11-07 event
                // log: 7045 install → 7023 stop failing in a chain, the tunnel never
                // comes up). Wait for the old service to fully exit before installing.
                self.wait_tunnel_service_gone(&self.interface);
                continue;
            }
            run_wireguard_command(&command, Some(exe))?;
        }
        self.wait_tunnel_service_running(&self.interface)
    }

    /// Poll until the old tunnel service has fully exited (no longer RUNNING in the
    /// SCM / deleted), at most about 4s; on timeout still proceed with the install
    /// (give it one chance — never let apply deadlock waiting for exit).
    fn wait_tunnel_service_gone(&self, tunnel_name: &str) {
        let service = crate::windows_tunnel::tunnel_service_query_name(tunnel_name);
        for _ in 0..16 {
            if self.sc_query_state_code(&service) != Some(4) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }

    /// Poll `sc query WireGuardTunnel$<name>` until RUNNING (after installing the
    /// service the driver needs a moment to bring the tunnel up); timeout
    /// (about 5s) → fail explicitly.
    fn wait_tunnel_service_running(&self, tunnel_name: &str) -> Result<(), NetworkError> {
        let service = crate::windows_tunnel::tunnel_service_query_name(tunnel_name);
        for _ in 0..20 {
            if self.sc_query_state_code(&service) == Some(4) {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        Err(NetworkError::ApplyRejected(format!(
            "tunnel service `{service}` did not reach RUNNING within 5s after install"
        )))
    }

    /// Numeric state code from `sc query <service>` (zh/en dual-label parsing lives
    /// in [windows_tunnel::parse_sc_query_state_code]); command failure /
    /// unparseable → None.
    fn sc_query_state_code(&self, service: &str) -> Option<u32> {
        let output = std::process::Command::new("sc")
            .args(["query", service])
            .no_window()
            .output()
            .ok()?;
        let text = format!(
            "{}{}",
            crate::windows_console::decode_output(&output.stdout),
            crate::windows_console::decode_output(&output.stderr),
        );
        crate::windows_tunnel::parse_sc_query_state_code(&text)
    }

    pub(super) fn read_tunnel_peers(&self, tunnel_name: &str) -> Vec<PeerObserved> {
        // Drift probe: read back the peers actually in effect from
        // `wg.exe show <name> dump`. Always return empty when it cannot be read
        // (wg.exe missing / tunnel not running / malformed output) — the caller
        // treats absence as "does not match expectations" and prefers reinstalling
        // to converge; never pretend to be consistent just because a reading is
        // missing.
        match self.read_tunnel_dump(tunnel_name) {
            Some(text) => crate::windows_tunnel::parse_wg_dump_peers(&text),
            None => Vec::new(),
        }
    }

    /// Raw text of `wg.exe show <name> dump` (interface line + peer lines; decoding
    /// uses the [windows_console] active code page fallback). Unreadable → None.
    pub(super) fn read_tunnel_dump(&self, tunnel_name: &str) -> Option<String> {
        let exe = self.find_wg_exe()?;
        let out = std::process::Command::new(&exe)
            .args(["show", tunnel_name, "dump"])
            .no_window()
            .output()
            .ok()?;
        Some(format!(
            "{}{}",
            crate::windows_console::decode_output(&out.stdout),
            crate::windows_console::decode_output(&out.stderr),
        ))
    }

    /// Actual IPv4 address of the managed interface adapter (parsed from
    /// `netsh interface ipv4 show addresses name=<if>`; the adapter-address
    /// reading used for drift detection, BUG②). Unreadable → None.
    pub(super) fn interface_address(&self) -> Option<std::net::Ipv4Addr> {
        let output = std::process::Command::new("netsh")
            .args(["interface", "ipv4", "show", "addresses", &self.interface])
            .no_window()
            .output()
            .ok()?;
        let text = format!(
            "{}{}",
            crate::windows_console::decode_output(&output.stdout),
            crate::windows_console::decode_output(&output.stderr),
        );
        parse_netsh_interface_ipv4_address(&text)
    }

    /// Resolve the `wg.exe` path (same discipline as [Self::find_wireguard_exe]:
    /// WireGuard for Windows installs wg.exe and wireguard.exe in the same
    /// directory, so prefer reusing that directory).
    pub(super) fn find_wg_exe(&self) -> Option<PathBuf> {
        if let Some(wireguard) = self.find_wireguard_exe() {
            if let Some(dir) = wireguard.parent() {
                let candidate = dir.join("wg.exe");
                if candidate.exists() {
                    return Some(candidate);
                }
            }
        }
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                let candidate = dir.join("wg.exe");
                if candidate.exists() {
                    return Some(candidate);
                }
            }
        }
        None
    }

    /// Private key → public key (pure Curve25519, x25519-dalek RFC 7748
    /// clamping, isomorphic to `wg pubkey` — the semantic anchor in keys.rs).
    /// The server uses this to fill in the hub peer public key it sends down to
    /// devices, ADR-010.
    ///
    /// No longer depends on `wg.exe`: the nt model (wireguard-nt embedded
    /// bindings) needs no WireGuard for Windows installation, so `wg.exe` may be
    /// absent — ledger public key fingerprint derivation must hold under both
    /// models.
    pub fn public_key_from_private(&self, private_key: &str) -> Result<String, NetworkError> {
        crate::keys::public_from_private(private_key).map_err(NetworkError::Io)
    }

    /// P2P direct connect execution layer (§12): `wg.exe show <if>
    /// latest-handshakes` → public key → age in seconds. Same parser as Linux
    /// ([crate::parse_handshake_ages]).
    pub fn handshake_ages_sync(
        &self,
    ) -> Result<std::collections::BTreeMap<String, u64>, NetworkError> {
        // nt model: handshake ages come from the driver get_config
        // last_handshake (no wg.exe needed; the service model uses
        // `wg show <if> latest-handshakes` with the same semantics).
        if let Some(nt) = &self.nt {
            let adapter_name = nt_adapter_name(&nt_adapter_handle(&self.interface))?;
            return nt.handshake_ages(&adapter_name);
        }
        let exe = self.find_wg_exe().ok_or_else(|| {
            NetworkError::Unsupported(
                "wg.exe not found. Install WireGuard for Windows.".to_string(),
            )
        })?;
        let out = std::process::Command::new(&exe)
            .args(["show", &self.interface, "latest-handshakes"])
            .no_window()
            .output()
            .map_err(|error| NetworkError::Io(format!("spawn wg.exe: {error}")))?;
        if !out.status.success() {
            return Err(NetworkError::ApplyRejected(format!(
                "wg show {} latest-handshakes: {}",
                self.interface,
                crate::windows_console::decode_output(&out.stderr)
            )));
        }
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Ok(crate::parse_handshake_ages(
            &crate::windows_console::decode_output(&out.stdout),
            now_secs,
        ))
    }

    /// P2P direct connect peer push (§12): `wg.exe set <if> peer …` — same
    /// parameter shape as Linux
    /// [`crate::linux::LinuxNetworkBackend::set_direct_peer_sync`]
    /// (allowed-ips peer overlay /32 + endpoint + persistent-keepalive).
    /// WireGuardNT adapters support runtime `wg set` (equally applicable to
    /// adapters created by the wireguard.exe tunnel service), so no tunnel
    /// reinstall is needed; writing requires elevation (the agent runs as admin).
    /// Idempotent: repeated calls yield the same result.
    ///
    /// Note: reinstalling the tunnel (apply) resets runtime peers — the caller
    /// (agent) re-pushes every tick, matching Linux's reconcile semantics.
    pub fn set_direct_peer_sync(
        &self,
        public_key: &str,
        allowed_ips: &[Ipv4Cidr],
        endpoint: std::net::SocketAddrV4,
        persistent_keepalive_secs: u32,
    ) -> Result<(), NetworkError> {
        let allowed = allowed_ips
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let endpoint = endpoint.to_string();
        let keepalive = persistent_keepalive_secs.to_string();
        self.run_wg_set(&[
            "peer",
            public_key,
            "allowed-ips",
            &allowed,
            "endpoint",
            &endpoint,
            "persistent-keepalive",
            &keepalive,
        ])
    }

    /// P2P direct connect peer removal (fall back to hub, §12):
    /// `wg.exe set <if> peer <key> remove`. Idempotent: succeeds even when absent
    /// (WireGuard treats removing a missing peer as a no-op).
    pub fn remove_peer_sync(&self, public_key: &str) -> Result<(), NetworkError> {
        self.run_wg_set(&["peer", public_key, "remove"])
    }

    /// SEL-002 direct connect endpoint roaming:
    /// `wg.exe set <if> peer <key> endpoint <ip:port>`. WireGuard changes a
    /// peer's endpoint seamlessly (existing handshakes are not dropped).
    /// Idempotent.
    pub fn set_direct_endpoint_sync(
        &self,
        public_key: &str,
        endpoint: std::net::SocketAddrV4,
    ) -> Result<(), NetworkError> {
        let endpoint = endpoint.to_string();
        self.run_wg_set(&["peer", public_key, "endpoint", &endpoint])
    }

    /// `wg.exe set <if> <args>`: mutate the managed adapter at runtime (silent on
    /// success; on failure carries wg.exe stderr text — insufficient privileges /
    /// missing adapter are all readable there).
    ///
    /// The interface name must go through [Self::effective_interface_alias]:
    /// service model = `self.interface`; nt model = OS alias (`WireGuard`).
    /// **Never use `self.interface` directly** — under the nt model it is the
    /// config value `wg-meshlet`, while `wg.exe set` addresses adapters by OS
    /// alias, and `wg-meshlet` does not exist → every call ends in
    /// `wg set wg-meshlet: Unable to modify interface: No such file or
    /// directory`, so the direct fast path can never be established under the nt
    /// model (wgnt-seven-item 2026-11-22 adjacent finding ①; the nt adapter
    /// itself supports runtime `wg set`, see the `set_direct_peer_sync` docs in
    /// this module).
    fn run_wg_set(&self, args: &[&str]) -> Result<(), NetworkError> {
        let interface = self.effective_interface_alias()?;
        let exe = self.find_wg_exe().ok_or_else(|| {
            NetworkError::Unsupported(
                "wg.exe not found. Install WireGuard for Windows.".to_string(),
            )
        })?;
        let out = std::process::Command::new(&exe)
            .arg("set")
            .arg(&interface)
            .args(args)
            .no_window()
            .output()
            .map_err(|error| NetworkError::Io(format!("spawn wg.exe: {error}")))?;
        if out.status.success() {
            return Ok(());
        }
        Err(NetworkError::ApplyRejected(format!(
            "wg set {}: {}",
            interface,
            crate::windows_console::decode_output(&out.stderr)
        )))
    }
}
