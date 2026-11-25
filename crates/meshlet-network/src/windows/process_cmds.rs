use super::backend::WindowsNetworkBackend;
use super::parsing::parse_ip_enable_router;
use crate::windows_console::NoWindowCommand;
use crate::NetworkError;

impl WindowsNetworkBackend {
    pub(super) fn tunnel_service_exists(&self, tunnel_name: &str) -> bool {
        let service_name = format!("WireGuardTunnel${tunnel_name}");
        std::process::Command::new("sc")
            .args(["query", &service_name])
            .no_window()
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    }

    pub(super) fn forwarding_enabled(&self) -> Option<bool> {
        let output = std::process::Command::new("reg")
            .args([
                "query",
                r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                "/v",
                "IPEnableRouter",
            ])
            .no_window()
            .output()
            .ok()?;
        parse_ip_enable_router(&String::from_utf8_lossy(&output.stdout))
    }

    /// Make sure IP forwarding is enabled (mirrors Linux
    /// `sysctl -w net.ipv4.ip_forward=1`).
    ///
    /// `forwarding_enabled` in [crate::NetworkSnapshot] reads the `IPEnableRouter`
    /// registry value; [the drift verdict in `apps/agent`] requires it to be
    /// `Some(true)`, otherwise `KernelDrift` replays every round. Windows
    /// clients default to missing / 0, so it must be set to 1 here to converge
    /// (idempotent: skip when already 1 — the `/f` overwrite write happens only
    /// on an actual change).
    pub(super) fn ensure_ip_forwarding_sync(&self) -> Result<(), NetworkError> {
        if self.forwarding_enabled() == Some(true) {
            return Ok(());
        }
        let status = std::process::Command::new("reg")
            .args([
                "add",
                r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                "/v",
                "IPEnableRouter",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f",
            ])
            .no_window()
            .status()
            .map_err(|error| {
                NetworkError::Io(format!(
                    "enable IP forwarding (reg add IPEnableRouter): {error}"
                ))
            })?;
        if !status.success() {
            return Err(NetworkError::ApplyRejected(
                "enable IP forwarding failed: `reg add IPEnableRouter=1` did not succeed \
                 (run the agent elevated)"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// AGENT-FW-1 wiring: on device plan apply, run the mesh reachability
    /// firewall per the profile category.
    ///
    /// Mirrors the discipline of Linux `ensure_host_firewall_sync` — a probe
    /// failure is treated as "not satisfied" (fail toward action; both the
    /// category set and the rule add are idempotent), while an execution failure
    /// reports an explicit error and never pretends to have taken effect. Called
    /// after the tunnel and routes: `SetNetworkCategoryPrivate` needs the
    /// interface to already exist.
    pub(super) fn ensure_mesh_reachability_sync(
        &self,
        device_addr: std::net::Ipv4Addr,
    ) -> Result<(), NetworkError> {
        // Under the nt model `self.interface` (e.g. `wg-meshlet`) is not an OS
        // alias (a WireGuardNT adapter's OS alias is the driver default name
        // `WireGuard`; the tunnel name appears only in
        // InterfaceDescription — seven-item acceptance item 1 evidence). Both
        // probe and set use the resolved OS alias; the service model path is
        // unchanged.
        let interface = self.effective_interface_alias()?;
        let category_is_private = self.probe_net_category_is_private(&interface);
        let icmp_rule_state = self.probe_icmp_rule_state(device_addr);
        let commands = crate::windows_firewall::mesh_reachability_commands(
            &interface,
            device_addr,
            category_is_private,
            icmp_rule_state,
        )?;
        for command in &commands {
            crate::windows_firewall::exec::run_mesh_firewall_command(command)?;
        }
        Ok(())
    }

    /// `(Get-NetConnectionProfile -InterfaceAlias <if>).NetworkCategory` probe:
    /// exit 0 with a Private value → already satisfied; interface not found /
    /// command failure → not satisfied (prefer setting it over missing it —
    /// the category set is naturally idempotent). Only the category value is
    /// read, never searching for `private` anywhere in the whole output —
    /// otherwise a Public profile whose connection name contains that word
    /// would be misjudged (review finding #4). `interface` is the OS-layer
    /// alias the caller has already resolved (see
    /// [Self::effective_interface_alias]).
    pub(super) fn probe_net_category_is_private(&self, interface: &str) -> bool {
        let Ok(output) = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "(Get-NetConnectionProfile -InterfaceAlias '{}').NetworkCategory",
                    interface
                ),
            ])
            .no_window()
            .output()
        else {
            return false;
        };
        if !output.status.success() {
            return false;
        }
        crate::windows_firewall::net_category_is_private(&String::from_utf8_lossy(&output.stdout))
    }

    /// Presence state of
    /// `netsh advfirewall firewall show rule name=Meshlet-ICMPv4-In`.
    ///
    /// Judging presence by name alone misreports satisfied after an address
    /// change or after a same-named rule gets disabled (review finding #1):
    /// each block must be checked for "enabled and localip matching the current
    /// device address". netsh output is encoded in the active code page, so this
    /// uses the GBK fallback decode.
    pub(super) fn probe_icmp_rule_state(
        &self,
        device_addr: std::net::Ipv4Addr,
    ) -> crate::windows_firewall::IcmpRuleState {
        let Ok(output) = std::process::Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "show",
                "rule",
                "name=Meshlet-ICMPv4-In",
            ])
            .no_window()
            .output()
        else {
            return crate::windows_firewall::IcmpRuleState::Absent;
        };
        if !output.status.success() {
            return crate::windows_firewall::IcmpRuleState::Absent;
        }
        let text = format!(
            "{}{}",
            crate::windows_console::decode_output(&output.stdout),
            crate::windows_console::decode_output(&output.stderr),
        );
        if !crate::windows_firewall::firewall_rule_present(&text) {
            return crate::windows_firewall::IcmpRuleState::Absent;
        }
        if crate::windows_firewall::rule_output_has_satisfied_icmp_rule(&text, device_addr) {
            crate::windows_firewall::IcmpRuleState::Satisfied
        } else {
            crate::windows_firewall::IcmpRuleState::Stale
        }
    }

    /// Inbound allowance for the direct-connect UDP port (batch ④ Windows
    /// wiring): the `Meshlet-Direct-UDP-In` rule (protocol=udp /
    /// localport=<port> / profile=any). Present with a matching port → skip;
    /// present but the port has changed (review finding #3) → first
    /// `delete name=<rule>` to clear all old-port rules of the same name, then
    /// add — netsh stacking duplicate entries on repeated same-name adds means
    /// adding without clearing would allow both the old and the new port after
    /// port drift.
    pub(super) fn ensure_direct_udp_firewall_sync(&self, port: u16) -> Result<(), NetworkError> {
        let output = self.direct_udp_rule_output();
        if crate::windows_firewall::firewall_rule_present(&output) {
            if crate::windows_firewall::rule_output_mentions_port(&output, port) {
                return Ok(());
            }
            // Port drift: clear the same-named rule (delete by name removes all
            // same-named entries, idempotent), then fall through to the add
            // below to rebuild the rule for the current port.
            let cleanup = crate::windows_firewall::FirewallRuleCommand::Delete {
                name: crate::windows_firewall::DIRECT_UDP_RULE_NAME.into(),
            };
            let result = crate::windows_firewall::exec::run_firewall_command(&cleanup)?;
            if !result.applied {
                return Err(NetworkError::ApplyRejected(format!(
                    "stale direct UDP firewall rule not removed: {}",
                    result.error.as_deref().unwrap_or("unknown")
                )));
            }
        }
        let command = crate::windows_firewall::FirewallRuleCommand::Add {
            rule: crate::windows_firewall::direct_udp_rule(port),
        };
        let result = crate::windows_firewall::exec::run_firewall_command(&command)?;
        if result.applied {
            return Ok(());
        }
        Err(NetworkError::ApplyRejected(format!(
            "direct UDP firewall rule not applied: {}",
            result.error.as_deref().unwrap_or("unknown")
        )))
    }

    /// Output of
    /// `netsh advfirewall firewall show rule name=Meshlet-Direct-UDP-In`
    /// (GBK fallback decode; command failure / spawn failure → empty text,
    /// treated as absent).
    fn direct_udp_rule_output(&self) -> String {
        std::process::Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "show",
                "rule",
                &format!("name={}", crate::windows_firewall::DIRECT_UDP_RULE_NAME),
            ])
            .no_window()
            .output()
            .map(|out| {
                format!(
                    "{}{}",
                    crate::windows_console::decode_output(&out.stdout),
                    crate::windows_console::decode_output(&out.stderr),
                )
            })
            .unwrap_or_default()
    }
}
