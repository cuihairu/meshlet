use super::backend::WindowsNetworkBackend;
use super::parsing::mask_to_prefix;
use crate::windows_console::NoWindowCommand;

impl WindowsNetworkBackend {
    /// MTU of the managed interface (`netsh interface ipv4 show subinterfaces`).
    /// Nothing readable (interface not up / command failure) → `None`; the drift
    /// verdict does not fire for plans that do not set MTU explicitly, while an
    /// explicit MTU plan is driven by `tunnel_mtu` from [Self::inspect_sync]
    /// (no longer permanently None, which used to mean never converging).
    pub(super) fn interface_mtu(&self) -> Option<u32> {
        let output = std::process::Command::new("netsh")
            .args(["interface", "ipv4", "show", "subinterfaces"])
            .no_window()
            .output()
            .ok()?;
        crate::windows_tunnel::parse_netsh_subinterface_mtu(
            &crate::windows_console::decode_output(&output.stdout),
            &self.interface,
        )
    }

    pub(super) fn routes_on_interface(&self) -> Vec<meshlet_domain::Ipv4Cidr> {
        let output = std::process::Command::new("netsh")
            .args(["interface", "ipv4", "show", "routes"])
            .no_window()
            .output()
            .ok();
        let Some(out) = output else { return Vec::new() };
        let text = crate::windows_console::decode_output(&out.stdout);
        let mut routes = Vec::new();
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4
                && parts[0].contains('.')
                && parts[3].eq_ignore_ascii_case(&self.interface)
            {
                if let Ok(cidr) = format!("{}/{}", parts[0], mask_to_prefix(parts[1]))
                    .parse::<meshlet_domain::Ipv4Cidr>()
                {
                    routes.push(cidr);
                }
            }
        }
        routes
    }
}
