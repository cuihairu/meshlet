use super::backend::WindowsNetworkBackend;
use super::parsing::mask_to_prefix;

impl WindowsNetworkBackend {
    /// 受管接口的 MTU（`netsh interface ipv4 show subinterfaces`）。
    /// 读不到（接口未起 / 命令失败）→ `None`，漂移判定对未显式配置 MTU 的
    /// 计划不触发；显式 MTU 计划则由 [Self::inspect_sync] 的 `tunnel_mtu`
    /// 驱动（不再恒 None 导致的永不收敛）。
    pub(super) fn interface_mtu(&self) -> Option<u32> {
        let output = std::process::Command::new("netsh")
            .args(["interface", "ipv4", "show", "subinterfaces"])
            .output()
            .ok()?;
        crate::windows_tunnel::parse_netsh_subinterface_mtu(
            &String::from_utf8_lossy(&output.stdout),
            &self.interface,
        )
    }

    pub(super) fn routes_on_interface(&self) -> Vec<meshlet_domain::Ipv4Cidr> {
        let output = std::process::Command::new("netsh")
            .args(["interface", "ipv4", "show", "routes"])
            .output()
            .ok();
        let Some(out) = output else { return Vec::new() };
        let text = String::from_utf8_lossy(&out.stdout);
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
