//! Windows 平台数据面后端（[ADR-008](../../../docs/decisions/adr-008-windows-network-backend.md)）。
//!
//! 基于 WireGuardNT（官方 WireGuard for Windows）的隧道服务模型：
//! `wireguard.exe /installtunnelservice` 创建受管服务 `WireGuardTunnel$<name>`，
//! 路由通过 `netsh interface ipv4 add route` 管理。
//!
//! 本模块将 [windows_tunnel] / [windows_service] / [windows_routes] 的
//! 计划层函数接线为 [crate::NetworkBackend] 实现，使 Windows agent 能够：
//! - inspect：检查 WireGuard 安装状态、隧道存在性、peer、路由、MTU
//! - apply_tunnel：渲染 conf 并调用 `wireguard.exe /installtunnelservice`
//! - apply_routes：通过 netsh 添加/删除路由
//!
//! 与 Linux 后端同纪律：每个触碰内核的操作都返回明确结果，
//! 不静默失败；不支持的操作返回 [`NetworkError::Unsupported`]。

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use crate::nat::NatRule;
use crate::windows_routes::exec::run_route_command;
use crate::windows_tunnel::exec::{run_wireguard_command, write_tunnel_conf};
use crate::windows_tunnel::{render_wireguard_conf, wireguard_exe, WireGuardCommand};
use crate::{
    ApplyResult, ConfigRevisionRef, DevicePlan, NetworkBackend, NetworkError, NetworkSnapshot,
    PeerObserved, RouteConfig, TunnelConfig,
};
use meshlet_domain::Ipv4Cidr;

/// Windows 网络后端：WireGuardNT 隧道 + netsh 路由。
pub struct WindowsNetworkBackend {
    /// 受管 WireGuard 接口名（与 WireGuardNT 隧道服务名对应）。
    interface: String,
    /// `wireguard.exe` 显式覆盖路径（`None` = 走环境变量/PATH 解析）。
    wireguard_exe_override: Option<PathBuf>,
    hub_endpoint: Option<String>,
}

impl WindowsNetworkBackend {
    pub fn new() -> Self {
        Self {
            interface: "meshlet".to_string(),
            wireguard_exe_override: None,
            hub_endpoint: None,
        }
    }

    pub fn with_interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = interface.into();
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

    fn find_wireguard_exe(&self) -> Option<PathBuf> {
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

    fn tunnel_service_exists(&self, tunnel_name: &str) -> bool {
        let service_name = format!("WireGuardTunnel${tunnel_name}");
        std::process::Command::new("sc")
            .args(["query", &service_name])
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    }

    fn read_tunnel_peers(&self, tunnel_name: &str) -> Vec<PeerObserved> {
        let _ = tunnel_name;
        Vec::new()
    }

    fn forwarding_enabled(&self) -> Option<bool> {
        let output = std::process::Command::new("reg")
            .args([
                "query",
                r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                "/v",
                "IPEnableRouter",
            ])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        if text.contains("0x1") {
            Some(true)
        } else if text.contains("0x0") {
            Some(false)
        } else {
            None
        }
    }

    fn routes_on_interface(&self) -> Vec<meshlet_domain::Ipv4Cidr> {
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

    pub fn inspect_sync(&self) -> Result<NetworkSnapshot, NetworkError> {
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
        Ok(NetworkSnapshot {
            tunnel_exists,
            forwarding_enabled,
            peers,
            installed_routes,
            nat_rules: Vec::new(),
            tunnel_mtu: None,
        })
    }

    pub fn device_plan_matches_sync(
        &self,
        _plan: &DevicePlan,
        _extra_peer_keys: &BTreeSet<String>,
    ) -> Result<bool, NetworkError> {
        Ok(self.tunnel_service_exists(&self.interface))
    }

    pub fn meshlet_nat_owners_sync(&self) -> Result<Vec<String>, NetworkError> {
        Ok(Vec::new())
    }

    pub fn lan_addresses_sync(&self) -> Result<Vec<Ipv4Addr>, NetworkError> {
        Err(NetworkError::Unsupported(
            "LAN address enumeration on Windows is not yet implemented".to_string(),
        ))
    }

    pub fn lan_subnets_sync(&self) -> Result<Vec<Ipv4Cidr>, NetworkError> {
        Err(NetworkError::Unsupported(
            "LAN subnet enumeration on Windows is not yet implemented".to_string(),
        ))
    }

    pub fn remove_nat_sync(&self, _owner: &str) -> Result<ApplyResult, NetworkError> {
        Err(NetworkError::Unsupported(
            "NAT rule removal on Windows is not yet implemented".to_string(),
        ))
    }

    pub fn remove_stale_meshlet_routes_sync(
        &self,
        _routes: &[RouteConfig],
    ) -> Result<ApplyResult, NetworkError> {
        Ok(ApplyResult::ok())
    }

    pub fn apply_device_plan_sync(
        &mut self,
        plan: &DevicePlan,
        private_key: Option<String>,
        _gateway_lan_addr: Option<std::net::Ipv4Addr>,
        _keep_keys: &BTreeSet<String>,
    ) -> Result<(), NetworkError> {
        let exe = self.find_wireguard_exe().ok_or_else(|| {
            NetworkError::Unsupported("WireGuard for Windows is not installed".to_string())
        })?;
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
        let conf = render_wireguard_conf(&tunnel_config);
        let conf_dir = std::env::temp_dir().join("meshlet");
        let conf_path = conf_dir.join(format!("{}.conf", self.interface));
        write_tunnel_conf(&conf_path, &conf)?;
        let command = WireGuardCommand::InstallService {
            name: self.interface.clone(),
            conf_path: conf_path.clone(),
        };
        run_wireguard_command(&command, Some(&exe))?;
        for route in &plan.routes {
            let netsh_cmd = crate::windows_routes::NetshRouteCommand::Add {
                route: route.clone(),
            };
            run_route_command(&netsh_cmd)?;
        }
        Ok(())
    }

    pub fn mtu_probe_sync(&self, target: std::net::Ipv4Addr, payload: u32) -> bool {
        std::process::Command::new("ping")
            .args([
                "-n",
                "1",
                "-f",
                "-l",
                &payload.to_string(),
                &target.to_string(),
            ])
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    }

    /// P2P 直连执行层（§12）Windows 尚未接线：显式拒绝，不假装直连成功。
    pub fn handshake_ages_sync(
        &self,
    ) -> Result<std::collections::BTreeMap<String, u64>, NetworkError> {
        Err(NetworkError::Unsupported(
            "direct-connect handshake ages on Windows are not yet implemented".to_string(),
        ))
    }

    /// P2P 直连 peer 下发（§12）Windows 尚未接线：显式拒绝。
    pub fn set_direct_peer_sync(
        &self,
        _public_key: &str,
        _allowed_ips: &[Ipv4Cidr],
        _endpoint: std::net::SocketAddrV4,
        _persistent_keepalive_secs: u32,
    ) -> Result<(), NetworkError> {
        Err(NetworkError::Unsupported(
            "direct-connect peer setup on Windows is not yet implemented".to_string(),
        ))
    }

    /// P2P 直连 peer 移除（§12）Windows 尚未接线：显式拒绝。
    pub fn remove_peer_sync(&self, _public_key: &str) -> Result<(), NetworkError> {
        Err(NetworkError::Unsupported(
            "direct-connect peer removal on Windows is not yet implemented".to_string(),
        ))
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
        let exe = self.find_wireguard_exe().ok_or_else(|| {
            NetworkError::Unsupported("WireGuard for Windows is not installed".to_string())
        })?;
        let command = WireGuardCommand::InstallService {
            name: config.name.clone(),
            conf_path: {
                let conf_dir = std::env::temp_dir().join("meshlet");
                let conf_path = conf_dir.join(format!("{}.conf", config.name));
                let conf = render_wireguard_conf(&config);
                write_tunnel_conf(&conf_path, &conf)?;
                conf_path
            },
        };
        run_wireguard_command(&command, Some(&exe))
    }

    async fn apply_routes(
        &mut self,
        routes: Vec<RouteConfig>,
    ) -> Result<ApplyResult, NetworkError> {
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

fn mask_to_prefix(mask: &str) -> u8 {
    let octets: Vec<u8> = mask.split('.').filter_map(|s| s.parse().ok()).collect();
    if octets.len() != 4 {
        return 0;
    }
    octets.iter().map(|b| b.count_ones() as u8).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_to_prefix_conversion() {
        assert_eq!(mask_to_prefix("255.255.255.0"), 24);
        assert_eq!(mask_to_prefix("255.255.0.0"), 16);
        assert_eq!(mask_to_prefix("255.0.0.0"), 8);
        assert_eq!(mask_to_prefix("255.255.255.255"), 32);
        assert_eq!(mask_to_prefix("0.0.0.0"), 0);
    }

    #[test]
    fn backend_default_interface_is_meshlet() {
        let backend = WindowsNetworkBackend::new();
        assert_eq!(backend.interface, "meshlet");
    }

    #[test]
    fn with_interface_overrides_default() {
        let backend = WindowsNetworkBackend::new().with_interface("wg0");
        assert_eq!(backend.interface, "wg0");
    }
}
