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
        // 漂移探测：从 `wg.exe show <name> dump` 读回实际生效的 peer。读不到
        // （wg.exe 缺失 / 隧道未运行 / 输出异常）一律返回空——调用方据存在性
        // 判定为「与期望不符」宁可重装收敛，绝不因读数缺失假装一致。
        let Some(exe) = self.find_wg_exe() else {
            return Vec::new();
        };
        let Ok(out) = std::process::Command::new(&exe)
            .args(["show", tunnel_name, "dump"])
            .output()
        else {
            return Vec::new();
        };
        let text = String::from_utf8_lossy(&out.stdout);
        crate::windows_tunnel::parse_wg_dump_peers(&text)
    }

    /// `wg.exe` 路径解析（与 [Self::find_wireguard_exe] 同纪律：WireGuard for
    /// Windows 把 wg.exe 与 wireguard.exe 装在同一目录，故优先复用其目录）。
    fn find_wg_exe(&self) -> Option<PathBuf> {
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
        parse_ip_enable_router(&String::from_utf8_lossy(&output.stdout))
    }

    /// 确保 IP 转发开启（镜像 Linux `sysctl -w net.ipv4.ip_forward=1`）。
    ///
    /// [crate::NetworkSnapshot] 的 `forwarding_enabled` 读 `IPEnableRouter`
    /// 注册表；[`apps/agent` 的漂移判定] 要求其为 `Some(true)`，否则
    /// `KernelDrift` 每轮重放。Windows 客户端默认缺失/为 0，必须在此置 1
    /// 才能收敛（幂等：已为 1 则跳过，`/f` 覆盖写仅在实际变更时）。
    fn ensure_ip_forwarding_sync(&self) -> Result<(), NetworkError> {
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

    /// 受管接口的 MTU（`netsh interface ipv4 show subinterfaces`）。
    /// 读不到（接口未起 / 命令失败）→ `None`，漂移判定对未显式配置 MTU 的
    /// 计划不触发；显式 MTU 计划则由 [Self::inspect_sync] 的 `tunnel_mtu`
    /// 驱动（不再恒 None 导致的永不收敛）。
    fn interface_mtu(&self) -> Option<u32> {
        let output = std::process::Command::new("netsh")
            .args(["interface", "ipv4", "show", "subinterfaces"])
            .output()
            .ok()?;
        crate::windows_tunnel::parse_netsh_subinterface_mtu(
            &String::from_utf8_lossy(&output.stdout),
            &self.interface,
        )
    }

    /// AGENT-FW-1 接线：设备计划 apply 时按档位走 mesh 可达性防火墙。
    ///
    /// 镜像 Linux `ensure_host_firewall_sync` 的纪律——探测
    /// 失败按「未满足」处理（fail toward action；档位 set 与规则 add 均幂等），
    /// 执行失败显式报错，绝不假装生效。置于隧道与路由之后调用：
    /// `SetNetworkCategoryPrivate` 需接口已存在。
    fn ensure_mesh_reachability_sync(
        &self,
        device_addr: std::net::Ipv4Addr,
    ) -> Result<(), NetworkError> {
        let category_is_private = self.probe_net_category_is_private();
        let icmp_rule_present = self.probe_icmp_rule_present();
        let commands = crate::windows_firewall::mesh_reachability_commands(
            &self.interface,
            device_addr,
            category_is_private,
            icmp_rule_present,
        )?;
        for command in &commands {
            crate::windows_firewall::exec::run_mesh_firewall_command(command)?;
        }
        Ok(())
    }

    /// `Get-NetConnectionProfile -InterfaceAlias <if>` 探测：exit 0 且输出含
    /// Private → 已满足；接口未找到 / 命令失败 → 未满足（宁补不漏，档位 set
    /// 天然幂等）。接口名由后端构造控制，与既有 apply 路径同信任级。
    fn probe_net_category_is_private(&self) -> bool {
        let Ok(output) = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "Get-NetConnectionProfile -InterfaceAlias '{}'",
                    self.interface
                ),
            ])
            .output()
        else {
            return false;
        };
        if !output.status.success() {
            return false;
        }
        crate::windows_firewall::net_category_is_private(&String::from_utf8_lossy(&output.stdout))
    }

    /// `netsh advfirewall firewall show rule name=Meshlet-ICMPv4-In` 探测：
    /// exit 0 且输出列出规则 → 已放行；其余 → 未放行（宁补不漏，add 重放
    /// 同名同谓词规则无害）。netsh 输出按活动代码页编码，走 GBK 兑底解码。
    fn probe_icmp_rule_present(&self) -> bool {
        let Ok(output) = std::process::Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "show",
                "rule",
                "name=Meshlet-ICMPv4-In",
            ])
            .output()
        else {
            return false;
        };
        if !output.status.success() {
            return false;
        }
        let text = format!(
            "{}{}",
            crate::windows_console::decode_output(&output.stdout),
            crate::windows_console::decode_output(&output.stderr),
        );
        crate::windows_firewall::firewall_rule_present(&text)
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
        let tunnel_mtu = if tunnel_exists {
            self.interface_mtu()
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
        })
    }

    pub fn device_plan_matches_sync(
        &self,
        plan: &DevicePlan,
        extra_peer_keys: &BTreeSet<String>,
    ) -> Result<bool, NetworkError> {
        // 逐项对账（peer 公钥 / routes / MTU）替代「只看隧道存在」——
        // 隧道在但配置漂移不再误判一致（todo.md:241）。
        let snapshot = self.inspect_sync()?;
        Ok(crate::device_plan_matches(plan, extra_peer_keys, &snapshot))
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
        // §内核漂移：IP 转发是 drifted() 的收敛前提（镜像 Linux
        // ip_forward=1）。先于任何隧道变更执行——失败即 fail closed，
        // 绝不改动隧道后留下半应用状态。
        self.ensure_ip_forwarding_sync()?;
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
        // AGENT-FW-1：mesh 可达性防火墙（Private 档位 + ICMPv4 放行，幂等）。
        // 置于隧道与路由之后（档位命令需接口已存在）；失败显式报错，不假装
        // 生效——真机「ping 直接通」属验收走查，见 todo.md AGENT-FW-1。
        self.ensure_mesh_reachability_sync(plan.tunnel.address)?;
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

/// 解析 `reg query IPEnableRouter` 输出为布尔（`0x1` → true、`0x0` → false，
/// 值缺失/其他 → None）。纯字符串判定：Windows 语言包不影响 `0x` 前缀。
fn parse_ip_enable_router(text: &str) -> Option<bool> {
    if text.contains("0x1") {
        Some(true)
    } else if text.contains("0x0") {
        Some(false)
    } else {
        None
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

    /// IPEnableRouter 注册表输出 → 转发开关（drifted() 收敛前提）。
    #[test]
    fn ip_enable_router_registry_text_maps_to_forwarding_flag() {
        assert_eq!(
            parse_ip_enable_router(
                r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
    IPEnableRouter    REG_DWORD    0x1"
            ),
            Some(true)
        );
        assert_eq!(
            parse_ip_enable_router(r"    IPEnableRouter    REG_DWORD    0x0"),
            Some(false)
        );
        // 值缺失（reg query 失败文本）→ None：漂移判定视为未开启。
        assert_eq!(
            parse_ip_enable_router(
                "ERROR: The system was unable to find the specified registry key or value."
            ),
            None
        );
        assert_eq!(parse_ip_enable_router(""), None);
    }
}
