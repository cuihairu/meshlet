use super::parsing::{is_windows_lan_interface, parse_lan_ip_json};
use crate::nat::NatRule;
use crate::windows_routes::exec::run_route_command;
use crate::windows_tunnel::exec::run_wireguard_command;
use crate::windows_tunnel::exec::write_tunnel_conf;
use crate::windows_tunnel::render_wireguard_conf;
use crate::windows_tunnel::wireguard_exe;
use crate::windows_tunnel::WireGuardCommand;
use crate::{
    ApplyResult, ConfigRevisionRef, DevicePlan, NetworkBackend, NetworkError, NetworkSnapshot,
    RouteConfig, TunnelConfig,
};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::PathBuf;
/// Windows 网络后端：WireGuardNT 隧道 + netsh 路由。
#[derive(Clone)]
pub struct WindowsNetworkBackend {
    /// 受管 WireGuard 接口名（与 WireGuardNT 隧道服务名对应）。
    pub(super) interface: String,
    /// `wireguard.exe` 显式覆盖路径（`None` = 走环境变量/PATH 解析）。
    pub(super) wireguard_exe_override: Option<PathBuf>,
    pub(super) hub_endpoint: Option<String>,
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
        // 逐项对账（peer 公钥 / routes / MTU）替代「只看隧道存在」——
        // 隧道在但配置漂移不再误判一致（todo.md:241）。
        let snapshot = self.inspect_sync()?;
        Ok(crate::device_plan_matches(plan, extra_peer_keys, &snapshot))
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
        // 本机身份读数（BUG② 修复的漂移判定输入）：dump 接口行第 2 列是
        // 本机公钥（读不到 → None，证据缺失不判）；适配器地址读 netsh。
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
        // 实际监听端口（直连钉端口的漂移判定输入）：同一 dump 接口行第 3 列
        // （读不到 → None，证据缺失不判）。
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
        })
    }

    /// 本机 RFC1918 局域网地址（§12 P2P 候选端点上报）。Windows 读数走
    /// `Get-NetIPAddress` JSON（字段名英文、locale 无关；netsh 输出按活动
    /// 代码页本地化，解析脆弱）。排除本受管接口 / 回环 / Hyper-V vEthernet /
    /// Tailscale / 其余 wg 接口；RFC1918 过滤掉 APIPA（169.254）与 CGNAT
    /// （100.64/10，Tailscale 地址），ZeroTier 等私有网段**保留**（与 Linux
    /// `is_lan_interface` 口径一致：可路由的私有网段都是候选）。
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

    /// 枚举本机 RFC1918 局域网**子网**：与 [`Self::lan_addresses_sync`] 同一
    /// 来源，但保留前缀长度（同网段判定需要网段）。
    pub fn lan_subnets_sync(&self) -> Result<Vec<meshlet_domain::Ipv4Cidr>, NetworkError> {
        let mut subnets: Vec<meshlet_domain::Ipv4Cidr> = self
            .lan_ip_entries()?
            .into_iter()
            .filter(|(alias, _, _)| is_windows_lan_interface(alias, &self.interface))
            .filter(|(_, addr, _)| meshlet_domain::is_private_ip(*addr))
            // 接口地址+前缀 → 所属网段（from_host_address 掩掉主机位）；前缀
            // 越界（JSON 读数畸形）按无子网处理，不吞掉其余读数。
            .filter_map(|(_, addr, prefix)| {
                meshlet_domain::Ipv4Cidr::from_host_address(addr, prefix).ok()
            })
            .collect();
        subnets.sort();
        subnets.dedup();
        Ok(subnets)
    }

    /// `Get-NetIPAddress` JSON 读数（locale 无关）：`(别名, 地址, 前缀)` 列表。
    /// PowerShell 单结果输出对象、多结果输出数组——按 `Value` 统一归一。
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

    // server 侧 revision.rs / device_plan.rs 按 SystemBackend 统一调用这组
    // 同形 sync 方法（Linux/unsupported 后端同签名），Windows 后端缺一个就
    // 编译不过。数据面尚未接线的操作一律 fail closed，绝不假装成功。
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
        self.install_tunnel_reconfigured(&exe, &conf_path)?;
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
        // P2P 批次④ Windows 接线：直连开启时计划把数据面隧道钉到固定监听
        // 端口（plan.tunnel.listen_port = Some(port)），防火墙联动放行该 UDP
        // 端口——无规则则对端入站握手包被 Public 档默认策略丢弃。与 Linux
        // ensure_direct_udp_firewall_sync 同条件、同幂等纪律。
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
        let exe = self.find_wireguard_exe().ok_or_else(|| {
            NetworkError::Unsupported("WireGuard for Windows is not installed".to_string())
        })?;
        let conf_dir = std::env::temp_dir().join("meshlet");
        let conf_path = conf_dir.join(format!("{}.conf", config.name));
        let conf = render_wireguard_conf(&config);
        write_tunnel_conf(&conf_path, &conf)?;
        // 与 apply_device_plan_sync 同路径：已存在服务必须停/卸载/装新 conf，
        // 绝不把 "already installed" 当成功（那会静默保留旧 key/地址）。
        self.install_tunnel_reconfigured(&exe, &conf_path)?;
        Ok(ApplyResult::ok())
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
