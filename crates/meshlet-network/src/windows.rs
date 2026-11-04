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
    ApplyResult, ConfigRevisionRef, DevicePlan, InterfaceDiagnostic, NetworkBackend,
    NetworkDiagnostics, NetworkError, NetworkSnapshot, PeerObserved, RouteConfig, TunnelConfig,
    WgPeerDiagnostic,
};
use meshlet_domain::Ipv4Cidr;

/// Windows 网络后端：WireGuardNT 隧道 + netsh 路由。
#[derive(Clone)]
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

    /// R-DIAG 网络诊断信息面采集（Windows，2026-11-01 用户令）：三类快照。
    ///
    /// - 路由表：`route print`（IPv4 全表原文）；
    /// - 接口清单：`Get-NetIPConfiguration`（Name / IPv4 / Prefix / MTU /
    ///   InterfaceOperationalStatus）；
    /// - wg-mlt 读数：`wg.exe show <if> dump` 解析（[parse_wg_dump_peers] 同
    ///   源但保留 endpoint / 握手 / 流量列，[WgPeerDiagnostic]）。
    ///
    /// 采集只读；单项失败按空/缺上报（诊断面如实展示「未取到」）。
    pub fn diagnostics_sync(&self) -> Result<NetworkDiagnostics, NetworkError> {
        let route_table = std::process::Command::new("route")
            .args(["print"])
            .output()
            .map(|out| {
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();

        let interfaces = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-NetIPConfiguration | Where-Object { $_.IPv4Address } | ForEach-Object {                  $addr = $_.IPv4Address | Select-Object -First 1;                  $name = $_.InterfaceAlias;                  $state = $_.NetAdapter.Status;                  $mtu = (Get-NetAdapter -Name $name -ErrorAction SilentlyContinue).MtuSize;                  $prefix = if ($addr) { $addr.PrefixLength } else { '' };                  [PSCustomObject]@{ Name=$name; IP=$addr.IPAddress; Prefix=$prefix; State=$state; Mtu=$mtu } } |                  ConvertTo-Json -Compress",
            ])
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).to_string())
            .unwrap_or_default();
        let interfaces = parse_windows_interfaces_json(&interfaces);

        let wg = if self.tunnel_service_exists(&self.interface) {
            self.read_tunnel_diag(&self.interface)
        } else {
            Vec::new()
        };

        Ok(NetworkDiagnostics {
            collected_at: Some(now_iso_utc()),
            route_table,
            interfaces,
            wg,
        })
    }

    /// 读 `wg.exe show <if> dump` 的诊断读数（保留 endpoint / 握手 / 流量列）。
    fn read_tunnel_diag(&self, tunnel_name: &str) -> Vec<WgPeerDiagnostic> {
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
        text.lines()
            .skip(1)
            .filter_map(parse_wg_dump_diag_line_windows)
            .collect()
    }

    /// 以 `ping -n 1` 实测直连路径 RTT（毫秒）。Windows 输出
    /// `Reply from 10.0.0.2: bytes=32 time=12ms TTL=64`（中文为
    /// `时间=12ms`，二者 `time` / `时间` 均匹配）；失败按 `None`。
    pub fn ping_rtt_ms(&self, target: Ipv4Addr) -> Option<u128> {
        let out = std::process::Command::new("ping")
            .args(["-n", "1", "-w", "2000", &target.to_string()])
            .output()
            .ok()?;
        parse_ping_rtt_ms_windows(&String::from_utf8_lossy(&out.stdout))
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

    /// 私钥 → 公钥（`wg pubkey`，密钥走 stdin、不进 argv，与 Linux 后端同法；
    /// 服务端据此填充下发给设备的 hub peer 公钥，ADR-010）。
    pub fn public_key_from_private(&self, private_key: &str) -> Result<String, NetworkError> {
        let Some(exe) = self.find_wg_exe() else {
            return Err(NetworkError::Unsupported(
                "wg.exe not found; cannot derive public key".to_string(),
            ));
        };
        use std::io::Write;
        let mut child = std::process::Command::new(&exe)
            .arg("pubkey")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| NetworkError::Io(format!("spawn wg pubkey: {e}")))?;
        child
            .stdin
            .take()
            .ok_or_else(|| NetworkError::Io("wg pubkey stdin unavailable".into()))?
            .write_all(format!("{private_key}\n").as_bytes())
            .map_err(|e| NetworkError::Io(format!("write wg pubkey stdin: {e}")))?;
        let out = child
            .wait_with_output()
            .map_err(|e| NetworkError::Io(format!("wg pubkey wait: {e}")))?;
        let key = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if key.is_empty() {
            return Err(NetworkError::Io("wg pubkey returned an empty key".into()));
        }
        Ok(key)
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

    /// 默认路由底层 MTU 在 Windows 暂无读数实现：`None` = 「读数不可得」，
    /// 探测回退默认尺寸 1392（lane/dataplane-speed 仅落 Linux 读数；Windows
    /// 侧以文档建议 `New-NetIPInterface`/`netsh` 手工核对，见
    /// docs/guide/performance.md）。
    pub fn underlay_path_mtu_sync(&self) -> Option<u32> {
        None
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

/// 从 Windows `ping` 输出解析首个 RTT（毫秒），支持英文 `time=1ms` 与
/// 中文 `时间=1ms`；无读数返回 `None`。
fn parse_ping_rtt_ms_windows(text: &str) -> Option<u128> {
    let marker = if text.contains("time") {
        "time"
    } else if text.contains("时间") {
        "时间"
    } else {
        return None;
    };
    let start = text.find(marker)?;
    let rest = &text[start + marker.len()..];
    let start = rest.find(|c: char| c.is_ascii_digit())?;
    let rest = &rest[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(rest.len());
    rest[..end].parse::<f64>().ok().map(|v| v.round() as u128)
}

/// 解析 `wg.exe show <name> dump` 的 peer 行为诊断读数（纯函数，任意平台
/// 单测）。官方格式为制表符分隔：首行接口，其后每行
/// `pubkey preshared endpoint allowed-ips latest-handshake transfer-rx
/// transfer-tx keepalive`。缺列按 0/空补。
fn parse_wg_dump_diag_line_windows(line: &str) -> Option<WgPeerDiagnostic> {
    let fields: Vec<&str> = line.split('\t').collect();
    let public_key = fields.first()?.trim();
    if public_key.is_empty() {
        return None;
    }
    let endpoint = fields.get(2).unwrap_or(&"").trim().to_string();
    let allowed_ips = fields.get(3).unwrap_or(&"").trim().to_string();
    let last_handshake: u64 = fields
        .get(4)
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let rx_bytes: u64 = fields
        .get(6)
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let tx_bytes: u64 = fields
        .get(7)
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    Some(WgPeerDiagnostic {
        public_key: public_key.to_string(),
        endpoint,
        allowed_ips,
        last_handshake,
        rx_bytes,
        tx_bytes,
    })
}

/// 解析 `Get-NetIPConfiguration | ConvertTo-Json` 的接口清单（纯函数，任意
/// 平台单测）。输出为对象数组或单个对象；字段缺省按空/None 处理。
fn parse_windows_interfaces_json(text: &str) -> Vec<InterfaceDiagnostic> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let value: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let items: Vec<&serde_json::Value> = match &value {
        serde_json::Value::Array(arr) => arr.iter().collect(),
        serde_json::Value::Object(_) => vec![&value],
        _ => return Vec::new(),
    };
    items
        .into_iter()
        .filter_map(|item| {
            let name = item.get("Name").and_then(|v| v.as_str()).unwrap_or("");
            if name.is_empty() {
                return None;
            }
            let ipv4 = item
                .get("IP")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let prefix = item.get("Prefix").and_then(|v| {
                v.as_str()
                    .and_then(|s| s.parse().ok())
                    .or_else(|| v.as_u64().and_then(|n| u8::try_from(n).ok()))
            });
            let state = item
                .get("State")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let mtu = item
                .get("Mtu")
                .and_then(|v| v.as_u64().and_then(|n| u32::try_from(n).ok()));
            Some(InterfaceDiagnostic {
                name: name.to_string(),
                ipv4,
                prefix,
                state,
                mtu,
            })
        })
        .collect()
}

/// 当前 UTC 时刻的 ISO-8601 字符串（Windows；不引 chrono）。用
/// `powershell` 读取，失败回退纪元秒。
fn now_iso_utc() -> String {
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')",
        ])
        .output();
    if let Ok(out) = out {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            let text = text.trim();
            if !text.is_empty() {
                return text.to_string();
            }
        }
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ping_rtt_windows_supports_english_and_chinese() {
        assert_eq!(
            parse_ping_rtt_ms_windows("Reply from 10.0.0.2: bytes=32 time=12ms TTL=64"),
            Some(12)
        );
        assert_eq!(
            parse_ping_rtt_ms_windows("来自 10.0.0.2 的回复: 字节=32 时间=1ms TTL=64"),
            Some(1)
        );
        assert_eq!(parse_ping_rtt_ms_windows("Request timed out."), None);
    }

    #[test]
    fn wg_dump_diag_line_windows_reads_all_columns() {
        let line =
            "PUB-KEY\t(preshared)\t198.51.100.10:51820\t10.240.0.1/32\t1234567\t1024\t2048\t25";
        let diag = parse_wg_dump_diag_line_windows(line).expect("valid");
        assert_eq!(diag.public_key, "PUB-KEY");
        assert_eq!(diag.endpoint, "198.51.100.10:51820");
        assert_eq!(diag.allowed_ips, "10.240.0.1/32");
        assert_eq!(diag.last_handshake, 1234567);
        assert_eq!(diag.rx_bytes, 2048);
        assert_eq!(diag.tx_bytes, 25);
        // 空行 / 空公钥 → None。
        assert!(parse_wg_dump_diag_line_windows("").is_none());
        assert!(parse_wg_dump_diag_line_windows("\t\t\t").is_none());
    }

    #[test]
    fn windows_interfaces_json_parses_object_and_array() {
        let single = r#"{"Name":"meshlet","IP":"10.240.0.2","Prefix":16,"State":"Up","Mtu":1420}"#;
        let v = parse_windows_interfaces_json(single);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "meshlet");
        assert_eq!(v[0].ipv4, "10.240.0.2");
        assert_eq!(v[0].prefix, Some(16));
        assert_eq!(v[0].state, "Up");
        assert_eq!(v[0].mtu, Some(1420));

        let arr = r#"[{"Name":"eth0","IP":"192.168.1.5","Prefix":24,"State":"Up","Mtu":1500},
                       {"Name":"meshlet","IP":"10.240.0.2","Prefix":16,"State":"Up","Mtu":1420}]"#;
        let v = parse_windows_interfaces_json(arr);
        assert_eq!(v.len(), 2);
        assert_eq!(v[1].name, "meshlet");
        assert_eq!(v[1].ipv4, "10.240.0.2");
        assert_eq!(v[1].prefix, Some(16));
        assert_eq!(v[1].state, "Up");
        assert_eq!(v[1].mtu, Some(1420));

        // 空 / 非法 JSON → 空（不臆造接口）。
        assert!(parse_windows_interfaces_json("").is_empty());
        assert!(parse_windows_interfaces_json("not-json").is_empty());
    }

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
