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

    /// 隧道服务安装（重配正确性，BUG 修复）：已存在 → 停/卸载/装新 conf；
    /// 不存在 → 直接装。装完轮询 `sc query` 直到服务 RUNNING（读不到运行
    /// 证据即报错，绝不假装生效——apply_device_plan_sync 随后有内核回读，
    /// 此处只负责「服务确实起来了」）。
    fn install_tunnel_reconfigured(
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
                // 卸载只是发停止信号：旧服务进程退出要时间，退出前仍持有
                // conf 文件。新服务立刻启动读同一份 conf 会报「The process
                // cannot access the file because it is being used by another
                // process」起不来（真机 imac 2026-11-07 事件日志：7045 安装 →
                // 7023 停止连环失败，隧道永远起不来）。等旧服务退干净再装。
                self.wait_tunnel_service_gone(&self.interface);
                continue;
            }
            run_wireguard_command(&command, Some(exe))?;
        }
        self.wait_tunnel_service_running(&self.interface)
    }

    /// 轮询直到旧隧道服务退干净（SCM 里不再 RUNNING / 已删除），最多约 4s；
    /// 超时也继续装（给一次机会，绝不为等退出卡死 apply）。
    fn wait_tunnel_service_gone(&self, tunnel_name: &str) {
        let service = crate::windows_tunnel::tunnel_service_query_name(tunnel_name);
        for _ in 0..16 {
            if self.sc_query_state_code(&service) != Some(4) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }

    /// 轮询 `sc query WireGuardTunnel$<name>` 直到 RUNNING（装服务后驱动
    /// 拉起隧道需要一点时间）；超时（约 5s）→ 显式失败。
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

    /// `sc query <service>` 的数字状态码（zh/en 双标签解析见
    /// [windows_tunnel::parse_sc_query_state_code]）；命令失败/解析不到 → None。
    fn sc_query_state_code(&self, service: &str) -> Option<u32> {
        let output = std::process::Command::new("sc")
            .args(["query", service])
            .output()
            .ok()?;
        let text = format!(
            "{}{}",
            crate::windows_console::decode_output(&output.stdout),
            crate::windows_console::decode_output(&output.stderr),
        );
        crate::windows_tunnel::parse_sc_query_state_code(&text)
    }

    fn read_tunnel_peers(&self, tunnel_name: &str) -> Vec<PeerObserved> {
        // 漂移探测：从 `wg.exe show <name> dump` 读回实际生效的 peer。读不到
        // （wg.exe 缺失 / 隧道未运行 / 输出异常）一律返回空——调用方据存在性
        // 判定为「与期望不符」宁可重装收敛，绝不因读数缺失假装一致。
        match self.read_tunnel_dump(tunnel_name) {
            Some(text) => crate::windows_tunnel::parse_wg_dump_peers(&text),
            None => Vec::new(),
        }
    }

    /// `wg.exe show <name> dump` 原文（接口行 + peer 行；解码走
    /// [windows_console] 的活动代码页兜底）。读不到 → None。
    fn read_tunnel_dump(&self, tunnel_name: &str) -> Option<String> {
        let exe = self.find_wg_exe()?;
        let out = std::process::Command::new(&exe)
            .args(["show", tunnel_name, "dump"])
            .output()
            .ok()?;
        Some(format!(
            "{}{}",
            crate::windows_console::decode_output(&out.stdout),
            crate::windows_console::decode_output(&out.stderr),
        ))
    }

    /// 受管接口适配器的实际 IPv4 地址（`netsh interface ipv4 show addresses
    /// name=<if>` 解析；漂移判定的适配器地址读数，BUG②）。读不到 → None。
    fn interface_address(&self) -> Option<std::net::Ipv4Addr> {
        let output = std::process::Command::new("netsh")
            .args(["interface", "ipv4", "show", "addresses", &self.interface])
            .output()
            .ok()?;
        let text = format!(
            "{}{}",
            crate::windows_console::decode_output(&output.stdout),
            crate::windows_console::decode_output(&output.stderr),
        );
        parse_netsh_interface_ipv4_address(&text)
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

    /// P2P 直连执行层（§12）：`wg.exe show <if> latest-handshakes` →
    /// 公钥 → 秒龄。与 Linux 同一解析器（[crate::parse_handshake_ages]）。
    pub fn handshake_ages_sync(
        &self,
    ) -> Result<std::collections::BTreeMap<String, u64>, NetworkError> {
        let exe = self.find_wg_exe().ok_or_else(|| {
            NetworkError::Unsupported(
                "wg.exe not found. Install WireGuard for Windows.".to_string(),
            )
        })?;
        let out = std::process::Command::new(&exe)
            .args(["show", &self.interface, "latest-handshakes"])
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

    /// P2P 直连 peer 下发（§12）：`wg.exe set <if> peer …`——与 Linux
    /// [`crate::linux::LinuxNetworkBackend::set_direct_peer_sync`] 同参数形状
    /// （allowed-ips 对端 overlay /32 + endpoint + persistent-keepalive）。
    /// WireGuardNT 适配器支持运行期 `wg set`（wireguard.exe 隧道服务创建的
    /// 适配器同样适用），无需重装隧道；写入要求提升权限（agent 以管理员运行）。
    /// 幂等：重复调用结果一致。
    ///
    /// 注意：隧道重装（apply）会重置运行期 peer——调用方（agent）按 tick 重推，
    /// 与 Linux 的 reconcile 语义一致。
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

    /// P2P 直连 peer 移除（回退 hub，§12）：`wg.exe set <if> peer <key> remove`。
    /// 幂等：不存在也成功（WireGuard 对缺失 peer 的 remove 是 no-op）。
    pub fn remove_peer_sync(&self, public_key: &str) -> Result<(), NetworkError> {
        self.run_wg_set(&["peer", public_key, "remove"])
    }

    /// SEL-002 直连 endpoint 漫游：`wg.exe set <if> peer <key> endpoint <ip:port>`。
    /// WireGuard 在同一 peer 上改 endpoint 是无缝的（不断开已有握手）。幂等。
    pub fn set_direct_endpoint_sync(
        &self,
        public_key: &str,
        endpoint: std::net::SocketAddrV4,
    ) -> Result<(), NetworkError> {
        let endpoint = endpoint.to_string();
        self.run_wg_set(&["peer", public_key, "endpoint", &endpoint])
    }

    /// `wg.exe set <if> <args>`：运行期变更受管适配器（成功静默；失败携带
    /// wg.exe stderr 文本——权限不足/适配器不存在都在其中可读）。
    fn run_wg_set(&self, args: &[&str]) -> Result<(), NetworkError> {
        let exe = self.find_wg_exe().ok_or_else(|| {
            NetworkError::Unsupported(
                "wg.exe not found. Install WireGuard for Windows.".to_string(),
            )
        })?;
        let out = std::process::Command::new(&exe)
            .arg("set")
            .arg(&self.interface)
            .args(args)
            .output()
            .map_err(|error| NetworkError::Io(format!("spawn wg.exe: {error}")))?;
        if out.status.success() {
            return Ok(());
        }
        Err(NetworkError::ApplyRejected(format!(
            "wg set {}: {}",
            self.interface,
            crate::windows_console::decode_output(&out.stderr)
        )))
    }

    /// 直连 UDP 端口入站放行（批次④ Windows 接线）：`Meshlet-Direct-UDP-In`
    /// 规则（protocol=udp / localport=<port> / profile=any），先探
    /// [crate::windows_firewall::firewall_rule_present] 再 add（netsh 重复
    /// add 同名规则会叠出重复项，探测是幂等性的一半）。
    fn ensure_direct_udp_firewall_sync(&self, port: u16) -> Result<(), NetworkError> {
        if self.direct_udp_rule_present(port) {
            return Ok(());
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

    /// `netsh advfirewall firewall show rule name=Meshlet-Direct-UDP-In` 探测。
    fn direct_udp_rule_present(&self, port: u16) -> bool {
        let output = std::process::Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "show",
                "rule",
                &format!("name={}", crate::windows_firewall::DIRECT_UDP_RULE_NAME),
            ])
            .output()
            .map(|out| {
                format!(
                    "{}{}",
                    crate::windows_console::decode_output(&out.stdout),
                    crate::windows_console::decode_output(&out.stderr),
                )
            })
            .unwrap_or_default();
        crate::windows_firewall::firewall_rule_present(&output)
            && crate::windows_firewall::rule_output_mentions_port(&output, port)
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

/// 解析 `netsh interface ipv4 show addresses name=<if>` 输出中该接口的首个
/// IPv4 地址（BUG② 漂移判定的适配器地址读数；纯函数，跨平台单测）。
///
/// 行形如 en `   IP Address:                           10.240.0.7` 或
/// zh-CN `   IP 地址:                           10.240.0.7`——标签宽匹配
/// （`IP Address` / `IP 地址`），取行内最后一个可解析为 IPv4 的词元。
/// 「子网前缀」行的 `(masked …)` 不含独立 IPv4 词元、且匹配不到地址标签，
/// 不会误命中。读不到 → None。
fn parse_netsh_interface_ipv4_address(text: &str) -> Option<std::net::Ipv4Addr> {
    for line in text.lines() {
        let is_address_label =
            line.to_ascii_lowercase().contains("ip address") || line.contains("IP 地址");
        if !is_address_label {
            continue;
        }
        if let Some(addr) = line
            .split_whitespace()
            .filter_map(|token| {
                token
                    .trim_end_matches(':')
                    .parse::<std::net::Ipv4Addr>()
                    .ok()
            })
            .next_back()
        {
            return Some(addr);
        }
    }
    None
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

/// Windows 局域网接口判定（§12 P2P 候选口径，镜像 Linux `is_lan_interface`）：
/// 排除本受管 wg 接口、回环、Hyper-V vEthernet、Tailscale 与其余 wg 接口；
/// ZeroTier 等私有网段**保留**（可路由的私有网段都是直连候选）。别名比对
/// 大小写不敏感（Windows 接口别名如 `Tailscale`、`vEthernet (WSL …)`）。
fn is_windows_lan_interface(alias: &str, wg_interface: &str) -> bool {
    let lower = alias.to_ascii_lowercase();
    if alias == wg_interface || lower.starts_with("loopback") {
        return false;
    }
    for prefix in ["vethernet", "tailscale", "wg", "docker", "veth"] {
        if lower.starts_with(prefix) {
            return false;
        }
    }
    true
}

/// `Get-NetIPAddress … | ConvertTo-Json -Compress` 解析：`(别名, 地址, 前缀)`
/// 列表。PowerShell **单结果**输出对象、多结果输出数组——按 `Value` 统一归一
/// （[parse_windows_interfaces_json] 同惯例）。畸形行（缺字段/解析失败）
/// 逐条跳过，不吞掉整批读数。
fn parse_lan_ip_json(text: &str) -> Result<Vec<(String, Ipv4Addr, u8)>, NetworkError> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let value: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|error| NetworkError::ApplyRejected(format!("Get-NetIPAddress json: {error}")))?;
    let items: Vec<&serde_json::Value> = match &value {
        serde_json::Value::Array(arr) => arr.iter().collect(),
        serde_json::Value::Object(_) => vec![&value],
        _ => return Ok(Vec::new()),
    };
    Ok(items
        .into_iter()
        .filter_map(|item| {
            let alias = item.get("InterfaceAlias").and_then(|v| v.as_str())?;
            let addr: Ipv4Addr = item
                .get("IPAddress")
                .and_then(|v| v.as_str())?
                .parse()
                .ok()?;
            let prefix = item
                .get("PrefixLength")
                .and_then(|v| v.as_u64())
                .and_then(|n| u8::try_from(n).ok())?;
            Some((alias.to_string(), addr, prefix))
        })
        .collect())
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
    fn lan_ip_json_parses_single_object_and_array() {
        // 多结果：PowerShell 输出数组。
        let arr = r#"[{"IPAddress":"192.168.88.51","InterfaceAlias":"WLAN 7","PrefixLength":24},{"IPAddress":"10.147.19.97","InterfaceAlias":"ZeroTier One [db64858fedb29f06]","PrefixLength":24},{"IPAddress":"169.254.209.18","InterfaceAlias":"WLAN 9","PrefixLength":16}]"#;
        let entries = parse_lan_ip_json(arr).expect("array");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].1, "192.168.88.51".parse::<Ipv4Addr>().unwrap());
        assert_eq!(entries[0].2, 24);
        // 单结果：PowerShell 输出裸对象。
        let obj = r#"{"IPAddress":"10.0.0.5","InterfaceAlias":"以太网","PrefixLength":24}"#;
        let one = parse_lan_ip_json(obj).expect("object");
        assert_eq!(one.len(), 1);
        // 空与畸形。
        assert!(parse_lan_ip_json("").unwrap().is_empty());
        assert!(parse_lan_ip_json("not json").is_err());
    }

    #[test]
    fn windows_lan_interface_filter_keeps_lan_and_zerotier_drops_virtual() {
        // 受管接口 / 回环 / Hyper-V / Tailscale / 其余 wg → 排除。
        assert!(!is_windows_lan_interface("wg-meshlet", "wg-meshlet"));
        assert!(!is_windows_lan_interface(
            "Loopback Pseudo-Interface 1",
            "wg-meshlet"
        ));
        assert!(!is_windows_lan_interface(
            "vEthernet (WSL (Hyper-V firewall))",
            "wg-meshlet"
        ));
        assert!(!is_windows_lan_interface("Tailscale", "wg-meshlet"));
        assert!(!is_windows_lan_interface("wg-newapi", "wg-meshlet"));
        // 物理 LAN 与 ZeroTier → 保留（候选口径与 Linux 一致）。
        assert!(is_windows_lan_interface("WLAN 7", "wg-meshlet"));
        assert!(is_windows_lan_interface(
            "ZeroTier One [db64858fedb29f06]",
            "wg-meshlet"
        ));
    }

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

    /// netsh 接口地址解析（BUG② 读数端）：en/zh 标签都命中，取行内 IPv4
    /// 词元；无标签行 / 无地址 → None。
    #[test]
    fn netsh_interface_address_parses_en_and_zh_labels() {
        let en = "Configuration for interface \"meshlet\"\r\n\
                  DHCP enabled:                         No\r\n\
                  IP Address:                           10.240.0.7\r\n\
                  Subnet Prefix:                        10.240.0.7/32 (masked 255.255.255.255)\r\n";
        assert_eq!(
            parse_netsh_interface_ipv4_address(en),
            Some("10.240.0.7".parse().unwrap())
        );
        let zh = "接口 \"meshlet\" 的 IP 配置\r\n\
                  DHCP 已启用:                          否\r\n\
                  IP 地址:                           10.240.0.9\r\n\
                  子网前缀:                          10.240.0.9/32 (掩码 255.255.255.255)\r\n";
        assert_eq!(
            parse_netsh_interface_ipv4_address(zh),
            Some("10.240.0.9".parse().unwrap())
        );
        // 无地址标签行 / 完全无关文本 → None。
        assert_eq!(
            parse_netsh_interface_ipv4_address("   子网前缀: 10.240.0.7/32\r\n"),
            None
        );
        assert_eq!(parse_netsh_interface_ipv4_address(""), None);
        assert_eq!(parse_netsh_interface_ipv4_address("not a netsh dump"), None);
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
