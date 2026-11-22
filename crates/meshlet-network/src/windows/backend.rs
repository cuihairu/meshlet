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
/// Windows 网络后端：WireGuardNT 隧道（服务模型或 wireguard-nt 模型）+
/// netsh 路由。
#[derive(Clone)]
pub struct WindowsNetworkBackend {
    /// 受管 WireGuard 接口名（服务模型的隧道服务名；nt 模型的 adapter
    /// handle 派生源）。
    pub(super) interface: String,
    /// `wireguard.exe` 显式覆盖路径（`None` = 走环境变量/PATH 解析）。
    pub(super) wireguard_exe_override: Option<PathBuf>,
    pub(super) hub_endpoint: Option<String>,
    /// wireguard-nt 运行时（`tunnel_backend = "nt"` 时 Some；`None` =
    /// 服务模型）。Arc 共享：backend 克隆进 [crate::direct_rtt] 等后台
    /// 线程时，adapter 句柄由同一运行时持久持有。
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

    /// 装配 wireguard-nt 运行时（`tunnel_backend = "nt"`）：adapter 句柄由
    /// 运行时持久持有，本后端所有数据面操作改走 nt 模型（[Self::nt]）。
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
        // 逐项对账（peer 公钥 / routes / MTU）替代「只看隧道存在」——
        // 隧道在但配置漂移不再误判一致（todo.md:241）。
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
            // service 模型：路由经 netsh 独立下发（plan.routes → 内核），
            // 与 peer allowed-ips 无关，drifted 按 plan.routes 对照。
            routes_from_peers: false,
        })
    }

    /// nt 模型的 inspect：事实来源是运行时已持 adapter 的 `get_config`
    /// 回读（[NtRuntime::inspect]），地址读 `Get-NetIPAddress`（locale
    /// 无关，同 [Self::lan_addresses_sync]）。adapter 未持（进程重启后
    /// 随句柄消亡）→ 空快照 `tunnel_exists=false`，reconcile 据此重放。
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
                // installed_routes = 驱动 set_default_route 装配的
                // allowed_ips（peers 的并集），与计划 routes 的对账口径
                // 同一集合。
                let mut installed_routes: Vec<meshlet_domain::Ipv4Cidr> = snapshot
                    .peers
                    .iter()
                    .flat_map(|peer| peer.allowed_ips.iter().copied())
                    .collect();
                installed_routes.sort();
                installed_routes.dedup();
                let local_public_key = Some(BASE64.encode(snapshot.public_key));
                let tunnel_listen_port = Some(snapshot.listen_port);
                // crate 的 set_default_route 把 NlMtu 硬编码 1420
                // （[NT_INTERFACE_MTU]）：adapter 在则 MTU 必是它。
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
            // nt 模型：路由由 adapter set_default_route 按 peer allowed-ips
            // 装配（见上 installed_routes 注释），plan.routes 不经 netsh 下发；
            // 漂移判定据此跳过 plan.routes 对照（peer 身份级比对已完全决定路由）。
            routes_from_peers: true,
        })
    }

    /// 受管接口在 OS 层的可用别名：service 模型 = `self.interface`；nt 模型
    /// = adapter 名（`wg-mlt-<handle>`）经
    /// [crate::windows_wireguard_nt::resolve_nt_os_alias] 反查 OS Name。
    ///
    /// 七项验收 item 1 证据（wgnt-seven-item-2026-11-21.md）：nt adapter 的
    /// OS InterfaceAlias 是驱动默认名 `WireGuard`，隧道名只出现在
    /// InterfaceDescription——绝不能把 `wg-mlt-<handle>` 或 `wg-meshlet`
    /// 直接当 OS 别名传给 `Set-NetConnectionProfile`/`Get-NetIPAddress`。
    /// 解析失败 fail closed（apply 拒绝），绝不带错名继续。
    pub(super) fn effective_interface_alias(&self) -> Result<String, NetworkError> {
        if self.nt.is_some() {
            let adapter_name = nt_adapter_name(&nt_adapter_handle(&self.interface))?;
            crate::windows_wireguard_nt::resolve_nt_os_alias(&adapter_name)
        } else {
            Ok(self.interface.clone())
        }
    }

    /// nt adapter 的地址读数：`Get-NetIPAddress` 里 InterfaceAlias 等于 OS
    /// 别名（[crate::windows_wireguard_nt::resolve_nt_os_alias] 按
    /// InterfaceDescription 反查——隧道名 `wg-mlt-<handle>` 不在 OS 别名上，
    /// 见七项验收 item 1 证据）的条目。读不到 → `None`（证据缺失不判，同
    /// [Self::lan_addresses_sync] 的口径）。
    fn nt_adapter_address(&self, adapter_name: &str) -> Option<Ipv4Addr> {
        let os_alias = crate::windows_wireguard_nt::resolve_nt_os_alias(adapter_name).ok()?;
        self.lan_ip_entries()
            .ok()?
            .into_iter()
            .find(|(alias, _, _)| alias.eq_ignore_ascii_case(&os_alias))
            .map(|(_, addr, _)| addr)
    }

    /// nt 模型的应用入口：[TunnelConfig] → adapter 计划（handle 从接口名
    /// 派生，[crate::windows_wireguard_nt::nt_adapter_handle]）→ 运行时装配。
    /// 返回驱动回读的生效 listen 端口（防火墙联动用）。计划层守门拒绝
    /// （listen_port 缺失 / MTU 非 1420 / peer endpoint 缺失等）原样 fail
    /// closed 透传——nt 不能像服务模型那样让驱动「自选端口」。
    fn nt_apply_tunnel_config(
        &self,
        nt: &NtRuntime,
        tunnel: &TunnelConfig,
    ) -> Result<u16, NetworkError> {
        let handle = nt_adapter_handle(&self.interface);
        let plan = crate::windows_wireguard_nt::nt_interface_plan(tunnel, &handle)?;
        nt.apply(&plan)
    }

    /// nt 模型接管数据面前的灰度/回滚面清理：卸掉同接口的旧
    /// `WireGuardTunnel$<interface>` 服务（服务模型遗留）。双数据面（服务 +
    /// nt adapter）同址同路由必冲突，绝不并存——卸载即停即删，无断流之外的
    /// 残留。幂等：无服务（含从未装过）跳过；wireguard.exe 缺失但服务在
    /// （无法卸载）→ 显式报错 fail closed，绝不带病切换。
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
        // 日志由 agent 层记录（本 crate 不依赖 tracing，保持数据面层静默）。
        Ok(())
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
        // 共享隧道配置：服务模型渲染 conf，nt 模型直接走 adapter 装配——
        // 两模型同一计划、同一 hub_endpoint 兜底、同一私钥语义。
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
        // nt 模型（tunnel_backend="nt"）：无 wireguard.exe——dll 内嵌绑定。
        // 防火墙联动用 adapter 回读的生效端口（模块纪律：回读为准，不用请求值）。
        if let Some(nt) = &self.nt {
            // 接管前卸掉服务模型遗留隧道（双数据面绝不并存，见方法注释）。
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
        // WIN-PORT-1 缺陷②：conf 落 ProgramData（受限令牌隧道服务读不到
        // 用户会话 temp）。目录先收紧 ACL 再写文件——新文件自创建起继承
        // 收紧后的 ACL，私钥不落宽继承窗口；写后对文件再兜底收紧一次。
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
        if let Some(nt) = &self.nt {
            self.uninstall_stale_service_tunnel_sync()?;
            self.nt_apply_tunnel_config(nt, &config)?;
            return Ok(ApplyResult::ok());
        }
        let exe = self.find_wireguard_exe().ok_or_else(|| {
            NetworkError::Unsupported("WireGuard for Windows is not installed".to_string())
        })?;
        let conf = render_wireguard_conf(&config);
        // 与 apply_device_plan_sync 同口径（WIN-PORT-1 缺陷②）：conf 落
        // ProgramData + 目录/文件 ACL 收紧，受限令牌服务可读、普通用户不可读。
        let conf_path = crate::windows_tunnel::tunnel_conf_path(&config.name);
        ensure_conf_dir_acl(&crate::windows_tunnel::tunnel_conf_dir())?;
        write_tunnel_conf(&conf_path, &conf)?;
        ensure_conf_file_acl(&conf_path)?;
        // 与 apply_device_plan_sync 同路径：已存在服务必须停/卸载/装新 conf，
        // 绝不把 "already installed" 当成功（那会静默保留旧 key/地址）。
        self.install_tunnel_reconfigured(&exe, &conf_path)?;
        Ok(ApplyResult::ok())
    }

    async fn apply_routes(
        &mut self,
        routes: Vec<RouteConfig>,
    ) -> Result<ApplyResult, NetworkError> {
        // nt 模型的路由由 adapter set_default_route（peer allowed_ips）装配，
        // 不经 netsh——独立调用本方法会与驱动路由重复/错位，明确拒绝而非
        // 假装成功（生产路径走 apply_device_plan_sync，不经过这里）。
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
        // nt 模型：adapter 随句柄消亡——从运行时取出并 Drop 即回滚；未持
        // （已回滚/从未应用）按幂等成功处理。
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
