use super::BackendFactory;
use meshlet_config::DataPlaneConfig;
use meshlet_domain::{
    AliasMapping, ConfigApplyBackend, ConfigRevision, DeviceStatus, Ipv4Cidr, NetworkId, RouteMode,
};
use meshlet_network::{PeerConfig, RouteConfig, SystemBackend, TunnelConfig};
use std::collections::BTreeSet;
use std::sync::Arc;

use crate::auth::SharedAppState;
use crate::service::{self, MeshState};

// ---------------------------------------------------------------------------
// Hub 数据面 backend（ADR-007 接线）
// ---------------------------------------------------------------------------

/// 一次应用的 hub 侧期望快照（从 [MeshState] 对账翻译，§10.1）。
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct HubPlan {
    tunnel: TunnelConfig,
    routes: Vec<RouteConfig>,
}

/// Last confirmed hub plan, stored without private keys for restart/rollback.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct Deployment {
    pub revision: u64,
    pub hub: HubPlan,
    pub routes: Vec<meshlet_domain::LanRoute>,
    pub aliases: Vec<AliasMapping>,
}

pub(crate) fn deployment(
    mesh: &MeshState,
    network_id: &str,
    cfg: &DataPlaneConfig,
    mtu: Option<u32>,
    revision: u64,
) -> Result<Deployment, String> {
    Ok(Deployment {
        revision,
        hub: hub_plan(mesh, network_id, &network_dataplane(cfg, network_id)?, mtu)?,
        routes: mesh.lan_routes.get(network_id).cloned().unwrap_or_default(),
        aliases: mesh.aliases.get(network_id).cloned().unwrap_or_default(),
    })
}

/// hub 数据面 backend：把网络当前期望配置真实下发到本机内核。
///
/// - apply = `apply_tunnel`（接口/地址/私钥/端口/peer 对账）+ `apply_routes`
///   （LAN/Alias 路由、ip_forward、FORWARD 放行），两步都成功才算成功（§10.3
///   失败不报成功）；
/// - rollback = Linux 后端的 Meshlet 自有对象清理（§10.3）；
/// - 网关侧 NAT 不在此执行（ADR-006：转换在目标网关，随 agent 交付）。
pub struct HubDataPlaneBackend {
    plan: Result<HubPlan, String>,
    interface: String,
    previous: Option<Deployment>,
    previous_error: Option<String>,
    private_key_file: Option<String>,
    /// 后端构造（生产 `SystemBackend::new()`；netns 集成测试注入指定
    /// netns 的后端，同一 hub 期望翻译跑进沙箱内核）。
    make_backend: Arc<dyn Fn() -> SystemBackend + Send + Sync>,
}

/// 撤销集合优先于机械恢复：已保存的 hub 部署在下发内核或写回恢复日志前，
/// 必须对当前授权快照重新过滤——安全语义优先于机械恢复。过滤顺序即优先级：
/// 被撤销设备的 peer 先走，网关不再活跃的路由随之删除，失去所属路由的
/// alias 再删，最后删掉失去 peer allowed-ips 依据的 hub 转发路由（网关侧
/// NAT 随路由集合在 agent 侧收敛，无需单独过滤）。
pub(crate) fn enforce_authorization(mesh: &MeshState, network_id: &str, saved: &mut Deployment) {
    let active_keys: std::collections::HashSet<_> = mesh
        .registry
        .devices()
        .iter()
        .filter(|d| d.is_active() && d.network_id.0 == network_id)
        .map(|d| d.public_key.as_str())
        .collect();
    saved
        .hub
        .tunnel
        .peers
        .retain(|p| active_keys.contains(p.public_key.as_str()));
    saved.routes.retain(|r| {
        mesh.registry
            .find_by_id(&r.gateway_device_id)
            .is_some_and(|d| d.is_active())
    });
    saved
        .aliases
        .retain(|a| saved.routes.iter().any(|r| r.id == a.lan_route_id));
    saved.hub.routes.retain(|r| {
        saved
            .hub
            .tunnel
            .peers
            .iter()
            .any(|p| p.allowed_ips.contains(&r.destination))
    });
}

impl HubDataPlaneBackend {
    /// 从期望状态快照构造（网络不存在/缺 IPAM 等构造错误延迟到 apply 报告，
    /// 保持工厂不可失败的签名）；后端构造可注入（netns 集成测试用）。
    fn from_mesh_with(
        mesh: &MeshState,
        network_id: &str,
        cfg: &DataPlaneConfig,
        tunnel_mtu: Option<u32>,
        make_backend: Arc<dyn Fn() -> SystemBackend + Send + Sync>,
    ) -> Self {
        let mut previous = mesh.deployments.get(network_id).cloned();
        if let Some(saved) = &mut previous {
            enforce_authorization(mesh, network_id, saved);
        }
        let previous_error = previous.as_ref().and_then(|saved| {
            saved.hub.routes.iter().find_map(|r| {
                service::check_forward_prefix(mesh, network_id, r.destination)
                    .err()
                    .map(|e| e.to_string())
            })
        });
        let scoped = network_dataplane(cfg, network_id);
        let plan = scoped
            .as_ref()
            .map_err(Clone::clone)
            .and_then(|cfg| hub_plan(mesh, network_id, cfg, tunnel_mtu));
        Self {
            plan,
            previous,
            previous_error,
            interface: scoped
                .as_ref()
                .map(|cfg| cfg.interface.clone())
                .unwrap_or_else(|_| cfg.interface.clone()),
            private_key_file: cfg.private_key_file.clone(),
            make_backend,
        }
    }

    /// hub 私钥：apply 时从文件读取（不落库，ADR-010）；未配置则保留接口
    /// 现有私钥（幂等重应用；首装必须配置否则无法握手——错误如实报出）。
    fn read_private_key(&self) -> Result<Option<String>, String> {
        match &self.private_key_file {
            None => Ok(None),
            Some(path) => std::fs::read_to_string(path)
                .map(|s| Some(s.trim().to_string()))
                .map_err(|e| format!("read private_key_file {path}: {e}")),
        }
    }
}

impl ConfigApplyBackend for HubDataPlaneBackend {
    fn reconcile(&mut self) -> Result<(), String> {
        if let Some(error) = &self.previous_error {
            return Err(error.clone());
        }
        let Some(saved) = self.previous.clone() else {
            return Ok(());
        };
        let backend = (self.make_backend)().with_interface(saved.hub.tunnel.name.clone());
        let mut check = meshlet_network::DevicePlan {
            desired_revision: saved.revision,
            hub_port: saved.hub.tunnel.listen_port,
            tunnel: saved.hub.tunnel.clone(),
            routes: saved.hub.routes.clone(),
            nat_rules: vec![],
            hub_address: None,
            publish: None,
            ssh_config: None,
            desired_config_hash: String::new(),
        };
        check.tunnel.private_key = self.read_private_key()?;
        backend
            .isolate_hub_sync(check.tunnel.address)
            .map_err(|e| e.to_string())?;
        if !backend
            .device_plan_matches_sync(&check, &BTreeSet::new())
            .unwrap_or(false)
            || backend
                .inspect_sync()
                .map_err(|e| e.to_string())?
                .forwarding_enabled
                != Some(true)
        {
            let wanted = std::mem::replace(&mut self.plan, Ok(saved.hub.clone()));
            let result = self.rollback(&meshlet_domain::ConfigRevision {
                network_id: NetworkId(String::new()),
                revision: saved.revision,
                desired_config_hash: String::new(),
                apply_status: meshlet_domain::ApplyStatus::Applied,
                created_at: String::new(),
                applied_at: None,
                error_summary: None,
            });
            self.plan = wanted;
            result?;
        }
        Ok(())
    }

    fn apply(&mut self, _revision: &ConfigRevision) -> Result<(), String> {
        let plan = self.plan.as_ref().map_err(Clone::clone)?;
        let mut tunnel = plan.tunnel.clone();
        tunnel.private_key = self.read_private_key()?;
        #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
        let mut backend = (self.make_backend)().with_interface(self.interface.clone());
        let tunnel_result = backend
            .apply_tunnel_sync(&tunnel, &BTreeSet::new())
            .map_err(|e| format!("apply tunnel: {e}"))?;
        if !tunnel_result.applied {
            return Err(format!(
                "apply tunnel rejected: {}",
                tunnel_result.error.unwrap_or_else(|| "unknown".into())
            ));
        }
        let routes_result = backend
            .apply_routes_sync(&plan.routes)
            .map_err(|e| format!("apply routes: {e}"))?;
        if !routes_result.applied {
            return Err(format!(
                "apply routes rejected: {}",
                routes_result.error.unwrap_or_else(|| "unknown".into())
            ));
        }
        backend
            .isolate_hub_sync(plan.tunnel.address)
            .map_err(|e| format!("isolate network: {e}"))?;
        let check = meshlet_network::DevicePlan {
            desired_revision: _revision.revision,
            hub_port: tunnel.listen_port,
            tunnel,
            routes: plan.routes.clone(),
            nat_rules: vec![],
            hub_address: None,
            publish: None,
            ssh_config: None,
            desired_config_hash: String::new(),
        };
        if !backend
            .device_plan_matches_sync(&check, &BTreeSet::new())
            .map_err(|e| e.to_string())?
        {
            return Err("hub plan did not match kernel readback".into());
        }
        Ok(())
    }

    fn rollback(&mut self, _revision: &ConfigRevision) -> Result<(), String> {
        if let Some(error) = &self.previous_error {
            return Err(error.clone());
        }
        #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
        let mut backend = (self.make_backend)().with_interface(self.interface.clone());
        if let Some(previous) = &self.previous {
            let mut tunnel = previous.hub.tunnel.clone();
            tunnel.private_key = self.read_private_key()?;
            backend
                .apply_tunnel_sync(&tunnel, &BTreeSet::new())
                .map_err(|e| e.to_string())?;
            backend
                .apply_routes_sync(&previous.hub.routes)
                .map_err(|e| e.to_string())?;
            backend
                .isolate_hub_sync(tunnel.address)
                .map_err(|e| e.to_string())?;
            let check = meshlet_network::DevicePlan {
                desired_revision: previous.revision,
                hub_port: tunnel.listen_port,
                tunnel,
                routes: previous.hub.routes.clone(),
                nat_rules: vec![],
                hub_address: None,
                publish: None,
                ssh_config: None,
                desired_config_hash: String::new(),
            };
            if !backend
                .device_plan_matches_sync(&check, &BTreeSet::new())
                .map_err(|e| e.to_string())?
            {
                return Err("previous hub plan could not be verified".into());
            }
        } else {
            // The hub has no NAT. Never sweep gateway rules or other networks.
            backend.clear_hub_sync().map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

/// Stable per-network hub resources. net-1 preserves the original interface/port.
pub fn network_dataplane(
    cfg: &DataPlaneConfig,
    network_id: &str,
) -> Result<DataPlaneConfig, String> {
    let index: u16 = network_id
        .strip_prefix("net-")
        .and_then(|s| s.parse().ok())
        .filter(|n| *n > 0)
        .ok_or_else(|| "invalid network resource id".to_string())?;
    let mut out = cfg.clone();
    out.listen_port = Some(
        cfg.listen_port
            .unwrap_or(51820)
            .checked_add(index - 1)
            .ok_or_else(|| "network WireGuard port range exhausted".to_string())?,
    );
    if index > 1 {
        out.interface = format!("mlt{index}");
        if out.interface == cfg.interface {
            return Err("base interface conflicts with a reserved network interface".into());
        }
    }
    Ok(out)
}

/// 把指定网络的期望配置翻译为 hub 侧数据面计划。
///
/// - peer = 全部 Active 设备；allowed-ips = 设备虚拟 IP `/32` + 经该设备
///   转发的 LAN/Alias 前缀（cryptkey 路由必须覆盖 hub 加密下发目的地）；
/// - 路由 = LAN 路由（`Direct` → 真实目的段；`Alias` → 绑定 Alias 前缀）经
///   网关设备虚拟 IP；网关设备非 Active 的路由跳过（无对端可发）。
fn hub_plan(
    mesh: &MeshState,
    network_id: &str,
    cfg: &DataPlaneConfig,
    tunnel_mtu: Option<u32>,
) -> Result<HubPlan, String> {
    let network = mesh
        .network_row(network_id)
        .ok_or_else(|| format!("network {network_id} not found"))?;
    let hub = mesh
        .hub_address(network_id)
        .ok_or_else(|| format!("ipam missing for network {network_id}"))?;

    let devices: Vec<_> = mesh
        .registry
        .devices()
        .iter()
        .filter(|d| {
            d.network_id == NetworkId(network_id.to_string()) && d.status == DeviceStatus::Active
        })
        .collect();
    let routes_in = mesh
        .lan_routes
        .get(network_id)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let aliases: &[AliasMapping] = mesh
        .aliases
        .get(network_id)
        .map(Vec::as_slice)
        .unwrap_or(&[]);

    // hub 侧转发路由：Direct 用真实目的段，Alias 用 Alias 前缀（§9.4：VPS 只
    // 按前缀转发，转换在目标网关做）。
    let mut routes = Vec::new();
    for route in routes_in {
        let Some(gateway) = devices.iter().find(|d| d.id == route.gateway_device_id) else {
            continue;
        };
        let destinations: Vec<Ipv4Cidr> = match route.route_mode {
            RouteMode::Direct => vec![route.destination_cidr],
            RouteMode::Alias => aliases
                .iter()
                .filter(|a| a.lan_route_id == route.id)
                .map(|a| a.alias_cidr)
                .collect(),
        };
        for destination in destinations {
            service::check_forward_prefix(mesh, network_id, destination)
                .map_err(|e| e.to_string())?;
            routes.push(RouteConfig {
                destination,
                interface: cfg.interface.clone(),
                gateway: Some(gateway.virtual_ipv4),
            });
        }
    }

    // peer allowed-ips：虚拟 IP /32 + 经该设备转发的全部前缀。
    let mut peers = Vec::new();
    for device in &devices {
        let mut allowed_ips = vec![host_cidr(device.virtual_ipv4)];
        for route in &routes {
            if route.gateway == Some(device.virtual_ipv4)
                && !allowed_ips.contains(&route.destination)
            {
                allowed_ips.push(route.destination);
            }
        }
        peers.push(PeerConfig {
            public_key: device.public_key.clone(),
            allowed_ips,
            endpoint: None,
            persistent_keepalive_secs: None,
        });
    }

    Ok(HubPlan {
        tunnel: TunnelConfig {
            name: cfg.interface.clone(),
            address: hub,
            address_prefix: network.overlay_cidr.prefix_len(),
            listen_port: cfg.listen_port,
            peers,
            mtu: tunnel_mtu,
            private_key: None,
        },
        routes,
    })
}

pub(crate) fn recover_deployment(
    state: &SharedAppState,
    network: &str,
    _saved: Deployment,
) -> Result<(), String> {
    let mut backend = {
        let mesh = state.mesh.lock().unwrap();
        (state.apply_backend)(&mesh, network)
    };
    backend.reconcile()
}

/// `/32` 主机段（设备虚拟 IP 的 allowed-ips 单元）。
fn host_cidr(addr: std::net::Ipv4Addr) -> Ipv4Cidr {
    Ipv4Cidr::new(addr, 32).expect("host cidr is always valid")
}

/// 数据面工厂（`[dataplane] enabled = true`）：apply/rollback 真实执行
/// （生产路径：后端在本机 root namespace 构造）。
pub fn hub_backend_factory(dataplane: DataPlaneConfig, tunnel_mtu: Option<u32>) -> BackendFactory {
    hub_backend_factory_with(dataplane, tunnel_mtu, SystemBackend::new)
}

/// 同 [`hub_backend_factory`]，后端构造可注入——netns 集成测试把 hub 数据面
/// （同一份期望翻译）跑进沙箱 netns，验证 server→agent→内核全链路。
pub fn hub_backend_factory_with(
    dataplane: DataPlaneConfig,
    tunnel_mtu: Option<u32>,
    make_backend: impl Fn() -> SystemBackend + Send + Sync + 'static,
) -> BackendFactory {
    let make_backend = Arc::new(make_backend);
    Arc::new(move |mesh, network_id| {
        Box::new(HubDataPlaneBackend::from_mesh_with(
            mesh,
            network_id,
            &dataplane,
            tunnel_mtu,
            make_backend.clone(),
        ))
    })
}
