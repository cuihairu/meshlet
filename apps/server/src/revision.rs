//! 配置版本与应用状态 API（[存档 §10](../../docs/review/chatgpt-2026-10-13.md)、
//! [ADR-009](../../docs/decisions/adr-009-config-revision-rollback.md)）。
//!
//! **DB 写入 ≠ 显示生效**（§10.1）：期望配置的每次变更只生成 `Pending` 修订；
//! 只有 backend 成功把配置应用到实际网络环境后才转为 `Applied`。应用失败
//! （**含结果不确定**）进入 `Failed` 并保留可诊断的 `error_summary`。
//!
//! 数据面接线（ADR-007）：`[dataplane] enabled = true` 时 apply 走
//! [`HubDataPlaneBackend`]——按当前期望配置快照在本机执行 WireGuard/路由
//! （平台后端 [`meshlet_network::SystemBackend`]：Linux 真实内核执行；其他
//! 平台每个操作显式 `Unsupported`，ADR-008 Windows 后端待接入）。默认（未配置或
//! `enabled = false`）仍是 [`UnconfiguredBackend`] 显式失败：失败可见、状态
//! 可区分，升级不悄悄接管内核。网关侧 NAT（ADR-006）在网关设备上执行，随
//! agent 数据面交付（server 只下 hub 侧转发面）。
//!
//! apply / rollback 的结论同时收敛到每条期望项的 `status`
//! （[`service::settle_desired_state`]）：只有真下发到内核的路由与 Alias 映射
//! 才转 `applied`，其余转 `failed`——agent 数据面据此取计划（§10.1）。
//!
//! 并发语义（§10.4）：修订版本号网络内单调递增，同一网络的配置修改由
//! 「先记录修订、再应用修订」串行化；非法跃迁（如对失败修订原地重试）返回
//! 409，重试路径是记录新修订。

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use meshlet_config::DataPlaneConfig;
use meshlet_domain::{
    AliasMapping, ConfigApplyBackend, ConfigRevision, DeviceStatus, Ipv4Cidr, NetworkId, RouteMode,
};
use meshlet_network::{PeerConfig, RouteConfig, SystemBackend, TunnelConfig};
use serde::Serialize;
use std::sync::Arc;

use crate::auth::{AuthenticatedUser, CsrfHeader, SharedAppState, WriteUser};
use crate::service::{self, MeshState, ServiceError};

/// 配置版本视图（`GET /config-revisions`、版本详情、apply/rollback 响应）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RevisionView {
    pub network_id: String,
    pub revision: u64,
    pub desired_config_hash: String,
    /// ADR-009 状态机：`pending`/`applying`/`applied`/`failed`/
    /// `rollback_pending`/`rolled_back`。
    pub apply_status: String,
    pub created_at: String,
    /// 成功应用时刻；`Failed`/`Pending` 恒为 `null`（不声称已生效）。
    pub applied_at: Option<String>,
    /// 失败诊断（§12.2：失败可见）；成功时为 `null`。
    pub error_summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub convergence: Option<serde_json::Value>,
}

pub fn to_revision_view(r: &ConfigRevision) -> RevisionView {
    RevisionView {
        network_id: r.network_id.to_string(),
        revision: r.revision,
        desired_config_hash: r.desired_config_hash.clone(),
        apply_status: r.apply_status.as_str().to_string(),
        created_at: r.created_at.clone(),
        applied_at: r.applied_at.clone(),
        error_summary: r.error_summary.clone(),
        convergence: None,
    }
}

/// 数据面未接入时的占位 backend：任何应用/回滚都**显式失败**（§10.3 不得假装
/// 成功）。错误文本刻意写明「已记录但未应用」，让调用方一眼看出 DB 写入与
/// 实际生效的差别。
pub struct UnconfiguredBackend;

impl ConfigApplyBackend for UnconfiguredBackend {
    fn apply(&mut self, _revision: &ConfigRevision) -> Result<(), String> {
        Err(
            "no network backend configured: desired config recorded but not applied to any \
             wireguard interface on this host"
                .to_string(),
        )
    }

    fn rollback(&mut self, _revision: &ConfigRevision) -> Result<(), String> {
        Err(
            "no network backend configured: no meshlet-managed objects on this host to \
             roll back"
                .to_string(),
        )
    }
}

/// 构造一次应用/回滚 backend 的工厂：按指定网络的当前期望配置取快照。
///
/// 每次请求构造独立实例（领域 trait 是 `&mut self`），但**必须在网络级互斥内
/// 调用**——§10.4 的「同一网络的配置修改串行化」由此保证：并发 apply 不会拿到
/// 各自的后端实例交叉改写 WireGuard Peer / 路由 / NAT。生产由 `[dataplane]`
/// 配置决定 [`hub_backend_factory`] 或 [`unconfigured_backend_factory`]；集成
/// 测试注入计数 backend，在 API 层验证幂等与回滚边界（§10.3 验收）。
pub type BackendFactory =
    Arc<dyn Fn(&MeshState, &str) -> Box<dyn ConfigApplyBackend + Send> + Send + Sync>;

/// 默认工厂：数据面未接入，显式失败。
pub fn unconfigured_backend_factory() -> BackendFactory {
    Arc::new(|_, _| Box::new(UnconfiguredBackend))
}

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
            desired_config_hash: String::new(),
        };
        check.tunnel.private_key = self.read_private_key()?;
        backend
            .isolate_hub_sync(check.tunnel.address)
            .map_err(|e| e.to_string())?;
        if !backend.device_plan_matches_sync(&check).unwrap_or(false)
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
        let backend = (self.make_backend)().with_interface(self.interface.clone());
        let tunnel_result = backend
            .apply_tunnel_sync(&tunnel)
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
            desired_config_hash: String::new(),
        };
        if !backend
            .device_plan_matches_sync(&check)
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
        let backend = (self.make_backend)().with_interface(self.interface.clone());
        if let Some(previous) = &self.previous {
            let mut tunnel = previous.hub.tunnel.clone();
            tunnel.private_key = self.read_private_key()?;
            backend
                .apply_tunnel_sync(&tunnel)
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
                desired_config_hash: String::new(),
            };
            if !backend
                .device_plan_matches_sync(&check)
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

/// 配置版本与应用状态路由（管理 API：会话认证 + 写请求 CSRF 头）。
pub fn routes() -> Router<SharedAppState> {
    Router::new()
        .route(
            "/api/v1/networks/{network_id}/config-revisions",
            get(list_revisions_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/config-revisions/{revision}",
            get(get_revision_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/config-revisions/{revision}/apply",
            post(apply_revision_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/config-revisions/{revision}/rollback",
            post(rollback_revision_handler),
        )
}

fn network_id_of(id: &str) -> meshlet_domain::NetworkId {
    meshlet_domain::NetworkId(id.to_string())
}

/// `GET /api/v1/networks/{network_id}/config-revisions`：全部修订（升序）。
pub async fn list_revisions_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path(network_id): Path<String>,
) -> Result<Json<Vec<RevisionView>>, ServiceError> {
    let _persist = state.persist.lock().await;
    let mut views = {
        let guard = state.mesh.lock().unwrap();
        service::require_network(&guard, &network_id)?;
        guard
            .ledger
            .revisions(&network_id_of(&network_id))
            .iter()
            .map(to_revision_view)
            .collect::<Vec<_>>()
    };
    if let Some(last) = views
        .iter_mut()
        .rev()
        .find(|r| r.apply_status != "rolled_back")
    {
        last.convergence = Some(
            serde_json::to_value(crate::convergence::status(&state, &network_id).await?)
                .map_err(|e| ServiceError::Internal(e.to_string()))?,
        );
    }
    Ok(Json(views))
}

/// `GET /api/v1/networks/{network_id}/config-revisions/{revision}`：版本详情。
pub async fn get_revision_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path((network_id, revision)): Path<(String, u64)>,
) -> Result<Json<RevisionView>, ServiceError> {
    let _persist = state.persist.lock().await;
    let (mut view, current) = {
        let guard = state.mesh.lock().unwrap();
        service::require_network(&guard, &network_id)?;
        let r = guard
            .ledger
            .get(&network_id_of(&network_id), revision)
            .ok_or_else(|| ServiceError::RevisionNotFound(revision.to_string()))?;
        (
            to_revision_view(r),
            guard
                .ledger
                .current(&network_id_of(&network_id))
                .is_some_and(|r| r.revision == revision),
        )
    };
    if current {
        view.convergence = Some(
            serde_json::to_value(crate::convergence::status(&state, &network_id).await?)
                .map_err(|e| ServiceError::Internal(e.to_string()))?,
        );
    }
    Ok(Json(view))
}

/// `POST .../config-revisions/{revision}/apply`：把该修订应用到实际环境。
///
/// 返回该修订的当前视图——`apply_status` 是结论；backend 失败时同样 200，
/// 但状态为 `failed` 且 `error_summary` 说明原因（失败可见，不伪装成功）。
pub async fn apply_revision_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path((network_id, revision)): Path<(String, u64)>,
) -> Result<Json<RevisionView>, ServiceError> {
    let _persist = state.persist.lock().await;
    // Write intent before touching the kernel, so a crash becomes an explicit failure.
    let should_apply = {
        let guard = state.mesh.lock().unwrap();
        let current = guard.ledger.current(&network_id_of(&network_id));
        current.is_some_and(|r| {
            r.revision == revision && r.apply_status == meshlet_domain::ApplyStatus::Pending
        })
    };
    if should_apply {
        sqlx::query("UPDATE config_revisions SET apply_status='applying' WHERE network_id=? AND revision=? AND apply_status='pending'")
            .bind(&network_id).bind(revision as i64).execute(state.auth.pool()).await.map_err(crate::persist::internal)?;
    }
    let (applied, settle, candidate) = {
        let mut guard = state.mesh.lock().unwrap();
        service::require_network(&guard, &network_id)?;
        if guard
            .ledger
            .get(&network_id_of(&network_id), revision)
            .is_none()
        {
            return Err(ServiceError::RevisionNotFound(revision.to_string()));
        }
        if let Some(current) = guard.ledger.current(&network_id_of(&network_id)) {
            if current.revision != revision {
                return Err(ServiceError::Conflict(format!(
                    "revision {revision} superseded by {}",
                    current.revision
                )));
            }
        }
        // backend 在网络级互斥内按当前期望配置构造快照（§10.4 串行化）。
        let mut backend = (state.apply_backend)(&guard, &network_id);
        let applied = guard
            .ledger
            .apply(
                &network_id_of(&network_id),
                revision,
                backend.as_mut(),
                service::now(),
            )
            .map_err(ServiceError::from_ledger)?;
        // 结论收敛到每条期望项（§10.1 的路由/映射层镜像）：只有真下发到内核
        // 的前缀才转 `applied`，agent 数据面据此取计划。
        let success = applied.apply_status == meshlet_domain::ApplyStatus::Applied;
        let candidate = if success && should_apply && state.dataplane.enabled {
            Some(
                deployment(
                    &guard,
                    &network_id,
                    &state.dataplane,
                    state.tunnel_mtu,
                    revision,
                )
                .map_err(ServiceError::Internal)?,
            )
        } else {
            None
        };
        let settle = if success && !should_apply {
            service::DesiredStateSettle::default()
        } else if success && state.dataplane.enabled {
            service::settle_desired_with_status(
                &mut guard,
                &network_id,
                meshlet_domain::DesiredStateStatus::Pending,
            )
        } else {
            service::settle_desired_state(&mut guard, &network_id, success)
        };
        (applied, settle, candidate)
    };
    if let Err(error) =
        crate::persist::commit_application(state.auth.pool(), &applied, &settle, candidate.as_ref())
            .await
    {
        let message = format!("apply outcome could not be persisted: {error}");
        let mut mesh = state.mesh.lock().unwrap();
        mesh.ledger
            .mark_apply_unconfirmed(&network_id_of(&network_id), revision, message.clone());
        service::settle_desired_state(&mut mesh, &network_id, false);
        return Err(ServiceError::Internal(message));
    }
    if let Some(candidate) = candidate {
        state
            .mesh
            .lock()
            .unwrap()
            .deployments
            .insert(network_id.clone(), candidate);
    }
    // 应用失败必留痕（§16.5）；结果以 apply_status 为准（`applied` 即成功，
    // 其余一律按失败留痕），不凭响应码判断。
    let mut view = to_revision_view(&applied);
    view.convergence = Some(
        serde_json::to_value(crate::convergence::status(&state, &network_id).await?)
            .map_err(|e| ServiceError::Internal(e.to_string()))?,
    );
    let applied_ok = view.apply_status == "applied";
    let (action, detail) = if !applied_ok {
        (
            "revision.apply_failed",
            serde_json::json!({
                "network_id": network_id,
                "error_summary": view.error_summary,
            }),
        )
    } else {
        (
            "revision.applied",
            serde_json::json!({ "network_id": network_id }),
        )
    };
    crate::audit::record_or_fail(
        &state,
        Some(&user_id.0),
        action,
        "revision",
        Some(&revision.to_string()),
        Some(detail),
    )
    .await?;
    // 指标（§17.2 配置应用成功率/失败数）：以状态机结论计数，不凭响应码。
    state.metrics.record_config_apply(applied_ok);
    if applied_ok {
        crate::op_log!(
            info,
            "revision",
            "apply_revision",
            &network_id,
            crate::telemetry::NOT_APPLICABLE,
            &revision.to_string(),
            crate::telemetry::ErrorCategory::None.as_str(),
            crate::telemetry::RESULT_OK
        );
    } else {
        crate::op_log!(
            warn,
            "revision",
            "apply_revision",
            &network_id,
            crate::telemetry::NOT_APPLICABLE,
            &revision.to_string(),
            crate::telemetry::ErrorCategory::Internal.as_str(),
            crate::telemetry::RESULT_ERROR
        );
    }
    Ok(Json(view))
}

/// `POST .../config-revisions/{revision}/rollback`：回滚一个 `Failed` 修订。
/// 回滚只允许动 Meshlet 自有对象（ADR-007），不得清空系统路由（§10.3）。
pub async fn rollback_revision_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path((network_id, revision)): Path<(String, u64)>,
) -> Result<Json<RevisionView>, ServiceError> {
    let _persist = state.persist.lock().await;
    let should_rollback = {
        let mesh = state.mesh.lock().unwrap();
        service::require_network(&mesh, &network_id)?;
        let target = mesh
            .ledger
            .get(&network_id_of(&network_id), revision)
            .ok_or_else(|| ServiceError::RevisionNotFound(revision.to_string()))?;
        if target.apply_status == meshlet_domain::ApplyStatus::RolledBack {
            return Ok(Json(to_revision_view(target)));
        }
        mesh.ledger
            .current(&network_id_of(&network_id))
            .is_some_and(|r| r.revision == revision)
            && matches!(
                target.apply_status,
                meshlet_domain::ApplyStatus::Failed | meshlet_domain::ApplyStatus::RollbackPending
            )
    };
    if should_rollback {
        sqlx::query("UPDATE config_revisions SET apply_status='rollback_pending' WHERE network_id=? AND revision=?")
            .bind(&network_id).bind(revision as i64).execute(state.auth.pool()).await.map_err(crate::persist::internal)?;
    }
    let (rolled, settle) = {
        let mut guard = state.mesh.lock().unwrap();
        service::require_network(&guard, &network_id)?;
        let mut backend = (state.apply_backend)(&guard, &network_id);
        let rolled = guard
            .ledger
            .rollback(&network_id_of(&network_id), revision, backend.as_mut())
            .map_err(ServiceError::from_ledger)?;
        if rolled.apply_status == meshlet_domain::ApplyStatus::RolledBack && state.dataplane.enabled
        {
            if let Some(mut saved) = guard.deployments.get(&network_id).cloned() {
                saved.routes.retain(|r| {
                    guard
                        .registry
                        .find_by_id(&r.gateway_device_id)
                        .is_some_and(|d| d.is_active())
                });
                saved
                    .aliases
                    .retain(|a| saved.routes.iter().any(|r| r.id == a.lan_route_id));
                guard
                    .lan_routes
                    .insert(network_id.clone(), saved.routes.clone());
                guard
                    .aliases
                    .insert(network_id.clone(), saved.aliases.clone());
                guard.deployments.insert(network_id.clone(), saved);
            } else {
                guard.lan_routes.remove(&network_id);
                guard.aliases.remove(&network_id);
            }
        }
        // 回滚清理了 hub 侧对象 → 期望项不得继续显示 `applied`（§10.3）：
        // 回滚确认即转 `failed`，未确认（rollback_pending）同样不算生效。
        let settle = if rolled.apply_status == meshlet_domain::ApplyStatus::RolledBack
            && state.dataplane.enabled
        {
            service::settle_desired_with_status(
                &mut guard,
                &network_id,
                meshlet_domain::DesiredStateStatus::Pending,
            )
        } else {
            service::settle_desired_state(&mut guard, &network_id, false)
        };
        (rolled, settle)
    };
    let restore =
        rolled.apply_status == meshlet_domain::ApplyStatus::RolledBack && state.dataplane.enabled;
    let saved = state
        .mesh
        .lock()
        .unwrap()
        .deployments
        .get(&network_id)
        .cloned();
    let committed = crate::persist::commit_rollback(
        state.auth.pool(),
        &rolled,
        &settle,
        restore,
        saved.as_ref(),
    )
    .await;
    if let Err(error) = committed {
        let message = format!("rollback outcome could not be persisted: {error}");
        state.mesh.lock().unwrap().ledger.mark_rollback_unconfirmed(
            &network_id_of(&network_id),
            revision,
            message.clone(),
        );
        return Err(ServiceError::Internal(message));
    }
    // 回滚失败同样留痕（§16.5）：无 backend 的回滚停在 `rollback_pending`
    //（明确未完成）——除 `rolled_back` 外一律按失败留痕。
    let mut view = to_revision_view(&rolled);
    if rolled.apply_status != meshlet_domain::ApplyStatus::RolledBack {
        view.convergence = Some(
            serde_json::to_value(crate::convergence::status(&state, &network_id).await?)
                .map_err(|e| ServiceError::Internal(e.to_string()))?,
        );
    }
    let rolled_back = view.apply_status == "rolled_back";
    let (action, detail) = if !rolled_back {
        (
            "revision.rollback_failed",
            serde_json::json!({
                "network_id": network_id,
                "error_summary": view.error_summary,
            }),
        )
    } else {
        (
            "revision.rolled_back",
            serde_json::json!({ "network_id": network_id }),
        )
    };
    crate::audit::record_or_fail(
        &state,
        Some(&user_id.0),
        action,
        "revision",
        Some(&revision.to_string()),
        Some(detail),
    )
    .await?;
    // 指标（§17.2 回滚结果）：`rolled_back` 计成功，`rollback_pending` 计未确认。
    state.metrics.record_config_rollback(rolled_back);
    if rolled_back {
        crate::op_log!(
            info,
            "revision",
            "rollback_revision",
            &network_id,
            crate::telemetry::NOT_APPLICABLE,
            &revision.to_string(),
            crate::telemetry::ErrorCategory::None.as_str(),
            crate::telemetry::RESULT_OK
        );
    } else {
        crate::op_log!(
            warn,
            "revision",
            "rollback_revision",
            &network_id,
            crate::telemetry::NOT_APPLICABLE,
            &revision.to_string(),
            crate::telemetry::ErrorCategory::Internal.as_str(),
            crate::telemetry::RESULT_ERROR
        );
    }
    Ok(Json(view))
}
