//! Network, enrollment, device, routing, alias, segment and forwarding operations.

use meshlet_domain::{
    generate_token, token_hash, AliasError, AliasMapping, AliasMappingId, BootstrapToken,
    DataplaneEvidence, DesiredStateStatus, Device, DeviceDirectState, DeviceId, DeviceRegistration,
    DirectEndpointReport, DirectLinkStatus, Invite, Ipam, Ipv4Cidr, LanRoute, LanRouteId, Network,
    Platform, ReturnPathMode, RouteMode, Segment, SegmentGrant, SegmentGrantBuilder,
    SegmentGrantId, SegmentGrantStatus, SegmentId, SegmentStatus, Timestamp, TranslationMode,
};
use meshlet_network::NetworkDiagnostics;
use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;

use crate::service::{
    error::ServiceError, operations_record::record_revision, shared::now, state::MeshState,
    views::*,
};
/// Creation-time validation, including this network. Plan readback uses
/// check_forward_prefix instead so a resource does not conflict with itself.
pub fn check_forward_prefix(
    state: &MeshState,
    network_id: &str,
    prefix: Ipv4Cidr,
) -> Result<(), ServiceError> {
    if let Some(n) = state
        .networks
        .values()
        .find(|n| n.id.to_string() != network_id && n.overlay_cidr.overlaps(&prefix))
    {
        return Err(ServiceError::RouteConflict(format!(
            "prefix {prefix} overlaps network {}",
            n.id
        )));
    }
    if state.lan_routes.iter().any(|(id, routes)| {
        id != network_id
            && routes
                .iter()
                .any(|r| r.route_mode == RouteMode::Direct && r.destination_cidr.overlaps(&prefix))
    }) || state.aliases.iter().any(|(id, aliases)| {
        id != network_id && aliases.iter().any(|a| a.alias_cidr.overlaps(&prefix))
    }) {
        return Err(ServiceError::RouteConflict(format!(
            "prefix {prefix} overlaps another network's forwarding prefix"
        )));
    }
    Ok(())
}

/// Creation-time validation, including this network. Plan readback uses
/// check_forward_prefix instead so a resource does not conflict with itself.
fn check_new_forward_prefix(
    state: &MeshState,
    network_id: &str,
    prefix: Ipv4Cidr,
) -> Result<(), ServiceError> {
    check_forward_prefix(state, network_id, prefix)?;
    if prefix.overlaps(&state.network(network_id)?.overlay_cidr) {
        return Err(ServiceError::RouteConflict(format!(
            "prefix {prefix} overlaps overlay"
        )));
    }
    if let Some(route) = state
        .lan_routes
        .get(network_id)
        .into_iter()
        .flatten()
        .find(|r| r.destination_cidr.overlaps(&prefix))
    {
        return Err(ServiceError::RouteConflict(format!(
            "prefix {prefix} overlaps existing route {} ({})",
            route.id, route.destination_cidr
        )));
    }
    check_local_alias_prefix(state, network_id, prefix)
}

fn check_local_alias_prefix(
    state: &MeshState,
    network_id: &str,
    prefix: Ipv4Cidr,
) -> Result<(), ServiceError> {
    if let Some(alias) = state
        .aliases
        .get(network_id)
        .into_iter()
        .flatten()
        .find(|a| a.alias_cidr.overlaps(&prefix))
    {
        return Err(ServiceError::RouteConflict(format!(
            "prefix {prefix} overlaps existing alias {} ({})",
            alias.id, alias.alias_cidr
        )));
    }
    Ok(())
}

pub fn create_network(
    state: &mut MeshState,
    req: CreateNetworkRequest,
) -> Result<NetworkView, ServiceError> {
    let overlay: Ipv4Cidr = req
        .overlay_cidr
        .parse()
        .map_err(|e| ServiceError::InvalidCidr(format!("{}: {e}", req.overlay_cidr)))?;
    if req.name.trim().is_empty() {
        return Err(ServiceError::InvalidInput("name must not be empty".into()));
    }
    if state
        .networks
        .values()
        .any(|n| n.overlay_cidr.overlaps(&overlay))
    {
        return Err(ServiceError::Conflict(format!(
            "overlay {overlay} already used by another network"
        )));
    }
    check_forward_prefix(state, "", overlay)?;
    let id = format!("net-{}", state.networks.len() + 1);
    let ts = now();
    let default_segment_ts = ts.clone();
    let network = Network::new(
        meshlet_domain::NetworkId(id.clone()),
        req.name.clone(),
        overlay,
        ts.clone(),
    );
    // IPAM：hub 取第一个可用地址（ADR-004），客户端从第二个起分配。
    let hub = overlay
        .iter_usable()
        .next()
        .expect("overlay has at least one usable address");
    let ipam = Ipam::new(overlay, hub).map_err(|e| ServiceError::Internal(e.to_string()))?;
    state.networks.insert(id.clone(), network);
    state.ipams.insert(id.clone(), ipam);
    state.restore_segment(Segment {
        id: meshlet_domain::default_segment_id(&meshlet_domain::NetworkId(id.clone())),
        network_id: meshlet_domain::NetworkId(id.clone()),
        name: "default".into(),
        cidr: overlay,
        status: meshlet_domain::SegmentStatus::Active,
        created_at: default_segment_ts,
    })?;
    // 记录初始期望配置修订（§10.1：DB 写入 ≠ 生效，初始修订为 Pending）。
    record_revision(state, &id)?;
    Ok(to_network_view(state, state.network(&id).unwrap()))
}

pub fn list_networks(state: &MeshState) -> Vec<NetworkView> {
    state
        .networks
        .values()
        .map(|n| to_network_view(state, n))
        .collect()
}

pub fn create_invite(
    state: &mut MeshState,
    network_id: &str,
    req: CreateInviteRequest,
) -> Result<CreateInviteResponse, ServiceError> {
    state.network(network_id)?; // 网络必须存在
    let max_uses = req.max_uses.unwrap_or(1);
    if max_uses == 0 {
        return Err(ServiceError::InvalidInput(
            "max_uses must be at least 1".into(),
        ));
    }
    let ts = now();
    let raw = generate_token();
    let invite = Invite::new(
        meshlet_domain::InviteId(format!("inv-{}", state.invites.len() + 1)),
        meshlet_domain::NetworkId(network_id.to_string()),
        &raw,
        req.expires_at.clone(),
        max_uses,
        ts.clone(),
    );
    let view = CreateInviteResponse {
        invite_id: invite.id.to_string(),
        token: raw,
        expires_at: req.expires_at,
    };
    // 只存摘要（§11.3）：索引键即 token_hash，原始 Token 不落地。
    state.invites.insert(invite.token_hash.clone(), invite);
    Ok(view)
}

pub fn revoke_invite(
    state: &mut MeshState,
    network_id: &str,
    invite_id: &str,
) -> Result<(), ServiceError> {
    state.network(network_id)?;
    let target = state
        .invites
        .values_mut()
        .find(|i| i.id.to_string() == invite_id)
        .ok_or_else(|| ServiceError::InviteNotFound(invite_id.to_string()))?;
    target
        .revoke(now())
        .map_err(|e| ServiceError::Conflict(e.to_string()))
}

// ---------------------------------------------------------------------------
// 设备自举注册（ZeroTier 式：自举码注册 → Pending → 控制中心审批/拒绝）
// ---------------------------------------------------------------------------

/// 创建自举码（控制中心侧）：长期、可复用的注册入口凭据。原始自举码
/// **仅此一次**返回，服务端只存 SHA-256 摘要（§11.3，同邀请）。
pub fn create_bootstrap_token(
    state: &mut MeshState,
    network_id: &str,
    req: CreateBootstrapTokenRequest,
) -> Result<CreateBootstrapTokenResponse, ServiceError> {
    state.network(network_id)?; // 网络必须存在
    if req.max_uses == Some(0) {
        return Err(ServiceError::InvalidInput(
            "max_uses must be at least 1, or unset for unlimited".into(),
        ));
    }
    // 自举码序列（`bootstrap_seq`，持久化到 mesh_meta）：重启不重号、不复用。
    let seq = state.bootstrap_seq() + 1;
    let raw = generate_token();
    let token = BootstrapToken {
        id: meshlet_domain::BootstrapTokenId(format!("bt-{seq}")),
        network_id: meshlet_domain::NetworkId(network_id.to_string()),
        token_hash: token_hash(&raw),
        max_uses: req.max_uses,
        used_count: 0,
        created_at: now(),
        revoked_at: None,
    };
    let view = CreateBootstrapTokenResponse {
        token_id: token.id.to_string(),
        token: raw,
        max_uses: req.max_uses,
    };
    // 只存摘要（§11.3）：索引键即 token_hash，原始自举码不落地。
    state
        .bootstrap_tokens
        .insert(token.token_hash.clone(), token);
    state.set_bootstrap_seq(seq);
    Ok(view)
}

/// 撤销自举码：之后任何用它发起的注册都被拒绝（已落地的 Pending 申请不受
/// 影响——审批流程独立于入口凭据）。返回撤销时刻供 handler 落库。
pub fn revoke_bootstrap_token(
    state: &mut MeshState,
    network_id: &str,
    token_id: &str,
) -> Result<Timestamp, ServiceError> {
    state.network(network_id)?;
    let target = state
        .bootstrap_tokens
        .values_mut()
        .find(|t| t.id.to_string() == token_id)
        .ok_or_else(|| ServiceError::BootstrapTokenNotFound(token_id.to_string()))?;
    if target.revoked_at.is_some() {
        return Err(ServiceError::Conflict(
            "bootstrap token already revoked".into(),
        ));
    }
    let revoked_at = now();
    target.revoked_at = Some(revoked_at.clone());
    Ok(revoked_at)
}

/// 自举码列表（控制台展示用量；只含元数据，不含摘要以外的任何凭据材料）。
pub fn list_bootstrap_tokens(
    state: &MeshState,
    network_id: &str,
) -> Result<Vec<BootstrapTokenView>, ServiceError> {
    state.network(network_id)?;
    let mut views: Vec<BootstrapTokenView> = state
        .bootstrap_tokens
        .values()
        .filter(|t| t.network_id.to_string() == network_id)
        .map(|t| BootstrapTokenView {
            id: t.id.to_string(),
            network_id: t.network_id.to_string(),
            max_uses: t.max_uses,
            used_count: t.used_count,
            created_at: t.created_at.clone(),
            revoked_at: t.revoked_at.clone(),
        })
        .collect();
    // 稳定输出：按创建时刻排序（`bt-N` 文本序在位数不同时不等价于创建序）。
    views.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    Ok(views)
}

/// 设备自举注册（公开端点）：持自举码换取 agent 凭证，落 **Pending** 申请。
/// 批准前不分配虚拟 IP、不进期望配置（`device_plan` 只读 `devices`），
/// 数据面对 Pending 设备完全不可见（migration 008 头注释的三条理由）。
pub fn register_device(
    state: &mut MeshState,
    req: RegisterDeviceRequest,
) -> Result<RegisterDeviceResponse, ServiceError> {
    let platform = match req.platform.as_str() {
        "linux" => Platform::Linux,
        "windows" => Platform::Windows,
        other => {
            return Err(ServiceError::InvalidInput(format!(
                "unsupported platform {other:?}"
            )));
        }
    };
    if req.device_name.trim().is_empty() {
        return Err(ServiceError::InvalidInput(
            "device_name must not be empty".into(),
        ));
    }
    if req.public_key.trim().is_empty() {
        return Err(ServiceError::InvalidInput(
            "public_key must not be empty".into(),
        ));
    }

    // 以摘要定位自举码并校验（持锁内原子完成，闭合并发竞态）。
    let token = state
        .bootstrap_tokens
        .get_mut(&token_hash(&req.bootstrap_token))
        .ok_or(ServiceError::InvalidBootstrapToken)?;
    if token.revoked_at.is_some() {
        return Err(ServiceError::InvalidBootstrapToken);
    }
    if let Some(max) = token.max_uses {
        if token.used_count >= max {
            return Err(ServiceError::InvalidBootstrapToken);
        }
    }
    token.used_count += 1;
    let network_id = token.network_id.to_string();

    let ts = now();
    let seq = state.registration_seq() + 1;
    let registration = DeviceRegistration {
        id: meshlet_domain::DeviceId(format!("dev-reg-{seq}")),
        network_id: meshlet_domain::NetworkId(network_id.clone()),
        name: req.device_name.clone(),
        public_key: req.public_key.clone(),
        platform,
        requested_at: ts.clone(),
        // 注册即首次上报（请求到达时刻）。
        last_report_at: Some(ts.clone()),
        dataplane_evidence: None,
    };
    // 名字唯一性跨 devices + registrations 两侧（域层 `add_registration`）。
    state.registry.add_registration(registration.clone())?;
    state.set_registration_seq(seq);

    Ok(RegisterDeviceResponse {
        device_id: registration.id.to_string(),
        network_id,
        status: "pending".to_string(),
        agent_token: String::new(), // 由 handler 用 AgentTokenStore 签发后回填
        requested_at: ts,
    })
}

/// 批准注册申请：**沿用注册时分配的设备 id** 转入 `devices`（`agent_tokens`
/// 等引用无需迁移），此刻才分配 overlay 地址（IPAM 顺序分配），并记录新
/// 修订——期望配置随之把新设备纳入数据面（§10.1/ADR-009）。
///
/// **凭证不轮换**：注册期签发的 agent 凭证原样沿用（设备 id 不变，批准
/// 动作对设备透明，审批者无需传递任何秘密）；拒绝路径才作废凭证。
pub fn approve_registration(
    state: &mut MeshState,
    network_id: &str,
    device_id: &str,
) -> Result<(DeviceRegistration, Device, u64), ServiceError> {
    state.network(network_id)?;
    let registration = state
        .registry
        .find_registration(&meshlet_domain::DeviceId(device_id.to_string()))
        .filter(|r| r.network_id.to_string() == network_id)
        .cloned()
        .ok_or_else(|| ServiceError::DeviceNotFound(device_id.to_string()))?;

    // 先摘除申请（名字唯一性检查跨两侧，摘除后同名转入 devices 才不撞自己）。
    let registration = state
        .registry
        .remove_registration(&registration.id)
        .expect("just found");

    let ipam = state
        .ipams
        .get_mut(network_id)
        .ok_or_else(|| ServiceError::NetworkNotFound(network_id.to_string()))?;
    let virtual_ip = match ipam.allocate() {
        Ok(ip) => ip,
        // IPAM 失败则把申请放回去：审批失败不得吞掉 Pending 申请。
        Err(e) => {
            state.registry.add_registration(registration.clone())?;
            return Err(ServiceError::Conflict(e.to_string()));
        }
    };

    let ts = now();
    let device = Device {
        id: registration.id.clone(),
        network_id: meshlet_domain::NetworkId(network_id.to_string()),
        name: registration.name.clone(),
        virtual_ipv4: virtual_ip,
        public_key: registration.public_key.clone(),
        platform: registration.platform,
        status: meshlet_domain::DeviceStatus::Active,
        // Pending 期的心跳证据直接带入：批准后 agent 无缝续报。
        last_seen_at: registration.last_report_at.clone(),
        last_handshake_at: None,
        last_report_at: registration.last_report_at.clone(),
        dataplane_evidence: registration.dataplane_evidence.clone(),
        // created_at = 申请时刻（Pending 起始），approved_at = 审批时刻。
        created_at: registration.requested_at.clone(),
        approved_at: Some(ts.clone()),
        revoked_at: None,
        segment_id: meshlet_domain::default_segment_id(&meshlet_domain::NetworkId(
            network_id.into(),
        )),
        labels: BTreeMap::new(),
    };
    if let Err(e) = state.registry.add(device.clone()) {
        // 登记失败（例如 IPAM 分配到重复地址）则回收地址并把申请放回去。
        if let Some(ipam) = state.ipams.get_mut(network_id) {
            ipam.release(virtual_ip);
        }
        state.registry.add_registration(registration.clone())?;
        return Err(e.into());
    }
    // 新设备改变期望配置：记录新修订（版本号网络内递增，§10.4）。
    let revision_id = record_revision(state, network_id)?;
    Ok((registration, device, revision_id))
}

/// 拒绝注册申请：摘除申请并返回（handler 据此清理 `device_registrations`
/// 行与 Pending 凭证）。**不记修订**（期望配置从未包含过 Pending 申请，
/// 拒绝是纯状态清理，§10.1「DB 写入 ≠ 生效」的反向：无生效即无修订）。
pub fn deny_registration(
    state: &mut MeshState,
    network_id: &str,
    device_id: &str,
) -> Result<DeviceRegistration, ServiceError> {
    state.network(network_id)?;
    let registration = state
        .registry
        .find_registration(&meshlet_domain::DeviceId(device_id.to_string()))
        .filter(|r| r.network_id.to_string() == network_id)
        .cloned()
        .ok_or_else(|| ServiceError::DeviceNotFound(device_id.to_string()))?;
    Ok(state
        .registry
        .remove_registration(&registration.id)
        .expect("just found"))
}

/// Pending 申请视图列表（控制台设备页「待审批」分区；`RegistrationView`
/// 不含虚拟 IP——批准前本就未分配，避免占位假值）。
pub fn list_registrations(
    state: &MeshState,
    network_id: &str,
) -> Result<Vec<RegistrationView>, ServiceError> {
    state.network(network_id)?;
    Ok(state
        .registry
        .registrations()
        .iter()
        .filter(|r| r.network_id.to_string() == network_id)
        .map(|r| RegistrationView {
            id: r.id.to_string(),
            network_id: r.network_id.to_string(),
            name: r.name.clone(),
            platform: match r.platform {
                Platform::Linux => "linux",
                Platform::Windows => "windows",
            }
            .to_string(),
            public_key: r.public_key.clone(),
            requested_at: r.requested_at.clone(),
            last_report_at: r.last_report_at.clone(),
            dataplane_evidence: r.dataplane_evidence.clone(),
        })
        .collect())
}

/// 设备加入（§11.2 第 3-9 步的控制平面部分）。
/// 私钥不出客户端：本函数只接收公钥；服务端登记公钥 + 指纹、分配虚拟 IP。
pub fn enroll(state: &mut MeshState, req: EnrollRequest) -> Result<EnrollResponse, ServiceError> {
    let platform = match req.platform.as_str() {
        "linux" => Platform::Linux,
        "windows" => Platform::Windows,
        other => {
            return Err(ServiceError::InvalidInput(format!(
                "unsupported platform {other:?}"
            )));
        }
    };
    if req.device_name.trim().is_empty() {
        return Err(ServiceError::InvalidInput(
            "device_name must not be empty".into(),
        ));
    }
    if req.public_key.trim().is_empty() {
        return Err(ServiceError::InvalidInput(
            "public_key must not be empty".into(),
        ));
    }

    // 以摘要定位邀请并兑换（持锁原子完成，闭合并发竞态）。
    let invite = state
        .invites
        .get_mut(&meshlet_domain::token_hash(&req.invite_token))
        .ok_or(ServiceError::InvalidInviteToken)?;
    let network_id = invite.network_id.to_string();
    invite
        .redeem(&req.invite_token, now())
        .map_err(|e| match e {
            meshlet_domain::InviteError::InvalidToken => ServiceError::InvalidInviteToken,
            other => ServiceError::InvalidInput(other.to_string()),
        })?;

    let ipam = state
        .ipams
        .get_mut(&network_id)
        .ok_or_else(|| ServiceError::NetworkNotFound(network_id.clone()))?;
    let virtual_ip = ipam
        .allocate()
        .map_err(|e| ServiceError::Conflict(e.to_string()))?;

    let ts = now();
    let device = Device {
        id: meshlet_domain::DeviceId(format!("dev-{}", state.registry.devices().len() + 1)),
        network_id: meshlet_domain::NetworkId(network_id.clone()),
        name: req.device_name.clone(),
        virtual_ipv4: virtual_ip,
        public_key: req.public_key.clone(),
        platform,
        status: meshlet_domain::DeviceStatus::Active,
        last_seen_at: Some(ts.clone()),
        last_handshake_at: None,
        last_report_at: None,
        dataplane_evidence: None,
        created_at: ts.clone(),
        approved_at: None,
        revoked_at: None,
        segment_id: meshlet_domain::default_segment_id(&meshlet_domain::NetworkId(
            network_id.clone(),
        )),
        labels: BTreeMap::new(),
    };
    state.registry.add(device.clone())?;
    // 新设备改变期望配置：记录新修订（版本号网络内递增，§10.4）。
    let revision_id = record_revision(state, &network_id)?;

    // 指纹 = 公钥 SHA-256；服务端不存任何私钥侧材料。
    let fingerprint = fingerprint_of(&req.public_key);
    Ok(EnrollResponse {
        device_id: device.id.to_string(),
        network_id,
        virtual_ipv4: virtual_ip,
        fingerprint,
        agent_token: String::new(), // 由 handler 用 AgentTokenStore 签发后回填
        revision_id,
        apply_status: meshlet_domain::ApplyStatus::Pending.as_str().to_string(),
    })
}

/// 记录一次 agent 心跳/上报（§14.1）：定位设备、更新 `last_report_at`（到达
/// 时刻）、可选的 `last_handshake_at`（agent 本地 `wg show` 读数）与
/// `last_seen_at`，返回当前在线判定（状态 + 数据来源）。
pub fn record_agent_report(
    state: &mut MeshState,
    device_id: &DeviceId,
    last_handshake_at: Option<String>,
    dataplane: Option<DataplaneEvidence>,
    now: Timestamp,
) -> Result<meshlet_domain::Presence, ServiceError> {
    let device = state
        .registry
        .find_by_id_mut(device_id)
        .ok_or_else(|| ServiceError::DeviceNotFound(device_id.to_string()))?;
    apply_agent_report(device, last_handshake_at, dataplane, &now);
    Ok(evaluate_presence(device, &now, &state.presence_thresholds))
}

/// Pending 申请的 agent 心跳（§7.5：证据不因 Pending 而丢弃）：只更新
/// `last_report_at` 与数据面证据。无隧道期握手读数无从谈起，`last_handshake_at`
/// 对 Pending 申请不采集（批准后从零开始，与 `devices.last_handshake_at` 一致）。
pub fn record_pending_agent_report(
    state: &mut MeshState,
    device_id: &DeviceId,
    dataplane: Option<DataplaneEvidence>,
    now: Timestamp,
) -> Result<(), ServiceError> {
    let registration = state
        .registry
        .find_registration_mut(device_id)
        .ok_or_else(|| ServiceError::DeviceNotFound(device_id.to_string()))?;
    if let Some(evidence) = dataplane {
        registration.dataplane_evidence = Some(evidence);
    }
    registration.last_report_at = Some(now);
    Ok(())
}

/// §12 P2P：记录一次直连候选上报（观测源地址 + agent 上报的 LAN 地址/端口）。
/// 上报省略（`None`）即移除候选——候选是临时性咨询数据，掉线/关闭后不得
/// 残留（对端据此决策直连路径，陈旧候选会误导）。
pub fn record_direct_state(
    state: &mut MeshState,
    device_id: &DeviceId,
    observed_ip: Option<Ipv4Addr>,
    report: Option<DirectEndpointReport>,
    links: Vec<DirectLinkStatus>,
) {
    match report {
        Some(report) => {
            state.direct_states.insert(
                device_id.clone(),
                DeviceDirectState {
                    observed_ip,
                    report: Some(report),
                    links,
                },
            );
        }
        None => {
            state.direct_states.remove(device_id);
        }
    }
}

/// 记录设备上报的真实主机名（内存态，心跳重报即覆盖）。`None`/空白 = 本轮
/// 未取到 → 保留旧值（主机名基本不变；重启后由下一轮心跳恢复）。
pub fn record_device_hostname(
    state: &mut MeshState,
    device_id: &DeviceId,
    hostname: Option<String>,
) {
    if let Some(name) = hostname
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        state.device_hostnames.insert(device_id.clone(), name);
    }
}

/// R-DIAG：记录设备最新一轮网络诊断三快照（内存态，心跳重报即覆盖）。
/// `None` = agent 采集失败/未上报 → 移除旧快照（证据缺失可见，不留陈旧读数）。
pub fn record_diagnostics(
    state: &mut MeshState,
    device_id: &DeviceId,
    diagnostics: Option<NetworkDiagnostics>,
) {
    match diagnostics {
        Some(snap) => {
            state.diagnostics.insert(device_id.clone(), snap);
        }
        None => {
            state.diagnostics.remove(device_id);
        }
    }
}

/// 把一次上报写到设备记录（内部共享）。证据与握手时间同一纪律：请求未携带
/// 时保留上次读数（「最后已知读数」， staleness 由 last_report_at 承载）。
fn apply_agent_report(
    device: &mut Device,
    last_handshake_at: Option<String>,
    dataplane: Option<DataplaneEvidence>,
    now: &Timestamp,
) {
    if let Some(ts) = last_handshake_at {
        device.last_handshake_at = Some(ts);
    }
    if let Some(evidence) = dataplane {
        device.dataplane_evidence = Some(evidence);
    }
    device.last_report_at = Some(now.clone());
    device.last_seen_at = Some(now.clone());
}

/// 在线判定（域层纯函数；判定时刻 = 当前时间，阈值来自状态）。
pub fn evaluate_presence(
    device: &Device,
    now: &Timestamp,
    thresholds: &meshlet_domain::PresenceThresholds,
) -> meshlet_domain::Presence {
    meshlet_domain::evaluate(
        meshlet_domain::PresenceInput {
            last_handshake_at: device.last_handshake_at.as_deref(),
            last_report_at: device.last_report_at.as_deref(),
            enrolled_at: Some(device.created_at.as_str()),
        },
        now,
        thresholds,
    )
}

pub fn list_devices(state: &MeshState, network_id: &str) -> Result<Vec<DeviceView>, ServiceError> {
    state.network(network_id)?;
    let now: Timestamp = now();
    Ok(state
        .registry
        .devices()
        .iter()
        .filter(|d| d.network_id.to_string() == network_id)
        .map(|d| {
            let direct = state.direct_states.get(&d.id);
            let direct_links = direct.map(|s| s.links.clone()).unwrap_or_default();
            let diagnostics = state.diagnostics.get(&d.id).cloned();
            to_device_view(
                d,
                &now,
                &state.presence_thresholds,
                direct,
                direct_links,
                diagnostics,
            )
        })
        .collect())
}

/// 单设备视图（MT-005 标签更新后回读；与 [list_devices] 同源渲染）。
pub fn device_view(
    state: &MeshState,
    network_id: &str,
    device_id: &str,
) -> Result<DeviceView, ServiceError> {
    state.network(network_id)?;
    let d = state
        .registry
        .find_by_id(&DeviceId(device_id.to_string()))
        .ok_or_else(|| ServiceError::DeviceNotFound(device_id.to_string()))?;
    if d.network_id.to_string() != network_id {
        return Err(ServiceError::DeviceNotFound(device_id.to_string()));
    }
    let now: Timestamp = now();
    let direct = state.direct_states.get(&d.id);
    let direct_links = direct.map(|s| s.links.clone()).unwrap_or_default();
    let diagnostics = state.diagnostics.get(&d.id).cloned();
    Ok(to_device_view(
        d,
        &now,
        &state.presence_thresholds,
        direct,
        direct_links,
        diagnostics,
    ))
}

/// 数据面证据量规快照（§17.2 指标 1/2/3/7 的数据源）：抓取时从 `MeshState`
/// **现算**，不存静态值。调用方持 mesh 锁；渲染（字符串拼接）在锁外做。
///
/// 「近期握手」= 握手落在 `handshake_window` 内（隧道证据，与「在线」的
/// agent 上报证据是两条独立来源——单看任一都会误判，见
/// `docs/architecture/observability.md` 组合判读）。
pub fn gauge_snapshot(state: &MeshState) -> crate::metrics::GaugeSnapshot {
    let now: Timestamp = now();
    let mut devices_online = 0u64;
    let mut devices_active = 0u64;
    let mut devices_with_recent_handshake = 0u64;
    let mut last_handshake_ts: i64 = 0;
    for device in state.registry.devices() {
        if device.is_active() {
            devices_active += 1;
        }
        let presence = evaluate_presence(device, &now, &state.presence_thresholds);
        if presence.state == meshlet_domain::presence::PresenceState::Online {
            devices_online += 1;
        }
        if let Some(ts) = device.last_handshake_at.as_deref() {
            if meshlet_domain::presence::fresh(ts, &now, state.presence_thresholds.handshake_window)
            {
                devices_with_recent_handshake += 1;
            }
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
                last_handshake_ts = last_handshake_ts.max(dt.timestamp());
            }
        }
    }
    crate::metrics::GaugeSnapshot {
        devices_online,
        devices_active,
        devices_with_recent_handshake,
        last_handshake_timestamp_seconds: last_handshake_ts,
        // 接口状态（§17.2 第 7 项）：至少一台设备有近期握手证据即视为数据面
        // 接口在；主机侧接口读数待数据面 backend 落地后并入（agent 侧证据
        // 先到）。
        interface_up: u8::from(devices_with_recent_handshake > 0),
        // Alias 应用状态（§17.2 第 8 项）：Phase 4 未落地，无 Alias 映射可
        // 应用——恒 0 表示「无东西可应用」，**不是**「健康」。
        alias_apply_status: 0,
    }
}

/// 发布一条 LAN 路由（ADR-005）。路由属于期望配置：创建即记录新修订（§10.1）。
pub fn create_route(
    state: &mut MeshState,
    network_id: &str,
    req: CreateRouteRequest,
) -> Result<RouteView, ServiceError> {
    state.network(network_id)?;
    let destination: Ipv4Cidr = req
        .destination_cidr
        .parse()
        .map_err(|e| ServiceError::InvalidCidr(format!("{}: {e}", req.destination_cidr)))?;
    let route_mode = match req.route_mode.as_deref() {
        None | Some("direct") => RouteMode::Direct,
        Some("alias") => RouteMode::Alias,
        Some(other) => {
            return Err(ServiceError::InvalidInput(format!(
                "route_mode must be \"direct\" or \"alias\", got {other:?}"
            )));
        }
    };
    let return_path_mode = ReturnPathMode::parse(&req.return_path_mode).ok_or_else(|| {
        ServiceError::InvalidInput(format!(
            "return_path_mode must be \"dual_route\" or \"controlled_snat\", got {:?}",
            req.return_path_mode
        ))
    })?;

    // overlay 自身/其子网不是 LAN 目的（它们走 overlay 内部转发）。
    let overlay = state.network(network_id)?.overlay_cidr;
    if destination.overlaps(&overlay) {
        return Err(ServiceError::RouteConflict(format!(
            "destination {destination} overlaps overlay {overlay}"
        )));
    }
    // 同网络目的网段互斥（重叠即冲突，不做超集合并）。拒绝发生在任何状态
    // 变更之前：既有路由绝不被覆盖（§8.3 不静默）。错误消息点名冲突对端
    // （既有路由 id + 网段），控制台据此展示「跟哪条路由冲突」。
    // 例外（ADR-006 旗舰场景）：新路由与既有路由**都是 Alias 模式**时允许
    // 真实前缀重叠——两个站点各有一个 192.168.1.0/24，经各自 Alias 前缀区分
    // 可达；对外可见的转发前缀是 Alias（唯一性由创建 Alias 时的
    // `alias_alias_overlap` 拒绝保证），真实前缀不进任何隧道 AllowedIPs。
    if let Some(existing) = state
        .lan_routes
        .get(network_id)
        .and_then(|routes| {
            routes
                .iter()
                .find(|r| r.destination_cidr.overlaps(&destination))
        })
        .cloned()
    {
        let both_alias = existing.route_mode == RouteMode::Alias && route_mode == RouteMode::Alias;
        if !both_alias {
            return Err(ServiceError::RouteConflict(format!(
                "destination {destination} overlaps existing route {} ({}) in network {network_id}",
                existing.id, existing.destination_cidr
            )));
        }
    }

    // 网关必须是本网络的 Active 设备。
    let gateway = DeviceId(req.gateway_device_id.clone());
    let device = state
        .registry
        .find_by_id(&gateway)
        .ok_or_else(|| ServiceError::DeviceNotFound(req.gateway_device_id.clone()))?;
    if device.network_id.to_string() != network_id {
        return Err(ServiceError::DeviceNotFound(req.gateway_device_id));
    }
    if !device.is_active() {
        return Err(ServiceError::Conflict(format!(
            "gateway device {} is not active",
            device.id
        )));
    }

    if route_mode == RouteMode::Direct {
        check_new_forward_prefix(state, network_id, destination)?;
    } else {
        // Preserve Alias real-prefix overlap, but never route a real target
        // through an existing visible Alias on this gateway.
        check_local_alias_prefix(state, network_id, destination)?;
    }

    state.route_seq += 1;
    let route = LanRoute {
        id: LanRouteId(format!("rt-{}", state.route_seq)),
        network_id: meshlet_domain::NetworkId(network_id.to_string()),
        gateway_device_id: gateway,
        destination_cidr: destination,
        route_mode,
        return_path_mode,
        status: DesiredStateStatus::Pending,
        created_at: now(),
    };
    state
        .lan_routes
        .entry(network_id.to_string())
        .or_default()
        .push(route.clone());
    let revision_id = record_revision(state, network_id)?;
    Ok(to_route_view(state, network_id, &route, revision_id))
}

pub fn list_routes(state: &MeshState, network_id: &str) -> Result<Vec<RouteView>, ServiceError> {
    state.network(network_id)?;
    let (revision_id, apply_status) = current_revision_ref(state, network_id);
    Ok(state
        .lan_routes
        .get(network_id)
        .map(|routes| {
            routes
                .iter()
                .map(|r| RouteView {
                    id: r.id.to_string(),
                    network_id: r.network_id.to_string(),
                    gateway_device_id: r.gateway_device_id.to_string(),
                    destination_cidr: r.destination_cidr.to_string(),
                    route_mode: r.route_mode.as_str().to_string(),
                    return_path_mode: r.return_path_mode.as_str().to_string(),
                    status: r.status.as_str().to_string(),
                    revision_id,
                    apply_status: apply_status.clone(),
                })
                .collect()
        })
        .unwrap_or_default())
}

pub fn get_route(
    state: &MeshState,
    network_id: &str,
    route_id: &str,
) -> Result<RouteView, ServiceError> {
    state.network(network_id)?;
    let route = state
        .lan_routes
        .get(network_id)
        .and_then(|routes| routes.iter().find(|r| r.id.to_string() == route_id))
        .ok_or_else(|| {
            ServiceError::RouteNotFound(format!("{route_id} in network {network_id}"))
        })?;
    let (revision_id, apply_status) = current_revision_ref(state, network_id);
    Ok(RouteView {
        id: route.id.to_string(),
        network_id: route.network_id.to_string(),
        gateway_device_id: route.gateway_device_id.to_string(),
        destination_cidr: route.destination_cidr.to_string(),
        route_mode: route.route_mode.as_str().to_string(),
        return_path_mode: route.return_path_mode.as_str().to_string(),
        status: route.status.as_str().to_string(),
        revision_id,
        apply_status,
    })
}

/// 删除一条 LAN 路由。删除也是期望配置变更：记录新修订。
/// §12.6 所有权清理：绑定该路由的 Alias 一并移除（alias-路由是一对一单元，
/// 留下孤儿 Alias 会让 AllowedIPs 推导引用不存在的翻译）。
pub fn delete_route(
    state: &mut MeshState,
    network_id: &str,
    route_id: &str,
) -> Result<(), ServiceError> {
    state.network(network_id)?;
    let routes = state.lan_routes.get_mut(network_id).ok_or_else(|| {
        ServiceError::RouteNotFound(format!("{route_id} in network {network_id}"))
    })?;
    let before = routes.len();
    routes.retain(|r| r.id.to_string() != route_id);
    if routes.len() == before {
        return Err(ServiceError::RouteNotFound(format!(
            "{route_id} in network {network_id}"
        )));
    }
    if let Some(aliases) = state.aliases.get_mut(network_id) {
        aliases.retain(|a| a.lan_route_id.to_string() != route_id);
    }
    record_revision(state, network_id)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Alias 映射（ADR-006：等长前缀一对一；§12.6 所有权与清理）
// ---------------------------------------------------------------------------

/// 创建 Alias 映射（§9.2 转换前检查的控制面部分）：绑定路由必须是本网络
/// `alias` 模式路由、网关 Active、每路由一映射；前缀等长（域层校验）、
/// 与 overlay / 既有 Alias / 既有路由目的网段互不重叠（§8.3/§9.2 不静默——
/// 冲突消息点名对端）。target 由绑定路由推导，客户端不可指定。
/// 拒绝发生在任何状态变更之前。
pub fn create_alias(
    state: &mut MeshState,
    network_id: &str,
    req: CreateAliasRequest,
) -> Result<AliasView, ServiceError> {
    state.network(network_id)?;
    let alias_cidr: Ipv4Cidr = req
        .alias_cidr
        .parse()
        .map_err(|e| ServiceError::InvalidCidr(format!("{}: {e}", req.alias_cidr)))?;
    let translation_mode = match req.translation_mode.as_deref() {
        None | Some("dnat_snat") => TranslationMode::DnatSnat,
        Some("dnat_only") => TranslationMode::DnatOnly,
        Some(other) => {
            return Err(ServiceError::InvalidInput(format!(
                "translation_mode must be \"dnat_snat\" or \"dnat_only\", got {other:?}"
            )));
        }
    };

    // 绑定路由：本网络、alias 模式（§5：route_mode=alias 即「经虚拟前缀」，
    // alias-路由是一对一单元）；网关 Active（§9.2「网关有效」）；每路由一映射。
    let routes = state.lan_routes.get(network_id).ok_or_else(|| {
        ServiceError::RouteNotFound(format!("{} in network {network_id}", req.lan_route_id))
    })?;
    let route = routes
        .iter()
        .find(|r| r.id.to_string() == req.lan_route_id)
        .ok_or_else(|| {
            ServiceError::RouteNotFound(format!("{} in network {network_id}", req.lan_route_id))
        })?;
    if route.route_mode != RouteMode::Alias {
        return Err(ServiceError::InvalidInput(format!(
            "alias can only bind to a route with route_mode = \"alias\", but route {} has route_mode = \"{}\" (create the route in alias mode first, §5/ADR-006)",
            route.id,
            route.route_mode.as_str()
        )));
    }
    let target_cidr = route.destination_cidr;
    AliasMapping::new(
        AliasMappingId(format!("al-{}", state.route_seq + 1)),
        meshlet_domain::NetworkId(network_id.to_string()),
        route.id.clone(),
        alias_cidr,
        target_cidr,
        translation_mode,
    )
    .map_err(|e: AliasError| ServiceError::InvalidInput(e.to_string()))?;
    check_new_forward_prefix(state, network_id, alias_cidr)?;
    let gateway = state
        .registry
        .find_by_id(&route.gateway_device_id)
        .ok_or_else(|| ServiceError::DeviceNotFound(route.gateway_device_id.to_string()))?;
    if !gateway.is_active() {
        return Err(ServiceError::Conflict(format!(
            "gateway device {} of route {} is not active",
            gateway.id, route.id
        )));
    }
    if let Some(aliases) = state.aliases.get(network_id) {
        if let Some(existing) = aliases.iter().find(|a| a.lan_route_id == route.id) {
            return Err(ServiceError::Conflict(format!(
                "route {} already has alias {} bound (one mapping per route, §12.6)",
                route.id, existing.id
            )));
        }
    }

    let id = AliasMappingId(format!("al-{}", state.route_seq + 1));
    let alias = AliasMapping::new(
        id,
        meshlet_domain::NetworkId(network_id.to_string()),
        route.id.clone(),
        alias_cidr,
        target_cidr,
        translation_mode,
    )
    .map_err(|e: AliasError| ServiceError::InvalidInput(e.to_string()))?;

    state.route_seq += 1;
    state
        .aliases
        .entry(network_id.to_string())
        .or_default()
        .push(alias.clone());
    let revision_id = record_revision(state, network_id)?;
    Ok(to_alias_view(state, network_id, &alias, revision_id))
}

pub fn list_aliases(state: &MeshState, network_id: &str) -> Result<Vec<AliasView>, ServiceError> {
    state.network(network_id)?;
    let (revision_id, _) = current_revision_ref(state, network_id);
    Ok(state
        .aliases
        .get(network_id)
        .map(|aliases| {
            aliases
                .iter()
                .map(|a| to_alias_view(state, network_id, a, revision_id))
                .collect()
        })
        .unwrap_or_default())
}

pub fn get_alias(
    state: &MeshState,
    network_id: &str,
    alias_id: &str,
) -> Result<AliasView, ServiceError> {
    state.network(network_id)?;
    let alias = state
        .aliases
        .get(network_id)
        .and_then(|aliases| aliases.iter().find(|a| a.id.to_string() == alias_id))
        .ok_or_else(|| {
            ServiceError::AliasNotFound(format!("{alias_id} in network {network_id}"))
        })?;
    let (revision_id, _) = current_revision_ref(state, network_id);
    Ok(to_alias_view(state, network_id, alias, revision_id))
}

/// 删除 Alias = 整单元清理（§12.6「删除 Alias 同步清理其路由和 NAT 规则」
/// 的控制面部分）：移除映射与其绑定路由，记录**一个**修订。内核侧 NAT 规则
/// 的移除随该修订的 apply 交 backend 执行（未接线时确定性失败可见，§10.3）。
/// 返回 (alias_id, route_id) 供 handler 落库与审计。
pub fn delete_alias(
    state: &mut MeshState,
    network_id: &str,
    alias_id: &str,
) -> Result<(String, String), ServiceError> {
    state.network(network_id)?;
    let aliases = state.aliases.get_mut(network_id).ok_or_else(|| {
        ServiceError::AliasNotFound(format!("{alias_id} in network {network_id}"))
    })?;
    let before = aliases.len();
    let route_id = aliases
        .iter()
        .find(|a| a.id.to_string() == alias_id)
        .map(|a| a.lan_route_id.to_string())
        .ok_or_else(|| {
            ServiceError::AliasNotFound(format!("{alias_id} in network {network_id}"))
        })?;
    aliases.retain(|a| a.id.to_string() != alias_id);
    debug_assert_eq!(aliases.len(), before - 1);
    // 绑定路由同删（一对一单元；孤儿 alias 模式路由没有翻译语义）。
    if let Some(routes) = state.lan_routes.get_mut(network_id) {
        routes.retain(|r| r.id.to_string() != route_id);
    }
    record_revision(state, network_id)?;
    Ok((alias_id.to_string(), route_id))
}

/// 创建非默认 Segment。默认段由建网事务固定，不能重复、替换或删除；
/// 新段必须是 overlay 的严格子段，并与同网其它段前缀互斥。
pub fn create_segment(
    state: &mut MeshState,
    network_id: &str,
    req: CreateSegmentRequest,
) -> Result<SegmentView, ServiceError> {
    let network_id = network_id.to_string();
    let network = state.network(&network_id)?;
    let domain_network_id = network.id.clone();
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(ServiceError::InvalidInput(
            "segment name must not be empty".into(),
        ));
    }
    if name == "default" {
        return Err(ServiceError::Conflict(
            "segment name \"default\" is reserved for the network overlay".into(),
        ));
    }
    if state
        .segments(&network_id)
        .iter()
        .any(|segment| segment.name == name)
    {
        return Err(ServiceError::Conflict(format!(
            "segment name {name:?} already exists in network {network_id}"
        )));
    }
    let cidr: Ipv4Cidr = req
        .cidr
        .parse()
        .map_err(|e| ServiceError::InvalidCidr(format!("{}: {e}", req.cidr)))?;
    let candidate = Segment {
        id: SegmentId("candidate".to_string()),
        network_id: network.id.clone(),
        name: name.clone(),
        cidr,
        status: SegmentStatus::Active,
        created_at: now(),
    };
    candidate
        .validate_cidr(network.overlay_cidr)
        .map_err(|e| ServiceError::InvalidCidr(e.to_string()))?;
    if state
        .segments(&network_id)
        .iter()
        .any(|segment| segment.cidr == cidr)
    {
        return Err(ServiceError::Conflict(format!(
            "cidr {cidr} is already used by an existing segment in network {network_id}"
        )));
    }

    state.route_seq += 1;
    let segment = Segment {
        id: SegmentId(format!("seg-{network_id}-{}", state.route_seq)),
        network_id: domain_network_id,
        name,
        cidr,
        status: SegmentStatus::Active,
        created_at: now(),
    };
    state
        .segments
        .entry(network_id.clone())
        .or_default()
        .push(segment.clone());
    let revision_id = record_revision(state, &network_id)?;
    Ok(to_segment_view(&segment, revision_id))
}

pub fn list_segments(
    state: &MeshState,
    network_id: &str,
) -> Result<Vec<SegmentView>, ServiceError> {
    state.network(network_id)?;
    Ok(state
        .segments(network_id)
        .iter()
        .map(|segment| {
            let (revision_id, _) = current_revision_ref(state, network_id);
            to_segment_view(segment, revision_id)
        })
        .collect())
}

fn to_segment_view(segment: &Segment, revision_id: u64) -> SegmentView {
    SegmentView {
        id: segment.id.to_string(),
        network_id: segment.network_id.to_string(),
        name: segment.name.clone(),
        cidr: segment.cidr.to_string(),
        status: segment.status.as_str().to_string(),
        created_at: segment.created_at.clone(),
        revision_id,
    }
}

fn segment_by_id<'a>(
    state: &'a MeshState,
    network_id: &'a str,
    segment_id: &str,
) -> Result<&'a Segment, ServiceError> {
    state.network(network_id)?;
    state
        .segments(network_id)
        .iter()
        .find(|segment| segment.id.to_string() == segment_id)
        .ok_or_else(|| {
            ServiceError::SegmentNotFound(format!("{segment_id} in network {network_id}"))
        })
}

/// 新建授权为 Pending：只有显式 apply 后的单向信任才进入期望哈希。
pub fn create_segment_grant(
    state: &mut MeshState,
    network_id: &str,
    req: CreateSegmentGrantRequest,
) -> Result<SegmentGrantView, ServiceError> {
    let network = state.network(network_id)?;
    let domain_network_id = network.id.clone();
    let source = segment_by_id(state, network_id, &req.source_segment_id)?;
    let source_id = source.id.clone();
    let destination = segment_by_id(state, network_id, &req.destination_segment_id)?;
    let destination_id = destination.id.clone();
    if source_id == destination_id {
        return Err(ServiceError::InvalidInput(
            "source and destination segments must differ".into(),
        ));
    }
    if state.segment_grants(network_id).iter().any(|grant| {
        grant.status != SegmentGrantStatus::Revoked
            && grant.source_segment_id == source_id
            && grant.destination_segment_id == destination_id
    }) {
        return Err(ServiceError::Conflict(format!(
            "an active grant already exists from segment {} to segment {}",
            source_id, destination_id
        )));
    }

    state.route_seq += 1;
    let grant = SegmentGrantBuilder::new(
        SegmentGrantId(format!("sg-{}", state.route_seq)),
        domain_network_id,
        source_id.clone(),
        destination_id.clone(),
        now(),
    )
    .build();
    state
        .grants
        .entry(network_id.to_string())
        .or_default()
        .push(grant.clone());
    let revision_id = record_revision(state, network_id)?;
    Ok(to_segment_grant_view(
        state,
        network_id,
        &grant,
        revision_id,
    ))
}

pub fn list_segment_grants(
    state: &MeshState,
    network_id: &str,
) -> Result<Vec<SegmentGrantView>, ServiceError> {
    state.network(network_id)?;
    let (revision_id, _) = current_revision_ref(state, network_id);
    Ok(state
        .segment_grants(network_id)
        .iter()
        .map(|grant| to_segment_grant_view(state, network_id, grant, revision_id))
        .collect())
}

/// 显式批准 Pending 授权：之后才进入计划编译与 desired_config_hash v4。
pub fn apply_segment_grant(
    state: &mut MeshState,
    network_id: &str,
    grant_id: &str,
) -> Result<SegmentGrantView, ServiceError> {
    state.network(network_id)?;
    let target_index = state
        .grants
        .get(network_id)
        .and_then(|grants| {
            grants
                .iter()
                .position(|grant| grant.id.to_string() == grant_id)
        })
        .ok_or_else(|| {
            ServiceError::SegmentGrantNotFound(format!("{grant_id} in network {network_id}"))
        })?;
    if state.grants[network_id][target_index].status != SegmentGrantStatus::Pending {
        return Err(ServiceError::Conflict(format!(
            "segment grant {} is {}, only pending grants can be applied",
            grant_id,
            state.grants[network_id][target_index].status.as_str()
        )));
    }
    state.grants.get_mut(network_id).expect("checked")[target_index].status =
        SegmentGrantStatus::Applied;
    let target = state.grants[network_id][target_index].clone();
    let revision_id = record_revision(state, network_id)?;
    Ok(to_segment_grant_view(
        state,
        network_id,
        &target,
        revision_id,
    ))
}

/// 撤销单向信任；二次撤销是 409，不生成无变化修订。
pub fn revoke_segment_grant(
    state: &mut MeshState,
    network_id: &str,
    grant_id: &str,
) -> Result<SegmentGrantView, ServiceError> {
    state.network(network_id)?;
    let target_index = state
        .grants
        .get(network_id)
        .and_then(|grants| {
            grants
                .iter()
                .position(|grant| grant.id.to_string() == grant_id)
        })
        .ok_or_else(|| {
            ServiceError::SegmentGrantNotFound(format!("{grant_id} in network {network_id}"))
        })?;
    let mut target = state.grants[network_id][target_index].clone();
    target
        .revoke(now())
        .map_err(|e| ServiceError::Conflict(e.to_string()))?;
    state.grants.get_mut(network_id).expect("checked")[target_index] = target.clone();
    let revision_id = record_revision(state, network_id)?;
    Ok(to_segment_grant_view(
        state,
        network_id,
        &target,
        revision_id,
    ))
}

fn to_segment_grant_view(
    state: &MeshState,
    network_id: &str,
    grant: &SegmentGrant,
    revision_id: u64,
) -> SegmentGrantView {
    let (_, apply_status) = current_revision_ref(state, network_id);
    SegmentGrantView {
        id: grant.id.to_string(),
        network_id: grant.network_id.to_string(),
        source_segment_id: grant.source_segment_id.to_string(),
        destination_segment_id: grant.destination_segment_id.to_string(),
        status: grant.status.as_str().to_string(),
        created_at: grant.created_at.clone(),
        revoked_at: grant.revoked_at.clone(),
        revision_id,
        apply_status,
    }
}

/// 创建单主机全端口转发：把「alias /32 → target /32」作为一个原子单元写入。
///
/// Host Forward 不新增端口防火墙模型：`/32` 使 TCP/UDP/ICMP 的所有端口和
/// 协议都经既有 LAN Route + Alias NETMAP 路径转发，删除路由/alias 单元即全删。
pub fn create_host_forward(
    state: &mut MeshState,
    network_id: &str,
    req: CreateHostForwardRequest,
) -> Result<HostForwardView, ServiceError> {
    state.network(network_id)?;
    let target = Ipv4Cidr::new(req.target_ipv4, 32)
        .map_err(|e| ServiceError::InvalidCidr(format!("{}/32: {e}", req.target_ipv4)))?;
    let alias_cidr = Ipv4Cidr::new(req.alias_ipv4, 32)
        .map_err(|e| ServiceError::InvalidCidr(format!("{}/32: {e}", req.alias_ipv4)))?;
    check_new_forward_prefix(state, network_id, alias_cidr)?;
    check_local_alias_prefix(state, network_id, target)?;
    let translation_mode = match req.translation_mode.as_deref() {
        None | Some("dnat_snat") => TranslationMode::DnatSnat,
        Some("dnat_only") => TranslationMode::DnatOnly,
        Some(other) => {
            return Err(ServiceError::InvalidInput(format!(
                "translation_mode must be \"dnat_snat\" or \"dnat_only\", got {other:?}"
            )));
        }
    };
    let overlay = state.network(network_id)?.overlay_cidr;
    if target.overlaps(&overlay) || alias_cidr.overlaps(&overlay) {
        return Err(ServiceError::RouteConflict(format!(
            "host forward target {target} or alias {alias_cidr} overlaps overlay {overlay}"
        )));
    }
    for existing in state
        .lan_routes
        .get(network_id)
        .map(Vec::as_slice)
        .unwrap_or(&[])
    {
        if existing.destination_cidr.overlaps(&target) {
            return Err(ServiceError::RouteConflict(format!(
                "host forward target {target} overlaps existing route {} ({})",
                existing.id, existing.destination_cidr
            )));
        }
    }

    let gateway = DeviceId(req.gateway_device_id.clone());
    let device = state
        .registry
        .find_by_id(&gateway)
        .ok_or_else(|| ServiceError::DeviceNotFound(req.gateway_device_id.clone()))?;
    if device.network_id.to_string() != network_id {
        return Err(ServiceError::DeviceNotFound(req.gateway_device_id));
    }
    if !device.is_active() {
        return Err(ServiceError::Conflict(format!(
            "gateway device {} is not active",
            device.id
        )));
    }

    let route = LanRoute {
        id: LanRouteId(format!("rt-{}", state.route_seq + 1)),
        network_id: meshlet_domain::NetworkId(network_id.to_string()),
        gateway_device_id: gateway,
        destination_cidr: target,
        route_mode: RouteMode::Alias,
        return_path_mode: ReturnPathMode::ControlledSnat,
        status: DesiredStateStatus::Pending,
        created_at: now(),
    };
    let alias = AliasMapping::new(
        AliasMappingId(format!("al-{}", state.route_seq + 2)),
        meshlet_domain::NetworkId(network_id.to_string()),
        route.id.clone(),
        alias_cidr,
        target,
        translation_mode,
    )
    .map_err(|e| ServiceError::InvalidInput(e.to_string()))?;

    state.route_seq += 2;

    state
        .lan_routes
        .entry(network_id.to_string())
        .or_default()
        .push(route);
    state
        .aliases
        .entry(network_id.to_string())
        .or_default()
        .push(alias.clone());
    let revision_id = record_revision(state, network_id)?;
    Ok(to_host_forward_view(state, network_id, &alias, revision_id))
}

/// Host Forward 列表 = 当前所有 /32 target 的 Alias 单元（真实 LAN 网段仍用
/// 原有 Alias 页面展示，避免把两种语义混在同一张表）。
pub fn list_host_forwards(
    state: &MeshState,
    network_id: &str,
) -> Result<Vec<HostForwardView>, ServiceError> {
    state.network(network_id)?;
    let routes: HashMap<String, &LanRoute> = state
        .lan_routes
        .get(network_id)
        .map(|routes| {
            routes
                .iter()
                .map(|route| (route.id.to_string(), route))
                .collect()
        })
        .unwrap_or_default();
    let mut views = state
        .aliases
        .get(network_id)
        .map(|aliases| {
            aliases
                .iter()
                .filter_map(|alias| {
                    let route = routes.get(&alias.lan_route_id.to_string())?;
                    if route.destination_cidr.prefix_len() != 32 {
                        return None;
                    }
                    let (_, apply_status) = current_revision_ref(state, network_id);
                    Some(HostForwardView {
                        id: alias.id.to_string(),
                        network_id: alias.network_id.to_string(),
                        gateway_device_id: route.gateway_device_id.to_string(),
                        target_ipv4: alias.target_cidr.network().to_string(),
                        alias_ipv4: alias.alias_cidr.network().to_string(),
                        translation_mode: alias.translation_mode.as_str().to_string(),
                        status: alias.status.as_str().to_string(),
                        revision_id: 0,
                        apply_status,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    views.sort_by_key(|view| view.alias_ipv4.clone());
    Ok(views)
}

/// 删除 Host Forward 的 alias id；绑定路由随既有 ownership 单元一并移除。
pub fn delete_host_forward(
    state: &mut MeshState,
    network_id: &str,
    alias_id: &str,
) -> Result<(String, String), ServiceError> {
    delete_alias(state, network_id, alias_id)
}

fn to_alias_view(
    state: &MeshState,
    network_id: &str,
    alias: &AliasMapping,
    revision_id: u64,
) -> AliasView {
    let (_, apply_status) = current_revision_ref(state, network_id);
    AliasView {
        id: alias.id.to_string(),
        network_id: alias.network_id.to_string(),
        lan_route_id: alias.lan_route_id.to_string(),
        alias_cidr: alias.alias_cidr.to_string(),
        target_cidr: alias.target_cidr.to_string(),
        translation_mode: alias.translation_mode.as_str().to_string(),
        status: alias.status.as_str().to_string(),
        revision_id,
        apply_status,
    }
}

fn to_host_forward_view(
    state: &MeshState,
    network_id: &str,
    alias: &AliasMapping,
    revision_id: u64,
) -> HostForwardView {
    let (_, apply_status) = current_revision_ref(state, network_id);
    let target_ipv4 = alias.target_cidr.network().to_string();
    let alias_ipv4 = alias.alias_cidr.network().to_string();
    HostForwardView {
        id: alias.id.to_string(),
        network_id: alias.network_id.to_string(),
        gateway_device_id: state
            .lan_routes
            .get(network_id)
            .and_then(|routes| routes.iter().find(|route| route.id == alias.lan_route_id))
            .map(|route| route.gateway_device_id.to_string())
            .unwrap_or_default(),
        target_ipv4,
        alias_ipv4,
        translation_mode: alias.translation_mode.as_str().to_string(),
        status: alias.status.as_str().to_string(),
        revision_id,
        apply_status,
    }
}

/// 撤销设备（peer 撤销，§11.5 控制面部分）：状态转 `Revoked`（下线）并记录
/// 新修订——被撤销设备不入期望配置哈希。agent 凭证失效由 handler 在锁外完成。
pub fn revoke_device(
    state: &mut MeshState,
    network_id: &str,
    device_id: &str,
) -> Result<RevisionRef, ServiceError> {
    state.network(network_id)?;
    let revoked_id = {
        let device = state
            .registry
            .find_by_id_mut(&DeviceId(device_id.to_string()))
            .ok_or_else(|| ServiceError::DeviceNotFound(device_id.to_string()))?;
        if device.network_id.to_string() != network_id {
            return Err(ServiceError::DeviceNotFound(device_id.to_string()));
        }
        device
            .revoke(now())
            .map_err(|e| ServiceError::Conflict(e.to_string()))?;
        device.id.clone()
    };
    // §11.5：撤销必须移除该设备发布的 LAN 路由，避免期望配置里留下指向
    // 已撤销 Peer 的路由（AllowedIPs 推导会把它当成远端网段继续下发）。
    // §12.6 所有权清理：随之移除绑定这些路由的 Alias 映射（不留孤儿翻译）。
    let orphaned: Vec<String> = state
        .lan_routes
        .get(network_id)
        .map(|routes| {
            routes
                .iter()
                .filter(|r| r.gateway_device_id == revoked_id)
                .map(|r| r.id.to_string())
                .collect()
        })
        .unwrap_or_default();
    if let Some(routes) = state.lan_routes.get_mut(network_id) {
        routes.retain(|r| r.gateway_device_id != revoked_id);
    }
    if let Some(aliases) = state.aliases.get_mut(network_id) {
        aliases.retain(|a| !orphaned.contains(&a.lan_route_id.to_string()));
    }
    let revision_id = record_revision(state, network_id)?;
    Ok(RevisionRef {
        revision_id,
        apply_status: meshlet_domain::ApplyStatus::Pending.as_str().to_string(),
    })
}

/// 设置设备标签（MT-005）：整体替换（PUT 语义）。标签是路由元数据，
/// 不进期望配置——不记修订、不触发 backend 应用；落库由调用方经
/// [crate::persist::commit_device_labels] 完成。设备必须归属该网络。
pub fn set_device_labels(
    state: &mut MeshState,
    network_id: &str,
    device_id: &str,
    labels: BTreeMap<String, String>,
) -> Result<Device, ServiceError> {
    state.network(network_id)?;
    let device = state
        .registry
        .find_by_id_mut(&DeviceId(device_id.to_string()))
        .ok_or_else(|| ServiceError::DeviceNotFound(device_id.to_string()))?;
    if device.network_id.to_string() != network_id {
        return Err(ServiceError::DeviceNotFound(device_id.to_string()));
    }
    device.labels = labels;
    Ok(device.clone())
}

/// 网络当前修订引用（网络视图语义复用：无修订时 0/`none`）。
pub fn current_revision_ref(state: &MeshState, network_id: &str) -> (u64, String) {
    state
        .ledger
        .current(&meshlet_domain::NetworkId(network_id.to_string()))
        .map(|r| (r.revision, r.apply_status.as_str().to_string()))
        .unwrap_or((0, "none".to_string()))
}

fn to_route_view(
    state: &MeshState,
    network_id: &str,
    route: &LanRoute,
    revision_id: u64,
) -> RouteView {
    let (_, apply_status) = current_revision_ref(state, network_id);
    RouteView {
        id: route.id.to_string(),
        network_id: route.network_id.to_string(),
        gateway_device_id: route.gateway_device_id.to_string(),
        destination_cidr: route.destination_cidr.to_string(),
        route_mode: route.route_mode.as_str().to_string(),
        return_path_mode: route.return_path_mode.as_str().to_string(),
        status: route.status.as_str().to_string(),
        revision_id,
        apply_status,
    }
}

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

pub fn fingerprint_of(public_key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(public_key.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn to_network_view(state: &MeshState, n: &Network) -> NetworkView {
    // 当前期望修订 = 最新一个未回滚的修订（ADR-009：显示以应用状态为准）。
    let current = state
        .ledger
        .current(&meshlet_domain::NetworkId(n.id.0.clone()));
    NetworkView {
        id: n.id.to_string(),
        name: n.name.clone(),
        overlay_cidr: n.overlay_cidr.to_string(),
        status: match n.status {
            meshlet_domain::NetworkStatus::Active => "active",
            meshlet_domain::NetworkStatus::Deleting => "deleting",
        }
        .to_string(),
        created_at: n.created_at.clone(),
        revision_id: current.map(|r| r.revision).unwrap_or(0),
        apply_status: current
            .map(|r| r.apply_status.as_str().to_string())
            .unwrap_or_else(|| "none".to_string()),
    }
}

fn to_device_view(
    d: &Device,
    now: &Timestamp,
    thresholds: &meshlet_domain::PresenceThresholds,
    direct: Option<&DeviceDirectState>,
    direct_links: Vec<DirectLinkStatus>,
    diagnostics: Option<NetworkDiagnostics>,
) -> DeviceView {
    let presence = evaluate_presence(d, now, thresholds);
    let observed_endpoint = direct
        .and_then(|s| s.observed_endpoint())
        .map(|(ip, port)| format!("{ip}:{port}"));
    let public_endpoint = direct
        .and_then(|s| s.public_endpoint())
        .map(|c| format!("{}:{}", c.ip, c.port));
    DeviceView {
        id: d.id.to_string(),
        network_id: d.network_id.to_string(),
        name: d.name.clone(),
        virtual_ipv4: d.virtual_ipv4,
        public_key: d.public_key.clone(),
        fingerprint: fingerprint_of(&d.public_key),
        status: match d.status {
            meshlet_domain::DeviceStatus::Pending => "pending",
            meshlet_domain::DeviceStatus::Active => "active",
            meshlet_domain::DeviceStatus::Revoked => "revoked",
        }
        .to_string(),
        created_at: d.created_at.clone(),
        approved_at: d.approved_at.clone(),
        last_seen_at: d.last_seen_at.clone(),
        online_state: presence.state.as_str().to_string(),
        presence_source: presence.source.as_str().to_string(),
        dataplane_evidence: d.dataplane_evidence.clone(),
        direct_links,
        observed_endpoint,
        public_endpoint,
        diagnostics,
        labels: d.labels.clone(),
    }
}
