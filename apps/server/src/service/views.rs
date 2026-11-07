//! HTTP request/response projections for the management APIs.

use meshlet_domain::{DataplaneEvidence, DirectLinkStatus};
use meshlet_network::NetworkDiagnostics;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct NetworkView {
    pub id: String,
    pub name: String,
    pub overlay_cidr: String,
    pub status: String,
    pub created_at: String,
    /// 当前期望修订号（ADR-009：配置修改类响应必须携带版本与应用状态）。
    pub revision_id: u64,
    /// 当前修订的应用状态：`pending`/`applying`/`applied`/`failed`/
    /// `rollback_pending`/`rolled_back`（ADR-009 状态机）。
    pub apply_status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceView {
    pub id: String,
    pub network_id: String,
    pub name: String,
    pub virtual_ipv4: Ipv4Addr,
    pub public_key: String,
    pub fingerprint: String,
    pub status: String,
    pub created_at: String,
    /// 批准时刻：自举注册路径 = 审批时刻（created_at 是申请时刻）；邀请入会
    /// 路径为 `None`（两时刻同值，无需重复展示）。控制台据此区分「刚批准」
    /// 与「已运行一段时间」。
    pub approved_at: Option<String>,
    /// 最后证据时间（加入/心跳/上报到达时刻）——控制台「最后在线时间」。
    pub last_seen_at: Option<String>,
    /// 在线状态判定：`online` / `tunnel_only` / `offline`（数据来源见下）。
    pub online_state: String,
    /// 状态的数据来源：`agent_report` / `handshake` / `enrollment` / `none`（§12.2）。
    pub presence_source: String,
    /// 最近一次心跳回传的数据面实测证据（§7.5）；`None` = 尚无上报。
    pub dataplane_evidence: Option<DataplaneEvidence>,
    /// §12.3 P2P 链路状态上报：本设备对各对端的直连链路（direct /
    /// direct_pending）。空 = 全中继或未上报；控制台据此展示 P2P/中继。
    pub direct_links: Vec<DirectLinkStatus>,
    /// P2P-⑤：hub 观测的源 endpoint，格式 `observed_ip:listen_port`（心跳源
    /// 地址拼接 agent 上报的 wg 监听端口）。`None` = 未观测到心跳或 agent 未
    /// 上报端口。不做私网过滤——这是原始观测。
    pub observed_endpoint: Option<String>,
    /// 公网候选 endpoint（观测地址非私网时才有；与 agent 拨号候选同源，
    /// 拓扑图/节点下钻复用）。`None` = 无观测/未上报或 hub 与 agent 同内网
    /// （观测地址非公网，标公网会误导打洞）。
    pub public_endpoint: Option<String>,
    /// R-DIAG 网络诊断三快照（路由表/接口/wg 读数）；`None` = 尚无上报或
    /// 采集失败。控制台诊断页据此展示。
    pub diagnostics: Option<NetworkDiagnostics>,
    /// MT-005 节点标签（操作员分配；任务标签路由的匹配依据）。空 = 未打标。
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateNetworkRequest {
    pub name: String,
    pub overlay_cidr: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateInviteRequest {
    /// ISO-8601 过期时刻；缺省表示永不过期。
    pub expires_at: Option<String>,
    /// 使用次数上限；缺省 1（一次性邀请，ADR-010）。
    pub max_uses: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateInviteResponse {
    pub invite_id: String,
    /// 原始 Token **仅此一次**返回；服务端只存 SHA-256 摘要（§11.3）。
    pub token: String,
    pub expires_at: Option<String>,
}

// ---------------------------------------------------------------------------
// 设备自举注册（ZeroTier 式：自举码注册 → Pending → 控制中心审批/拒绝）
// ---------------------------------------------------------------------------

/// 自举码（bootstrap token）：长期、可复用的注册入口凭据，区别于一次性邀请。
#[derive(Debug, Deserialize)]
pub struct CreateBootstrapTokenRequest {
    /// 使用次数上限；缺省不限次（自举码是长期入口，不是单次邀请）。
    pub max_uses: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateBootstrapTokenResponse {
    pub token_id: String,
    /// 原始自举码 **仅此一次**返回；服务端只存 SHA-256 摘要（§11.3）。
    pub token: String,
    pub max_uses: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BootstrapTokenView {
    pub id: String,
    pub network_id: String,
    pub max_uses: Option<u32>,
    pub used_count: u32,
    pub created_at: String,
    pub revoked_at: Option<String>,
}

/// 设备自举注册请求（`POST /device-registrations`，公开端点）。
/// `deny_unknown_fields` 同 [EnrollRequest]：客户端尝试发送私钥即被 400 拒绝
/// （私钥不出客户端，§11.2）。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterDeviceRequest {
    pub bootstrap_token: String,
    pub device_name: String,
    pub public_key: String,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegisterDeviceResponse {
    pub device_id: String,
    pub network_id: String,
    /// 恒为 `pending`（控制中心批准前不参与数据面）。
    pub status: String,
    /// Agent API 凭证（Bearer）：**仅此一次**返回。Pending 期可心跳上报
    /// （证明 agent 活着），但拉不到计划——批准前不进数据面。
    pub agent_token: String,
    pub requested_at: String,
}

/// 待审批申请视图（控制台设备页与设备列表共用；`status = "pending"`）。
#[derive(Debug, Clone, Serialize)]
pub struct RegistrationView {
    pub id: String,
    pub network_id: String,
    pub name: String,
    pub platform: String,
    pub public_key: String,
    pub requested_at: String,
    pub last_report_at: Option<String>,
    /// agent 心跳回传的数据面证据（Pending 设备尚无 `devices` 行，证据只在这里）。
    pub dataplane_evidence: Option<DataplaneEvidence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApproveRegistrationResponse {
    pub device_id: String,
    pub network_id: String,
    /// 批准时刻才分配的 overlay 地址（ADR-004 顺序分配）。
    pub virtual_ipv4: Ipv4Addr,
    /// 设备公钥指纹（SHA-256；服务端不存私钥侧材料）。
    pub fingerprint: String,
    /// **不含 agent 凭证**：注册时签发的凭证绑定设备 id（批准沿用同一 id），
    /// 设备端继续使用原凭证拉计划；轮换只会让无人能送达的新凭证作废设备。
    pub revision_id: u64,
    pub apply_status: String,
    pub approved_at: String,
}

/// 加入请求：**不允许携带任何私钥字段**（`deny_unknown_fields` 强制，
/// 客户端尝试发送私钥会被 400 拒绝——私钥不出客户端，§11.2）。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollRequest {
    pub invite_token: String,
    pub device_name: String,
    pub public_key: String,
    pub platform: String,
}

/// MT-005 设备标签更新（操作员 PATCH/POST 语义：整体替换）。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetDeviceLabelsRequest {
    /// 新标签集（空对象 = 清空全部标签）。
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnrollResponse {
    pub device_id: String,
    pub network_id: String,
    pub virtual_ipv4: Ipv4Addr,
    pub fingerprint: String,
    /// Agent API 凭证（Bearer）：**仅此一次**返回，服务端只存 SHA-256 摘要。
    pub agent_token: String,
    /// 本次变更生成的期望配置修订号（ADR-009）。
    pub revision_id: u64,
    /// 该修订的应用状态（新修订恒为 `pending`——DB 写入 ≠ 生效）。
    pub apply_status: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateRouteRequest {
    /// 网关设备（必须是本网络的 Active 设备，ADR-005）。
    pub gateway_device_id: String,
    pub destination_cidr: String,
    /// `direct`（缺省）或 `alias`。
    pub route_mode: Option<String>,
    /// `dual_route` 或 `controlled_snat`（必选，ADR-005）。
    pub return_path_mode: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteView {
    pub id: String,
    pub network_id: String,
    pub gateway_device_id: String,
    pub destination_cidr: String,
    pub route_mode: String,
    pub return_path_mode: String,
    /// `pending` / `applied` / `failed`（路由自身的期望态）。
    pub status: String,
    /// 本次变更生成的期望配置修订号（ADR-009）。
    pub revision_id: u64,
    pub apply_status: String,
}

/// 修订引用（撤销设备等操作返回；契约 `RevisionRef`）。
#[derive(Debug, Clone, Serialize)]
pub struct RevisionRef {
    pub revision_id: u64,
    pub apply_status: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateAliasRequest {
    /// 绑定的 LAN Route（必须存在且 `route_mode = "alias"`，ADR-006 单元语义）。
    pub lan_route_id: String,
    pub alias_cidr: String,
    /// `dnat_snat`（缺省）或 `dnat_only`。
    pub translation_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateHostForwardRequest {
    /// 本网络 Active 网关设备：流量经它进入目标主机所在 LAN。
    pub gateway_device_id: String,
    /// LAN 内真实主机地址（不是 CIDR；Host Forward 会在服务端转成 /32）。
    pub target_ipv4: Ipv4Addr,
    /// 虚拟主机地址（必须是与 target 等长的 /32，且不落在 overlay）。
    pub alias_ipv4: Ipv4Addr,
    /// `dnat_snat`（缺省，兼容无返回路由的 LAN）或 `dnat_only`。
    pub translation_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostForwardView {
    pub id: String,
    pub network_id: String,
    pub gateway_device_id: String,
    pub target_ipv4: String,
    pub alias_ipv4: String,
    pub translation_mode: String,
    pub status: String,
    pub revision_id: u64,
    pub apply_status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AliasView {
    pub id: String,
    pub network_id: String,
    pub lan_route_id: String,
    pub alias_cidr: String,
    /// 真实目标网段 = 绑定路由的目的网段（服务端推导，客户端不可指定）。
    pub target_cidr: String,
    pub translation_mode: String,
    /// `pending` / `applied` / `failed`（映射自身的期望态）。
    pub status: String,
    /// 本次变更生成的期望配置修订号（ADR-009）。
    pub revision_id: u64,
    pub apply_status: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateSegmentRequest {
    pub name: String,
    pub cidr: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SegmentView {
    pub id: String,
    pub network_id: String,
    pub name: String,
    pub cidr: String,
    pub status: String,
    pub created_at: String,
    pub revision_id: u64,
}

#[derive(Debug, Deserialize)]
pub struct CreateSegmentGrantRequest {
    pub source_segment_id: String,
    pub destination_segment_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SegmentGrantView {
    pub id: String,
    pub network_id: String,
    pub source_segment_id: String,
    pub destination_segment_id: String,
    pub status: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
    pub revision_id: u64,
    pub apply_status: String,
}
