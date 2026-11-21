//! wireguard-nt 嵌入式绑定——计划层（[ADR-008](../../../docs/decisions/adr-008-windows-network-backend.md)
//! 复审候选模型，[分析文档](../../../docs/design/userspace-wireguard-analysis.md) spike 前置）。
//!
//! 目标模型：去掉 `wireguard.exe` 隧道服务层（每隧道一个
//! `WireGuardTunnel$<name>` Windows 服务），单 agent 进程内经
//! `wireguard_nt::Adapter::create` 直接创建 N 个 WireGuardNT adapter——
//! **一个网络一个 adapter**（`wg-mlt-<handle>`），多网络成本从一个
//! Windows 服务降为一个 Rust 对象，根治服务单例互踩（分析文档 §1.2：
//! 后装服务的 conf 顶掉先装服务的 peer 表 + 51820 撞绑 0xc0000022）。
//!
//! 分层（同 [windows_tunnel] 纪律）：
//!
//! - **计划层**（任意平台编译+单测）：[TunnelConfig] → [NtInterfacePlan]
//!   的纯转换与命名/端口守门（[nt_interface_plan]）。
//! - **执行规格层**（任意平台编译+单测）：[NtInterfacePlan] →
//!   [NtApplySpec]——密钥 base64 解码为 32 字节、MTU 守门、
//!   `private_key: None` 原样透传（[nt_apply_spec]）。
//! - **`#[cfg(windows)]` 执行层**：dll 装载（[nt_dll_path]）与
//!   [NtRuntime]——open-or-create adapter、`set_config` → `up` →
//!   地址+路由装配 → `get_config` 回读（真机 PoC 验证过的序列，
//!   wgnt-step12-2026-11-21 8/8 PASS）。宿主 CI 不跑 Windows 测试，
//!   本层经 windows-gnu 交叉 clippy/check 编译验证，字段映射保持
//!   机械直译（全部语义判定在规格层完成）。
//!
//! 前提（ADR-008 复审落档）：wireguard.dll **必须随 meshlet 分发**
//! （官方 WireGuard for Windows 安装不含 dll，tunnel 静态链在 exe 内），
//! 候选搜索序见 [nt_dll_candidates]；binding crate 0.5.0 × 官方
//! wireguard-nt 1.1 amd64 dll 真机可行（PoC 实证，driver version
//! 65537）。backend 接线批已把本模块接进 [crate::windows] 后端分派
//! （`tunnel_backend = "nt"` 时经 [NtRuntime] 装配，默认仍 service 模型）
//! ——生产三台仍跑 wireguard.exe 服务模型，切换等 PoC 验收+用户点头。
//!
//! 纪律（承 [windows_tunnel] / ADR-010）：
//!
//! - **fail closed（端口）**：[TunnelConfig::listen_port] 为 `None` 时
//!   拒绝——wireguard-nt 的 `SetInterface.listen_port: None` 不是"让
//!   OS 选口"而是**落默认 51820**（crate 字段文档实证），多网络下必然
//!   撞绑；端口必须 agent 逐网络显式分配（分析文档 §2.5），生效值以
//!   `Adapter::get_config()` 回读为准（上报用回读值，不得用请求值）。
//!   见 [nt_listen_port]。
//! - **fail closed（peer）**：`SetPeer.endpoint` 是必填
//!   `SocketAddr`（无 Option 余地），peer 无 endpoint 或解析失败一律
//!   拒绝；`persistent_keepalive_secs` 超出 `u16` 上界拒绝
//!   （`SetPeer.keep_alive: Option<u16>`），绝不静默截断。
//! - **命名守门**：adapter 名 `wg-mlt-<handle>`，总长 ≤15（Linux 侧
//!   iface 上限同规，跨平台对称，见 [nt_adapter_name]）；字符白名单
//!   同 Linux 侧 `apply_tunnel_sync`（字母数字 `_-`）。注意
//!   wireguard-nt crate 自身的 `MAX_NAME` 是 256（UTF-16 编码层），
//!   不是本约束——本约束来自网络接口名通用上限。
//! - **私钥边界（ADR-010）**：[NtInterfacePlan::private_key] 只透传
//!   [TunnelConfig::private_key]（`None` = 保留现有密钥，幂等重应用，
//!   与 Linux 侧 `apply_tunnel_sync` 的 `None` 契约同构）；手工
//!   [std::fmt::Debug] 实现对私钥字段脱敏——计划对象可安全进日志。
//!   `SetInterface.private_key: None` 的驱动语义已从 crate 源码锚定：
//!   `set_config` 按**位 flag** 组装（`None` → `HAS_PRIVATE_KEY` 位
//!   不设 → 驱动保留现有私钥，不清空）——规格层
//!   [nt_apply_spec] 以 `None → None` 透传测试锚定该契约；**真机
//!   行为锚定 PoC 仍是 backend 接线批的前置**（todo 禁区条款），
//!   在那之前 `NtRuntime` 不进生产分派。
//! - **MTU**：wireguard-nt 的 `SetInterface` 不含 MTU 字段；crate 的
//!   `set_default_route` 把适配器 `NlMtu` **硬编码 1420**（源码
//!   实证）。规格层据此守门：计划 MTU 非 `None` 且 ≠1420 一律拒
//!   （[NT_INTERFACE_MTU]）——绝不静默套用 1420 假装满足计划。meshlet
//!   缺省计划 MTU 恰为 1420（[crate::DEFAULT_TUNNEL_MTU]）；非 1420
//!   计划（如 PPPoE 1412）在本路径被明确拒绝而非错配。按计划值装配
//!   MTU 需自行调 `SetIpInterfaceEntry`，是后续批次的活，不在本层。

use crate::windows_console::NoWindowCommand;
use crate::NetworkError;
use crate::TunnelConfig;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use meshlet_domain::Ipv4Cidr;
use std::fmt;
use std::net::SocketAddr;

/// adapter 名前缀：`wg-mlt-` + 网络 handle。
const ADAPTER_NAME_PREFIX: &str = "wg-mlt-";
/// adapter 名总长上界（含前缀）。与 Linux 侧 `apply_tunnel_sync` 的
/// iface 名上界同值，跨平台对称。
const ADAPTER_NAME_MAX: usize = 15;

/// wireguard-nt 计划层错误：命名/端口/peer 转换守门的拒绝原因。
///
/// 执行层（后批）落 [`crate::NetworkError`] 时按变体映射；
/// 计划层先独立成类型，避免执行语义污染计划语义。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NtPlanError {
    #[error("adapter handle is empty")]
    AdapterNameEmpty,
    #[error("adapter name too long: {len} > {max} (prefix {ADAPTER_NAME_PREFIX:?} + handle)")]
    AdapterNameTooLong { len: usize, max: usize },
    #[error("adapter handle has invalid character at {pos}: allowed [A-Za-z0-9_-]")]
    AdapterNameInvalidChar { pos: usize },
    #[error(
        "listen_port is required: wireguard-nt None falls back to default 51820 (port collision across networks)"
    )]
    ListenPortMissing,
    #[error("peer {index}: endpoint is required (SetPeer.endpoint is a mandatory SocketAddr)")]
    PeerEndpointMissing { index: usize },
    #[error("peer {index}: endpoint not parseable as SocketAddr: {raw}")]
    PeerEndpointInvalid { index: usize, raw: String },
    #[error("peer {index}: keepalive {value} exceeds u16 range of SetPeer.keep_alive")]
    PeerKeepAliveTooLarge { index: usize, value: u32 },
}

impl From<NtPlanError> for crate::NetworkError {
    /// 计划层守门拒绝 → 应用拒绝（语义不变：计划不合法就是拒绝，绝不静默
    /// 修正）。backend 分派用 `?` 直接收编。
    fn from(error: NtPlanError) -> Self {
        crate::NetworkError::ApplyRejected(error.to_string())
    }
}

/// 单 peer 的 wireguard-nt 计划（[PeerConfig] 的执行形态前置转换）。
///
/// 字段与 wireguard-nt `SetPeer` 一一对应（公钥/keepalive 仍持
/// 计划层形态：base64 `String` / `Option<u16>`，二进制 `[u8; 32]`
/// 转换留给 cfg(windows) 执行层——私钥/密钥字节只应存在于执行瞬间）。
#[derive(Clone, PartialEq, Eq)]
pub struct NtPeerPlan {
    /// peer 公钥（base64）。
    pub public_key: String,
    /// peer 的 UDP 可达端点。**必填**（`SetPeer.endpoint` 非 Option），
    /// 缺失在 [nt_interface_plan] 即拒。
    pub endpoint: SocketAddr,
    /// AllowedIPs（与目标路由一致，§7.2）。
    pub allowed_ips: Vec<Ipv4Cidr>,
    /// 持久 keepalive 秒数；`None` = 不发。
    pub keep_alive: Option<u16>,
}

impl fmt::Debug for NtPeerPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtPeerPlan")
            .field("public_key", &self.public_key)
            .field("endpoint", &self.endpoint)
            .field("allowed_ips", &self.allowed_ips)
            .field("keep_alive", &self.keep_alive)
            .finish()
    }
}

/// 单网络的 wireguard-nt adapter 计划：[TunnelConfig] 经守门后的
/// 执行形态。
///
/// 私钥边界（ADR-010）：[private_key](NtInterfacePlan::private_key)
/// 只在 agent 本地存在；[Debug](std::fmt::Debug) 实现脱敏，计划对象
/// 可安全进日志。
#[derive(Clone, PartialEq, Eq)]
pub struct NtInterfacePlan {
    /// WireGuardNT adapter 名（`wg-mlt-<handle>`，≤15，见
    /// [nt_adapter_name]）。一网络一 adapter，服务单例互踩的根治面。
    pub adapter_name: String,
    /// 显式分配的 UDP listen 端口（**非 Option**，见 [nt_listen_port]）。
    /// 生效值以执行层 `get_config()` 回读为准。
    pub listen_port: u16,
    /// 接口地址（Windows 侧经 IP Helper 装配，非 `SetInterface` 字段）。
    pub address: std::net::Ipv4Addr,
    /// 接口地址前缀长度。
    pub address_prefix: u8,
    /// MTU 意图（`SetInterface` 无此字段；执行层经 Windows API 装配）。
    pub mtu: Option<u32>,
    /// 私钥（base64）。`None` = 保留现有密钥（幂等重应用）；**Debug
    /// 脱敏**，绝不进日志。
    pub private_key: Option<String>,
    /// peer 计划。
    pub peers: Vec<NtPeerPlan>,
}

impl fmt::Debug for NtInterfacePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtInterfacePlan")
            .field("adapter_name", &self.adapter_name)
            .field("listen_port", &self.listen_port)
            .field("address", &self.address)
            .field("address_prefix", &self.address_prefix)
            .field("mtu", &self.mtu)
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "<redacted>"),
            )
            .field("peers", &self.peers)
            .finish()
    }
}

/// adapter 名守门：`wg-mlt-<handle>`，总长 ≤15，字符白名单
/// `[A-Za-z0-9_-]`（只校验 handle 部分；前缀是常量恒合法）。
///
/// fail closed：handle 为空、总长超界、含白名单外字符均拒。
/// 白名单与 Linux 侧 `apply_tunnel_sync` 的 iface 名校验同规，
/// 计划对象跨平台语义一致。
pub fn nt_adapter_name(handle: &str) -> Result<String, NtPlanError> {
    if handle.is_empty() {
        return Err(NtPlanError::AdapterNameEmpty);
    }
    for (pos, ch) in handle.chars().enumerate() {
        let ok = ch.is_ascii_alphanumeric() || ch == '_' || ch == '-';
        if !ok {
            return Err(NtPlanError::AdapterNameInvalidChar { pos });
        }
    }
    let name = format!("{ADAPTER_NAME_PREFIX}{handle}");
    if name.len() > ADAPTER_NAME_MAX {
        return Err(NtPlanError::AdapterNameTooLong {
            len: name.len(),
            max: ADAPTER_NAME_MAX,
        });
    }
    Ok(name)
}

/// FNV-1a 32 位（确定性、无依赖）：adapter handle 派生用短哈希。
fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &byte in bytes {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// 生产接口名 → adapter handle（≤8 字符，见 [nt_adapter_name]）。
///
/// 网络接口名（`[dataplane] interface`，如 `meshlet-overlay` 14 字符）常超
/// 过 adapter handle 上界（`wg-mlt-` 前缀后只剩 8 字符），不能直接当
/// handle——必须确定性压缩：跨进程/重启稳定（否则 restart 找不到原
/// adapter 而重复 create），且不同接口名不塌缩到同一 handle。
///
/// 规则：白名单字符 `[A-Za-z0-9_-]` 保留、其余替换为 `-`；长度 ≤8 原样
/// 用；超长取前 4 字符 + 全名 FNV-1a 低 16 位 4 位十六进制（8 字符）。
/// 结果可能为空（空接口名）——由 [nt_adapter_name] fail closed。
pub fn nt_adapter_handle(interface: &str) -> String {
    let sanitized: String = interface
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if sanitized.len() <= 8 {
        return sanitized;
    }
    let prefix: String = sanitized.chars().take(4).collect();
    let hash = fnv1a32(interface.as_bytes()) & 0xffff;
    format!("{prefix}{hash:04x}")
}

/// listen 端口守门：`None` 拒绝。
///
/// wireguard-nt 的 `SetInterface.listen_port: None` 落默认 51820
/// （crate 字段文档实证），不是"让 OS 选口"——多网络下第二个 adapter
/// 必然撞绑（服务模型时代的 0xc0000022 同源）。端口必须 agent 逐网络
/// 显式分配。
pub fn nt_listen_port(listen_port: Option<u16>) -> Result<u16, NtPlanError> {
    listen_port.ok_or(NtPlanError::ListenPortMissing)
}

/// peer 计划转换：`PeerConfig` → [NtPeerPlan]，fail closed。
///
/// - endpoint 缺失 / 解析失败 → 拒（`SetPeer.endpoint` 必填）；
/// - keepalive 超出 `u16` → 拒（绝不静默截断）；
/// - `allowed_ips` 透传（IPv4 CIDR 已规范化）。
fn nt_peer_plan(peer: &crate::PeerConfig, index: usize) -> Result<NtPeerPlan, NtPlanError> {
    let endpoint = match peer.endpoint.as_deref() {
        None => return Err(NtPlanError::PeerEndpointMissing { index }),
        Some(raw) => {
            raw.trim()
                .parse::<SocketAddr>()
                .map_err(|_| NtPlanError::PeerEndpointInvalid {
                    index,
                    raw: raw.to_string(),
                })?
        }
    };
    let keep_alive = match peer.persistent_keepalive_secs {
        None => None,
        Some(v) if v <= u16::MAX as u32 => Some(v as u16),
        Some(v) => return Err(NtPlanError::PeerKeepAliveTooLarge { index, value: v }),
    };
    Ok(NtPeerPlan {
        public_key: peer.public_key.clone(),
        endpoint,
        allowed_ips: peer.allowed_ips.clone(),
        keep_alive,
    })
}

/// 计划转换：[TunnelConfig] → [NtInterfacePlan]（纯函数，任意平台）。
///
/// 全量 fail closed：端口 `None` 拒、peer endpoint 缺失/坏值拒、
/// keepalive 越界拒、adapter 名不合法拒（`handle` 入参经
/// [nt_adapter_name]）。`private_key`/`mtu`/`address` 等按 [TunnelConfig]
/// 语义透传（`None` 私钥 = 保留现有密钥）。
pub fn nt_interface_plan(
    tunnel: &TunnelConfig,
    handle: &str,
) -> Result<NtInterfacePlan, NtPlanError> {
    let adapter_name = nt_adapter_name(handle)?;
    let listen_port = nt_listen_port(tunnel.listen_port)?;
    let peers = tunnel
        .peers
        .iter()
        .enumerate()
        .map(|(index, peer)| nt_peer_plan(peer, index))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(NtInterfacePlan {
        adapter_name,
        listen_port,
        address: tunnel.address,
        address_prefix: tunnel.address_prefix,
        mtu: tunnel.mtu,
        private_key: tunnel.private_key.clone(),
        peers,
    })
}

// ---------------------------------------------------------------------------
// 执行规格层：NtInterfacePlan → NtApplySpec（任意平台编译+单测）。
// ---------------------------------------------------------------------------

/// wireguard-nt crate 的 `set_default_route` 对适配器 `NlMtu` 的硬编码值
/// （源码实证）。计划 MTU 与它不一致时执行规格层拒绝，见 [nt_apply_spec]。
pub const NT_INTERFACE_MTU: u32 = 1420;

/// WireGuard 密钥字节数（Curve25519）：base64 解码后必须是这个长度。
const KEY_LEN: usize = 32;

/// base64 密钥 → 32 字节。计划层公钥/私钥都持 base64 字符串（与 `wg`
/// 工具同构），驱动 API 收 `[u8; 32]`——解码失败/长度不对一律拒，
/// 绝不静默截断或补零。
fn nt_decode_key(raw: &str, what: &str) -> Result<[u8; KEY_LEN], crate::NetworkError> {
    let decoded = BASE64.decode(raw.trim()).map_err(|e| {
        crate::NetworkError::ApplyRejected(format!("{what}: base64 decode failed: {e}"))
    })?;
    decoded.try_into().map_err(|v: Vec<u8>| {
        crate::NetworkError::ApplyRejected(format!(
            "{what}: decoded to {} bytes, expected {KEY_LEN}",
            v.len()
        ))
    })
}

/// 单 peer 的执行规格：与 wireguard-nt `SetPeer` 字段一一对应的中性形态
/// （公钥已解码为字节；preshared_key 未用恒 None）。
#[derive(Clone, PartialEq, Eq)]
pub struct NtApplyPeerSpec {
    /// peer 公钥（32 字节，base64 已解码）。
    pub public_key: [u8; KEY_LEN],
    /// peer UDP 端点（计划层已守门必填）。
    pub endpoint: SocketAddr,
    /// AllowedIPs（canonical `Ipv4Cidr`，驱动路由目标直接来源）。
    pub allowed_ips: Vec<Ipv4Cidr>,
    /// 持久 keepalive 秒数；`None` = 不发。
    pub keep_alive: Option<u16>,
}

impl fmt::Debug for NtApplyPeerSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 公钥可日志（身份字段），无密钥材料需脱敏——与 NtPeerPlan 同口径。
        f.debug_struct("NtApplyPeerSpec")
            .field("public_key", &BASE64.encode(self.public_key))
            .field("endpoint", &self.endpoint)
            .field("allowed_ips", &self.allowed_ips)
            .field("keep_alive", &self.keep_alive)
            .finish()
    }
}

/// 单 adapter 的执行规格：与 wireguard-nt `SetInterface` 字段一一对应的
/// 中性形态。**全部语义判定（密钥解码、MTU 守门、None 透传）在本层
/// 完成并被宿主 CI 单测锚定**；cfg(windows) 的 `SetInterface` 装配只剩
/// 机械直译。
#[derive(Clone, PartialEq, Eq)]
pub struct NtApplySpec {
    /// 显式 listen 端口（计划层已守门非 `None`）。
    pub listen_port: u16,
    /// 私钥（32 字节）。`None` = **原样透传**给驱动的按位 flag 语义——
    /// `HAS_PRIVATE_KEY` 位不设，驱动保留现有私钥（幂等重应用契约，
    /// 见模块文档私钥边界）。
    pub private_key: Option<[u8; KEY_LEN]>,
    /// peer 规格。
    pub peers: Vec<NtApplyPeerSpec>,
}

impl fmt::Debug for NtApplySpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtApplySpec")
            .field("listen_port", &self.listen_port)
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "<redacted>"),
            )
            .field("peers", &self.peers)
            .finish()
    }
}

/// 计划 → 执行规格（纯函数，任意平台）：
///
/// - 公钥/私钥 base64 解码，失败即拒（[nt_decode_key]）；
/// - `private_key: None` 原样透传（锚定驱动的按位保留语义）；
/// - **MTU 守门**：计划 `mtu` 非 `None` 且 ≠ [NT_INTERFACE_MTU] 拒——
///   crate 的地址/路由装配把 NlMtu 硬编码 1420，静默接受非 1420 计划
///   就是错配（见模块文档 MTU 条）。
pub fn nt_apply_spec(plan: &NtInterfacePlan) -> Result<NtApplySpec, crate::NetworkError> {
    if let Some(mtu) = plan.mtu {
        if mtu != NT_INTERFACE_MTU {
            return Err(crate::NetworkError::ApplyRejected(format!(
                "plan mtu {mtu} != wireguard-nt pinned interface mtu {NT_INTERFACE_MTU}: \
                 the nt path cannot honor a custom mtu yet"
            )));
        }
    }
    let private_key = match plan.private_key.as_deref() {
        None => None,
        Some(raw) => Some(nt_decode_key(raw, "tunnel private_key")?),
    };
    let peers = plan
        .peers
        .iter()
        .enumerate()
        .map(|(index, peer)| {
            Ok(NtApplyPeerSpec {
                public_key: nt_decode_key(&peer.public_key, &format!("peer {index} public_key"))?,
                endpoint: peer.endpoint,
                allowed_ips: peer.allowed_ips.clone(),
                keep_alive: peer.keep_alive,
            })
        })
        .collect::<Result<Vec<_>, crate::NetworkError>>()?;
    Ok(NtApplySpec {
        listen_port: plan.listen_port,
        private_key,
        peers,
    })
}

// ---------------------------------------------------------------------------
// 只读快照层（跨平台纯结构；cfg(windows) 执行层从 get_config 回读构造）。
// ---------------------------------------------------------------------------

/// 单 peer 的快照读数（[WireguardInterface] 回读的只读视图）。
///
/// 公钥仍持字节形态——base64 编解码是诊断面的事（backend 接线处转
/// [crate::PeerObserved]），与规格层「密钥字节只存在于执行瞬间」同一
/// 边界纪律。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtPeerSnapshot {
    /// peer 公钥（32 字节，回读原样）。
    pub public_key: [u8; 32],
    /// AllowedIPs（回读 canonical；V6 项在构造处丢弃——本层从未设 V6，
    /// 出现即异常，丢段自愈）。
    pub allowed_ips: Vec<Ipv4Cidr>,
}

/// 单 adapter 的只读快照（inspect / 漂移对账输入，[NtRuntime::snapshot]）。
///
/// **无 MTU/接口地址字段**——wireguard-nt `get_config` 只回读
/// listen_port/private_key/public_key/peers（registry 源码实证），MTU
/// 与地址读数不在 [WireguardInterface] 上。对账处这两维按「证据缺失
/// 不判」处理（[crate::device_plan_matches] ④/⑥ 只在读数存在时判），
/// 不制造重放死循环。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtAdapterSnapshot {
    /// 回读的生效 listen 端口（生效值以回读为准，不用请求值）。
    pub listen_port: u16,
    /// 回读的本机公钥（对账「本机私钥被换」指纹用）。
    pub public_key: [u8; 32],
    /// peer 读数。
    pub peers: Vec<NtPeerSnapshot>,
}

// ---------------------------------------------------------------------------
// dll 搜索序（跨平台纯函数 + cfg(windows) 落地解析）。
// ---------------------------------------------------------------------------

/// dll 搜索的环境变量覆写（排障/真机 PoC 同款入口）。
pub const NT_DLL_ENV: &str = "MESHLET_WIREGUARD_NT_DLL";

/// `C:\ProgramData\meshlet\wireguard.dll`——deploy staging 布局的固定位置。
const NT_DLL_PROGRAMDATA: &str = r"C:\ProgramData\meshlet\wireguard.dll";

/// dll 候选搜索序（纯函数）：环境变量覆写 → exe 同目录（MSI/zip 与
/// agent 二进制并排布局）→ ProgramData staging 位。
///
/// 候选只排**序**不查存在性——真机解析（[nt_dll_path]）取第一个存在的
/// 候选；全不存在时报出完整候选列表（排障不需要再翻源码）。
pub fn nt_dll_candidates(
    env_value: Option<&str>,
    exe_dir: Option<&std::path::Path>,
) -> Vec<std::path::PathBuf> {
    let mut candidates = Vec::new();
    if let Some(env) = env_value.map(str::trim).filter(|s| !s.is_empty()) {
        candidates.push(std::path::PathBuf::from(env));
    }
    if let Some(dir) = exe_dir {
        candidates.push(dir.join("wireguard.dll"));
    }
    candidates.push(std::path::PathBuf::from(NT_DLL_PROGRAMDATA));
    candidates
}

// ---------------------------------------------------------------------------
// nt adapter OS 别名解析（跨平台纯函数 + 真机 PowerShell 查询）。
//
// 七项验收 item 1 证据（wgnt-seven-item-2026-11-21.md）：wireguard-nt 给
// adapter 的 OS 级 InterfaceAlias 是驱动固定名 `WireGuard`，隧道名
// `wg-mlt-<handle>` 只出现在 InterfaceDescription（`<adapter_name> Tunnel`）。
// 因此任何 `-InterfaceAlias` / `InterfaceAlias ==` 匹配都**不能**直接用
// `wg-mlt-<handle>` 或受管接口名——必须按 InterfaceDescription 反查 OS
// Name。绝不硬编码 `WireGuard`（crate 默认名，但不得依赖它做匹配）。
// ---------------------------------------------------------------------------

/// 从 `Get-NetAdapter | Select Name,InterfaceDescription | ConvertTo-Json`
/// 输出中按 InterfaceDescription 反查 OS 接口名（Name）。
///
/// 匹配规则：InterfaceDescription **大小写不敏感** 精确等于
/// `"<adapter_name> Tunnel"`（wireguard-nt 命名约定，证据见模块头）。
/// 返回对应 `Name`；JSON 畸形 / 无匹配 → `None`（调用方按 fail closed
/// 语义处理，绝不静默落空）。PowerShell 单对象输出为 object、多对象为
/// array——按 `Value` 统一归一（同 `parse_lan_ip_json` 的模式）；畸形条目
/// 跳过，不阻断后续匹配。
pub fn os_alias_from_adapter_enum_json(json: &str, adapter_name: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let entries: Vec<&serde_json::Value> = match &value {
        serde_json::Value::Array(items) => items.iter().collect(),
        serde_json::Value::Object(_) => vec![&value],
        _ => return None,
    };
    let needle = format!("{adapter_name} Tunnel");
    for entry in entries {
        let Some(name) = entry.get("Name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(desc) = entry.get("InterfaceDescription").and_then(|v| v.as_str()) else {
            continue;
        };
        if desc.eq_ignore_ascii_case(&needle) {
            return Some(name.to_string());
        }
    }
    None
}

/// 真机解析 nt adapter 的 OS 接口名：`Get-NetAdapter` 枚举（字段名英文、
/// locale 无关）→ 按 InterfaceDescription 反查（[os_alias_from_adapter_enum_json]）。
///
/// fail closed：命令失败 / 适配器不存在 / JSON 畸形 → `Err(ApplyRejected)`
/// （调用方绝不带错名继续，宁可整次 apply 拒）。仅 Windows 真机有效；
/// 跨平台可编译（宿主 CI 跑 windows-gnu 交叉验证）。
pub fn resolve_nt_os_alias(adapter_name: &str) -> Result<String, NetworkError> {
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-NetAdapter | Select-Object Name,InterfaceDescription | \
             ConvertTo-Json -Compress",
        ])
        .no_window()
        .output()
        .map_err(|error| NetworkError::Io(format!("spawn powershell (Get-NetAdapter): {error}")))?;
    if !output.status.success() {
        return Err(NetworkError::ApplyRejected(format!(
            "Get-NetAdapter failed: {}",
            crate::windows_console::decode_output(&output.stderr)
        )));
    }
    let json = crate::windows_console::decode_output(&output.stdout);
    os_alias_from_adapter_enum_json(&json, adapter_name).ok_or_else(|| {
        NetworkError::ApplyRejected(format!(
            "no nt adapter with InterfaceDescription '{adapter_name} Tunnel' in \
             Get-NetAdapter output (is the wireguard-nt adapter up?)"
        ))
    })
}

#[cfg(windows)]
mod exec {
    //! cfg(windows) 执行层：dll 装载与 [NtRuntime]。语义判定全部在上层
    //! 完成，本模块只剩装配与错误映射；宿主 CI 经 windows-gnu 交叉
    //! clippy/check 编译验证（不跑测试）。

    use super::{
        nt_apply_spec, nt_dll_candidates, NtAdapterSnapshot, NtApplySpec, NtPeerSnapshot, BASE64,
        NT_DLL_ENV,
    };
    use crate::NetworkError;
    use base64::Engine;
    use meshlet_domain::Ipv4Cidr;
    use std::collections::{BTreeMap, HashMap};
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// adapter pool 名（wireguard-nt 官方示例/PoC 同款）。
    const NT_ADAPTER_POOL: &str = "WireGuard";

    /// 真机解析 dll 路径：候选序见 [super::nt_dll_candidates]，取第一个
    /// 存在的文件；全不存在时 `None`（调用方报候选列表）。
    pub fn nt_dll_path() -> Option<PathBuf> {
        let env_value = std::env::var_os(NT_DLL_ENV).map(|v| v.to_string_lossy().into_owned());
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(std::path::Path::to_path_buf));
        nt_dll_candidates(env_value.as_deref(), exe_dir.as_deref())
            .into_iter()
            .find(|p| p.is_file())
    }

    /// wireguard-nt crate 错误 → [NetworkError]：权限类错误
    /// （`PermissionDenied`，典型=未提权装驱动）映射 InsufficientPrivileges，
    /// 其余 Io——agent 侧能直接读出「该提权还是该修环境」。
    fn nt_map_err(op: &str, err: wireguard_nt::Error) -> NetworkError {
        let denied = match &err {
            wireguard_nt::Error::Driver(e) | wireguard_nt::Error::Windows(_, e) => {
                e.kind() == std::io::ErrorKind::PermissionDenied
            }
            _ => false,
        };
        if denied {
            NetworkError::InsufficientPrivileges(format!("{op}: {err}"))
        } else {
            NetworkError::Io(format!("{op}: {err}"))
        }
    }

    /// 执行规格 → crate `SetInterface`（机械直译，无语义判定）。
    ///
    /// `allowed_ips` 从 canonical [meshlet_domain::Ipv4Cidr]（主机位恒零，
    /// 反序列化即拒非规范值）构造 `Ipv4Net`——`Ipv4Net::new` 只可能因
    /// prefix > 32 失败，domain 类型已排除，`expect` 不可达。
    fn nt_set_interface(spec: &NtApplySpec) -> wireguard_nt::SetInterface {
        wireguard_nt::SetInterface {
            listen_port: Some(spec.listen_port),
            public_key: None,
            private_key: spec.private_key,
            peers: spec
                .peers
                .iter()
                .map(|peer| wireguard_nt::SetPeer {
                    public_key: Some(peer.public_key),
                    preshared_key: None,
                    keep_alive: peer.keep_alive,
                    endpoint: peer.endpoint,
                    allowed_ips: peer
                        .allowed_ips
                        .iter()
                        .map(|cidr| {
                            ipnet::IpNet::V4(
                                ipnet::Ipv4Net::new(cidr.network(), cidr.prefix_len())
                                    .expect("canonical Ipv4Cidr prefix <= 32"),
                            )
                        })
                        .collect(),
                })
                .collect(),
        }
    }

    /// open-or-create：先 `Adapter::open`（已存在 adapter 幂等打开），
    /// 失败再 `Adapter::create`（pool 内随机 GUID）。
    fn nt_open_or_create(
        wireguard: &wireguard_nt::Wireguard,
        adapter_name: &str,
    ) -> Result<wireguard_nt::Adapter, NetworkError> {
        wireguard_nt::Adapter::open(wireguard, adapter_name)
            .or_else(|_| {
                wireguard_nt::Adapter::create(wireguard, NT_ADAPTER_POOL, adapter_name, None)
            })
            .map_err(|e| nt_map_err(&format!("open or create adapter {adapter_name}"), e))
    }

    /// wireguard-nt 运行时：agent 进程生命周期内**持久持有**已建 adapter
    /// 的句柄（crate `Adapter` 的 `Drop` → `WireGuardCloseAdapter` 会移除
    /// adapter——句柄不放住，apply 完 adapter 就没了；PoC 退出零残留正
    /// 是这个语义）。
    ///
    /// 经 [crate::windows] 后端的 `nt` 分派装配（`tunnel_backend = "nt"`
    /// 时 [crate::windows::WindowsNetworkBackend] 持有本运行时；默认
    /// service 模型不进本路径）。
    pub struct NtRuntime {
        wireguard: wireguard_nt::Wireguard,
        dll_path: PathBuf,
        /// adapter 名 → 持久句柄。apply 复用已持句柄（`Adapter` 非 Clone，
        /// 重开第二个句柄再 Drop 反而制造生灭抖动）。
        adapters: Mutex<HashMap<String, wireguard_nt::Adapter>>,
    }

    impl NtRuntime {
        /// 装载 wireguard.dll 并建立运行时。dll 候选序见
        /// [super::nt_dll_candidates]；全候选不存在时报 Io 并携带完整
        /// 候选列表。
        pub fn load() -> Result<Self, NetworkError> {
            let dll_path = nt_dll_path().ok_or_else(|| {
                let env_value = std::env::var_os(NT_DLL_ENV)
                    .map(|v| v.to_string_lossy().into_owned());
                let exe_dir = std::env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(std::path::Path::to_path_buf));
                let searched = nt_dll_candidates(env_value.as_deref(), exe_dir.as_deref())
                    .iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("; ");
                NetworkError::Io(format!(
                    "wireguard.dll not found (ship it beside the agent exe or set {NT_DLL_ENV}); searched: {searched}"
                ))
            })?;
            // SAFETY: 路径来自固定候选序/受控环境变量（模块文档分发纪律），
            // 与 PoC 同一装载方式。
            let wireguard = unsafe { wireguard_nt::load_from_path(&dll_path) }
                .map_err(|e| NetworkError::Io(format!("load wireguard.dll: {e}")))?;
            Ok(Self {
                wireguard,
                dll_path,
                adapters: Mutex::new(HashMap::new()),
            })
        }

        /// 实际装载的 dll 路径（诊断用）。
        pub fn dll_path(&self) -> &std::path::Path {
            &self.dll_path
        }

        /// 应用计划：open-or-create → `set_config`（全量替换 peer 表，
        /// crate 恒含 `REPLACE_PEERS`）→ `up`（socket 在 up 态创建，PoC
        /// 实证不 up 则无握手）→ 地址+allowed_ips 路由一次装配 →
        /// `get_config` 回读。
        ///
        /// 返回**回读**的 listen 端口（计划层纪律：生效值以回读为准，
        /// 不用请求值）。装配序列与 PoC wg-nt-poc 逐字一致（真机 8/8
        /// PASS 的序列）。
        pub fn apply(&self, plan: &super::NtInterfacePlan) -> Result<u16, NetworkError> {
            let spec = nt_apply_spec(plan)?;
            let set_interface = nt_set_interface(&spec);
            let addr_net = ipnet::Ipv4Net::new(plan.address, plan.address_prefix)
                .map_err(|_| NetworkError::ApplyRejected("interface address prefix > 32".into()))?;
            let mut adapters = self.adapters.lock().unwrap_or_else(|p| p.into_inner());
            let adapter = match adapters.get_mut(&plan.adapter_name) {
                Some(held) => held,
                None => {
                    let created = nt_open_or_create(&self.wireguard, &plan.adapter_name)?;
                    adapters.insert(plan.adapter_name.clone(), created);
                    adapters
                        .get_mut(&plan.adapter_name)
                        .expect("adapter inserted above")
                }
            };
            adapter
                .set_config(&set_interface)
                .map_err(|e| nt_map_err("adapter set_config", e))?;
            adapter.up().map_err(|e| nt_map_err("adapter up", e))?;
            // 地址赋值带主机位（接口地址 10.x.y.z 本身），路由目标来自
            // canonical allowed_ips（主机位恒零）——两条约束都由上游类型
            // 保证，此处无需 trunc（PoC 的 trunc 教训是主机位进
            // CreateIpForwardEntry2 报 87，canonical CIDR 不可能触发）。
            adapter
                .set_default_route(&[ipnet::IpNet::V4(addr_net)], &set_interface)
                .map_err(|e| nt_map_err("assign address and routes", e))?;
            let readback = adapter.get_config();
            Ok(readback.listen_port)
        }

        /// 移除 adapter：从句柄表取出并 Drop（→ `WireGuardCloseAdapter`，
        /// adapter 随句柄消亡）。不存在返回 `false`。
        pub fn remove(&self, adapter_name: &str) -> bool {
            self.adapters
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(adapter_name)
                .is_some()
        }

        /// 当前持有句柄的 adapter 名（诊断用，排序稳定输出）。
        pub fn adapter_names(&self) -> Vec<String> {
            let mut names = self
                .adapters
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .keys()
                .cloned()
                .collect::<Vec<_>>();
            names.sort();
            names
        }

        /// 已持 adapter 的 `get_config` 回读快照（nt 后端 inspect 输入）。
        /// adapter 未持 → `None`（进程重启后 adapter 随句柄消亡，
        /// `tunnel_exists=false` 让 reconcile 重放）。
        pub fn inspect(&self, adapter_name: &str) -> Option<NtAdapterSnapshot> {
            let adapters = self.adapters.lock().unwrap_or_else(|p| p.into_inner());
            let config = adapters.get(adapter_name)?.get_config();
            Some(NtAdapterSnapshot {
                listen_port: config.listen_port,
                public_key: config.public_key,
                peers: config
                    .peers
                    .iter()
                    .map(|peer| NtPeerSnapshot {
                        public_key: peer.public_key,
                        allowed_ips: peer
                            .allowed_ips
                            .iter()
                            .filter_map(ipnet_v4_to_cidr)
                            .collect(),
                    })
                    .collect(),
            })
        }

        /// 已持 adapter 的 peer 握手年龄（公钥 → 距今秒，P2P 直连判定输入）。
        /// 与 `wg show <if> latest-handshakes` 同一语义（[crate] 的解析器
        /// 口径：从未握手 / 时钟回拨的行丢弃——证据缺失不臆造）。
        /// adapter 未持 → 错误（直连判定按无数据走，不假装）。
        pub fn handshake_ages(
            &self,
            adapter_name: &str,
        ) -> Result<BTreeMap<String, u64>, NetworkError> {
            let adapters = self.adapters.lock().unwrap_or_else(|p| p.into_inner());
            let adapter = adapters.get(adapter_name).ok_or_else(|| {
                NetworkError::Io(format!("no held wireguard-nt adapter {adapter_name}"))
            })?;
            let config = adapter.get_config();
            let now = std::time::SystemTime::now();
            Ok(config
                .peers
                .iter()
                .filter_map(|peer| {
                    let last = peer.last_handshake?;
                    let age = now.duration_since(last).ok()?.as_secs();
                    Some((BASE64.encode(peer.public_key), age))
                })
                .collect())
        }
    }

    /// `ipnet::IpNet` → canonical [Ipv4Cidr]（meshlet 当前 IPv4-only：V6
    /// 路由在 nt 路径不出现，直接过滤）。
    fn ipnet_v4_to_cidr(net: &ipnet::IpNet) -> Option<Ipv4Cidr> {
        match net {
            ipnet::IpNet::V4(v4) => Ipv4Cidr::from_host_address(v4.network(), v4.prefix_len()).ok(),
            ipnet::IpNet::V6(_) => None,
        }
    }
}

#[cfg(windows)]
pub use exec::{nt_dll_path, NtRuntime};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PeerConfig;

    fn tunnel() -> TunnelConfig {
        TunnelConfig {
            name: "net-a".into(),
            address: "10.99.1.1".parse().unwrap(),
            address_prefix: 24,
            listen_port: Some(51821),
            peers: vec![peer("pub-a", Some("100.64.0.2:51820"))],
            mtu: Some(1380),
            private_key: Some("secret-key-material".into()),
        }
    }

    fn peer(public_key: &str, endpoint: Option<&str>) -> PeerConfig {
        PeerConfig {
            public_key: public_key.into(),
            allowed_ips: vec!["10.99.2.0/24".parse().unwrap()],
            endpoint: endpoint.map(str::to_string),
            persistent_keepalive_secs: Some(25),
        }
    }

    #[test]
    fn adapter_name_accepts_handle_up_to_15_total() {
        // 7 前缀 + 8 handle = 15，恰好达界。
        assert_eq!(nt_adapter_name("abcdefgh").unwrap(), "wg-mlt-abcdefgh");
        assert_eq!(nt_adapter_name("net1").unwrap(), "wg-mlt-net1");
    }

    #[test]
    fn adapter_name_rejects_oversize_empty_and_bad_chars() {
        // 7 + 9 = 16 > 15。
        assert_eq!(
            nt_adapter_name("abcdefghi"),
            Err(NtPlanError::AdapterNameTooLong { len: 16, max: 15 })
        );
        assert_eq!(nt_adapter_name(""), Err(NtPlanError::AdapterNameEmpty));
        assert_eq!(
            nt_adapter_name("net a"),
            Err(NtPlanError::AdapterNameInvalidChar { pos: 3 })
        );
        // 点、斜杠均不在白名单（路径分隔语义一律不进接口名）。
        assert!(matches!(
            nt_adapter_name("net.a"),
            Err(NtPlanError::AdapterNameInvalidChar { pos: 3 })
        ));
        assert!(matches!(
            nt_adapter_name("net/a"),
            Err(NtPlanError::AdapterNameInvalidChar { pos: 3 })
        ));
    }

    #[test]
    fn adapter_handle_passes_short_names_through() {
        // ≤8 字符原样保留（无哈希扰动，诊断友好）。
        assert_eq!(nt_adapter_handle("meshlet"), "meshlet");
        assert_eq!(nt_adapter_handle("meshlet2"), "meshlet2");
        // 非白名单字符替换为 `-`。
        assert_eq!(nt_adapter_handle("mesh.let"), "mesh-let");
        // 空接口名 → 空 handle（由 nt_adapter_name fail closed）。
        assert_eq!(nt_adapter_handle(""), "");
    }

    #[test]
    fn adapter_handle_compresses_long_names_deterministically() {
        // 生产接口名 14 字符 > 8：压缩为 4 前缀 + 4 十六进制哈希 = 8。
        let handle = nt_adapter_handle("meshlet-overlay");
        assert_eq!(
            handle.len(),
            8,
            "long interface must compress to 8 chars: {handle}"
        );
        assert!(
            handle.starts_with("mesh"),
            "prefix preserves the leading chars: {handle}"
        );
        assert!(
            handle
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
            "handle chars must stay in the whitelist: {handle}"
        );
        // 确定性：同输入恒同输出（重启后稳定，restart 不重复 create）。
        assert_eq!(nt_adapter_handle("meshlet-overlay"), handle);
        // 全名参与哈希：仅尾缀不同的长名不塌缩。
        assert_ne!(
            nt_adapter_handle("meshlet-overlay-1"),
            nt_adapter_handle("meshlet-overlay-2")
        );
        // 压缩后的 adapter 名（wg-mlt- + handle）恰好 ≤15。
        let name = nt_adapter_name(&handle).unwrap();
        assert_eq!(
            name.len(),
            15,
            "compressed adapter name sits at the 15-char limit: {name}"
        );
    }

    #[test]
    fn listen_port_requires_explicit_value() {
        assert_eq!(nt_listen_port(Some(51821)).unwrap(), 51821);
        assert_eq!(nt_listen_port(None), Err(NtPlanError::ListenPortMissing));
    }

    #[test]
    fn interface_plan_maps_fields_and_guards_peers() {
        let plan = nt_interface_plan(&tunnel(), "net-a").unwrap();
        assert_eq!(plan.adapter_name, "wg-mlt-net-a");
        assert_eq!(plan.listen_port, 51821);
        assert_eq!(
            plan.address,
            "10.99.1.1".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(plan.address_prefix, 24);
        assert_eq!(plan.mtu, Some(1380));
        assert_eq!(plan.private_key.as_deref(), Some("secret-key-material"));
        assert_eq!(plan.peers.len(), 1);
        assert_eq!(plan.peers[0].public_key, "pub-a");
        assert_eq!(
            plan.peers[0].endpoint,
            "100.64.0.2:51820".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(plan.peers[0].keep_alive, Some(25));
    }

    #[test]
    fn interface_plan_fails_closed_on_missing_port_and_bad_peers() {
        let mut t = tunnel();
        t.listen_port = None;
        assert_eq!(
            nt_interface_plan(&t, "net-a"),
            Err(NtPlanError::ListenPortMissing)
        );

        let mut t = tunnel();
        t.peers[0].endpoint = None;
        assert_eq!(
            nt_interface_plan(&t, "net-a"),
            Err(NtPlanError::PeerEndpointMissing { index: 0 })
        );

        let mut t = tunnel();
        t.peers[0].endpoint = Some("not-an-endpoint".into());
        assert_eq!(
            nt_interface_plan(&t, "net-a"),
            Err(NtPlanError::PeerEndpointInvalid {
                index: 0,
                raw: "not-an-endpoint".into()
            })
        );

        // keepalive 越界：u32 65536 无法进 u16 的 SetPeer.keep_alive。
        let mut t = tunnel();
        t.peers[0].persistent_keepalive_secs = Some(65_536);
        assert_eq!(
            nt_interface_plan(&t, "net-a"),
            Err(NtPlanError::PeerKeepAliveTooLarge {
                index: 0,
                value: 65_536
            })
        );

        // adapter 名守门在 peer 校验之前。
        assert!(matches!(
            nt_interface_plan(&tunnel(), "bad handle"),
            Err(NtPlanError::AdapterNameInvalidChar { pos: 3 })
        ));

        // 空 peers 合法（hub 未下发 peer 的空载计划）。
        let mut t = tunnel();
        t.peers.clear();
        assert!(nt_interface_plan(&t, "net-a").unwrap().peers.is_empty());
    }

    #[test]
    fn interface_plan_debug_redacts_private_key() {
        let plan = nt_interface_plan(&tunnel(), "net-a").unwrap();
        let rendered = format!("{plan:?}");
        assert!(!rendered.contains("secret-key-material"));
        assert!(rendered.contains("<redacted>"));
        // peer 计划不含密钥材料（公钥可日志，endpoint/allowed_ips 同）。
        let peer_rendered = format!("{:?}", plan.peers[0]);
        assert!(peer_rendered.contains("pub-a"));
    }

    #[test]
    fn keepalive_boundary_values_pass() {
        // u16 上界恰好通过，无静默截断。
        let mut t = tunnel();
        t.peers[0].persistent_keepalive_secs = Some(u16::MAX as u32);
        let plan = nt_interface_plan(&t, "net-a").unwrap();
        assert_eq!(plan.peers[0].keep_alive, Some(u16::MAX));
    }

    // ----- 执行规格层 -----

    fn valid_key_bytes(seed: u8) -> String {
        BASE64.encode([seed; 32])
    }

    /// 规格层夹具：计划层默认 `mtu: Some(1380)`，规格层守门要求 1420
    /// ——统一钉到 [NT_INTERFACE_MTU]，个别测试再覆写。
    fn spec_tunnel() -> TunnelConfig {
        let mut t = tunnel();
        t.mtu = Some(NT_INTERFACE_MTU);
        t
    }

    #[test]
    fn apply_spec_decodes_keys_and_maps_peers() {
        let mut t = spec_tunnel();
        t.private_key = Some(valid_key_bytes(1));
        t.peers[0].public_key = valid_key_bytes(2);
        let plan = nt_interface_plan(&t, "net-a").unwrap();
        let spec = nt_apply_spec(&plan).unwrap();
        assert_eq!(spec.listen_port, 51821);
        assert_eq!(spec.private_key, Some([1u8; 32]));
        assert_eq!(spec.peers.len(), 1);
        assert_eq!(spec.peers[0].public_key, [2u8; 32]);
        assert_eq!(spec.peers[0].keep_alive, Some(25));
        assert_eq!(
            spec.peers[0].endpoint,
            "100.64.0.2:51820".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn apply_spec_passes_private_key_none_through_untouched() {
        // 锚定：None → None 原样透传。wireguard-nt `set_config` 按位
        // flag 组装（None → HAS_PRIVATE_KEY 位不设 → 驱动保留现有私钥，
        // crate 源码实证）——幂等重应用契约跨平台成立的第一环；真机
        // 行为锚定 PoC 是 backend 接线批前置（todo 禁区条款）。
        let mut t = spec_tunnel();
        t.private_key = None;
        t.peers[0].public_key = valid_key_bytes(2);
        let plan = nt_interface_plan(&t, "net-a").unwrap();
        let spec = nt_apply_spec(&plan).unwrap();
        assert!(spec.private_key.is_none());
    }

    #[test]
    fn apply_spec_rejects_undecodable_keys() {
        // 非 base64 / 长度不对 / 空串，私钥与 peer 公钥同规。
        let mut t = spec_tunnel();
        t.private_key = Some("not-base64!!".into());
        t.peers[0].public_key = valid_key_bytes(2);
        let plan = nt_interface_plan(&t, "net-a").unwrap();
        assert!(matches!(
            nt_apply_spec(&plan),
            Err(crate::NetworkError::ApplyRejected(msg))
                if msg.contains("private_key") && msg.contains("base64")
        ));

        let mut t = spec_tunnel();
        t.private_key = Some(valid_key_bytes(1));
        t.peers[0].public_key = BASE64.encode([9u8; 4]); // 合法 base64，长度错
        let plan = nt_interface_plan(&t, "net-a").unwrap();
        assert!(matches!(
            nt_apply_spec(&plan),
            Err(crate::NetworkError::ApplyRejected(msg))
                if msg.contains("peer 0") && msg.contains("expected 32")
        ));

        let mut t = spec_tunnel();
        t.private_key = Some("   ".into()); // trim 后为空
        t.peers[0].public_key = valid_key_bytes(2);
        let plan = nt_interface_plan(&t, "net-a").unwrap();
        assert!(matches!(
            nt_apply_spec(&plan),
            Err(crate::NetworkError::ApplyRejected(_))
        ));
    }

    #[test]
    fn apply_spec_pins_mtu_to_the_crate_hardcoded_1420() {
        // crate set_default_route 硬编码 NlMtu=1420：非 1420 计划明确拒绝
        // （PPPoE 1412 这类计划在 nt 路径不可用），绝不静默套 1420。
        let mut t = tunnel();
        t.private_key = Some(valid_key_bytes(1));
        t.peers[0].public_key = valid_key_bytes(2);
        t.mtu = Some(1380);
        let plan = nt_interface_plan(&t, "net-a").unwrap();
        assert!(matches!(
            nt_apply_spec(&plan),
            Err(crate::NetworkError::ApplyRejected(msg)) if msg.contains("1380")));

        // None（随 crate 1420）与显式 1420 都放行。
        for mtu in [None, Some(NT_INTERFACE_MTU)] {
            let mut t = spec_tunnel();
            t.private_key = Some(valid_key_bytes(1));
            t.peers[0].public_key = valid_key_bytes(2);
            t.mtu = mtu;
            let plan = nt_interface_plan(&t, "net-a").unwrap();
            assert!(nt_apply_spec(&plan).is_ok(), "mtu {mtu:?} should pass");
        }
    }

    #[test]
    fn apply_spec_debug_redacts_private_key() {
        let mut t = spec_tunnel();
        t.private_key = Some(valid_key_bytes(7));
        t.peers[0].public_key = valid_key_bytes(2);
        let plan = nt_interface_plan(&t, "net-a").unwrap();
        let spec = nt_apply_spec(&plan).unwrap();
        let rendered = format!("{spec:?}");
        assert!(
            !rendered.contains(&valid_key_bytes(7)),
            "raw key must not leak"
        );
        assert!(rendered.contains("<redacted>"));
    }

    // ----- dll 候选序 -----

    #[test]
    fn dll_candidates_order_env_exe_then_programdata() {
        let env = Some("/srv/override/wireguard.dll");
        let exe_dir = Some(std::path::Path::new(r"C:\Program Files\Meshlet"));
        let got = nt_dll_candidates(env, exe_dir);
        assert_eq!(got.len(), 3);
        assert_eq!(
            got[0],
            std::path::PathBuf::from("/srv/override/wireguard.dll")
        );
        assert_eq!(
            got[1],
            std::path::Path::new(r"C:\Program Files\Meshlet").join("wireguard.dll")
        );
        assert_eq!(
            got[2],
            std::path::PathBuf::from(r"C:\ProgramData\meshlet\wireguard.dll")
        );

        // 环境变量空白串不进候选；exe 目录缺失时只剩 ProgramData 兜底。
        assert_eq!(
            nt_dll_candidates(Some("  "), None),
            vec![std::path::PathBuf::from(
                r"C:\ProgramData\meshlet\wireguard.dll"
            )]
        );
        assert_eq!(nt_dll_candidates(None, None).len(), 1);
    }

    // ----- nt adapter OS 别名解析（七项验收 item 1 缺陷回归） -----

    #[test]
    fn os_alias_matches_by_interface_description_case_insensitive() {
        // 真机形态（wgnt-seven-item-2026-11-21.md）：OS Name 是驱动默认名
        // `WireGuard`，隧道名只在 InterfaceDescription。
        let json = r#"[
            {"Name":"Ethernet","InterfaceDescription":"Intel(R) Ethernet Connection"},
            {"Name":"WireGuard","InterfaceDescription":"wg-mlt-wg-mdc44 Tunnel"}
        ]"#;
        assert_eq!(
            os_alias_from_adapter_enum_json(json, "wg-mlt-wg-mdc44"),
            Some("WireGuard".to_string())
        );
        // 大小写不敏感（OS 给的描述大小写不作信任前提）。
        let upper = r#"[{"Name":"WireGuard","InterfaceDescription":"WG-MLT-WG-MDC44 TUNNEL"}]"#;
        assert_eq!(
            os_alias_from_adapter_enum_json(upper, "wg-mlt-wg-mdc44"),
            Some("WireGuard".to_string())
        );
    }

    #[test]
    fn os_alias_survives_noise_and_malformed_entries() {
        // 多 adapter 噪声行 + 畸形条目（缺 InterfaceDescription）不阻断后续匹配。
        let json = r#"[
            {"Name":"Ethernet"},
            {"Name":"Hyper-V","InterfaceDescription":"Microsoft Hyper-V Virtual Ethernet Adapter"},
            {"Name":"WireGuard","InterfaceDescription":"wg-mlt-a1b2 Tunnel"}
        ]"#;
        assert_eq!(
            os_alias_from_adapter_enum_json(json, "wg-mlt-a1b2"),
            Some("WireGuard".to_string())
        );
    }

    #[test]
    fn os_alias_single_object_and_fail_closed_on_miss() {
        // PowerShell 单对象输出（非数组）。
        let single = r#"{"Name":"WireGuard","InterfaceDescription":"wg-mlt-net1 Tunnel"}"#;
        assert_eq!(
            os_alias_from_adapter_enum_json(single, "wg-mlt-net1"),
            Some("WireGuard".to_string())
        );
        // 查不到 → None（调用方 fail closed）。
        assert_eq!(
            os_alias_from_adapter_enum_json(single, "wg-mlt-other"),
            None
        );
        // 畸形 JSON / 数组元素非对象 / 非对象非数组 → None。
        assert_eq!(
            os_alias_from_adapter_enum_json("not json", "wg-mlt-net1"),
            None
        );
        assert_eq!(
            os_alias_from_adapter_enum_json(r#"[42]"#, "wg-mlt-net1"),
            None
        );
        assert_eq!(os_alias_from_adapter_enum_json(r#"3"#, "wg-mlt-net1"), None);
    }
}
