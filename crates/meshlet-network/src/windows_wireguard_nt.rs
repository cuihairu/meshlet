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
//! 本模块现在只含**计划层**：[TunnelConfig] → [NtInterfacePlan] 的纯
//! 转换与命名/端口守门，任意平台编译并单测（同 [windows_tunnel] 纪律）。
//! `#[cfg(windows)]` 执行层（load wireguard.dll → `Adapter::create` →
//! `set_config` → 地址/路由/MTU 的 Windows 侧装配）**本批不写**——等
//! spike Step 3 双 adapter 真机 PoC 通过、ADR-008 复审落档后再接，避免
//! 在驱动可用性未验证时把执行面假绿进 CI。`wireguard-nt = "0.5.0"`
//! 依赖已 target-gated 进 `Cargo.toml`
//! （`[target.'cfg(windows)'.dependencies]`）并锁定进 `Cargo.lock`；
//! API 真值已从 registry 源码核实：配置类型名是 `SetInterface`/`SetPeer`
//! （非 Configuration/Peer），`Adapter::create(&wireguard, pool, name,
//! guid)`，加载入口 `unsafe { wireguard_nt::load_from_path("…/wireguard.dll") }`。
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
//!   `SetInterface.private_key: None` 在 wireguard-nt 驱动侧的语义
//!   （保留 vs 清空）Step 3 PoC 时从真机行为核实，执行层落地前必须有
//!   锚定测试。
//! - **MTU**：wireguard-nt 的 `SetInterface` 不含 MTU 字段（隧道语义
//!   全在驱动内，适配器 MTU 是 Windows 网络栈属性）；计划层保留
//!   [NtInterfacePlan::mtu] 记录 [TunnelConfig::mtu] 意图，执行层经
//!   Windows IP Helper API 装配（后批）。

use crate::TunnelConfig;
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
}
