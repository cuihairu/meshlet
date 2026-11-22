//! boringtun 嵌入式用户态后端——计划层（[分析文档](../../../docs/design/userspace-wireguard-analysis.md)
//! 同源；meshlet 数据面从内核 WireGuard 迁到 boringtun 用户态协议）。
//!
//! 目标模型：macOS 上以 boringtun（Cloudflare）跑 WireGuard 用户态协议，
//! 替代内核 WireGuard 模块。**Intel mac 选型钉死**（2026-11-22 用户拍板：
//! `x86_64-apple-darwin` 官方支持；gotatun/wireguard-go 出局）。
//!
//! 分层（同 [crate::windows_wireguard_nt] 纪律）：
//!
//! **计划层**（任意平台编译+单测）：[TunnelConfig] → [BtInterfacePlan]
//! 的纯转换与 utun 命名/端口/MTU 守门（[bt_interface_plan]）。
//!
//! **命令计划**（任意平台编译+单测）：[BtInterfacePlan] →
//! `Vec<[crate::macos::backend::BtCommand]>`（ifconfig/route/MTU——utun
//! 是**哑设备**，IP/路由
//! 自管，见 [crate::macos] 的 `bt_apply_commands`）。
//!
//! **`#[cfg(target_os = "macos")]` 执行层**：spawn boringtun-cli——起 utun
//! 并挂 `/var/run/wireguard/*.sock` UAPI，然后跑命令执行器（见
//! [crate::macos::backend]）。宿主 CI 不跑 macOS 测试，本层经
//! `x86_64-apple-darwin` 交叉 check 编译验证。
//!
//! 路径选择（②-3 决策）：**PATH B——spawn boringtun-cli + wg.sock UAPI**，
//! 非库级嵌入（PATH A）。理由：boringtun 0.7.1 库是 WireGuard 协议库
//! （`noise`/`x25519` 模块），**不提供 macOS utun 设备抽象**（`device`
//! feature 走 socket2，非 utun ioctl）——PATH A 需 meshlet 自建 utun
//! ioctl + 协议事件循环 + 线程生命周期管理，远超本批（测试钉）范围；
//! PATH B 由 boringtun-cli 起 utun 并暴露 UAPI socket，meshlet 经标准
//! `wg` 工具配密钥/peer、`ifconfig`/`route` 配哑设备 IP/路由；命令执行器
//! 与对账模型从 linux 后端平移。**boringtun crate 依赖因此不加**（PATH B
//! 运行时只依赖 `boringtun-cli` 二进制，打包是 ⑤ 真机批事项）。
//!
//! 纪律（承 [crate::windows_wireguard_nt] / ADR-010）：
//!
//! - **fail closed（端口）**：[TunnelConfig::listen_port] 为 `None` 时
//!   拒绝——boringtun/utun 需要显式端口，`None` 落默认 51820 在多网络下
//!   必然撞绑（服务模型时代同源）。见 [bt_listen_port]。
//! - **fail closed（peer）**：peer `endpoint` 是必填 `SocketAddr`（无
//!   Option 余地），缺失/解析失败一律拒绝；`persistent_keepalive_secs`
//!   超出 `u16` 上界拒绝，绝不静默截断。
//! - **命名守门**：utun 名必须 `utun`（让内核选）或 `utun<digits>`
//!   （`utun[0-9]+`，如 `utun5`）；其余一律拒。macOS utun 是内核管理
//!   的哑设备，名字只能由内核分配或显式指定。
//! - **私钥边界（ADR-010）**：[BtInterfacePlan::private_key] 只透传
//!   [TunnelConfig::private_key]（`None` = 保留现有密钥，幂等重应用）；
//!   手工 [std::fmt::Debug] 实现对私钥字段脱敏——计划对象可安全进日志。
//! - **MTU**：[BT_INTERFACE_MTU] 守门——计划 `mtu` 非 `None` 且 ≠1420
//!   一律拒（与 NT 同规）；meshlet 缺省计划 MTU 恰为 1420
//!   （[crate::DEFAULT_TUNNEL_MTU]）。

use crate::NetworkError;
use crate::TunnelConfig;
use meshlet_domain::Ipv4Cidr;
use std::fmt;
use std::net::SocketAddr;

/// boringtun 计划层错误：命名/端口/peer 转换守门的拒绝原因。
///
/// 执行层（后批）落 [`crate::NetworkError`] 时按变体映射；
/// 计划层先独立成类型，避免执行语义污染计划语义（同 NT 口径）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BtPlanError {
    #[error("utun interface name is empty")]
    UtunNameEmpty,
    #[error(
        "utun interface name {name:?} invalid: must be 'utun' (kernel picks) or 'utun<digits>'"
    )]
    UtunNameInvalid { name: String },
    #[error(
        "listen_port is required: boringtun/utun needs an explicit port (None falls back to default 51820, port collision across networks)"
    )]
    ListenPortMissing,
    #[error(
        "peer {index}: endpoint is required (boringtun peer endpoint is a mandatory SocketAddr)"
    )]
    PeerEndpointMissing { index: usize },
    #[error("peer {index}: endpoint not parseable as SocketAddr: {raw}")]
    PeerEndpointInvalid { index: usize, raw: String },
    #[error("peer {index}: keepalive {value} exceeds u16 range of persistent_keepalive_secs")]
    PeerKeepAliveTooLarge { index: usize, value: u32 },
    #[error(
        "mtu {mtu} unsupported: boringtun path only accepts {expected} (same rule as wireguard-nt)"
    )]
    MtuUnsupported { mtu: u32, expected: u32 },
}

impl From<BtPlanError> for NetworkError {
    /// 计划层守门拒绝 → 应用拒绝（语义不变：计划不合法就是拒绝，绝不静默
    /// 修正）。backend 分派用 `?` 直接收编。
    fn from(error: BtPlanError) -> Self {
        NetworkError::ApplyRejected(error.to_string())
    }
}

/// 单 peer 的 boringtun 计划（[crate::PeerConfig] 的执行形态前置转换）。
///
/// 字段对应标准 `wg` 配置面（boringtun-cli UAPI 同构）：公钥/keepalive 仍持
/// 计划层形态（base64 `String` / `Option<u16>`），二进制转换留给执行层——
/// 密钥字节只应存在于执行瞬间。
#[derive(Clone, PartialEq, Eq)]
pub struct BtPeerPlan {
    /// peer 公钥（base64）。
    pub public_key: String,
    /// peer 的 UDP 可达端点。**必填**，缺失在 [bt_interface_plan] 即拒。
    pub endpoint: SocketAddr,
    /// AllowedIPs（与目标路由一致，§7.2）。
    pub allowed_ips: Vec<Ipv4Cidr>,
    /// 持久 keepalive 秒数；`None` = 不发。
    pub keep_alive: Option<u16>,
}

impl fmt::Debug for BtPeerPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BtPeerPlan")
            .field("public_key", &self.public_key)
            .field("endpoint", &self.endpoint)
            .field("allowed_ips", &self.allowed_ips)
            .field("keep_alive", &self.keep_alive)
            .finish()
    }
}

/// 单网络的 boringtun 计划：[TunnelConfig] 经守门后的执行形态。
///
/// 私钥边界（ADR-010）：[private_key](BtInterfacePlan::private_key) 只在
/// agent 本地存在；[Debug](std::fmt::Debug) 实现脱敏，计划对象可安全进日志。
#[derive(Clone, PartialEq, Eq)]
pub struct BtInterfacePlan {
    /// utun 接口名（`utun` 让内核选，或 `utun<digits>` 显式；见
    /// [bt_utun_name]）。执行层在 `utun` 时经 `WG_TUN_NAME_FILE` 取实际名。
    pub interface_name: String,
    /// 显式分配的 UDP listen 端口（**非 Option**，见 [bt_listen_port]）。
    pub listen_port: u16,
    /// 接口地址。
    pub address: std::net::Ipv4Addr,
    /// 接口地址前缀长度。
    pub address_prefix: u8,
    /// MTU 意图（守门 [BT_INTERFACE_MTU]；执行层经 `ifconfig` 装配）。
    pub mtu: Option<u32>,
    /// 私钥（base64）。`None` = 保留现有密钥（幂等重应用）；**Debug
    /// 脱敏**，绝不进日志。
    pub private_key: Option<String>,
    /// peer 计划。
    pub peers: Vec<BtPeerPlan>,
}

impl fmt::Debug for BtInterfacePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BtInterfacePlan")
            .field("interface_name", &self.interface_name)
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

/// boringtun 接口 MTU 守门值（与 NT 同规）：meshlet 缺省计划 MTU 恰为
/// 1420（[crate::DEFAULT_TUNNEL_MTU]），本路径目前只接受 1420——非 1420
/// 计划（如 PPPoE 1412）明确拒绝而非静默套用 1420 假装满足。
pub const BT_INTERFACE_MTU: u32 = 1420;

/// utun 接口名守门：`utun`（让内核选）或 `utun<digits>`（如 `utun5`）。
///
/// fail closed：空串、非 `utun` 前缀、前缀后含非数字字符均拒。macOS utun
/// 是内核管理的哑设备，名字只能由内核分配或显式指定——不接受任意字符串。
pub fn bt_utun_name(requested: &str) -> Result<String, BtPlanError> {
    if requested.is_empty() {
        return Err(BtPlanError::UtunNameEmpty);
    }
    let rest = requested
        .strip_prefix("utun")
        .ok_or_else(|| BtPlanError::UtunNameInvalid {
            name: requested.to_string(),
        })?;
    if !rest.is_empty() && !rest.chars().all(|c| c.is_ascii_digit()) {
        return Err(BtPlanError::UtunNameInvalid {
            name: requested.to_string(),
        });
    }
    Ok(requested.to_string())
}

/// listen 端口守门：`None` 拒绝。
///
/// boringtun/utun 需要显式端口；`None` 落默认 51820 在多网络下第二个接口
/// 必然撞绑（服务模型时代的 0xc0000022 同源）。端口必须 agent 逐网络
/// 显式分配。
pub fn bt_listen_port(listen_port: Option<u16>) -> Result<u16, BtPlanError> {
    listen_port.ok_or(BtPlanError::ListenPortMissing)
}

/// peer 计划转换：`PeerConfig` → [BtPeerPlan]，fail closed。
///
/// - endpoint 缺失 / 解析失败 → 拒（boringtun peer endpoint 必填）；
/// - keepalive 超出 `u16` → 拒（绝不静默截断）；
/// - `allowed_ips` 透传（IPv4 CIDR 已规范化）。
fn bt_peer_plan(peer: &crate::PeerConfig, index: usize) -> Result<BtPeerPlan, BtPlanError> {
    let endpoint = match peer.endpoint.as_deref() {
        None => return Err(BtPlanError::PeerEndpointMissing { index }),
        Some(raw) => {
            raw.trim()
                .parse::<SocketAddr>()
                .map_err(|_| BtPlanError::PeerEndpointInvalid {
                    index,
                    raw: raw.to_string(),
                })?
        }
    };
    let keep_alive = match peer.persistent_keepalive_secs {
        None => None,
        Some(v) if v <= u16::MAX as u32 => Some(v as u16),
        Some(v) => return Err(BtPlanError::PeerKeepAliveTooLarge { index, value: v }),
    };
    Ok(BtPeerPlan {
        public_key: peer.public_key.clone(),
        endpoint,
        allowed_ips: peer.allowed_ips.clone(),
        keep_alive,
    })
}

/// 计划转换：[TunnelConfig] → [BtInterfacePlan]（纯函数，任意平台）。
///
/// 全量 fail closed：端口 `None` 拒、peer endpoint 缺失/坏值拒、
/// keepalive 越界拒、utun 名不合法拒（[bt_utun_name]）、MTU 非 [BT_INTERFACE_MTU]
/// 拒。`private_key`/`address` 等按 [TunnelConfig] 语义透传（`None` 私钥 =
/// 保留现有密钥）。
pub fn bt_interface_plan(
    tunnel: &TunnelConfig,
    interface_name: &str,
) -> Result<BtInterfacePlan, BtPlanError> {
    let interface_name = bt_utun_name(interface_name)?;
    let listen_port = bt_listen_port(tunnel.listen_port)?;
    if let Some(mtu) = tunnel.mtu.filter(|mtu| *mtu != BT_INTERFACE_MTU) {
        return Err(BtPlanError::MtuUnsupported {
            mtu,
            expected: BT_INTERFACE_MTU,
        });
    }
    let peers = tunnel
        .peers
        .iter()
        .enumerate()
        .map(|(index, peer)| bt_peer_plan(peer, index))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BtInterfacePlan {
        interface_name,
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

    /// 合法基线计划：端口显式、MTU 恰为守门值、peer endpoint 齐。
    fn tunnel() -> TunnelConfig {
        TunnelConfig {
            name: "net-a".into(),
            address: "10.240.0.7".parse().unwrap(),
            address_prefix: 16,
            listen_port: Some(51821),
            peers: vec![peer("pub-a", Some("100.64.0.2:51820"))],
            mtu: Some(BT_INTERFACE_MTU),
            private_key: Some("secret-key-material".into()),
        }
    }

    fn peer(public_key: &str, endpoint: Option<&str>) -> PeerConfig {
        PeerConfig {
            public_key: public_key.into(),
            allowed_ips: vec!["10.240.0.8/32".parse().unwrap()],
            endpoint: endpoint.map(str::to_string),
            persistent_keepalive_secs: Some(25),
        }
    }

    fn plan() -> BtInterfacePlan {
        bt_interface_plan(&tunnel(), "utun").unwrap()
    }

    /// ④ 钉：utun 名白名单——`utun`（内核选）与 `utun<digits>` 皆合法。
    #[test]
    fn utun_name_accepts_bare_and_numbered() {
        assert_eq!(bt_utun_name("utun").unwrap(), "utun");
        assert_eq!(bt_utun_name("utun0").unwrap(), "utun0");
        assert_eq!(bt_utun_name("utun12").unwrap(), "utun12");
    }

    /// ④ 钉：非白名单一律拒（含前缀后拖非数字字符、大小写、前后空白）。
    #[test]
    fn utun_name_rejects_empty_nonprefix_and_trailing_junk() {
        assert_eq!(bt_utun_name(""), Err(BtPlanError::UtunNameEmpty));
        for bad in ["wg0", "tun5", "utun5x", "utun-1", "UTUN5", "utun ", " utun"] {
            assert_eq!(
                bt_utun_name(bad),
                Err(BtPlanError::UtunNameInvalid {
                    name: bad.to_string()
                }),
                "{bad:?} must be rejected"
            );
        }
    }

    /// ④ 钉：MTU 守门——1420 过，其余（1412/1500/900）拒不静默。
    #[test]
    fn mtu_guard_accepts_1420_and_rejects_others() {
        let guard = |got: u32| {
            let mut tunnel = tunnel();
            tunnel.mtu = Some(got);
            bt_interface_plan(&tunnel, "utun")
        };
        assert_eq!(guard(BT_INTERFACE_MTU).unwrap().mtu, Some(1420));
        // `None` = 不指定，透传（不守门也不补默认）。
        let mut bare = tunnel();
        bare.mtu = None;
        assert_eq!(bt_interface_plan(&bare, "utun").unwrap().mtu, None);
        for mtu in [1412u32, 1500, 900] {
            assert_eq!(
                guard(mtu),
                Err(BtPlanError::MtuUnsupported {
                    mtu,
                    expected: BT_INTERFACE_MTU,
                }),
                "mtu {mtu} must be rejected, not coerced to 1420"
            );
        }
    }

    /// ④ 钉：listen_port `None` fail-closed（拒，不落默认 51820）。
    #[test]
    fn listen_port_none_is_rejected() {
        assert_eq!(bt_listen_port(None), Err(BtPlanError::ListenPortMissing));
        assert_eq!(bt_listen_port(Some(51821)), Ok(51821));
        let mut tunnel = tunnel();
        tunnel.listen_port = None;
        assert_eq!(
            bt_interface_plan(&tunnel, "utun"),
            Err(BtPlanError::ListenPortMissing)
        );
    }

    /// ④ 钉：peer endpoint 缺失 / 坏值拒。
    #[test]
    fn peer_endpoint_missing_or_invalid_is_rejected() {
        let mut tunnel = tunnel();
        tunnel.peers = vec![peer("pub-a", None)];
        assert_eq!(
            bt_interface_plan(&tunnel, "utun"),
            Err(BtPlanError::PeerEndpointMissing { index: 0 })
        );
        tunnel.peers = vec![peer("pub-a", Some("not-an-address"))];
        assert_eq!(
            bt_interface_plan(&tunnel, "utun"),
            Err(BtPlanError::PeerEndpointInvalid {
                index: 0,
                raw: "not-an-address".to_string(),
            })
        );
    }

    /// ④ 钉：keepalive 越界拒（绝不截断），界内保留，`None` 透传。
    #[test]
    fn keepalive_over_u16_is_rejected_not_truncated() {
        let mut tunnel = tunnel();
        // 越界拒（绝不截断）。
        let mut p = peer("pub-a", Some("100.64.0.2:51820"));
        p.persistent_keepalive_secs = Some(u16::MAX as u32 + 1);
        tunnel.peers = vec![p];
        assert_eq!(
            bt_interface_plan(&tunnel, "utun"),
            Err(BtPlanError::PeerKeepAliveTooLarge {
                index: 0,
                value: u16::MAX as u32 + 1,
            })
        );
        // 上界内保留原值（无截断、无放大）。
        let mut p = peer("pub-a", Some("100.64.0.2:51820"));
        p.persistent_keepalive_secs = Some(u16::MAX as u32);
        tunnel.peers = vec![p];
        assert_eq!(
            bt_interface_plan(&tunnel, "utun").unwrap().peers[0].keep_alive,
            Some(u16::MAX)
        );
        // `None` 透传（不发 keepalive）。
        let mut p = peer("pub-a", Some("100.64.0.2:51820"));
        p.persistent_keepalive_secs = None;
        tunnel.peers = vec![p];
        assert_eq!(
            bt_interface_plan(&tunnel, "utun").unwrap().peers[0].keep_alive,
            None
        );
    }

    /// ④ 钉：计划对象承载地址/前缀/端口/peer（含 `utun` 原名透传）。
    #[test]
    fn interface_plan_carries_address_port_and_peers() {
        let plan = plan();
        assert_eq!(plan.interface_name, "utun");
        assert_eq!(plan.listen_port, 51821);
        assert_eq!(plan.address.to_string(), "10.240.0.7");
        assert_eq!(plan.address_prefix, 16);
        assert_eq!(plan.private_key.as_deref(), Some("secret-key-material"));
        assert_eq!(plan.peers.len(), 1);
        assert_eq!(plan.peers[0].public_key, "pub-a");
        assert_eq!(plan.peers[0].endpoint.to_string(), "100.64.0.2:51820");
        assert_eq!(plan.peers[0].keep_alive, Some(25));
    }

    /// ④ 钉：私钥在 Debug 输出中脱敏（ADR-010）——`<redacted>` 在场，
    /// 私钥字节一个不出现。
    #[test]
    fn debug_output_never_leaks_private_key_bytes() {
        let key = "super-secret-base64-material";
        let mut tunnel = tunnel();
        tunnel.private_key = Some(key.to_string());
        let plan = bt_interface_plan(&tunnel, "utun").unwrap();
        let rendered = format!("{plan:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(
            !rendered.contains(key),
            "private key bytes leaked into Debug: {rendered}"
        );
    }

    /// ④ 钉：`private_key: None` 透传（幂等重应用保留现有密钥）。
    #[test]
    fn private_key_none_passes_through() {
        let mut tunnel = tunnel();
        tunnel.private_key = None;
        assert_eq!(
            bt_interface_plan(&tunnel, "utun").unwrap().private_key,
            None
        );
    }

    /// ④ 钉：计划层守门拒绝 → [`NetworkError::ApplyRejected`]（backend 分派
    /// 用 `?` 直接收编，语义不降级）。
    #[test]
    fn plan_error_maps_to_apply_rejected() {
        for error in [
            BtPlanError::UtunNameEmpty,
            BtPlanError::ListenPortMissing,
            BtPlanError::MtuUnsupported {
                mtu: 1412,
                expected: BT_INTERFACE_MTU,
            },
        ] {
            assert!(
                matches!(
                    NetworkError::from(error.clone()),
                    NetworkError::ApplyRejected(_)
                ),
                "{error:?} must map to ApplyRejected"
            );
        }
    }
}
