//! 诊断载体类型（R-DIAG，从 lib.rs 拆出）：结构化诊断快照的 Serde 类型；
//! crate 根 re-export 保持 `meshlet_network::{NetworkDiagnostics, ...}` 路径。

/// 网络诊断信息面（R-DIAG，2026-11-01 用户令）：agent 本地路由表 / 接口
/// 清单 / wg-mlt 读数三类快照的**结构化**载体。agent 采集（[crate::NetworkBackend]
/// 各平台实现，Linux 复用既有 `ip route` / `wg show dump` 解析器，不重写），
/// 随心跳上报服务端；控制台诊断页与 CLI `meshlet agent diag` 据此展示。
///
/// 纪律与 [crate::NetworkSnapshot] 同源：读不到的真实状态按 `None` / 空数组上报
/// （证据缺失可见），绝不臆测默认值。
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct NetworkDiagnostics {
    /// 采集时刻（agent 本地 ISO-8601）；`None` = 采集未完成。
    pub collected_at: Option<String>,
    /// 全表路由（Linux `ip route show table all` 原文 / Windows `route print`）。
    /// 原文保留以便与真实路由表逐行对照；空 = 未取到。
    pub route_table: Vec<String>,
    /// 接口清单（名称 + IPv4 地址/前缀 + 状态 + MTU）。
    pub interfaces: Vec<InterfaceDiagnostic>,
    /// wg-mlt 接口读数（`wg show dump` 解析；每行一个 peer）。
    pub wg: Vec<WgPeerDiagnostic>,
}

/// 单条接口诊断（R-DIAG「接口清单：含地址/状态/MTU」）。
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct InterfaceDiagnostic {
    pub name: String,
    /// IPv4 地址（点分）；无 IPv4 地址留空串。
    pub ipv4: String,
    /// 前缀长度（0–32）；未取到留空。
    pub prefix: Option<u8>,
    /// `up` / `down` / `unknown`（Linux 按 `ip link` 的 UP flag，Windows 按
    /// `Get-NetIPConfiguration` 的 InterfaceOperationalStatus）。
    pub state: String,
    /// 接口 MTU（字节）；`None` = 未取到。
    pub mtu: Option<u32>,
}

/// 单条 wg-mlt 接口读数（R-DIAG「wg show：peer/握手/流量」）。
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct WgPeerDiagnostic {
    pub public_key: String,
    /// 对端 endpoint（`ip:port`）；空 = 未配置。
    pub endpoint: String,
    /// 对端 AllowedIPs（逗号分隔 CIDR 字符串）。
    pub allowed_ips: String,
    /// 最近握手时间（Unix 秒）；0 = 从未握手。
    pub last_handshake: u64,
    /// 累计接收字节（`transfer-rx`）。
    pub rx_bytes: u64,
    /// 累计发送字节（`transfer-tx`）。
    pub tx_bytes: u64,
}
