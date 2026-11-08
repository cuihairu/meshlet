//! P2P 节点直连（[ADR-015](../../docs/decisions/adr-015-p2p-direct-connect.md)）：
//! 类型、直连路径决策与对端链路状态机。
//!
//! 纯逻辑层，无 IO：候选 endpoint 分类（公网 / 局域网）、直连路径决策
//! （同 LAN 直连 / 公网打洞 / 保持 hub 中继）、对端直连 Peer 的 AllowedIPs
//! `/32` 拆分与冲突检查、30s 探测的升降级状态机。接口枚举、`wg` 命令与
//! 打洞发包属于 agent / meshlet-network 执行层，不在这里。
//!
//! 设计要点（与任务书一一对应）：
//! - hub 下发的候选 endpoint 是**建议**而非承诺：决策函数对不可达候选一律
//!   回落中继，绝不报错；
//! - 直连 Peer 的 AllowedIPs 只写对端 overlay `/32`——WireGuard 最长前缀
//!   匹配使 `/32` 天然优先于 hub peer 的整段路由，移除 `/32` 即自动回落
//!   hub，无需改动其他节点配置；
//! - 建立与回退是同一台 agent 本机的状态机（[PeerLinkState]），每探测周期
//!   跃迁一次，幂等可重放。
//!
//! 按职责划分的子模块：
//! - `endpoint`：候选 endpoint 类型、RFC1918/同网段判定与直连路径决策；
//! - `report`：hub 侧上报与分发——候选合并、`peers/endpoints` 聚合；
//! - `allowed_ips`：直连 Peer 的 AllowedIPs `/32` 与冲突检查；
//! - `link`：对端链路状态机、探测分类、迟滞常量与 §12.3 链路状态上报契约。

mod allowed_ips;
mod endpoint;
mod link;
mod report;

#[cfg(test)]
mod test_support;

pub use allowed_ips::{direct_peer_allowed_ips, DirectPeerError};
pub use endpoint::{
    decide_direct_path, is_lan_reachable, is_private_ip, DirectDecision, EndpointCandidate,
    EndpointKind,
};
pub use link::{
    classify_probe, classify_promote_probe, on_probe, DirectCandidateStatus, DirectLinkStatus,
    PeerLinkAction, PeerLinkState, ProbeResult, DIRECT_HEALTH_WINDOW_SECS,
    DIRECT_PERSISTENT_KEEPALIVE_SECS, DIRECT_PROBE_INTERVAL_SECS, DIRECT_PROMOTE_FRESH_SECS,
    MAX_PROMOTE_ATTEMPTS,
};
pub use report::{
    endpoint_candidates, peer_endpoints_for, public_candidate, DeviceDirectState,
    DirectEndpointReport, PeerEndpoints,
};
