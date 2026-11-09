//! Windows 平台数据面后端（[ADR-008](../../../docs/decisions/adr-008-windows-network-backend.md)）。
//!
//! 基于 WireGuardNT（官方 WireGuard for Windows）的隧道服务模型：
//! `wireguard.exe /installtunnelservice` 创建受管服务 `WireGuardTunnel$<name>`，
//! 路由通过 `netsh interface ipv4 add route` 管理。
//!
//! 本模块将 [windows_tunnel] / [windows_service] / [windows_routes] 的
//! 计划层函数接线为 [crate::NetworkBackend] 实现，使 Windows agent 能够：
//! - inspect：检查 WireGuard 安装状态、隧道存在性、peer、路由、MTU
//! - apply_tunnel：渲染 conf 并调用 `wireguard.exe /installtunnelservice`
//! - apply_routes：通过 netsh 添加/删除路由
//!
//! 与 Linux 后端同纪律：每个触碰内核的操作都返回明确结果，
//! 不静默失败；不支持的操作返回 [`NetworkError::Unsupported`]。

mod backend;
pub use backend::WindowsNetworkBackend;
mod diagnostics;
mod nat;
mod netsh;
mod parsing;
mod process_cmds;
mod route;
mod wireguard;

#[cfg(test)]
mod tests;
