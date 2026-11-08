//! 配置状态机与版本簿记（[存档 §10](../../docs/review/chatgpt-2026-10-13.md)、
//! [ADR-009](../../docs/decisions/adr-009-config-revision-rollback.md)）。
//!
//! 「数据库写入成功 ≠ WireGuard/路由/NAT 已生效」（§10.1）：期望配置的每次
//! 变更先生成新的 [`ConfigRevision`]（`Pending`，只代表 DB 已写入），再由
//! backend 显式应用到实际环境后才算 `Applied`；应用失败必须把错误写入修订
//! 记录（`Failed` + `error_summary`），**结果不确定时同样进入失败态、不得
//! 假装成功**（§10.3）。控制台以应用状态为准，不以 DB 写入为准。
//!
//! 应用幂等（§10.3）：同一版本重复应用结果一致——已 `Applied` 的修订直接返回，
//! 不再调用 backend；失败版本不允许原地重试（重试 = 以相同哈希记录新修订，
//! 保持状态机严格）；回滚只针对**当前**（最新未回滚的）`Failed` 修订
//! （`Applied` 的撤销走前滚新版本；被更新修订取代的失败修订拒绝回滚，
//! §10.4 不交叉破坏）。
//!
//! 按职责划分的子模块：
//! - `hash`：期望配置哈希（ADR-009 `desired_config_hash`）；
//! - `backend`：应用后端契约（WireGuard/路由/NAT 的 OS 侧执行者接口）；
//! - `ledger`：每网络修订簿记——记录、查询、启动重建与中断收敛；
//! - `apply`：apply/rollback 语义——状态机跃迁与 backend 交互。

mod apply;
mod backend;
mod hash;
mod ledger;

#[cfg(test)]
mod test_support;

pub use backend::ConfigApplyBackend;
pub use hash::desired_config_hash;
pub use ledger::{ConfigLedger, LedgerError};
