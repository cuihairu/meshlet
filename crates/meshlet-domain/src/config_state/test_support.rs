//! 跨子模块共享的测试夹具：时钟常量、网络构造器与 [`ConfigApplyBackend`]
//! 测试实现。仅在 `cfg(test)` 下编译。

use crate::config_state::backend::ConfigApplyBackend;
use crate::entities::{ConfigRevision, NetworkId};

pub const T0: &str = "2026-10-14T08:00:00Z";
pub const T1: &str = "2026-10-14T08:01:00Z";
pub const T2: &str = "2026-10-14T08:02:00Z";

pub fn net(id: &str) -> NetworkId {
    NetworkId(id.into())
}

/// apply/rollback 均成功的后端。
pub struct OkBackend;

impl ConfigApplyBackend for OkBackend {
    fn apply(&mut self, _r: &ConfigRevision) -> Result<(), String> {
        Ok(())
    }
    fn rollback(&mut self, _r: &ConfigRevision) -> Result<(), String> {
        Ok(())
    }
}

/// apply/rollback 均按预设文案失败的后端。
pub struct BrokenBackend {
    apply_error: String,
    rollback_error: String,
}

impl BrokenBackend {
    pub fn new(apply_error: &str, rollback_error: &str) -> Self {
        Self {
            apply_error: apply_error.into(),
            rollback_error: rollback_error.into(),
        }
    }
}

impl ConfigApplyBackend for BrokenBackend {
    fn apply(&mut self, _r: &ConfigRevision) -> Result<(), String> {
        Err(self.apply_error.clone())
    }
    fn rollback(&mut self, _r: &ConfigRevision) -> Result<(), String> {
        Err(self.rollback_error.clone())
    }
}

/// 计数后端：统计 backend 被调用次数，用于断言幂等路径不触碰 backend。
pub struct CountingBackend {
    pub calls: u32,
}

impl ConfigApplyBackend for CountingBackend {
    fn apply(&mut self, _r: &ConfigRevision) -> Result<(), String> {
        self.calls += 1;
        Ok(())
    }
    fn rollback(&mut self, _r: &ConfigRevision) -> Result<(), String> {
        self.calls += 1;
        Ok(())
    }
}
