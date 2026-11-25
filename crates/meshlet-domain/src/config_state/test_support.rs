//! Test fixtures shared across submodules: clock constants, network builders and
//! [`ConfigApplyBackend`] test implementations. Compiled only under `cfg(test)`.

use crate::config_state::backend::ConfigApplyBackend;
use crate::entities::{ConfigRevision, NetworkId};

pub const T0: &str = "2026-10-14T08:00:00Z";
pub const T1: &str = "2026-10-14T08:01:00Z";
pub const T2: &str = "2026-10-14T08:02:00Z";

pub fn net(id: &str) -> NetworkId {
    NetworkId(id.into())
}

/// Backend where both apply and rollback succeed.
pub struct OkBackend;

impl ConfigApplyBackend for OkBackend {
    fn apply(&mut self, _r: &ConfigRevision) -> Result<(), String> {
        Ok(())
    }
    fn rollback(&mut self, _r: &ConfigRevision) -> Result<(), String> {
        Ok(())
    }
}

/// Backend where apply/rollback fail with preset messages.
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

/// Counting backend: tallies backend invocations to assert the idempotent path never touches the backend.
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
