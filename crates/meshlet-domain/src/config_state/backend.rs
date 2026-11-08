//! 应用后端契约：把期望配置落到实际网络环境（WireGuard/路由/NAT 的 OS 侧执行者）。

use crate::entities::ConfigRevision;

/// 把期望配置应用到实际网络环境的后端（WireGuard/路由/NAT 的 OS 侧执行者）。
///
/// 实现纪律（§10.3、ADR-007）：
/// - 幂等：重复应用同一版本不得破坏网络；
/// - 结果不确定（如 applying 中途失联、无法确认接口状态）也必须返回 `Err`，
///   **不得返回 `Ok` 假装成功**；
/// - 只操作 Meshlet 自有对象，不得清空系统路由。
pub trait ConfigApplyBackend {
    /// Inspect and repair the last confirmed plan without publishing pending edits.
    fn reconcile(&mut self) -> Result<(), String> {
        Err("backend recovery is not configured".into())
    }
    fn apply(&mut self, revision: &ConfigRevision) -> Result<(), String>;
    /// 回滚一个 `Failed` 修订：只删除/恢复 Meshlet 自有对象。
    fn rollback(&mut self, revision: &ConfigRevision) -> Result<(), String>;
}

#[cfg(test)]
mod tests {
    use super::ConfigApplyBackend;
    use crate::config_state::test_support::OkBackend;
    use crate::entities::ConfigRevision;

    #[test]
    fn backend_recovery_default_fails_closed_until_configured() {
        let mut unconfigured = OkBackend;
        assert_eq!(
            unconfigured.reconcile().unwrap_err(),
            "backend recovery is not configured"
        );

        struct ConfiguredBackend;

        impl ConfigApplyBackend for ConfiguredBackend {
            fn apply(&mut self, _r: &ConfigRevision) -> Result<(), String> {
                Ok(())
            }

            fn rollback(&mut self, _r: &ConfigRevision) -> Result<(), String> {
                Ok(())
            }

            fn reconcile(&mut self) -> Result<(), String> {
                Ok(())
            }
        }

        assert!(ConfiguredBackend.reconcile().is_ok());
    }
}
