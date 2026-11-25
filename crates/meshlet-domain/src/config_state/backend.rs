//! Apply-backend contract: pushes the desired configuration onto the real network environment (the OS-side executor for WireGuard/routes/NAT).

use crate::entities::ConfigRevision;

/// Backend that applies the desired configuration to the real network environment (the OS-side executor for WireGuard/routes/NAT).
///
/// Implementation discipline (§10.3, ADR-007):
/// - Idempotent: re-applying the same revision must not break the network;
/// - An uncertain outcome (e.g. lost contact mid-apply, interface state unverifiable) must also return `Err`,
///   **never `Ok` as if it had succeeded**;
/// - Touch only Meshlet's own objects; never flush the system routes.
pub trait ConfigApplyBackend {
    /// Inspect and repair the last confirmed plan without publishing pending edits.
    fn reconcile(&mut self) -> Result<(), String> {
        Err("backend recovery is not configured".into())
    }
    fn apply(&mut self, revision: &ConfigRevision) -> Result<(), String>;
    /// Roll back a `Failed` revision: only deletes/restores Meshlet's own objects.
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
