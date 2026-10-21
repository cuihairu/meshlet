//! Verify dataplane state and choose a security-preserving recovery input.

use crate::{drift::detect, last_good::recovery_state, model::HubState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    AlreadyGood,
    ApplyDesired,
    ApplyRecovery,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileDecision {
    pub action: RecoveryAction,
}

pub fn decide(
    desired: &HubState,
    last_good: Option<&HubState>,
    plan: &crate::HubPlan,
    observed: &crate::drift::HubObserved,
) -> Result<ReconcileDecision, crate::model::ValidationError> {
    if detect(plan, observed).in_sync() {
        return Ok(ReconcileDecision {
            action: RecoveryAction::AlreadyGood,
        });
    }
    if let Some(last_good) = last_good {
        let recovered = recovery_state(last_good, desired);
        let recovered_plan = crate::HubPlan::compile(&recovered)?;
        if !recovered_plan.networks.is_empty() && detect(&recovered_plan, observed).in_sync() {
            return Ok(ReconcileDecision {
                action: RecoveryAction::ApplyRecovery,
            });
        }
    }
    Ok(ReconcileDecision {
        action: RecoveryAction::ApplyDesired,
    })
}
