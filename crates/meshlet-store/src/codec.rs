use meshlet_planner::{OutboxStatus, PlanOp, RevisionStatus};
use serde_json::Value;

use crate::error::StoreError;

pub fn encode_plan(ops: &[PlanOp]) -> Result<String, StoreError> {
    let encoded = ops
        .iter()
        .map(|op| {
            let PlanOp::PublishLanRoute {
                prefix,
                owner_device,
                metric,
            } = op;
            serde_json::json!({
                "type": "publish_lan_route",
                "prefix": prefix,
                "owner_device": owner_device,
                "metric": metric,
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_string(&encoded).map_err(|error| StoreError::Serialization(error.to_string()))
}

pub fn encode_plan_op(op: &PlanOp) -> Result<String, StoreError> {
    let PlanOp::PublishLanRoute {
        prefix,
        owner_device,
        metric,
    } = op;
    serde_json::to_string(&serde_json::json!({
        "type": "publish_lan_route",
        "prefix": prefix,
        "owner_device": owner_device,
        "metric": metric,
    }))
    .map_err(|error| StoreError::Serialization(error.to_string()))
}

pub fn decode_plan_op(value: Value) -> Result<PlanOp, StoreError> {
    let kind = value
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_op("missing type"))?;
    if kind != "publish_lan_route" {
        return Err(invalid_op(&format!("unsupported type {kind}")));
    }
    Ok(PlanOp::PublishLanRoute {
        prefix: required_string(&value, "prefix")?,
        owner_device: required_string(&value, "owner_device")?,
        metric: value
            .get("metric")
            .and_then(Value::as_u64)
            .filter(|metric| *metric <= u32::MAX as u64)
            .ok_or_else(|| invalid_op("metric is not a u32"))? as u32,
    })
}

pub fn encode_revision_status(status: RevisionStatus) -> &'static str {
    match status {
        RevisionStatus::Pending => "pending",
        RevisionStatus::Preparing => "preparing",
        RevisionStatus::Applying => "applying",
        RevisionStatus::Succeeded => "succeeded",
        RevisionStatus::Failed => "failed",
        RevisionStatus::RollingBack => "rolling_back",
        RevisionStatus::RolledBack => "rolled_back",
    }
}

pub fn decode_revision_status(status: &str) -> Result<RevisionStatus, StoreError> {
    match status {
        "pending" => Ok(RevisionStatus::Pending),
        "preparing" => Ok(RevisionStatus::Preparing),
        "applying" => Ok(RevisionStatus::Applying),
        "succeeded" => Ok(RevisionStatus::Succeeded),
        "failed" => Ok(RevisionStatus::Failed),
        "rolling_back" => Ok(RevisionStatus::RollingBack),
        "rolled_back" => Ok(RevisionStatus::RolledBack),
        _ => Err(StoreError::InvalidRevisionStatus(status.to_string())),
    }
}

pub fn encode_outbox_status(status: OutboxStatus) -> &'static str {
    match status {
        OutboxStatus::Pending => "pending",
        OutboxStatus::Dispatched => "dispatched",
        OutboxStatus::Acked => "acked",
        OutboxStatus::Failed => "failed",
    }
}

pub fn decode_outbox_status(status: &str) -> Result<OutboxStatus, StoreError> {
    match status {
        "pending" => Ok(OutboxStatus::Pending),
        "dispatched" => Ok(OutboxStatus::Dispatched),
        "acked" => Ok(OutboxStatus::Acked),
        "failed" => Ok(OutboxStatus::Failed),
        _ => Err(StoreError::InvalidPlanOp(format!(
            "unsupported status {status}"
        ))),
    }
}

fn required_string(value: &Value, key: &str) -> Result<String, StoreError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| invalid_op(&format!("missing {key}")))
}

fn invalid_op(reason: &str) -> StoreError {
    StoreError::InvalidPlanOp(reason.to_string())
}
