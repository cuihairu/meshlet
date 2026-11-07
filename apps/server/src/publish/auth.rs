//! 发布对象共享入口校验与授权策略解析。

use crate::service::{MeshState, ServiceError};
use meshlet_publish::AuthorizationPolicy;

/// 设备校验与 create_route 同口径：属于本网络且 Active。
pub(crate) fn device_in_network(
    state: &MeshState,
    network_id: &str,
    device_id: &str,
) -> Result<meshlet_domain::Device, ServiceError> {
    let device = state
        .registry
        .find_by_id(&meshlet_domain::DeviceId(device_id.to_string()))
        .ok_or_else(|| ServiceError::DeviceNotFound(device_id.to_string()))?;
    if device.network_id.to_string() != network_id {
        return Err(ServiceError::DeviceNotFound(format!(
            "{device_id} is not in network {network_id}"
        )));
    }
    if !device.is_active() {
        return Err(ServiceError::Conflict(format!(
            "device {device_id} is not active"
        )));
    }
    Ok(device.clone())
}

pub(crate) fn parse_policy(
    allowed_source_cidrs: &[String],
    allowed_bearer_tokens: &[String],
) -> Result<AuthorizationPolicy, ServiceError> {
    if allowed_source_cidrs.is_empty() && allowed_bearer_tokens.is_empty() {
        return Err(ServiceError::InvalidInput(
            "publish object must allow at least one source cidr or one bearer token".into(),
        ));
    }
    let mut cidrs = Vec::new();
    for text in allowed_source_cidrs {
        let cidr: meshlet_domain::Ipv4Cidr = text
            .parse()
            .map_err(|e| ServiceError::InvalidCidr(format!("{text}: {e}")))?;
        cidrs.push(cidr);
    }
    let mut tokens = Vec::new();
    for token in allowed_bearer_tokens {
        let token = token.trim().to_string();
        if token.is_empty() {
            return Err(ServiceError::InvalidInput(
                "allowed_bearer_tokens must not contain empty entries".into(),
            ));
        }
        tokens.push(token);
    }
    Ok(AuthorizationPolicy {
        allowed_source_cidrs: cidrs,
        allowed_bearer_tokens: tokens,
    })
}

/// 计划对象校验入口：错误转 [`ServiceError`]（400）。
pub(crate) fn plan_error(e: meshlet_publish::PublishError) -> ServiceError {
    ServiceError::InvalidInput(e.to_string())
}

pub(crate) fn default_true() -> bool {
    true
}

pub(crate) fn default_dns_priority() -> u16 {
    100
}
