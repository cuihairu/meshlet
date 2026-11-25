//! Service errors and their API error-code mapping.

use meshlet_api_types::ErrorResponse;
use meshlet_domain::RegistryError;

#[derive(Debug, Clone, thiserror::Error)]
pub enum ServiceError {
    #[error("network {0} not found")]
    NetworkNotFound(String),
    #[error("invite {0} not found")]
    InviteNotFound(String),
    #[error("device {0} not found")]
    DeviceNotFound(String),
    #[error("revision {0} not found")]
    RevisionNotFound(String),
    #[error("route {0} not found")]
    RouteNotFound(String),
    #[error("alias {0} not found")]
    AliasNotFound(String),
    /// The publishing object (PortForward / HTTP route / probe / DNS record) does not exist (R-06).
    #[error("publish object {0} not found")]
    PublishNotFound(String),
    #[error("segment {0} not found")]
    SegmentNotFound(String),
    #[error("segment grant {0} not found")]
    SegmentGrantNotFound(String),
    /// The task does not exist (a resource missing from MT-003 confirm/reject/list).
    #[error("task {0} not found")]
    TaskNotFound(String),
    /// Diagnostics have never run (§12.7: GET returns the most recent run; if there is none, there is none — nothing
    /// is computed on the fly and nothing is claimed). The message names the POST trigger.
    #[error("{0}")]
    DiagnosticsNotRun(String),
    #[error("invalid invite token")]
    InvalidInviteToken,
    /// The bootstrap code presented by the device is invalid/revoked/exhausted (401: a credential problem, not a missing resource —
    /// the admin-side revoke-by-id path is what returns `BootstrapTokenNotFound` 404).
    #[error("invalid bootstrap token")]
    InvalidBootstrapToken,
    #[error("bootstrap token {0} not found")]
    BootstrapTokenNotFound(String),
    #[error("{0}")]
    InvalidCidr(String),
    #[error("{0}")]
    InvalidInput(String),
    #[error("{0}")]
    Conflict(String),
    /// Route conflict (the §17.2 "route conflict count" metric definition): used only when "the destination
    /// segment overlaps the overlay or an existing LAN route" — kept distinct from other 409s such as an inactive device, so the metric
    /// does not count non-conflict rejections.
    #[error("{0}")]
    RouteConflict(String),
    #[error("{0}")]
    Internal(String),
}

impl ServiceError {
    /// Convert into the unified error response (structure: docs/architecture/api-contract.md).
    pub fn into_response(self) -> ErrorResponse {
        match self {
            ServiceError::NetworkNotFound(_)
            | ServiceError::InviteNotFound(_)
            | ServiceError::BootstrapTokenNotFound(_)
            | ServiceError::DeviceNotFound(_)
            | ServiceError::RouteNotFound(_)
            | ServiceError::AliasNotFound(_)
            | ServiceError::PublishNotFound(_)
            | ServiceError::SegmentNotFound(_)
            | ServiceError::SegmentGrantNotFound(_)
            | ServiceError::RevisionNotFound(_)
            | ServiceError::TaskNotFound(_)
            | ServiceError::DiagnosticsNotRun(_) => {
                ErrorResponse::new(meshlet_api_types::ErrorCode::NotFound, self.to_string())
            }
            ServiceError::InvalidInviteToken => ErrorResponse::new(
                meshlet_api_types::ErrorCode::NotFound,
                "invite token is not valid",
            ),
            ServiceError::InvalidBootstrapToken => ErrorResponse::new(
                meshlet_api_types::ErrorCode::Unauthorized,
                "bootstrap token is not valid",
            ),
            ServiceError::InvalidCidr(_) | ServiceError::InvalidInput(_) => ErrorResponse::new(
                meshlet_api_types::ErrorCode::ValidationFailed,
                self.to_string(),
            ),
            ServiceError::Conflict(_) | ServiceError::RouteConflict(_) => {
                ErrorResponse::new(meshlet_api_types::ErrorCode::Conflict, self.to_string())
            }
            ServiceError::Internal(_) => {
                ErrorResponse::new(meshlet_api_types::ErrorCode::Internal, self.to_string())
            }
        }
    }
}

impl From<RegistryError> for ServiceError {
    fn from(e: RegistryError) -> Self {
        match e {
            RegistryError::DuplicateVirtualIp(ip) => {
                ServiceError::Conflict(format!("virtual ip {ip} already in use"))
            }
            RegistryError::DuplicateName(name) => {
                ServiceError::Conflict(format!("device name {name:?} already in use"))
            }
        }
    }
}

impl ServiceError {
    /// Version-ledger error -> API error (unknown revision 404; illegal transition and superseded rollback 409,
    /// §10.4 optimistic concurrency).
    pub fn from_ledger(e: meshlet_domain::LedgerError) -> Self {
        match e {
            meshlet_domain::LedgerError::RevisionNotFound {
                network_id,
                revision,
            } => ServiceError::RevisionNotFound(format!("{revision} in network {network_id}")),
            meshlet_domain::LedgerError::IllegalTransition(err) => {
                ServiceError::Conflict(err.to_string())
            }
            meshlet_domain::LedgerError::SupersededRevision {
                network_id,
                revision,
                latest,
            } => ServiceError::Conflict(format!(
                "revision {revision} in network {network_id} is superseded by revision \
                 {latest}; roll back revision {latest} or record a new revision"
            )),
        }
    }
}
