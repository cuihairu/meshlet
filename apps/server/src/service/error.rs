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
    /// 发布对象（PortForward / HTTP 路由 / 探针 / DNS 记录）不存在（R-06）。
    #[error("publish object {0} not found")]
    PublishNotFound(String),
    #[error("segment {0} not found")]
    SegmentNotFound(String),
    #[error("segment grant {0} not found")]
    SegmentGrantNotFound(String),
    /// 任务不存在（MT-003 确认/驳回/列取的资源缺失）。
    #[error("task {0} not found")]
    TaskNotFound(String),
    /// 诊断从未运行过（§12.7：GET 返回最近一次运行，没有就是没有，不现算
    /// 也不假称有）。消息点名 POST 触发方式。
    #[error("{0}")]
    DiagnosticsNotRun(String),
    #[error("invalid invite token")]
    InvalidInviteToken,
    /// 设备出示的自举码无效/已撤销/已耗尽（401：凭据问题，非资源缺失——
    /// 管理侧按 id 撤销时才走 `BootstrapTokenNotFound` 404）。
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
    /// 路由冲突（§17.2「路由冲突数」指标口径）：仅「目的网段与 overlay 或
    /// 既有 LAN 路由重叠」时使用——与设备未激活等其它 409 区分，保证指标
    /// 不把非冲突的拒绝计进来。
    #[error("{0}")]
    RouteConflict(String),
    #[error("{0}")]
    Internal(String),
}

impl ServiceError {
    /// 转为统一错误响应（结构见 docs/architecture/api-contract.md）。
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
    /// 版本簿记错误 → API 错误（未知修订 404；非法跃迁与被取代的回滚 409，
    /// §10.4 乐观并发）。
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
