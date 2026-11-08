//! 网络后端错误类型（从 lib.rs 拆出）。

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetworkError {
    #[error("operation not supported on this platform: {0}")]
    Unsupported(String),
    #[error("insufficient privileges: {0}")]
    InsufficientPrivileges(String),
    #[error("backend io failure: {0}")]
    Io(String),
    #[error("apply rejected: {0}")]
    ApplyRejected(String),
}
