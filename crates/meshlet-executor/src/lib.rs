//! R-01 特权执行器契约：控制面只依赖本接口，不直接执行系统命令。

use std::future::Future;

pub mod mock;

#[cfg(test)]
mod tests;

pub trait Executor {
    type State;

    fn prepare(
        &mut self,
        revision: &Revision,
    ) -> impl Future<Output = Result<Self::State, ExecuteError>> + Send;

    fn verify(
        &mut self,
        revision: &Revision,
        state: &Self::State,
    ) -> impl Future<Output = Result<(), ExecuteError>> + Send;

    fn recover(
        &mut self,
        revision: &Revision,
        state: Self::State,
    ) -> impl Future<Output = Result<(), ExecuteError>> + Send;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision {
    pub network_id: String,
    pub revision_id: String,
    pub op_json: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecuteError {
    PrepareFailed { revision_id: String, reason: String },
    VerifyFailed { revision_id: String, reason: String },
    RecoverFailed { revision_id: String, reason: String },
}
