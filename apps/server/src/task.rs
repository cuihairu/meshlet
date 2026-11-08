//! 任务通道组合模块：契约记录、派发状态机、超时回收与 HTTP 路由。
//!
//! 幂等语义和安全边界在实现模块内保留；对外仍沿用原有 `task::*`
//! 符号，避免影响 server/agent 路由和集成测试调用方。
pub(crate) mod dispatch;
pub(crate) mod models;
pub(crate) mod recovery;
pub(crate) mod routes;

pub use models::{AssignTaskRequest, TaskRecord, TaskResult, TaskResultReport, TaskView};
pub use recovery::{
    age_task_for_test, complete_task_for_test, start_task_recovery, task_for_test,
    task_recovery_for_test,
};
pub(crate) use routes::{ack_handler, console_routes, pending_handler, result_handler};
