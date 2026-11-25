//! Task channel composite module: contract records, dispatch state machine, timeout reclamation, and HTTP routes.
//!
//! Idempotency semantics and safety boundaries are kept inside the implementation modules; the public API still uses the original `task::*`
//! symbols so that server/agent routing and integration-test callers are unaffected.
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
