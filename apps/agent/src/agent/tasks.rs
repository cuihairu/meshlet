//! Non-blocking task-worker kick-off.

impl super::Agent {
    pub(super) fn process_tasks(&mut self) {
        self.task_runtime.kick();
    }
}
