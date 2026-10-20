use crate::{ExecuteError, Executor, Revision};

#[derive(Debug, Default)]
pub struct MockExecutor {
    fail_prepare_for: Vec<String>,
    fail_verify_for: Vec<String>,
}

impl MockExecutor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fail_prepare(mut self, revision_id: &str) -> Self {
        self.fail_prepare_for.push(revision_id.to_string());
        self
    }

    pub fn fail_verify(mut self, revision_id: &str) -> Self {
        self.fail_verify_for.push(revision_id.to_string());
        self
    }
}

impl Executor for MockExecutor {
    type State = String;

    async fn prepare(&mut self, revision: &Revision) -> Result<Self::State, ExecuteError> {
        if self
            .fail_prepare_for
            .iter()
            .any(|id| id == &revision.revision_id)
        {
            return Err(ExecuteError::PrepareFailed {
                revision_id: revision.revision_id.clone(),
                reason: "injected failure".to_string(),
            });
        }
        Ok(revision.revision_id.clone())
    }

    async fn verify(
        &mut self,
        revision: &Revision,
        state: &Self::State,
    ) -> Result<(), ExecuteError> {
        if state != &revision.revision_id {
            return Err(ExecuteError::VerifyFailed {
                revision_id: revision.revision_id.clone(),
                reason: "state belongs to another revision".to_string(),
            });
        }
        if self
            .fail_verify_for
            .iter()
            .any(|id| id == &revision.revision_id)
        {
            return Err(ExecuteError::VerifyFailed {
                revision_id: revision.revision_id.clone(),
                reason: "injected failure".to_string(),
            });
        }
        Ok(())
    }

    async fn recover(
        &mut self,
        revision: &Revision,
        state: Self::State,
    ) -> Result<(), ExecuteError> {
        self.verify(revision, &state).await
    }
}
