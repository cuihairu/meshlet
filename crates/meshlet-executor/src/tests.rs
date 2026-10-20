use crate::mock::MockExecutor;
use crate::{ExecuteError, Executor, Revision};

fn revision(id: &str) -> Revision {
    Revision {
        network_id: "net-1".to_string(),
        revision_id: id.to_string(),
        op_json: vec!["{\"kind\":\"PublishLanRoute\"}".to_string()],
    }
}

#[tokio::test]
async fn happy_path_passes_prepare_verify_and_recover() {
    let mut executor = MockExecutor::new();
    let revision = revision("rev-1");
    let state = executor.prepare(&revision).await.unwrap();
    executor.verify(&revision, &state).await.unwrap();
    executor.recover(&revision, state).await.unwrap();
}

#[tokio::test]
async fn injected_prepare_failure_is_reported() {
    let mut executor = MockExecutor::new().fail_prepare("rev-2");
    assert!(matches!(
        executor.prepare(&revision("rev-2")).await,
        Err(ExecuteError::PrepareFailed { .. })
    ));
}

#[tokio::test]
async fn injected_verify_failure_is_reported() {
    let mut executor = MockExecutor::new().fail_verify("rev-3");
    let revision = revision("rev-3");
    let state = executor.prepare(&revision).await.unwrap();
    assert!(matches!(
        executor.verify(&revision, &state).await,
        Err(ExecuteError::VerifyFailed { .. })
    ));
}

#[tokio::test]
async fn foreign_state_is_rejected() {
    let mut executor = MockExecutor::new();
    let revision = revision("rev-4");
    assert!(matches!(
        executor.verify(&revision, &"rev-other".to_string()).await,
        Err(ExecuteError::VerifyFailed { .. })
    ));
}
