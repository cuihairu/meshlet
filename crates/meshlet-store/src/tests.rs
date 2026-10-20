use std::path::PathBuf;

use meshlet_planner::{OutboxStatus, PlanOp};

use crate::store::{RevisionDraft, Store};

fn draft(revision_id: &str, ops: u32) -> RevisionDraft {
    RevisionDraft {
        network_id: "net-1".to_string(),
        revision_id: revision_id.to_string(),
        ops: (0..ops)
            .map(|index| PlanOp::PublishLanRoute {
                prefix: format!("10.{index}.0.0/16"),
                owner_device: "device-a".to_string(),
                metric: 100 + index,
            })
            .collect(),
        created_at: 1_760_000_000,
    }
}

#[tokio::test]
async fn revision_and_outbox_are_persisted_atomically() {
    let (store, path) = store("atomic").await;
    store.append_revision(draft("rev-1", 2)).await.unwrap();
    assert_revision(&store, "rev-1", 2).await;
    drop(store);
    let reopened = Store::new(&path).await.unwrap();
    assert_revision(&reopened, "rev-1", 2).await;
}

#[tokio::test]
async fn unacked_messages_survive_database_reopen() {
    let (store, path) = store("replay").await;
    store.append_revision(draft("rev-crash", 1)).await.unwrap();
    let first = store.claim_next(1_760_000_010).await.unwrap().unwrap();
    assert_eq!(first.idempotency_key, "rev-crash#0");
    assert_eq!(first.status, OutboxStatus::Dispatched);
    assert_eq!(first.delivery_count, 1);
    drop(store);

    let reopened = Store::new(&path).await.unwrap();
    let recovered = reopened
        .claim_next(1_760_000_020)
        .await
        .unwrap()
        .expect("unacked outbox entry should survive reopen");
    assert_eq!(recovered.id, first.id);
    assert_eq!(recovered.status, OutboxStatus::Dispatched);
    assert_eq!(recovered.delivery_count, 2);

    reopened
        .ack_entry(recovered.id, 1_760_000_030)
        .await
        .unwrap();
    let entries = reopened.revision_outbox("rev-crash").await.unwrap();
    assert_eq!(entries[0].status, OutboxStatus::Acked);
    assert_eq!(entries[0].acked_at, Some(1_760_000_030));
    assert!(reopened.claim_next(1_760_000_040).await.unwrap().is_none());
}

#[tokio::test]
async fn duplicate_revision_is_rejected_without_new_outbox_rows() {
    let (store, _path) = store("duplicate").await;
    store.append_revision(draft("rev-dup", 2)).await.unwrap();
    assert!(store.append_revision(draft("rev-dup", 2)).await.is_err());
    assert_eq!(store.revision_outbox("rev-dup").await.unwrap().len(), 2);
}

async fn assert_revision(store: &Store, revision_id: &str, ops_total: u32) {
    let revision = store
        .get_revision("net-1", revision_id)
        .await
        .unwrap()
        .expect("revision should be persisted");
    assert_eq!(revision.ops_total, ops_total);
    assert_eq!(
        store.revision_outbox(revision_id).await.unwrap().len(),
        ops_total as usize
    );
}

async fn store(prefix: &str) -> (Store, PathBuf) {
    let unique = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let path = std::env::temp_dir().join(format!("meshlet-store-{prefix}-{unique}.db"));
    let _ = std::fs::remove_file(&path);
    let store = Store::new(&path).await.unwrap();
    (store, path)
}
