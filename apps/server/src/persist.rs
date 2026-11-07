//! Stable persistence facade.
//!
//! The implementation is split by boundary:
//! - `shared` — SQLite transaction helpers and row string mappings;
//! - `entities` — entity mirroring and transactional request writes;
//! - `tasks` — boot reconstruction, revision ledger replay, and task loading;
//! - `backup` — consistent backup validation and atomic restore;
//! - `diagnostics` — diagnostic snapshots and alias projections.

mod backup;
mod diagnostics;
mod entities;
mod shared;
mod tasks;
#[cfg(test)]
mod tests;

pub use backup::{
    backup_once, backup_to, restore_from_backup, validate_backup, BackupError, BackupReport,
    RestoreReport,
};
pub use diagnostics::{alias_rows, insert_diagnostics_run, latest_diagnostics_run};
pub use entities::{
    commit_alias, commit_approve_registration, commit_device_labels, commit_enrollment,
    commit_host_forward, commit_network, commit_revoke_device, commit_route, commit_route_delete,
    commit_segment, commit_segment_grant, commit_segment_grant_status, delete_registration_db,
    delete_route, delete_routes_of_device, insert_alias, insert_device, insert_host_forward,
    insert_network, insert_registration, insert_revision, promote_registration,
    revoke_bootstrap_token_db, save_bootstrap_token, save_invite, update_desired_status,
    update_device_presence, update_device_status, update_registration_report,
    update_revision_status,
};
pub use shared::{AuditDraft, MeshStatePersistedView};
pub use tasks::{commit_task, internal, load, load_tasks, BootState, INTERRUPTED_SUMMARY};

pub(crate) use diagnostics::commit_application;
pub(crate) use diagnostics::commit_rollback;
pub(crate) use shared::insert_audit_tx;
pub(crate) use shared::insert_revision_tx;
pub(crate) use shared::save_seq_tx;
