//! R-01 SQLite persistence boundary: atomic writes for Revision and Outbox, replayable after a crash.

mod codec;
mod error;
mod models;
mod store;

#[cfg(test)]
mod tests;

pub use error::StoreError;
pub use models::{OutboxRecord, RevisionRecord};
pub use store::{RevisionDraft, Store};
