//! R-01 SQLite 持久化边界：Revision 与 Outbox 原子写入，可从崩溃后重放。

mod codec;
mod error;
mod models;
mod store;

#[cfg(test)]
mod tests;

pub use error::StoreError;
pub use models::{OutboxRecord, RevisionRecord};
pub use store::{RevisionDraft, Store};
