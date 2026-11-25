//! Config state machine and revision bookkeeping ([archive §10](../../docs/review/chatgpt-2026-10-13.md),
//! [ADR-009](../../docs/decisions/adr-009-config-revision-rollback.md)).
//!
//! "A successful database write != WireGuard/routing/NAT being in effect" (§10.1): every change
//! to the desired config first yields a new [`ConfigRevision`] (`Pending`, meaning only that the DB write
//! happened) and is `Applied` only after the backend has explicitly applied it to the real environment;
//! a failed apply must record the error on the revision (`Failed` + `error_summary`), and **an uncertain
//! outcome enters the failure state too — never claim success** (§10.3). The console keys off apply state, not the DB write.
//!
//! Apply is idempotent (§10.3): reapplying the same version gives the same result — an already
//! `Applied` revision is returned directly without calling the backend; failed versions may not be retried
//! in place (a retry records a new revision with the same hash, keeping the machine strict); a rollback
//! targets only the **current** (latest un-rolled-back) `Failed` revision (undoing an `Applied` one goes
//! forward via a new version; a superseded failed revision refuses rollback, §10.4 no cross-damage).
//!
//! Submodules, split by responsibility:
//! - `hash`: desired-config hash (ADR-009 `desired_config_hash`);
//! - `backend`: apply-backend contract (the OS-side executor interface for WireGuard/routing/NAT);
//! - `ledger`: per-network revision bookkeeping — recording, querying, startup rebuild, crash convergence;
//! - `apply`: apply/rollback semantics — state-machine transitions and backend interaction.

mod apply;
mod backend;
mod hash;
mod ledger;

#[cfg(test)]
mod test_support;

pub use backend::ConfigApplyBackend;
pub use hash::desired_config_hash;
pub use ledger::{ConfigLedger, LedgerError};
