//! Config revision and application-state API ([archive §10](../../docs/review/chatgpt-2026-10-13.md),
//! [ADR-009](../../docs/decisions/adr-009-config-revision-rollback.md)).
//!
//! **DB write != displayed effect** (§10.1): each change to the desired config only
//! produces a `Pending` revision; it transitions to `Applied` only after the
//! backend successfully applies the config to the actual network environment.
//! An application failure (**including an indeterminate outcome**) goes to
//! `Failed` and keeps a diagnostic `error_summary`.
//!
//! Data-plane wiring (ADR-007): when `[dataplane] enabled = true`, apply goes
//! through [`HubDataPlaneBackend`] — it executes WireGuard/routing on this host
//! against the current desired-config snapshot (platform backend
//! [`meshlet_network::SystemBackend`]: real kernel execution on Linux; every
//! operation explicitly `Unsupported` on other platforms, the ADR-008 Windows
//! backend is pending). The default (unconfigured or `enabled = false`) remains
//! [`UnconfiguredBackend`] failing explicitly: failures stay visible, states stay
//! distinguishable, and an upgrade never silently takes over the kernel.
//! Gateway-side NAT (ADR-006) runs on the gateway device and ships with the
//! agent data plane (the server only issues the hub-side forwarding plane).
//!
//! The outcome of apply/rollback also converges into the `status` of each
//! desired item ([`service::settle_desired_state`]): only routes and alias
//! mappings actually pushed down to the kernel transition to `applied`, the rest
//! go to `failed` — the agent data plane takes its plan from there (§10.1).
//!
//! Concurrency semantics (§10.4): revision numbers increase monotonically within
//! a network, and configuration changes for the same network are serialized by
//! "record the revision first, then apply it"; illegal transitions (such as
//! retrying in place against a failed revision) return 409 — the retry path is
//! to record a new revision.

// Split by responsibility: the Hub data-plane backend (backend, ADR-007 wiring) /
// the API endpoints and their implementation (handlers); this file keeps the view
// conversion, the placeholder backend, the factory type and the route assembly.
mod backend;
mod handlers;

pub(crate) use backend::{deployment, enforce_authorization, recover_deployment, Deployment};
pub use backend::{
    hub_backend_factory, hub_backend_factory_with, network_dataplane, HubDataPlaneBackend,
};
pub use handlers::{
    apply_revision_handler, get_revision_handler, list_revisions_handler, rollback_revision_handler,
};

use axum::routing::{get, post};
use axum::Router;
use meshlet_domain::{ConfigApplyBackend, ConfigRevision};
use serde::Serialize;
use std::sync::Arc;

use crate::auth::SharedAppState;
use crate::service::MeshState;

/// Config revision view (`GET /config-revisions`, revision detail, apply/rollback responses).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RevisionView {
    pub network_id: String,
    pub revision: u64,
    pub desired_config_hash: String,
    /// ADR-009 state machine: `pending`/`applying`/`applied`/`failed`/
    /// `rollback_pending`/`rolled_back`.
    pub apply_status: String,
    pub created_at: String,
    /// When the apply succeeded; always `null` for `Failed`/`Pending` (no claim of being in effect).
    pub applied_at: Option<String>,
    /// Failure diagnostics (§12.2: failures stay visible); `null` on success.
    pub error_summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub convergence: Option<serde_json::Value>,
}

pub fn to_revision_view(r: &ConfigRevision) -> RevisionView {
    RevisionView {
        network_id: r.network_id.to_string(),
        revision: r.revision,
        desired_config_hash: r.desired_config_hash.clone(),
        apply_status: r.apply_status.as_str().to_string(),
        created_at: r.created_at.clone(),
        applied_at: r.applied_at.clone(),
        error_summary: r.error_summary.clone(),
        convergence: None,
    }
}

/// Placeholder backend used while the data plane is not wired up: every apply or
/// rollback fails **explicitly** (§10.3 forbids pretending success). The error text
/// deliberately says "recorded but not applied" so callers see at a glance the gap
/// between the DB write and the actual effect.
pub struct UnconfiguredBackend;

impl ConfigApplyBackend for UnconfiguredBackend {
    fn apply(&mut self, _revision: &ConfigRevision) -> Result<(), String> {
        Err(
            "no network backend configured: desired config recorded but not applied to any \
             wireguard interface on this host"
                .to_string(),
        )
    }

    fn rollback(&mut self, _revision: &ConfigRevision) -> Result<(), String> {
        Err(
            "no network backend configured: no meshlet-managed objects on this host to \
             roll back"
                .to_string(),
        )
    }
}

/// Factory that builds the backend for one apply/rollback: snapshots the current
/// desired config of the given network.
///
/// Each request constructs an independent instance (the domain trait takes
/// `&mut self`), but it **must be called inside the per-network mutex** — this is
/// what guarantees §10.4's "configuration changes for the same network are
/// serialized": concurrent applies cannot each get their own backend instance and
/// cross-overwrite WireGuard peers / routes / NAT. In production the `[dataplane]`
/// config decides between [`hub_backend_factory`] and
/// [`unconfigured_backend_factory`]; integration tests inject a counting backend
/// and verify idempotency and rollback boundaries at the API layer (§10.3 acceptance).
pub type BackendFactory =
    Arc<dyn Fn(&MeshState, &str) -> Box<dyn ConfigApplyBackend + Send> + Send + Sync>;

/// Default factory: data plane not wired up, fails explicitly.
pub fn unconfigured_backend_factory() -> BackendFactory {
    Arc::new(|_, _| Box::new(UnconfiguredBackend))
}

/// Config revision and application-state routes (management API: session auth + CSRF header on writes).
pub fn routes() -> Router<SharedAppState> {
    Router::new()
        .route(
            "/api/v1/networks/{network_id}/config-revisions",
            get(list_revisions_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/config-revisions/{revision}",
            get(get_revision_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/config-revisions/{revision}/apply",
            post(apply_revision_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/config-revisions/{revision}/rollback",
            post(rollback_revision_handler),
        )
}
