//! Console authentication: session store + auth/CSRF extractors + login/bootstrap
//! endpoints ([Archive §11.4](../../docs/review/chatgpt-2026-10-13.md),
//! [ADR-010](../../docs/decisions/adr-010-console-auth-enrollment.md)).
//!
//! - Management API (network/invitation/device) handlers always take the
//!   `AuthenticatedUser` (Cookie session or `mlt_` API Token Bearer, see
//!   api_token.rs) plus `CsrfHeader` + `WriteUser` (sessions always pass; tokens
//!   need the `write` scope) extractors for write requests; extractors are only
//!   evaluated after a route matches, so unknown paths stay 404;
//! - `/api/v1/enroll` and `/api/v1/system/status` stay public (enroll carries its
//!   own invitation Token auth);
//! - Cookie: HttpOnly + SameSite=Strict + Max-Age = session TTL; `Secure` comes
//!   from config (set true behind an HTTPS reverse proxy in production);
//! - CSRF: Cookie-authenticated admin "write" requests must carry
//!   `X-Requested-With: XMLHttpRequest` (Console front-end convention), which
//!   together with SameSite=Strict forms a double defence;
//! - Login rate limiting: in-process fixed window (per email), cleared on success;
//! - **No default admin password**: the first admin can only be created via the
//!   "empty-DB bootstrap".

// Split by responsibility: storage (store) / errors (error) / cookies · request
// headers · extractors · audit (extract) / DTOs · sessions · endpoints
// (endpoints); this file keeps the rate-limit constants and AppState.
mod endpoints;
mod error;
mod extract;
mod store;

pub use endpoints::{
    bootstrap_handler, login_handler, logout_handler, me_handler, two_factor_activate_handler,
    two_factor_disable_handler, two_factor_enroll_handler, two_factor_status_handler,
    CredentialsRequest, SessionResponse, TotpCodeRequest, TotpEnrollResponse, TotpStatusResponse,
};
pub use error::AuthApiError;
pub use extract::{AuthenticatedUser, CsrfHeader, WriteUser};
pub use store::{AuthStore, UserRecord};

use meshlet_domain::auth::RateLimiter;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use crate::service;

/// Login rate-limit parameters: at most 5 failed attempts per email per window,
/// window of 15 minutes.
pub const LOGIN_MAX_ATTEMPTS: u32 = 5;
pub const LOGIN_WINDOW: Duration = Duration::from_secs(15 * 60);

/// Argon2 blocking-task cap: keeps CPU-heavy hashing/verification from saturating
/// the workers at the same time.
pub const AUTH_BLOCKING_CONCURRENCY: usize = 4;

/// Constant-time verification target for an unknown email (removes the "user does
/// not exist" timing side channel).
/// It holds an invalid hash in Argon2id PHC format — verification always fails,
/// but takes the same time as a real hash.
const DUMMY_HASH: &str = "$argon2id$v=19$m=32768,t=2,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Application state: in-memory Mesh state + SQLite users/sessions/agent/API
/// tokens + the login rate limiter.
#[derive(Clone)]
pub struct AppState {
    pub mesh: service::SharedState,
    pub auth: AuthStore,
    pub agent_tokens: crate::agent::AgentTokenStore,
    pub api_tokens: crate::api_token::ApiTokenStore,
    /// Audit log (Archive §16.5): stored in the same database as the credentials.
    pub audit: crate::audit::AuditStore,
    pub login_limiter: Arc<RateLimiter>,
    pub cookie_secure: bool,
    /// Config apply/rollback backend factory (§10.3 idempotency, §10.4 rollback
    /// boundary); the dataplane is not wired up by default (explicit failure), and
    /// tests can inject a counting backend to verify idempotency and serialization.
    pub apply_backend: crate::revision::BackendFactory,
    /// Runtime metrics (§17.2): in-process counters + gauges computed at scrape
    /// time; `GET /api/v1/system/metrics`.
    pub metrics: crate::metrics::Metrics,
    /// Mesh persistence mutex (§17.3): the mutation plus the DB write finish inside
    /// one mutex section, so no concurrent interleaving can let a stale row
    /// snapshot overwrite a newer row (write-order guarantee for the request-path
    /// DB mirror).
    pub persist: Arc<tokio::sync::Mutex<()>>,
    /// Backup directory (§17.4): `None` = backup not configured
    /// (`POST /system/backup` returns 503).
    pub backup_dir: Option<std::path::PathBuf>,
    /// Planned tunnel MTU (§7.5 "MTU configurable"): `None` = not explicitly
    /// configured, so diagnostics interpret large-packet/fragmentation risk
    /// against the WireGuard default of 1420; diagnostic check 13 reads from this.
    pub tunnel_mtu: Option<u32>,
    /// Server `[dataplane]` config (used for device plan delivery: interface name /
    /// private key file); when `enabled = false`,
    /// `GET /agent/device/desired` returns 503.
    pub dataplane: meshlet_config::DataPlaneConfig,
    /// SSH alias distribution section (in production from `[ssh_config]`): `None` =
    /// the hub side is not enabled, so the plan carries no `ssh_config` section;
    /// `Some` = the plan carries the alias table of all Active nodes in the mesh.
    pub ssh_config: Option<meshlet_config::SshDistributeConfig>,
    /// Apply/rollback serialization gate per network (§10.4); other networks may
    /// still run in parallel.
    pub revision_locks: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    /// Trusted reverse-proxy sources (TODO-116): `X-Forwarded-For`/`X-Real-IP` are
    /// only trusted when the request comes directly from a trusted proxy; the
    /// default is loopback 127.0.0.1/::1 only.
    pub trusted_proxies: meshlet_config::TrustedProxyConfig,
    /// Concurrency cap for password hashing/verification blocking tasks (§11.4).
    pub auth_blocking: Arc<tokio::sync::Semaphore>,
}

pub type SharedAppState = Arc<AppState>;

impl AppState {
    pub fn new(
        mesh: service::SharedState,
        auth: AuthStore,
        agent_tokens: crate::agent::AgentTokenStore,
        api_tokens: crate::api_token::ApiTokenStore,
        cookie_secure: bool,
    ) -> Self {
        // The audit log shares the credentials database; clone the pool handle rather
        // than sharing a borrow (the `auth` below is moved into Self).
        let audit = crate::audit::AuditStore::new(auth.pool().clone());
        Self {
            mesh,
            auth,
            agent_tokens,
            api_tokens,
            audit,
            login_limiter: Arc::new(RateLimiter::new(LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW)),
            cookie_secure,
            apply_backend: crate::revision::unconfigured_backend_factory(),
            metrics: crate::metrics::Metrics::new(),
            persist: Arc::new(tokio::sync::Mutex::new(())),
            revision_locks: Arc::new(Mutex::new(HashMap::new())),
            auth_blocking: Arc::new(tokio::sync::Semaphore::new(AUTH_BLOCKING_CONCURRENCY)),
            backup_dir: None,
            tunnel_mtu: None,
            dataplane: meshlet_config::DataPlaneConfig::default(),
            ssh_config: None,
            trusted_proxies: meshlet_config::TrustedProxyConfig::default(),
        }
    }

    /// Inject a custom config-apply backend (dataplane wiring / integration tests).
    pub fn with_apply_backend(mut self, factory: crate::revision::BackendFactory) -> Self {
        self.apply_backend = factory;
        self
    }

    /// Inject the backup directory (§17.4; in production from `[backup] dir`, tests
    /// inject a temporary directory).
    pub fn with_backup_dir(mut self, dir: Option<std::path::PathBuf>) -> Self {
        self.backup_dir = dir;
        self
    }

    /// Inject the planned tunnel MTU (§7.5; in production from `tunnel_mtu`, tests
    /// inject one to exercise the diagnostic branches).
    pub fn with_tunnel_mtu(mut self, mtu: Option<u32>) -> Self {
        self.tunnel_mtu = mtu;
        self
    }

    /// Inject the server `[dataplane]` config (in production from `config.dataplane`;
    /// tests inject one to verify device plan delivery and the unconfigured
    /// branch).
    pub fn with_dataplane(mut self, dataplane: meshlet_config::DataPlaneConfig) -> Self {
        self.dataplane = dataplane;
        self
    }

    /// Inject the SSH alias distribution config (in production from `[ssh_config]`;
    /// `None` = the hub side is not enabled).
    pub fn with_ssh_config(
        mut self,
        ssh_config: Option<meshlet_config::SshDistributeConfig>,
    ) -> Self {
        self.ssh_config = ssh_config;
        self
    }

    /// Inject the trusted reverse-proxy sources (TODO-116; in production from
    /// `config.trusted_proxies`, tests inject one to verify the "only trusted
    /// sources get their headers believed" security stance).
    pub fn with_trusted_proxies(
        mut self,
        trusted_proxies: meshlet_config::TrustedProxyConfig,
    ) -> Self {
        self.trusted_proxies = trusted_proxies;
        self
    }

    /// Inject the metrics registry (for integration tests to assert counters;
    /// production uses the `AppState::new` defaults).
    pub fn with_metrics(mut self, metrics: crate::metrics::Metrics) -> Self {
        self.metrics = metrics;
        self
    }

    /// Inject the auth blocking concurrency cap (production keeps the default, tests
    /// verify bounded concurrency).
    pub fn with_auth_blocking_concurrency(mut self, concurrency: usize) -> Self {
        self.auth_blocking = Arc::new(tokio::sync::Semaphore::new(concurrency));
        self
    }

    /// Get the apply/rollback serialization gate for a network; other networks are
    /// not blocked by this config operation.
    pub fn revision_lock(&self, network_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut guard = self.revision_locks.lock().unwrap();
        Arc::clone(
            guard
                .entry(network_id.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    }
}
