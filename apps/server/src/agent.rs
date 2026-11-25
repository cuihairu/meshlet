//! Agent heartbeat/status reporting ([archive §14.1](../../docs/review/chatgpt-2026-10-13.md),
//! [§12.4](../../docs/review/chatgpt-2026-10-13.md)).
//!
//! - Agent credentials (`agent_tokens` table, migration 003) follow the same
//!   discipline as invitations/sessions: only the SHA-256 digest is stored,
//!   and the raw token appears exactly once, in the join response;
//! - The heartbeat endpoint `POST /api/v1/agent/heartbeat` is the **agent
//!   API** (Bearer credentials), with a clear authentication boundary from the
//!   admin API (cookie sessions + CSRF) (§13.5);
//! - Heartbeats carry the `wg show` handshake time read locally by the agent
//!   (`last_handshake_at`); the server combines it with the report time for
//!   online determination ([presence] domain layer).

use axum::extract::{ConnectInfo, FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use meshlet_api_types::{ErrorCode, ErrorResponse};
use meshlet_domain::{
    generate_token, token_hash, DataplaneEvidence, DeviceId, DirectEndpointReport,
    DirectLinkStatus, PeerEndpoints, Timestamp,
};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::net::SocketAddr;

use crate::auth::SharedAppState;
use crate::service;

/// Agent credential store (SQLite, migration 003).
#[derive(Clone)]
pub struct AgentTokenStore {
    pool: SqlitePool,
}

impl AgentTokenStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Issue: returns (`raw_token`, `token_hash`). The raw token appears here only once.
    pub async fn issue(
        &self,
        device_id: &DeviceId,
        now: Timestamp,
    ) -> Result<(String, String), sqlx::Error> {
        let raw = generate_token();
        let hash = token_hash(&raw);
        sqlx::query(
            "INSERT INTO agent_tokens (token_hash, device_id, created_at)
             VALUES (?, ?, ?)",
        )
        .bind(&hash)
        .bind(&device_id.0)
        .bind(now.as_str())
        .execute(&self.pool)
        .await?;
        Ok((raw, hash))
    }

    /// Validate: exists and not revoked → device ID.
    pub async fn validate(&self, raw_token: &str) -> Result<Option<DeviceId>, sqlx::Error> {
        let row = sqlx::query_as::<_, (String, Option<String>)>(
            "SELECT device_id, revoked_at FROM agent_tokens WHERE token_hash = ?",
        )
        .bind(token_hash(raw_token))
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|(device_id, revoked_at)| {
            if revoked_at.is_none() {
                Some(DeviceId(device_id))
            } else {
                None
            }
        }))
    }

    pub async fn revoke(&self, raw_token: &str, at: &Timestamp) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE agent_tokens SET revoked_at = ? WHERE token_hash = ?")
            .bind(at.as_str())
            .bind(token_hash(raw_token))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Revoke every agent credential of a device (device revocation flow, §11.5): returns the number of invalidated credentials.
    pub async fn revoke_for_device(
        &self,
        device_id: &DeviceId,
        at: &Timestamp,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE agent_tokens SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL",
        )
        .bind(at.as_str())
        .bind(&device_id.0)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}

/// Parse `Authorization: Bearer <token>` (the scheme is case-insensitive).
pub fn bearer_token_from_headers(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, value) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") || value.is_empty() {
        return None;
    }
    Some(value.to_string())
}

/// §12 P2P: observed source address → public candidate IP. Connections coming
/// from IPv6 (no IPv4 address) or with no address at all return `None` —
/// meshlet is an IPv4 overlay, so a v6 observation does not form an IPv4 public
/// candidate.
///
/// TODO-116 security policy: only trust `X-Forwarded-For`/`X-Real-IP` when the
/// request comes **directly from a trusted reverse proxy**; sources that are
/// not trusted have the headers ignored entirely (spoofing protection).
/// `X-Forwarded-For` is a "client, proxy1, proxy2..." chain; take the
/// **rightmost non-trusted proxy** address (skip every trusted proxy address
/// from right to left and take the first non-trusted one — the real client).
fn direct_observed_ip(
    addr: &SocketAddr,
    headers: &HeaderMap,
    trusted_proxies: &meshlet_config::TrustedProxyConfig,
) -> Option<std::net::Ipv4Addr> {
    // Trust the headers only when the request source (the socket peer) is a trusted proxy.
    if trusted_proxies.is_trusted(addr.ip()) {
        if let Some(ip) = forwarded_for_client(headers, trusted_proxies) {
            return Some(ip);
        }
        if let Some(ip) = real_ip_client(headers) {
            return Some(ip);
        }
    }
    // Fall back to the socket address.
    match addr.ip() {
        std::net::IpAddr::V4(ip) => Some(ip),
        std::net::IpAddr::V6(_) => None,
    }
}

/// `X-Forwarded-For` takes the rightmost non-trusted proxy address. Skip
/// every entry belonging to a trusted proxy, right to left; the first
/// non-trusted entry is the real client. If the whole chain is trusted proxies
/// (or empty), return `None` (no provable real client, fall back to the socket).
fn forwarded_for_client(
    headers: &HeaderMap,
    trusted_proxies: &meshlet_config::TrustedProxyConfig,
) -> Option<std::net::Ipv4Addr> {
    let raw = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())?;
    let mut parts = raw.split(',');
    // Skip trusted proxy addresses right to left. If the trusted set covers the whole chain (including an empty one), None.
    while let Some(entry) = parts.next_back() {
        let ip = entry.trim().parse::<std::net::IpAddr>().ok()?;
        // Rightmost non-trusted proxy address = real client.
        if !trusted_proxies.is_trusted(ip) {
            // An IPv6 observation does not form an IPv4 public candidate (same rule as the socket fallback).
            return match ip {
                std::net::IpAddr::V4(ip) => Some(ip),
                std::net::IpAddr::V6(_) => None,
            };
        }
    }
    // The whole chain is trusted proxies (or empty): no provable real client,
    // fall back to the socket. The caller has already checked that the direct
    // peer is in the trusted set, so no further validation is needed here.
    None
}

/// `X-Real-IP`: a single-address header, used only after the caller has
/// checked that the source is a trusted proxy.
fn real_ip_client(headers: &HeaderMap) -> Option<std::net::Ipv4Addr> {
    let ip = headers.get("x-real-ip")?.to_str().ok()?.parse().ok()?;
    match ip {
        std::net::IpAddr::V4(ip) => Some(ip),
        std::net::IpAddr::V6(_) => None,
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum AgentApiError {
    Unauthorized,
    InvalidInput(String),
    NotFound(String),
    /// Server-side `[dataplane] enabled = false`: no dataplane plan is handed
    /// to agents (503, retryable — once the admin enables it, the plan is
    /// available).
    DataplaneNotConfigured(String),
    Internal(String),
}

impl IntoResponse for AgentApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            AgentApiError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                ErrorCode::Unauthorized,
                "valid agent token required".into(),
            ),
            AgentApiError::InvalidInput(m) => {
                (StatusCode::BAD_REQUEST, ErrorCode::ValidationFailed, m)
            }
            AgentApiError::NotFound(m) => (StatusCode::NOT_FOUND, ErrorCode::NotFound, m),
            AgentApiError::DataplaneNotConfigured(m) => (
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::DataplaneNotConfigured,
                m,
            ),
            AgentApiError::Internal(m) => {
                (StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::Internal, m)
            }
        };
        (status, Json(ErrorResponse::new(code, message))).into_response()
    }
}

// ---------------------------------------------------------------------------
// Extractors (run only on matched routes; unknown paths stay 404)
// ---------------------------------------------------------------------------

/// Agent API authentication extractor: an invalid `Authorization: Bearer <agent_token>` always yields 401.
#[derive(Debug, Clone)]
pub struct AuthorizedAgent(pub DeviceId);

impl FromRequestParts<SharedAppState> for AuthorizedAgent {
    type Rejection = AgentApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedAppState,
    ) -> Result<Self, Self::Rejection> {
        let Some(token) = bearer_token_from_headers(&parts.headers) else {
            return Err(AgentApiError::Unauthorized);
        };
        match state.agent_tokens.validate(&token).await {
            Ok(Some(device_id)) => Ok(AuthorizedAgent(device_id)),
            Ok(None) => Err(AgentApiError::Unauthorized),
            Err(e) => Err(AgentApiError::Internal(e.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatRequest {
    /// Most recent handshake time read locally by the agent via `wg show`
    /// (ISO-8601); absent means it could not be obtained.
    pub last_handshake_at: Option<String>,
    /// Device-side dataplane measurement evidence (kernel readings + large
    /// packet probes, §7.5); absent means not reported.
    #[serde(default)]
    pub dataplane: Option<DataplaneEvidence>,
    /// §12 P2P direct-connect candidate endpoints (listen port + LAN
    /// addresses); absent means not reported / direct connect is off.
    #[serde(default)]
    pub direct: Option<DirectEndpointReport>,
    /// §12.3 link status report: this device's direct links to each peer
    /// (direct / direct_pending). Empty default = all-relay / legacy version
    /// that did not report; the hub keeps it in memory only, for the console
    /// to display P2P/relay.
    #[serde(default)]
    pub direct_links: Vec<DirectLinkStatus>,
    /// R-DIAG network diagnostics three snapshots (routing table / interfaces /
    /// wg readings); absent means not reported / collection failed. Same
    /// discipline as `direct_links`: the hub keeps it in memory only, and the
    /// console diagnostics page renders from it.
    #[serde(default)]
    pub diagnostics: Option<meshlet_network::NetworkDiagnostics>,
    /// The machine's real hostname (default alias source for SSH alias
    /// distribution); absent means a legacy agent that did not report. Same
    /// discipline as `direct_links`: the hub keeps it in memory only, and it
    /// is restored by the next heartbeat report.
    #[serde(default)]
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeartbeatResponse {
    pub online_state: String,
    pub presence_source: String,
    pub last_seen_at: Option<String>,
}

/// `POST /api/v1/agent/heartbeat`: records one agent report (+ optional
/// handshake time + §12 P2P direct-connect candidate endpoints) and returns
/// the current online determination (state + data source + last evidence time).
///
/// The observed source address (public candidate) comes from the connection
/// socket ([ConnectInfo], wired up on the serve side; tests inject it via
/// `request.extensions_mut().insert(ConnectInfo(..))`); the LAN addresses
/// reported in the request are enumerated by the agent itself. Candidates are
/// transient advisory data, kept in memory only.
pub async fn heartbeat_handler(
    State(state): State<SharedAppState>,
    AuthorizedAgent(device_id): AuthorizedAgent,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, AgentApiError> {
    if let Some(ts) = &req.last_handshake_at {
        if chrono::DateTime::parse_from_rfc3339(ts).is_err() {
            return Err(AgentApiError::InvalidInput(format!(
                "last_handshake_at {ts:?} is not an RFC 3339 timestamp"
            )));
        }
    }
    let now: Timestamp = service::now();
    // The heartbeat evidence timestamp is also persisted (§17.3): after a
    // restart presence is judged from the original evidence and never
    // fabricated as online (§12.4). Heartbeats from Pending registration
    // applications go through the `device_registrations` evidence channel
    // (there is no devices row before approval, §7.5 evidence is not lost).
    let _persist = state.persist.lock().await;
    let (presence, network_id, device) = {
        let mut guard = state.mesh.lock().unwrap();
        match service::record_agent_report(
            &mut guard,
            &device_id,
            req.last_handshake_at.clone(),
            req.dataplane.clone(),
            now.clone(),
        ) {
            Ok(presence) => {
                let device = guard
                    .registry
                    .find_by_id(&device_id)
                    .expect("report just recorded")
                    .clone();
                let network_id = device.network_id.to_string();
                // §12: direct-connect candidates are recorded only for registered devices (Pending has no tunnel and does not join the dataplane).
                service::record_direct_state(
                    &mut guard,
                    &device_id,
                    direct_observed_ip(&addr, &headers, &state.trusted_proxies),
                    req.direct.clone(),
                    req.direct_links.clone(),
                );
                // R-DIAG: network diagnostics snapshots follow the same discipline — recorded only for registered devices.
                service::record_diagnostics(&mut guard, &device_id, req.diagnostics.clone());
                // Default alias source for SSH alias distribution: the machine's real hostname (in-memory state).
                service::record_device_hostname(&mut guard, &device_id, req.hostname.clone());
                (Some(presence), network_id, Some(device))
            }
            Err(service::ServiceError::DeviceNotFound(_)) => {
                service::record_pending_agent_report(
                    &mut guard,
                    &device_id,
                    req.dataplane.clone(),
                    now.clone(),
                )
                .map_err(|e| match e {
                    service::ServiceError::DeviceNotFound(id) => AgentApiError::NotFound(id),
                    other => AgentApiError::Internal(other.to_string()),
                })?;
                let network_id = guard
                    .registry
                    .find_registration(&device_id)
                    .expect("just reported")
                    .network_id
                    .to_string();
                (None, network_id, None)
            }
            Err(other) => return Err(AgentApiError::Internal(other.to_string())),
        }
    };
    if let Some(device) = &device {
        crate::persist::update_device_presence(state.auth.pool(), device)
            .await
            .map_err(|e| AgentApiError::Internal(e.to_string()))?;
    } else {
        // Pending application: the evidence goes to device_registrations (the only evidence channel before approval).
        let evidence = req
            .dataplane
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| AgentApiError::Internal(e.to_string()))?;
        crate::persist::update_registration_report(
            state.auth.pool(),
            &device_id,
            &now,
            evidence.as_deref(),
        )
        .await
        .map_err(|e| AgentApiError::Internal(e.to_string()))?;
    }
    // Metrics (§17.2 agent heartbeat counter) + structured log (§17.1: device component event).
    state.metrics.record_agent_heartbeat();
    crate::op_log!(
        info,
        "agent",
        "heartbeat",
        &network_id,
        &device_id.0,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    // A Pending application has no tunnel and does not join the dataplane:
    // `pending` is explicitly distinct from the three online states, so the
    // agent keeps backing off and retrying instead of treating it as a tunnel
    // fault.
    let (online_state, presence_source) = match presence {
        Some(presence) => (
            presence.state.as_str().to_string(),
            presence.source.as_str().to_string(),
        ),
        None => ("pending".to_string(), "registration".to_string()),
    };
    Ok(Json(HeartbeatResponse {
        online_state,
        presence_source,
        last_seen_at: Some(now),
    }))
}

/// `GET /api/v1/agent/device/desired`: this device's desired dataplane plan.
///
/// Returns a [`meshlet_network::DevicePlan`] — a **structured configuration
/// object** (§16.4): the typed tunnel/routing/NAT plan + `desired_config_hash`.
/// The server **never** hands out Shell commands; the agent consumes typed
/// objects only and replays its local backend as needed. `private_key` in the
/// plan is always `null` (ADR-010: the private key never leaves the device;
/// the agent injects it locally).
///
/// When the server has `[dataplane] enabled = false` this returns 503 (the
/// plan becomes available once the admin enables it, and the agent may retry);
/// it never returns an empty plan — so the agent does not mistake "not
/// configured" for "already in effect".
pub async fn desired_device_plan_handler(
    State(state): State<SharedAppState>,
    AuthorizedAgent(device_id): AuthorizedAgent,
) -> Result<Json<meshlet_network::DevicePlan>, AgentApiError> {
    let _persist = state.persist.lock().await;
    // Identity resolution comes before the global dataplane switch: a
    // pending-approval registration always 404s with "pending approval",
    // otherwise while the dataplane is off that signal would be masked by 503
    // and neither agent nor admin could read the real state.
    let (plan, network_id) = {
        let guard = state.mesh.lock().unwrap();
        let Some(device) = guard.registry.find_by_id(&device_id) else {
            // A pending-approval registration (ZeroTier-style bootstrap flow):
            // 404 semantics are the same as "plan does not exist" — before
            // approval it does not enter the desired config (migration 008
            // trade-off), the agent backs off and retries, and this endpoint
            // returns the plan once approved.
            if guard.registry.find_registration(&device_id).is_some() {
                return Err(AgentApiError::NotFound(format!(
                    "device {device_id} is pending approval: no desired plan until an operator \
                     approves the registration"
                )));
            }
            return Err(AgentApiError::NotFound(format!(
                "device {device_id} not found"
            )));
        };
        let network_id = device.network_id.to_string();
        if !state.dataplane.enabled {
            return Err(AgentApiError::DataplaneNotConfigured(
                "server dataplane is disabled: set [dataplane] enabled = true to distribute \
                 device plans"
                    .into(),
            ));
        }
        if !device.is_active() {
            return Err(AgentApiError::Unauthorized);
        }
        if !guard
            .ledger
            .current(&device.network_id)
            .is_some_and(|r| r.apply_status == meshlet_domain::ApplyStatus::Applied)
        {
            return Err(AgentApiError::DataplaneNotConfigured(
                "hub desired revision has not been applied".into(),
            ));
        }
        if !guard.deployments.contains_key(&network_id) {
            return Err(AgentApiError::DataplaneNotConfigured(
                "hub recovery has not yet confirmed this network".into(),
            ));
        }
        let hub_public_key = crate::device_plan::hub_public_key(&state.dataplane)
            .map_err(AgentApiError::Internal)?;
        let plan = crate::device_plan::build_device_plan(
            &guard,
            &network_id,
            &device_id,
            &state.dataplane,
            state.tunnel_mtu,
            &hub_public_key,
            state.ssh_config.as_ref(),
        )
        .map_err(AgentApiError::Internal)?;
        (plan, network_id)
    };
    crate::op_log!(
        info,
        "agent",
        "desired_plan",
        &network_id,
        &device_id.0,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok(Json(plan))
}

/// `GET /api/v1/networks/{network_id}/peers/endpoints`: the list of peer
/// candidate endpoints this device can connect to directly (§12 P2P).
///
/// - Credential: agent device Bearer (the same authentication boundary as
///   heartbeat/plan);
/// - Returns the [`meshlet_domain::peer_endpoints_for`] result: excludes self,
///   non-Active peers, peers that have not reported candidates, and peers
///   outside this device's routable segment; deterministic ordering by
///   device_id;
/// - The same segment rule as peer AllowedIPs: a segmented network takes its
///   own segment prefix, a single-segment network takes the whole overlay
///   (`device_plan::segment_for` is reused).
pub async fn peers_endpoints_handler(
    State(state): State<SharedAppState>,
    AuthorizedAgent(device_id): AuthorizedAgent,
    Path(network_id): Path<String>,
) -> Result<Json<Vec<PeerEndpoints>>, AgentApiError> {
    let _persist = state.persist.lock().await;
    let guard = state.mesh.lock().unwrap();
    let Some(device) = guard.registry.find_by_id(&device_id) else {
        // Pending-approval registration: no endpoints before approval (no tunnel, no dataplane).
        if guard.registry.find_registration(&device_id).is_some() {
            return Err(AgentApiError::NotFound(format!(
                "device {device_id} is pending approval: no endpoints until approved"
            )));
        }
        return Err(AgentApiError::NotFound(format!(
            "device {device_id} not found"
        )));
    };
    if device.network_id.to_string() != network_id {
        return Err(AgentApiError::NotFound(format!(
            "network {network_id} does not own device {device_id}"
        )));
    }
    if !device.is_active() {
        return Err(AgentApiError::NotFound(format!(
            "device {device_id} is not active"
        )));
    }
    let Some(source_segment) = crate::device_plan::segment_for(&guard, &network_id, device) else {
        return Err(AgentApiError::Internal(format!(
            "device {device_id} has no segment assignment"
        )));
    };
    let peers = meshlet_domain::peer_endpoints_for(
        source_segment.cidr,
        &device_id,
        guard.registry.devices(),
        &guard.direct_states,
    );
    Ok(Json(peers))
}

/// `GET /api/v1/agent/device/peers/endpoints`: the list of peer candidate
/// endpoints this device can connect to directly (§12 P2P, agent view).
///
/// The same aggregation as [`peers_endpoints_handler`], but without a network
/// ID path parameter — the agent credential itself is the identity, and the
/// network is resolved from the device record (the same rule as
/// `desired_device_plan_handler`). The agent can therefore fetch candidates
/// without knowing the network ID.
pub async fn agent_peers_endpoints_handler(
    State(state): State<SharedAppState>,
    AuthorizedAgent(device_id): AuthorizedAgent,
) -> Result<Json<Vec<PeerEndpoints>>, AgentApiError> {
    let guard = state.mesh.lock().unwrap();
    let Some(device) = guard.registry.find_by_id(&device_id) else {
        if guard.registry.find_registration(&device_id).is_some() {
            return Err(AgentApiError::NotFound(format!(
                "device {device_id} is pending approval: no endpoints until approved"
            )));
        }
        return Err(AgentApiError::NotFound(format!(
            "device {device_id} not found"
        )));
    };
    if !device.is_active() {
        return Err(AgentApiError::NotFound(format!(
            "device {device_id} is not active"
        )));
    }
    let network_id = device.network_id.to_string();
    let Some(source_segment) = crate::device_plan::segment_for(&guard, &network_id, device) else {
        return Err(AgentApiError::Internal(format!(
            "device {device_id} has no segment assignment"
        )));
    };
    let peers = meshlet_domain::peer_endpoints_for(
        source_segment.cidr,
        &device_id,
        guard.registry.devices(),
        &guard.direct_states,
    );
    Ok(Json(peers))
}
