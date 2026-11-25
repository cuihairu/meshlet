//! Server interaction (agent API, Bearer credential; §16.4 issues no commands).
//!
//! Three endpoints, each reading/writing only **typed objects**:
//! - `GET /api/v1/agent/device/desired` -> [`DevicePlan`] (tunnel/routing/NAT +
//!   the publish section [`meshlet_publish::PublishPlan`] + `desired_config_hash`;
//!   `private_key` is always `null`);
//! - `POST /api/v1/agent/heartbeat` -> reports local time + an optional handshake time + dataplane
//!   measured evidence (kernel readings + large-packet probe, §7.5/§12.4);
//! - `POST /api/v1/agent/publish-health` -> batch-reports probe results
//!   ([`meshlet_publish::ProbeReport`], persisted server-side into `publish_probe_reports`).
//!
//! Authentication boundary (§13.5): the agent API uses Bearer credentials, entirely separate from the
//! management API's Cookie + CSRF; a missing/invalid credential always yields 401 and **must not**
//! fall back to any other authentication scheme. When the server dataplane is not enabled it returns
//! 503 (`dataplane_not_configured`) - the agent treats that as "plan temporarily unavailable" and
//! retries, never treating an empty plan as "applied".

use meshlet_domain::{DataplaneEvidence, PeerEndpoints};
use meshlet_network::DevicePlan;

/// Fetch this device's desired dataplane plan.
pub fn fetch_plan(server_url: &str, token: &str) -> Result<DevicePlan, String> {
    let url = format!(
        "{}/api/v1/agent/device/desired",
        server_url.trim_end_matches('/')
    );
    let req = ureq::get(&url).set("authorization", &format!("Bearer {token}"));
    let body = read(req.call())?;
    // The server contract is a structured configuration object. A parse failure must be reported
    // explicitly - never swallowed, and never substituted with an "empty plan" (an empty plan would wipe the existing tunnel configuration).
    serde_json::from_str(&body).map_err(|e| format!("parse the desired plan: {e}"))
}

/// Fetch this device's directly-connectable peer candidate endpoints (§12 P2P).
///
/// The server has already aggregated from this device's perspective (excluding itself / non-Active /
/// unreported / out-of-routing-scope peers) and sorted deterministically. Failures (server unreachable /
/// 401 / pending approval 404) are reported as `Err` and left to the caller - direct connect is a
/// bonus, and a failure must not interrupt the hub relay path.
pub fn fetch_peer_endpoints(server_url: &str, token: &str) -> Result<Vec<PeerEndpoints>, String> {
    let url = format!(
        "{}/api/v1/agent/device/peers/endpoints",
        server_url.trim_end_matches('/')
    );
    let req = ureq::get(&url).set("authorization", &format!("Bearer {token}"));
    let body = read(req.call())?;
    serde_json::from_str(&body).map_err(|e| format!("parse the peer endpoints: {e}"))
}

/// Public control-plane response reader for endpoints that deliberately have
/// no device bearer credential (for example the release update manifest).
pub(crate) fn read_public(response: Result<ureq::Response, ureq::Error>) -> Result<String, String> {
    read_response(response)
}

/// Response reader (non-2xx -> categorized error): shared by the agent-side HTTP endpoints,
/// including the task channel (`crate::tasks`).
pub(crate) fn read_response(
    response: Result<ureq::Response, ureq::Error>,
) -> Result<String, String> {
    read(response)
}

/// Bootstrap registration response (`POST /api/v1/device-registrations`).
#[derive(Debug, serde::Deserialize)]
pub struct RegisterDeviceResponse {
    pub device_id: String,
    pub network_id: String,
    /// Always `pending` (it does not take part in the dataplane before control-center approval).
    pub status: String,
    /// Agent API credential, issued **this one time only**.
    pub agent_token: String,
    pub requested_at: String,
}

/// Bootstrap registration: report this machine's public key with a bootstrap token, filing a Pending request to await control-center approval.
///
/// 401 (bootstrap token invalid/revoked/exhausted), 409 (device-name conflict), and the like are all
/// reported as the server's own categorized error verbatim - this is information operators can read directly, so no local rewording is done.
pub fn register_device(
    server_url: &str,
    bootstrap_token: &str,
    device_name: &str,
    public_key: &str,
    platform: &str,
) -> Result<RegisterDeviceResponse, String> {
    let url = format!(
        "{}/api/v1/device-registrations",
        server_url.trim_end_matches('/')
    );
    let payload = serde_json::json!({
        "bootstrap_token": bootstrap_token,
        "device_name": device_name,
        "public_key": public_key,
        "platform": platform,
    })
    .to_string();
    let req = ureq::post(&url)
        .set("content-type", "application/json")
        .send(payload.as_bytes());
    let body = read(req)?;
    serde_json::from_str(&body).map_err(|e| format!("parse the registration response: {e}"))
}

/// Acknowledge only the exact plan successfully read back from the kernel.
pub fn report_apply(
    server_url: &str,
    token: &str,
    plan: &DevicePlan,
    error: Option<&str>,
) -> Result<(), String> {
    let payload = serde_json::json!({"desired_revision": plan.desired_revision, "plan_hash": plan.desired_config_hash, "error": error}).to_string();
    read(
        ureq::post(&format!(
            "{}/api/v1/agent/device/applied",
            server_url.trim_end_matches('/')
        ))
        .set("authorization", &format!("Bearer {token}"))
        .set("content-type", "application/json")
        .send(payload.as_bytes()),
    )
    .map(|_| ())
}

/// Heartbeat report: returns the server's online verdict receipt (for logging / troubleshooting only).
///
/// Failures are always reported as `Err` (including categories such as 401/503), and the caller decides whether to retry.
#[allow(clippy::too_many_arguments)] // the heartbeat has many fields, matching the direct.rs/peers_endpoints.rs convention
pub fn heartbeat(
    server_url: &str,
    token: &str,
    last_handshake_at: Option<String>,
    dataplane: Option<DataplaneEvidence>,
    direct: Option<meshlet_domain::DirectEndpointReport>,
    direct_links: Vec<meshlet_domain::DirectLinkStatus>,
    diagnostics: Option<meshlet_network::NetworkDiagnostics>,
    hostname: Option<String>,
) -> Result<String, String> {
    let url = format!(
        "{}/api/v1/agent/heartbeat",
        server_url.trim_end_matches('/')
    );
    let payload = serde_json::json!({
        "last_handshake_at": last_handshake_at,
        "dataplane": dataplane,
        "direct": direct,
        "direct_links": direct_links,
        "diagnostics": diagnostics,
        "hostname": hostname,
    })
    .to_string();
    let req = ureq::post(&url)
        .set("authorization", &format!("Bearer {token}"))
        .set("content-type", "application/json")
        .send(payload.as_bytes());
    read(req)
}

/// Batch reporting of probe results (R-06): `{"reports": [...]}`, with the server guarding the insert on (probe_id,
/// device_id). Failures are reported as `Err`, and the caller retains the undelivered reports for a retry next round.
pub fn report_publish_health(
    server_url: &str,
    token: &str,
    reports: &[meshlet_publish::ProbeReport],
) -> Result<(), String> {
    let url = format!(
        "{}/api/v1/agent/publish-health",
        server_url.trim_end_matches('/')
    );
    let payload = serde_json::json!({ "reports": reports }).to_string();
    read(
        ureq::post(&url)
            .set("authorization", &format!("Bearer {token}"))
            .set("content-type", "application/json")
            .send(payload.as_bytes()),
    )
    .map(|_| ())
}

/// Read the response body (non-2xx -> categorized error).
fn read(res: Result<ureq::Response, ureq::Error>) -> Result<String, String> {
    let resp = res.map_err(describe)?;
    resp.into_string()
        .map_err(|e| format!("read response body: {e}"))
}

/// Error categorization: non-2xx HTTP always reports with the status code and a body fragment (§12.2 failure visibility -
/// the agent-side log shows at a glance whether it is a 401 credential problem or a 503 server dataplane not enabled).
fn describe(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, resp) => {
            let detail = resp.into_string().unwrap_or_default();
            format!("server returned {code}: {}", truncate(&detail, 200))
        }
        ureq::Error::Transport(t) => format!("transport failure: {t}"),
    }
}

#[cfg(test)]
fn status_error(code: u16, body: &str) -> ureq::Error {
    ureq::Error::Status(
        code,
        ureq::Response::new(code, "error", body).expect("static response"),
    )
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect::<String>() + "…"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_plan_rejects_malformed_json() {
        // A contract parse failure must stay visible: an empty plan must never be returned disguised as "applied".
        let body = "{\"tunnel\": {}}";
        assert!(serde_json::from_str::<DevicePlan>(body).is_err());
    }

    #[test]
    fn fetch_plan_requires_private_key_to_be_absent() {
        // The server must deliver private_key as null (ADR-010); an accidental value would mean the
        // contract was broken, which the agent should notice (this unit test pins the boundary "null parses, a value also parses
        // but is never entered into the ledger", and the netns integration test ultimately asserts the executor writes no private key to disk).
        let plan: DevicePlan = serde_json::from_str(
            r#"{"tunnel":{"name":"wg0","address":"10.240.0.7","address_prefix":16,
            "listen_port":null,"peers":[],"mtu":null,"private_key":null},
            "routes":[],"nat_rules":[],"desired_config_hash":"abc"}"#,
        )
        .expect("plan parses");
        assert_eq!(plan.tunnel.private_key, None);
        assert_eq!(plan.tunnel.address.to_string(), "10.240.0.7");
        assert_eq!(plan.desired_config_hash, "abc");
    }

    #[test]
    fn truncate_keeps_short_bodies_intact() {
        assert_eq!(truncate("short", 10), "short");
        let long = "x".repeat(30);
        assert_eq!(truncate(&long, 10).chars().count(), 11); // 10 + ellipsis
    }

    #[test]
    fn non_2xx_responses_keep_status_and_a_bounded_body() {
        let body = "x".repeat(500);
        let error = describe(status_error(401, &body));
        assert!(error.starts_with("server returned 401: "));
        assert!(error.ends_with('…'));
        assert_eq!(
            error.chars().count(),
            "server returned 401: ".chars().count() + 201
        );

        let error = describe(ureq::Error::Status(
            503,
            ureq::Response::new(503, "error", "unavailable").expect("static response"),
        ));
        assert_eq!(error, "server returned 503: unavailable");
    }
}
