//! HTTP request/response projections for the management APIs.

use meshlet_domain::{DataplaneEvidence, DirectLinkStatus};
use meshlet_network::NetworkDiagnostics;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct NetworkView {
    pub id: String,
    pub name: String,
    pub overlay_cidr: String,
    pub status: String,
    pub created_at: String,
    /// Current desired revision id (ADR-009: config-mutating responses must carry
    /// the version and its apply status).
    pub revision_id: u64,
    /// Apply status of the current revision: `pending`/`applying`/`applied`/`failed`/
    /// `rollback_pending`/`rolled_back` (ADR-009 state machine).
    pub apply_status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceView {
    pub id: String,
    pub network_id: String,
    pub name: String,
    pub virtual_ipv4: Ipv4Addr,
    pub public_key: String,
    pub fingerprint: String,
    pub status: String,
    pub created_at: String,
    /// Approval time: bootstrap-registration path = the moment of approval
    /// (created_at is the request time); the invitation path is `None` (the two
    /// moments hold the same value, no need to show it twice). The console uses
    /// this to tell "just approved" apart from "running for a while".
    pub approved_at: Option<String>,
    /// Time of the last evidence (join / heartbeat / report arrival) — the
    /// console's "last seen" value.
    pub last_seen_at: Option<String>,
    /// Online-state verdict: `online` / `tunnel_only` / `offline` (data sources
    /// below).
    pub online_state: String,
    /// Data source of the state: `agent_report` / `handshake` / `enrollment` /
    /// `none` (§12.2).
    pub presence_source: String,
    /// Dataplane measurement evidence from the latest heartbeat (§7.5); `None` =
    /// nothing reported yet.
    pub dataplane_evidence: Option<DataplaneEvidence>,
    /// §12.3 P2P link status report: this device's direct links to each peer
    /// (direct / direct_pending). Empty = all-relay or nothing reported; the
    /// console renders P2P vs relay from this.
    pub direct_links: Vec<DirectLinkStatus>,
    /// P2P-⑤: source endpoint observed by the hub, format
    /// `observed_ip:listen_port` (heartbeat source address joined with the wg
    /// listen port reported by the agent). `None` = no heartbeat observed or the
    /// agent reported no port. No private-range filtering — this is the raw
    /// observation.
    pub observed_endpoint: Option<String>,
    /// Public candidate endpoint (only present when the observed address is not
    /// private; same source as the agent's dial candidates, reused by the
    /// topology graph / node drilldown). `None` = no observation / not reported,
    /// or hub and agent share a LAN (the observed address is not public;
    /// labeling it public would mislead hole punching).
    pub public_endpoint: Option<String>,
    /// R-DIAG network diagnostics three snapshots (route table / interfaces / wg
    /// readings); `None` = nothing reported yet or collection failed. The console
    /// diagnostics page renders from this.
    pub diagnostics: Option<NetworkDiagnostics>,
    /// MT-005 node labels (assigned by the operator; the matching key for
    /// label-based task routing). Empty = unlabeled.
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateNetworkRequest {
    pub name: String,
    pub overlay_cidr: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateInviteRequest {
    /// ISO-8601 expiry time; omitted means never expires.
    pub expires_at: Option<String>,
    /// Use-count cap; default 1 (one-time invitation, ADR-010).
    pub max_uses: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateInviteResponse {
    pub invite_id: String,
    /// The raw Token is returned **only this once**; the server stores only the
    /// SHA-256 digest (§11.3).
    pub token: String,
    pub expires_at: Option<String>,
}

// ---------------------------------------------------------------------------
// Device bootstrap registration (ZeroTier style: bootstrap-token registration →
// Pending → control-center approval/rejection)
// ---------------------------------------------------------------------------

/// Bootstrap token: a long-lived, reusable registration-entry credential,
/// distinct from a one-time invitation.
#[derive(Debug, Deserialize)]
pub struct CreateBootstrapTokenRequest {
    /// Use-count cap; default unlimited (a bootstrap token is a long-lived entry,
    /// not a single-use invitation).
    pub max_uses: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateBootstrapTokenResponse {
    pub token_id: String,
    /// The raw bootstrap token is returned **only this once**; the server stores
    /// only the SHA-256 digest (§11.3).
    pub token: String,
    pub max_uses: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BootstrapTokenView {
    pub id: String,
    pub network_id: String,
    pub max_uses: Option<u32>,
    pub used_count: u32,
    pub created_at: String,
    pub revoked_at: Option<String>,
}

/// Device bootstrap registration request (`POST /device-registrations`, public
/// endpoint).
/// `deny_unknown_fields` like [EnrollRequest]: a client that tries to send a
/// private key gets a 400 rejection (private keys never leave the client, §11.2).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterDeviceRequest {
    pub bootstrap_token: String,
    pub device_name: String,
    pub public_key: String,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegisterDeviceResponse {
    pub device_id: String,
    pub network_id: String,
    /// Always `pending` (does not join the dataplane before control-center
    /// approval).
    pub status: String,
    /// Agent API credential (Bearer): returned **only this once**. While pending
    /// it may send heartbeats (proof the agent is alive), but it cannot pull a
    /// plan — it does not enter the dataplane before approval.
    pub agent_token: String,
    pub requested_at: String,
}

/// Registration-request view pending approval (shared by the console device
/// page and the device list; `status = "pending"`).
#[derive(Debug, Clone, Serialize)]
pub struct RegistrationView {
    pub id: String,
    pub network_id: String,
    pub name: String,
    pub platform: String,
    pub public_key: String,
    pub requested_at: String,
    pub last_report_at: Option<String>,
    /// Dataplane evidence returned by the agent heartbeat (a pending device has no
    /// `devices` row yet, so evidence lives only here).
    pub dataplane_evidence: Option<DataplaneEvidence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApproveRegistrationResponse {
    pub device_id: String,
    pub network_id: String,
    /// Overlay address assigned only at approval time (ADR-004 sequential
    /// allocation).
    pub virtual_ipv4: Ipv4Addr,
    /// Device public-key fingerprint (SHA-256; the server stores no private-key
    /// material).
    pub fingerprint: String,
    /// **No agent credential included**: the credential issued at registration is
    /// bound to the device id (approval keeps the same id), and the device keeps
    /// pulling plans with its original credential; rotation would only orphan a
    /// credential nobody can deliver.
    pub revision_id: u64,
    pub apply_status: String,
    pub approved_at: String,
}

/// Enrollment request: **must not carry any private-key field**
/// (`deny_unknown_fields` enforces it; a client that tries to send a private key
/// gets a 400 rejection — private keys never leave the client, §11.2).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollRequest {
    pub invite_token: String,
    pub device_name: String,
    pub public_key: String,
    pub platform: String,
}

/// MT-005 device label update (operator PATCH/POST semantics: replace in full).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetDeviceLabelsRequest {
    /// New label set (an empty object = clear all labels).
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnrollResponse {
    pub device_id: String,
    pub network_id: String,
    pub virtual_ipv4: Ipv4Addr,
    pub fingerprint: String,
    /// Agent API credential (Bearer): returned **only this once**; the server
    /// stores only the SHA-256 digest.
    pub agent_token: String,
    /// Desired-config revision id produced by this change (ADR-009).
    pub revision_id: u64,
    /// Apply status of that revision (a new revision is always `pending` — a DB
    /// write is not the same as being in effect).
    pub apply_status: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateRouteRequest {
    /// Gateway device (must be an Active device of this network, ADR-005).
    pub gateway_device_id: String,
    pub destination_cidr: String,
    /// `direct` (default) or `alias`.
    pub route_mode: Option<String>,
    /// `dual_route` or `controlled_snat` (required, ADR-005).
    pub return_path_mode: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteView {
    pub id: String,
    pub network_id: String,
    pub gateway_device_id: String,
    pub destination_cidr: String,
    pub route_mode: String,
    pub return_path_mode: String,
    /// `pending` / `applied` / `failed` (the route's own desired state).
    pub status: String,
    /// Desired-config revision id produced by this change (ADR-009).
    pub revision_id: u64,
    pub apply_status: String,
}

/// Revision reference (returned by operations such as device revocation;
/// contract `RevisionRef`).
#[derive(Debug, Clone, Serialize)]
pub struct RevisionRef {
    pub revision_id: u64,
    pub apply_status: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateAliasRequest {
    /// The bound LAN Route (must exist and have `route_mode = "alias"`, ADR-006
    /// unit semantics).
    pub lan_route_id: String,
    pub alias_cidr: String,
    /// `dnat_snat` (default) or `dnat_only`.
    pub translation_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateHostForwardRequest {
    /// Active gateway device of this network: traffic enters the LAN of the
    /// target host through it.
    pub gateway_device_id: String,
    /// Real host address inside the LAN (not a CIDR; Host Forward converts it
    /// to a /32 on the server side).
    pub target_ipv4: Ipv4Addr,
    /// Virtual host address (must be a /32 of the same length as the target,
    /// and must not fall inside the overlay).
    pub alias_ipv4: Ipv4Addr,
    /// `dnat_snat` (default, for LANs without a return route) or `dnat_only`.
    pub translation_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostForwardView {
    pub id: String,
    pub network_id: String,
    pub gateway_device_id: String,
    pub target_ipv4: String,
    pub alias_ipv4: String,
    pub translation_mode: String,
    pub status: String,
    pub revision_id: u64,
    pub apply_status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AliasView {
    pub id: String,
    pub network_id: String,
    pub lan_route_id: String,
    pub alias_cidr: String,
    /// Real target CIDR = the destination CIDR of the bound route (derived on the
    /// server; the client cannot specify it).
    pub target_cidr: String,
    pub translation_mode: String,
    /// `pending` / `applied` / `failed` (the mapping's own desired state).
    pub status: String,
    /// Desired-config revision id produced by this change (ADR-009).
    pub revision_id: u64,
    pub apply_status: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateSegmentRequest {
    pub name: String,
    pub cidr: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SegmentView {
    pub id: String,
    pub network_id: String,
    pub name: String,
    pub cidr: String,
    pub status: String,
    pub created_at: String,
    pub revision_id: u64,
}

#[derive(Debug, Deserialize)]
pub struct CreateSegmentGrantRequest {
    pub source_segment_id: String,
    pub destination_segment_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SegmentGrantView {
    pub id: String,
    pub network_id: String,
    pub source_segment_id: String,
    pub destination_segment_id: String,
    pub status: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
    pub revision_id: u64,
    pub apply_status: String,
}
