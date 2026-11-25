//! Network, enrollment, device, routing, alias, segment and forwarding operations.

use meshlet_domain::{
    generate_token, token_hash, AliasError, AliasMapping, AliasMappingId, BootstrapToken,
    DataplaneEvidence, DesiredStateStatus, Device, DeviceDirectState, DeviceId, DeviceRegistration,
    DirectEndpointReport, DirectLinkStatus, Invite, Ipam, Ipv4Cidr, LanRoute, LanRouteId, Network,
    Platform, ReturnPathMode, RouteMode, Segment, SegmentGrant, SegmentGrantBuilder,
    SegmentGrantId, SegmentGrantStatus, SegmentId, SegmentStatus, Timestamp, TranslationMode,
};
use meshlet_network::NetworkDiagnostics;
use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;

use crate::service::{
    error::ServiceError, operations_record::record_revision, shared::now, state::MeshState,
    views::*,
};
/// Creation-time validation, including this network. Plan readback uses
/// check_forward_prefix instead so a resource does not conflict with itself.
pub fn check_forward_prefix(
    state: &MeshState,
    network_id: &str,
    prefix: Ipv4Cidr,
) -> Result<(), ServiceError> {
    if let Some(n) = state
        .networks
        .values()
        .find(|n| n.id.to_string() != network_id && n.overlay_cidr.overlaps(&prefix))
    {
        return Err(ServiceError::RouteConflict(format!(
            "prefix {prefix} overlaps network {}",
            n.id
        )));
    }
    if state.lan_routes.iter().any(|(id, routes)| {
        id != network_id
            && routes
                .iter()
                .any(|r| r.route_mode == RouteMode::Direct && r.destination_cidr.overlaps(&prefix))
    }) || state.aliases.iter().any(|(id, aliases)| {
        id != network_id && aliases.iter().any(|a| a.alias_cidr.overlaps(&prefix))
    }) {
        return Err(ServiceError::RouteConflict(format!(
            "prefix {prefix} overlaps another network's forwarding prefix"
        )));
    }
    Ok(())
}

/// Creation-time validation, including this network. Plan readback uses
/// check_forward_prefix instead so a resource does not conflict with itself.
fn check_new_forward_prefix(
    state: &MeshState,
    network_id: &str,
    prefix: Ipv4Cidr,
) -> Result<(), ServiceError> {
    check_forward_prefix(state, network_id, prefix)?;
    if prefix.overlaps(&state.network(network_id)?.overlay_cidr) {
        return Err(ServiceError::RouteConflict(format!(
            "prefix {prefix} overlaps overlay"
        )));
    }
    if let Some(route) = state
        .lan_routes
        .get(network_id)
        .into_iter()
        .flatten()
        .find(|r| r.destination_cidr.overlaps(&prefix))
    {
        return Err(ServiceError::RouteConflict(format!(
            "prefix {prefix} overlaps existing route {} ({})",
            route.id, route.destination_cidr
        )));
    }
    check_local_alias_prefix(state, network_id, prefix)
}

fn check_local_alias_prefix(
    state: &MeshState,
    network_id: &str,
    prefix: Ipv4Cidr,
) -> Result<(), ServiceError> {
    if let Some(alias) = state
        .aliases
        .get(network_id)
        .into_iter()
        .flatten()
        .find(|a| a.alias_cidr.overlaps(&prefix))
    {
        return Err(ServiceError::RouteConflict(format!(
            "prefix {prefix} overlaps existing alias {} ({})",
            alias.id, alias.alias_cidr
        )));
    }
    Ok(())
}

pub fn create_network(
    state: &mut MeshState,
    req: CreateNetworkRequest,
) -> Result<NetworkView, ServiceError> {
    let overlay: Ipv4Cidr = req
        .overlay_cidr
        .parse()
        .map_err(|e| ServiceError::InvalidCidr(format!("{}: {e}", req.overlay_cidr)))?;
    if req.name.trim().is_empty() {
        return Err(ServiceError::InvalidInput("name must not be empty".into()));
    }
    if state
        .networks
        .values()
        .any(|n| n.overlay_cidr.overlaps(&overlay))
    {
        return Err(ServiceError::Conflict(format!(
            "overlay {overlay} already used by another network"
        )));
    }
    check_forward_prefix(state, "", overlay)?;
    let id = format!("net-{}", state.networks.len() + 1);
    let ts = now();
    let default_segment_ts = ts.clone();
    let network = Network::new(
        meshlet_domain::NetworkId(id.clone()),
        req.name.clone(),
        overlay,
        ts.clone(),
    );
    // IPAM: the hub takes the first usable address (ADR-004); clients are allocated from the second onward.
    let hub = overlay
        .iter_usable()
        .next()
        .expect("overlay has at least one usable address");
    let ipam = Ipam::new(overlay, hub).map_err(|e| ServiceError::Internal(e.to_string()))?;
    state.networks.insert(id.clone(), network);
    state.ipams.insert(id.clone(), ipam);
    state.restore_segment(Segment {
        id: meshlet_domain::default_segment_id(&meshlet_domain::NetworkId(id.clone())),
        network_id: meshlet_domain::NetworkId(id.clone()),
        name: "default".into(),
        cidr: overlay,
        status: meshlet_domain::SegmentStatus::Active,
        created_at: default_segment_ts,
    })?;
    // Record the initial desired-config revision (§10.1: a DB write ≠ in effect; the initial revision is Pending).
    record_revision(state, &id)?;
    Ok(to_network_view(state, state.network(&id).unwrap()))
}

pub fn list_networks(state: &MeshState) -> Vec<NetworkView> {
    state
        .networks
        .values()
        .map(|n| to_network_view(state, n))
        .collect()
}

pub fn create_invite(
    state: &mut MeshState,
    network_id: &str,
    req: CreateInviteRequest,
) -> Result<CreateInviteResponse, ServiceError> {
    state.network(network_id)?; // the network must exist
    let max_uses = req.max_uses.unwrap_or(1);
    if max_uses == 0 {
        return Err(ServiceError::InvalidInput(
            "max_uses must be at least 1".into(),
        ));
    }
    let ts = now();
    let raw = generate_token();
    let invite = Invite::new(
        meshlet_domain::InviteId(format!("inv-{}", state.invites.len() + 1)),
        meshlet_domain::NetworkId(network_id.to_string()),
        &raw,
        req.expires_at.clone(),
        max_uses,
        ts.clone(),
    );
    let view = CreateInviteResponse {
        invite_id: invite.id.to_string(),
        token: raw,
        expires_at: req.expires_at,
    };
    // Store only the summary (§11.3): the index key is token_hash; the raw Token is never persisted.
    state.invites.insert(invite.token_hash.clone(), invite);
    Ok(view)
}

pub fn revoke_invite(
    state: &mut MeshState,
    network_id: &str,
    invite_id: &str,
) -> Result<(), ServiceError> {
    state.network(network_id)?;
    let target = state
        .invites
        .values_mut()
        .find(|i| i.id.to_string() == invite_id)
        .ok_or_else(|| ServiceError::InviteNotFound(invite_id.to_string()))?;
    target
        .revoke(now())
        .map_err(|e| ServiceError::Conflict(e.to_string()))
}

// ---------------------------------------------------------------------------
// Device bootstrap registration (ZeroTier-style: bootstrap-code registration -> Pending -> control-center approval/rejection)
// ---------------------------------------------------------------------------

/// Create a bootstrap code (control-center side): a long-lived, reusable
/// registration entry credential. The raw code is returned **exactly once**; the server stores only its SHA-256 summary (§11.3, as with invites).
pub fn create_bootstrap_token(
    state: &mut MeshState,
    network_id: &str,
    req: CreateBootstrapTokenRequest,
) -> Result<CreateBootstrapTokenResponse, ServiceError> {
    state.network(network_id)?; // the network must exist
    if req.max_uses == Some(0) {
        return Err(ServiceError::InvalidInput(
            "max_uses must be at least 1, or unset for unlimited".into(),
        ));
    }
    // Bootstrap-code sequence (`bootstrap_seq`, persisted in mesh_meta): no renumbering and no reuse across restarts.
    let seq = state.bootstrap_seq() + 1;
    let raw = generate_token();
    let token = BootstrapToken {
        id: meshlet_domain::BootstrapTokenId(format!("bt-{seq}")),
        network_id: meshlet_domain::NetworkId(network_id.to_string()),
        token_hash: token_hash(&raw),
        max_uses: req.max_uses,
        used_count: 0,
        created_at: now(),
        revoked_at: None,
    };
    let view = CreateBootstrapTokenResponse {
        token_id: token.id.to_string(),
        token: raw,
        max_uses: req.max_uses,
    };
    // Store only the summary (§11.3): the index key is token_hash; the raw bootstrap code is never persisted.
    state
        .bootstrap_tokens
        .insert(token.token_hash.clone(), token);
    state.set_bootstrap_seq(seq);
    Ok(view)
}

/// Revoke a bootstrap code: any registration attempt using it afterwards is rejected (already
/// persisted Pending applications are unaffected — the approval flow is independent of the entry credential). Returns the revocation time so the handler can persist it.
pub fn revoke_bootstrap_token(
    state: &mut MeshState,
    network_id: &str,
    token_id: &str,
) -> Result<Timestamp, ServiceError> {
    state.network(network_id)?;
    let target = state
        .bootstrap_tokens
        .values_mut()
        .find(|t| t.id.to_string() == token_id)
        .ok_or_else(|| ServiceError::BootstrapTokenNotFound(token_id.to_string()))?;
    if target.revoked_at.is_some() {
        return Err(ServiceError::Conflict(
            "bootstrap token already revoked".into(),
        ));
    }
    let revoked_at = now();
    target.revoked_at = Some(revoked_at.clone());
    Ok(revoked_at)
}

/// Bootstrap-code list (console-facing usage display; metadata only — no credential material beyond the summary).
pub fn list_bootstrap_tokens(
    state: &MeshState,
    network_id: &str,
) -> Result<Vec<BootstrapTokenView>, ServiceError> {
    state.network(network_id)?;
    let mut views: Vec<BootstrapTokenView> = state
        .bootstrap_tokens
        .values()
        .filter(|t| t.network_id.to_string() == network_id)
        .map(|t| BootstrapTokenView {
            id: t.id.to_string(),
            network_id: t.network_id.to_string(),
            max_uses: t.max_uses,
            used_count: t.used_count,
            created_at: t.created_at.clone(),
            revoked_at: t.revoked_at.clone(),
        })
        .collect();
    // Stable output: sort by creation time (`bt-N` text order is not equivalent to creation order once digit counts differ).
    views.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    Ok(views)
}

/// Device bootstrap registration (public endpoint): exchange a bootstrap code for an agent credential, creating a **Pending** application.
/// No virtual IP is assigned before approval and it is not part of the desired config (`device_plan` only reads `devices`),
/// so the dataplane cannot see Pending devices at all (the three reasons given in the migration 008 header comment).
pub fn register_device(
    state: &mut MeshState,
    req: RegisterDeviceRequest,
) -> Result<RegisterDeviceResponse, ServiceError> {
    let platform = match req.platform.as_str() {
        "linux" => Platform::Linux,
        "windows" => Platform::Windows,
        other => {
            return Err(ServiceError::InvalidInput(format!(
                "unsupported platform {other:?}"
            )));
        }
    };
    if req.device_name.trim().is_empty() {
        return Err(ServiceError::InvalidInput(
            "device_name must not be empty".into(),
        ));
    }
    if req.public_key.trim().is_empty() {
        return Err(ServiceError::InvalidInput(
            "public_key must not be empty".into(),
        ));
    }

    // Locate the bootstrap code by summary and validate it (done atomically while holding the lock, closing the concurrency race).
    let token = state
        .bootstrap_tokens
        .get_mut(&token_hash(&req.bootstrap_token))
        .ok_or(ServiceError::InvalidBootstrapToken)?;
    if token.revoked_at.is_some() {
        return Err(ServiceError::InvalidBootstrapToken);
    }
    if let Some(max) = token.max_uses {
        if token.used_count >= max {
            return Err(ServiceError::InvalidBootstrapToken);
        }
    }
    token.used_count += 1;
    let network_id = token.network_id.to_string();

    let ts = now();
    let seq = state.registration_seq() + 1;
    let registration = DeviceRegistration {
        id: meshlet_domain::DeviceId(format!("dev-reg-{seq}")),
        network_id: meshlet_domain::NetworkId(network_id.clone()),
        name: req.device_name.clone(),
        public_key: req.public_key.clone(),
        platform,
        requested_at: ts.clone(),
        // Registration counts as the first report (at request arrival time).
        last_report_at: Some(ts.clone()),
        dataplane_evidence: None,
    };
    // Name uniqueness spans both devices and registrations (domain-layer `add_registration`).
    state.registry.add_registration(registration.clone())?;
    state.set_registration_seq(seq);

    Ok(RegisterDeviceResponse {
        device_id: registration.id.to_string(),
        network_id,
        status: "pending".to_string(),
        agent_token: String::new(), // filled in by the handler after issuing from AgentTokenStore
        requested_at: ts,
    })
}

/// Approve a registration application: move it into `devices` while **keeping the device id assigned at registration** (references such as `agent_tokens`
/// need no migration), assign the overlay address only now (sequential IPAM allocation), and record a new
/// revision — the desired config thereby brings the new device into the dataplane (§10.1/ADR-009).
///
/// **Credentials are not rotated**: the agent credential issued during registration is reused as-is (the device id is unchanged, approval
/// is transparent to the device, and the approver never has to hand over any secret); only the rejection path invalidates the credential.
pub fn approve_registration(
    state: &mut MeshState,
    network_id: &str,
    device_id: &str,
) -> Result<(DeviceRegistration, Device, u64), ServiceError> {
    state.network(network_id)?;
    let registration = state
        .registry
        .find_registration(&meshlet_domain::DeviceId(device_id.to_string()))
        .filter(|r| r.network_id.to_string() == network_id)
        .cloned()
        .ok_or_else(|| ServiceError::DeviceNotFound(device_id.to_string()))?;

    // Remove the application first (the name uniqueness check spans both sides, so moving it into devices under the same name no longer collides with itself).
    let registration = state
        .registry
        .remove_registration(&registration.id)
        .expect("just found");

    let ipam = state
        .ipams
        .get_mut(network_id)
        .ok_or_else(|| ServiceError::NetworkNotFound(network_id.to_string()))?;
    let virtual_ip = match ipam.allocate() {
        Ok(ip) => ip,
        // If IPAM fails, put the application back: a failed approval must not swallow a Pending application.
        Err(e) => {
            state.registry.add_registration(registration.clone())?;
            return Err(ServiceError::Conflict(e.to_string()));
        }
    };

    let ts = now();
    let device = Device {
        id: registration.id.clone(),
        network_id: meshlet_domain::NetworkId(network_id.to_string()),
        name: registration.name.clone(),
        virtual_ipv4: virtual_ip,
        public_key: registration.public_key.clone(),
        platform: registration.platform,
        status: meshlet_domain::DeviceStatus::Active,
        // Heartbeat evidence from the Pending period carries over directly: the agent keeps reporting seamlessly after approval.
        last_seen_at: registration.last_report_at.clone(),
        last_handshake_at: None,
        last_report_at: registration.last_report_at.clone(),
        dataplane_evidence: registration.dataplane_evidence.clone(),
        // created_at = the application time (Pending start), approved_at = the approval time.
        created_at: registration.requested_at.clone(),
        approved_at: Some(ts.clone()),
        revoked_at: None,
        segment_id: meshlet_domain::default_segment_id(&meshlet_domain::NetworkId(
            network_id.into(),
        )),
        labels: BTreeMap::new(),
    };
    if let Err(e) = state.registry.add(device.clone()) {
        // If registration fails (e.g. IPAM allocated a duplicate address), release the address and put the application back.
        if let Some(ipam) = state.ipams.get_mut(network_id) {
            ipam.release(virtual_ip);
        }
        state.registry.add_registration(registration.clone())?;
        return Err(e.into());
    }
    // A new device changes the desired config: record a new revision (version numbers increase within the network, §10.4).
    let revision_id = record_revision(state, network_id)?;
    Ok((registration, device, revision_id))
}

/// Reject a registration application: remove the application and return it (the handler uses this to clean up the `device_registrations`
/// row and the Pending credential). **No revision is recorded** (the desired config never contained Pending applications;
/// rejection is pure state cleanup — the converse of §10.1's "DB write ≠ in effect": nothing takes effect, so no revision).
pub fn deny_registration(
    state: &mut MeshState,
    network_id: &str,
    device_id: &str,
) -> Result<DeviceRegistration, ServiceError> {
    state.network(network_id)?;
    let registration = state
        .registry
        .find_registration(&meshlet_domain::DeviceId(device_id.to_string()))
        .filter(|r| r.network_id.to_string() == network_id)
        .cloned()
        .ok_or_else(|| ServiceError::DeviceNotFound(device_id.to_string()))?;
    Ok(state
        .registry
        .remove_registration(&registration.id)
        .expect("just found"))
}

/// Pending application views (the "awaiting approval" section of the console device page; `RegistrationView`
/// carries no virtual IP — none is assigned before approval, so no placeholder fakes are shown).
pub fn list_registrations(
    state: &MeshState,
    network_id: &str,
) -> Result<Vec<RegistrationView>, ServiceError> {
    state.network(network_id)?;
    Ok(state
        .registry
        .registrations()
        .iter()
        .filter(|r| r.network_id.to_string() == network_id)
        .map(|r| RegistrationView {
            id: r.id.to_string(),
            network_id: r.network_id.to_string(),
            name: r.name.clone(),
            platform: match r.platform {
                Platform::Linux => "linux",
                Platform::Windows => "windows",
            }
            .to_string(),
            public_key: r.public_key.clone(),
            requested_at: r.requested_at.clone(),
            last_report_at: r.last_report_at.clone(),
            dataplane_evidence: r.dataplane_evidence.clone(),
        })
        .collect())
}

/// Enroll a device (the control-plane part of steps 3-9 in §11.2).
/// The private key never leaves the client: this function only receives the public key; the server registers the public key plus fingerprint and assigns a virtual IP.
pub fn enroll(state: &mut MeshState, req: EnrollRequest) -> Result<EnrollResponse, ServiceError> {
    let platform = match req.platform.as_str() {
        "linux" => Platform::Linux,
        "windows" => Platform::Windows,
        other => {
            return Err(ServiceError::InvalidInput(format!(
                "unsupported platform {other:?}"
            )));
        }
    };
    if req.device_name.trim().is_empty() {
        return Err(ServiceError::InvalidInput(
            "device_name must not be empty".into(),
        ));
    }
    if req.public_key.trim().is_empty() {
        return Err(ServiceError::InvalidInput(
            "public_key must not be empty".into(),
        ));
    }

    // Locate the invite by summary and redeem it (done atomically while holding the lock, closing the concurrency race).
    let invite = state
        .invites
        .get_mut(&meshlet_domain::token_hash(&req.invite_token))
        .ok_or(ServiceError::InvalidInviteToken)?;
    let network_id = invite.network_id.to_string();
    invite
        .redeem(&req.invite_token, now())
        .map_err(|e| match e {
            meshlet_domain::InviteError::InvalidToken => ServiceError::InvalidInviteToken,
            other => ServiceError::InvalidInput(other.to_string()),
        })?;

    let ipam = state
        .ipams
        .get_mut(&network_id)
        .ok_or_else(|| ServiceError::NetworkNotFound(network_id.clone()))?;
    let virtual_ip = ipam
        .allocate()
        .map_err(|e| ServiceError::Conflict(e.to_string()))?;

    let ts = now();
    let device = Device {
        id: meshlet_domain::DeviceId(format!("dev-{}", state.registry.devices().len() + 1)),
        network_id: meshlet_domain::NetworkId(network_id.clone()),
        name: req.device_name.clone(),
        virtual_ipv4: virtual_ip,
        public_key: req.public_key.clone(),
        platform,
        status: meshlet_domain::DeviceStatus::Active,
        last_seen_at: Some(ts.clone()),
        last_handshake_at: None,
        last_report_at: None,
        dataplane_evidence: None,
        created_at: ts.clone(),
        approved_at: None,
        revoked_at: None,
        segment_id: meshlet_domain::default_segment_id(&meshlet_domain::NetworkId(
            network_id.clone(),
        )),
        labels: BTreeMap::new(),
    };
    state.registry.add(device.clone())?;
    // A new device changes the desired config: record a new revision (version numbers increase per network, §10.4).
    let revision_id = record_revision(state, &network_id)?;

    // Fingerprint = SHA-256 of the public key; the server stores no private-side material.
    let fingerprint = fingerprint_of(&req.public_key);
    Ok(EnrollResponse {
        device_id: device.id.to_string(),
        network_id,
        virtual_ipv4: virtual_ip,
        fingerprint,
        agent_token: String::new(), // filled in by the handler after issuing from AgentTokenStore
        revision_id,
        apply_status: meshlet_domain::ApplyStatus::Pending.as_str().to_string(),
    })
}

/// Record one agent heartbeat/report (§14.1): locate the device, update
/// `last_report_at` (arrival time), the optional `last_handshake_at` (the agent's local
/// `wg show` reading) and `last_seen_at`, and return the current presence verdict (state + evidence source).
pub fn record_agent_report(
    state: &mut MeshState,
    device_id: &DeviceId,
    last_handshake_at: Option<String>,
    dataplane: Option<DataplaneEvidence>,
    now: Timestamp,
) -> Result<meshlet_domain::Presence, ServiceError> {
    let device = state
        .registry
        .find_by_id_mut(device_id)
        .ok_or_else(|| ServiceError::DeviceNotFound(device_id.to_string()))?;
    apply_agent_report(device, last_handshake_at, dataplane, &now);
    Ok(evaluate_presence(device, &now, &state.presence_thresholds))
}

/// Agent heartbeat for a Pending application (§7.5: evidence is not dropped just because
/// the application is Pending): only `last_report_at` and dataplane evidence are updated. With no tunnel there is no handshake reading to speak of, so
/// `last_handshake_at` is not collected for Pending applications (it starts from zero after approval, matching `devices.last_handshake_at`).
pub fn record_pending_agent_report(
    state: &mut MeshState,
    device_id: &DeviceId,
    dataplane: Option<DataplaneEvidence>,
    now: Timestamp,
) -> Result<(), ServiceError> {
    let registration = state
        .registry
        .find_registration_mut(device_id)
        .ok_or_else(|| ServiceError::DeviceNotFound(device_id.to_string()))?;
    if let Some(evidence) = dataplane {
        registration.dataplane_evidence = Some(evidence);
    }
    registration.last_report_at = Some(now);
    Ok(())
}

/// §12 P2P: record one direct-connect candidate report (observed source address + the LAN address/port reported by the agent).
/// An omitted report (`None`) removes the candidate — candidates are ephemeral advisory data and must not linger after a peer goes offline or shuts down
/// (peers decide direct paths from them; stale candidates mislead).
pub fn record_direct_state(
    state: &mut MeshState,
    device_id: &DeviceId,
    observed_ip: Option<Ipv4Addr>,
    report: Option<DirectEndpointReport>,
    links: Vec<DirectLinkStatus>,
) {
    match report {
        Some(report) => {
            state.direct_states.insert(
                device_id.clone(),
                DeviceDirectState {
                    observed_ip,
                    report: Some(report),
                    links,
                },
            );
        }
        None => {
            state.direct_states.remove(device_id);
        }
    }
}

/// Record the real hostname reported by the device (in-memory; overwritten by each heartbeat). `None`/blank means
/// nothing was obtained this round -> keep the old value (hostnames barely change; a restart is repaired by the next heartbeat).
pub fn record_device_hostname(
    state: &mut MeshState,
    device_id: &DeviceId,
    hostname: Option<String>,
) {
    if let Some(name) = hostname
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        state.device_hostnames.insert(device_id.clone(), name);
    }
}

/// R-DIAG: record the device's latest round of network diagnostics snapshots (in-memory; overwritten by each heartbeat).
/// `None` = the agent failed to collect / did not report -> remove the old snapshot (missing evidence stays visible; no stale readings are kept).
pub fn record_diagnostics(
    state: &mut MeshState,
    device_id: &DeviceId,
    diagnostics: Option<NetworkDiagnostics>,
) {
    match diagnostics {
        Some(snap) => {
            state.diagnostics.insert(device_id.clone(), snap);
        }
        None => {
            state.diagnostics.remove(device_id);
        }
    }
}

/// Write a single report into the device record (internal helper shared by callers). Same discipline for evidence and handshake time: when
/// the request omits them, keep the previous reading (a "last known reading"; staleness is carried by last_report_at).
fn apply_agent_report(
    device: &mut Device,
    last_handshake_at: Option<String>,
    dataplane: Option<DataplaneEvidence>,
    now: &Timestamp,
) {
    if let Some(ts) = last_handshake_at {
        device.last_handshake_at = Some(ts);
    }
    if let Some(evidence) = dataplane {
        device.dataplane_evidence = Some(evidence);
    }
    device.last_report_at = Some(now.clone());
    device.last_seen_at = Some(now.clone());
}

/// Presence verdict (a pure domain-layer function; verdict time = now, thresholds come from state).
pub fn evaluate_presence(
    device: &Device,
    now: &Timestamp,
    thresholds: &meshlet_domain::PresenceThresholds,
) -> meshlet_domain::Presence {
    meshlet_domain::evaluate(
        meshlet_domain::PresenceInput {
            last_handshake_at: device.last_handshake_at.as_deref(),
            last_report_at: device.last_report_at.as_deref(),
            enrolled_at: Some(device.created_at.as_str()),
        },
        now,
        thresholds,
    )
}

pub fn list_devices(state: &MeshState, network_id: &str) -> Result<Vec<DeviceView>, ServiceError> {
    state.network(network_id)?;
    let now: Timestamp = now();
    Ok(state
        .registry
        .devices()
        .iter()
        .filter(|d| d.network_id.to_string() == network_id)
        .map(|d| {
            let direct = state.direct_states.get(&d.id);
            let direct_links = direct.map(|s| s.links.clone()).unwrap_or_default();
            let diagnostics = state.diagnostics.get(&d.id).cloned();
            to_device_view(
                d,
                &now,
                &state.presence_thresholds,
                direct,
                direct_links,
                diagnostics,
            )
        })
        .collect())
}

/// Single-device view (read back after an MT-005 label update; rendered from the same source as [list_devices]).
pub fn device_view(
    state: &MeshState,
    network_id: &str,
    device_id: &str,
) -> Result<DeviceView, ServiceError> {
    state.network(network_id)?;
    let d = state
        .registry
        .find_by_id(&DeviceId(device_id.to_string()))
        .ok_or_else(|| ServiceError::DeviceNotFound(device_id.to_string()))?;
    if d.network_id.to_string() != network_id {
        return Err(ServiceError::DeviceNotFound(device_id.to_string()));
    }
    let now: Timestamp = now();
    let direct = state.direct_states.get(&d.id);
    let direct_links = direct.map(|s| s.links.clone()).unwrap_or_default();
    let diagnostics = state.diagnostics.get(&d.id).cloned();
    Ok(to_device_view(
        d,
        &now,
        &state.presence_thresholds,
        direct,
        direct_links,
        diagnostics,
    ))
}

/// Dataplane evidence gauge snapshot (data source for §17.2 metrics 1/2/3/7): computed
/// **on the fly** from `MeshState` at collection time, no static values stored. The caller holds the mesh lock; rendering (string concatenation) happens outside the lock.
///
/// "Recent handshake" = a handshake within `handshake_window` (tunnel evidence, a separate
/// source from the "online" agent report evidence — judging from either one alone misleads; see
/// `docs/architecture/observability.md` for the combined reading).
pub fn gauge_snapshot(state: &MeshState) -> crate::metrics::GaugeSnapshot {
    let now: Timestamp = now();
    let mut devices_online = 0u64;
    let mut devices_active = 0u64;
    let mut devices_with_recent_handshake = 0u64;
    let mut last_handshake_ts: i64 = 0;
    for device in state.registry.devices() {
        if device.is_active() {
            devices_active += 1;
        }
        let presence = evaluate_presence(device, &now, &state.presence_thresholds);
        if presence.state == meshlet_domain::presence::PresenceState::Online {
            devices_online += 1;
        }
        if let Some(ts) = device.last_handshake_at.as_deref() {
            if meshlet_domain::presence::fresh(ts, &now, state.presence_thresholds.handshake_window)
            {
                devices_with_recent_handshake += 1;
            }
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
                last_handshake_ts = last_handshake_ts.max(dt.timestamp());
            }
        }
    }
    crate::metrics::GaugeSnapshot {
        devices_online,
        devices_active,
        devices_with_recent_handshake,
        last_handshake_timestamp_seconds: last_handshake_ts,
        // Interface status (§17.2 item 7): the dataplane interface is considered up as soon as
        // at least one device has recent handshake evidence; host-side interface readings will be merged in once the dataplane backend lands (agent-side
        // evidence arrives first).
        interface_up: u8::from(devices_with_recent_handshake > 0),
        // Alias application status (§17.2 item 8): Phase 4 is not landed, so no Alias mappings can
        // be applied — a constant 0 means "nothing to apply", **not** "healthy".
        alias_apply_status: 0,
    }
}

/// Publish one LAN route (ADR-005). Routes belong to the desired config: creating one records a new revision (§10.1).
pub fn create_route(
    state: &mut MeshState,
    network_id: &str,
    req: CreateRouteRequest,
) -> Result<RouteView, ServiceError> {
    state.network(network_id)?;
    let destination: Ipv4Cidr = req
        .destination_cidr
        .parse()
        .map_err(|e| ServiceError::InvalidCidr(format!("{}: {e}", req.destination_cidr)))?;
    let route_mode = match req.route_mode.as_deref() {
        None | Some("direct") => RouteMode::Direct,
        Some("alias") => RouteMode::Alias,
        Some(other) => {
            return Err(ServiceError::InvalidInput(format!(
                "route_mode must be \"direct\" or \"alias\", got {other:?}"
            )));
        }
    };
    let return_path_mode = ReturnPathMode::parse(&req.return_path_mode).ok_or_else(|| {
        ServiceError::InvalidInput(format!(
            "return_path_mode must be \"dual_route\" or \"controlled_snat\", got {:?}",
            req.return_path_mode
        ))
    })?;

    // The overlay itself and its subnets are not LAN destinations (they are forwarded inside the overlay).
    let overlay = state.network(network_id)?.overlay_cidr;
    if destination.overlaps(&overlay) {
        return Err(ServiceError::RouteConflict(format!(
            "destination {destination} overlaps overlay {overlay}"
        )));
    }
    // Destination segments within one network are mutually exclusive (overlap is a conflict; no superset merging). Rejection happens before any state
    // change: an existing route is never overwritten (§8.3, no silent behavior). The error message names the conflicting peer
    // (existing route id + segment), so the console can show "which route this conflicts with".
    // Exception (ADR-006 flagship scenario): when **both** the new and the existing route are in **Alias mode**, overlapping
    // real prefixes are allowed — two sites each have a 192.168.1.0/24, and reachability is disambiguated through their respective Alias prefixes;
    // the externally visible forwarding prefix is the Alias (uniqueness is guaranteed by the `alias_alias_overlap` rejection
    // when creating an Alias), and real prefixes never enter any tunnel's AllowedIPs.
    if let Some(existing) = state
        .lan_routes
        .get(network_id)
        .and_then(|routes| {
            routes
                .iter()
                .find(|r| r.destination_cidr.overlaps(&destination))
        })
        .cloned()
    {
        let both_alias = existing.route_mode == RouteMode::Alias && route_mode == RouteMode::Alias;
        if !both_alias {
            return Err(ServiceError::RouteConflict(format!(
                "destination {destination} overlaps existing route {} ({}) in network {network_id}",
                existing.id, existing.destination_cidr
            )));
        }
    }

    // The gateway must be an Active device of this network.
    let gateway = DeviceId(req.gateway_device_id.clone());
    let device = state
        .registry
        .find_by_id(&gateway)
        .ok_or_else(|| ServiceError::DeviceNotFound(req.gateway_device_id.clone()))?;
    if device.network_id.to_string() != network_id {
        return Err(ServiceError::DeviceNotFound(req.gateway_device_id));
    }
    if !device.is_active() {
        return Err(ServiceError::Conflict(format!(
            "gateway device {} is not active",
            device.id
        )));
    }

    if route_mode == RouteMode::Direct {
        check_new_forward_prefix(state, network_id, destination)?;
    } else {
        // Preserve Alias real-prefix overlap, but never route a real target
        // through an existing visible Alias on this gateway.
        check_local_alias_prefix(state, network_id, destination)?;
    }

    state.route_seq += 1;
    let route = LanRoute {
        id: LanRouteId(format!("rt-{}", state.route_seq)),
        network_id: meshlet_domain::NetworkId(network_id.to_string()),
        gateway_device_id: gateway,
        destination_cidr: destination,
        route_mode,
        return_path_mode,
        status: DesiredStateStatus::Pending,
        created_at: now(),
    };
    state
        .lan_routes
        .entry(network_id.to_string())
        .or_default()
        .push(route.clone());
    let revision_id = record_revision(state, network_id)?;
    Ok(to_route_view(state, network_id, &route, revision_id))
}

pub fn list_routes(state: &MeshState, network_id: &str) -> Result<Vec<RouteView>, ServiceError> {
    state.network(network_id)?;
    let (revision_id, apply_status) = current_revision_ref(state, network_id);
    Ok(state
        .lan_routes
        .get(network_id)
        .map(|routes| {
            routes
                .iter()
                .map(|r| RouteView {
                    id: r.id.to_string(),
                    network_id: r.network_id.to_string(),
                    gateway_device_id: r.gateway_device_id.to_string(),
                    destination_cidr: r.destination_cidr.to_string(),
                    route_mode: r.route_mode.as_str().to_string(),
                    return_path_mode: r.return_path_mode.as_str().to_string(),
                    status: r.status.as_str().to_string(),
                    revision_id,
                    apply_status: apply_status.clone(),
                })
                .collect()
        })
        .unwrap_or_default())
}

pub fn get_route(
    state: &MeshState,
    network_id: &str,
    route_id: &str,
) -> Result<RouteView, ServiceError> {
    state.network(network_id)?;
    let route = state
        .lan_routes
        .get(network_id)
        .and_then(|routes| routes.iter().find(|r| r.id.to_string() == route_id))
        .ok_or_else(|| {
            ServiceError::RouteNotFound(format!("{route_id} in network {network_id}"))
        })?;
    let (revision_id, apply_status) = current_revision_ref(state, network_id);
    Ok(RouteView {
        id: route.id.to_string(),
        network_id: route.network_id.to_string(),
        gateway_device_id: route.gateway_device_id.to_string(),
        destination_cidr: route.destination_cidr.to_string(),
        route_mode: route.route_mode.as_str().to_string(),
        return_path_mode: route.return_path_mode.as_str().to_string(),
        status: route.status.as_str().to_string(),
        revision_id,
        apply_status,
    })
}

/// Delete one LAN route. Deletion is also a desired-config change: record a new revision.
/// §12.6 ownership cleanup: remove the Aliases bound to that route together with it (an alias and a route are a one-to-one unit,
/// and leaving an orphan Alias would make AllowedIPs derivation reference a translation that does not exist).
pub fn delete_route(
    state: &mut MeshState,
    network_id: &str,
    route_id: &str,
) -> Result<(), ServiceError> {
    state.network(network_id)?;
    let routes = state.lan_routes.get_mut(network_id).ok_or_else(|| {
        ServiceError::RouteNotFound(format!("{route_id} in network {network_id}"))
    })?;
    let before = routes.len();
    routes.retain(|r| r.id.to_string() != route_id);
    if routes.len() == before {
        return Err(ServiceError::RouteNotFound(format!(
            "{route_id} in network {network_id}"
        )));
    }
    if let Some(aliases) = state.aliases.get_mut(network_id) {
        aliases.retain(|a| a.lan_route_id.to_string() != route_id);
    }
    record_revision(state, network_id)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Alias mappings (ADR-006: equal-length prefixes, one-to-one; §12.6 ownership and cleanup)
// ---------------------------------------------------------------------------

/// Create an Alias mapping (the control-plane part of the §9.2 pre-translation checks): the bound route
/// must be an `alias`-mode route of this network, its gateway Active, and at most one mapping per route; the prefixes
/// must be equal in length (validated in the domain layer) and must not overlap the overlay, existing Aliases, or existing route destination segments (§8.3/§9.2, no silent behavior —
/// conflict messages name the counterpart). The target is derived from the bound route; clients cannot specify it.
/// Rejection happens before any state change.
pub fn create_alias(
    state: &mut MeshState,
    network_id: &str,
    req: CreateAliasRequest,
) -> Result<AliasView, ServiceError> {
    state.network(network_id)?;
    let alias_cidr: Ipv4Cidr = req
        .alias_cidr
        .parse()
        .map_err(|e| ServiceError::InvalidCidr(format!("{}: {e}", req.alias_cidr)))?;
    let translation_mode = match req.translation_mode.as_deref() {
        None | Some("dnat_snat") => TranslationMode::DnatSnat,
        Some("dnat_only") => TranslationMode::DnatOnly,
        Some(other) => {
            return Err(ServiceError::InvalidInput(format!(
                "translation_mode must be \"dnat_snat\" or \"dnat_only\", got {other:?}"
            )));
        }
    };

    // Bound route: belongs to this network and is in alias mode (§5: route_mode=alias means "via a virtual prefix",
    // and an alias and a route are a one-to-one unit); the gateway must be Active (§9.2 "gateway valid"); one mapping per route.
    let routes = state.lan_routes.get(network_id).ok_or_else(|| {
        ServiceError::RouteNotFound(format!("{} in network {network_id}", req.lan_route_id))
    })?;
    let route = routes
        .iter()
        .find(|r| r.id.to_string() == req.lan_route_id)
        .ok_or_else(|| {
            ServiceError::RouteNotFound(format!("{} in network {network_id}", req.lan_route_id))
        })?;
    if route.route_mode != RouteMode::Alias {
        return Err(ServiceError::InvalidInput(format!(
            "alias can only bind to a route with route_mode = \"alias\", but route {} has route_mode = \"{}\" (create the route in alias mode first, §5/ADR-006)",
            route.id,
            route.route_mode.as_str()
        )));
    }
    let target_cidr = route.destination_cidr;
    AliasMapping::new(
        AliasMappingId(format!("al-{}", state.route_seq + 1)),
        meshlet_domain::NetworkId(network_id.to_string()),
        route.id.clone(),
        alias_cidr,
        target_cidr,
        translation_mode,
    )
    .map_err(|e: AliasError| ServiceError::InvalidInput(e.to_string()))?;
    check_new_forward_prefix(state, network_id, alias_cidr)?;
    let gateway = state
        .registry
        .find_by_id(&route.gateway_device_id)
        .ok_or_else(|| ServiceError::DeviceNotFound(route.gateway_device_id.to_string()))?;
    if !gateway.is_active() {
        return Err(ServiceError::Conflict(format!(
            "gateway device {} of route {} is not active",
            gateway.id, route.id
        )));
    }
    if let Some(aliases) = state.aliases.get(network_id) {
        if let Some(existing) = aliases.iter().find(|a| a.lan_route_id == route.id) {
            return Err(ServiceError::Conflict(format!(
                "route {} already has alias {} bound (one mapping per route, §12.6)",
                route.id, existing.id
            )));
        }
    }

    let id = AliasMappingId(format!("al-{}", state.route_seq + 1));
    let alias = AliasMapping::new(
        id,
        meshlet_domain::NetworkId(network_id.to_string()),
        route.id.clone(),
        alias_cidr,
        target_cidr,
        translation_mode,
    )
    .map_err(|e: AliasError| ServiceError::InvalidInput(e.to_string()))?;

    state.route_seq += 1;
    state
        .aliases
        .entry(network_id.to_string())
        .or_default()
        .push(alias.clone());
    let revision_id = record_revision(state, network_id)?;
    Ok(to_alias_view(state, network_id, &alias, revision_id))
}

pub fn list_aliases(state: &MeshState, network_id: &str) -> Result<Vec<AliasView>, ServiceError> {
    state.network(network_id)?;
    let (revision_id, _) = current_revision_ref(state, network_id);
    Ok(state
        .aliases
        .get(network_id)
        .map(|aliases| {
            aliases
                .iter()
                .map(|a| to_alias_view(state, network_id, a, revision_id))
                .collect()
        })
        .unwrap_or_default())
}

pub fn get_alias(
    state: &MeshState,
    network_id: &str,
    alias_id: &str,
) -> Result<AliasView, ServiceError> {
    state.network(network_id)?;
    let alias = state
        .aliases
        .get(network_id)
        .and_then(|aliases| aliases.iter().find(|a| a.id.to_string() == alias_id))
        .ok_or_else(|| {
            ServiceError::AliasNotFound(format!("{alias_id} in network {network_id}"))
        })?;
    let (revision_id, _) = current_revision_ref(state, network_id);
    Ok(to_alias_view(state, network_id, alias, revision_id))
}

/// Deleting an Alias = whole-unit cleanup (the control-plane part of §12.6's "deleting an Alias also cleans up its route and NAT rules"):
/// remove the mapping together with its bound route, recording **a single** revision. Removing the kernel-side NAT rules is handed to the backend
/// as part of that revision's apply (when not wired up the deterministic failure is visible, §10.3).
/// Returns (alias_id, route_id) so the handler can persist and audit it.
pub fn delete_alias(
    state: &mut MeshState,
    network_id: &str,
    alias_id: &str,
) -> Result<(String, String), ServiceError> {
    state.network(network_id)?;
    let aliases = state.aliases.get_mut(network_id).ok_or_else(|| {
        ServiceError::AliasNotFound(format!("{alias_id} in network {network_id}"))
    })?;
    let before = aliases.len();
    let route_id = aliases
        .iter()
        .find(|a| a.id.to_string() == alias_id)
        .map(|a| a.lan_route_id.to_string())
        .ok_or_else(|| {
            ServiceError::AliasNotFound(format!("{alias_id} in network {network_id}"))
        })?;
    aliases.retain(|a| a.id.to_string() != alias_id);
    debug_assert_eq!(aliases.len(), before - 1);
    // Delete the bound route along with it (a one-to-one unit; an orphan alias-mode route has no translation semantics).
    if let Some(routes) = state.lan_routes.get_mut(network_id) {
        routes.retain(|r| r.id.to_string() != route_id);
    }
    record_revision(state, network_id)?;
    Ok((alias_id.to_string(), route_id))
}

/// Create a non-default segment. The default segment is fixed by the network-creation transaction and cannot be duplicated, replaced, or deleted;
/// a new segment must be a strict sub-segment of the overlay and must not overlap the prefixes of other segments in the same network.
pub fn create_segment(
    state: &mut MeshState,
    network_id: &str,
    req: CreateSegmentRequest,
) -> Result<SegmentView, ServiceError> {
    let network_id = network_id.to_string();
    let network = state.network(&network_id)?;
    let domain_network_id = network.id.clone();
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(ServiceError::InvalidInput(
            "segment name must not be empty".into(),
        ));
    }
    if name == "default" {
        return Err(ServiceError::Conflict(
            "segment name \"default\" is reserved for the network overlay".into(),
        ));
    }
    if state
        .segments(&network_id)
        .iter()
        .any(|segment| segment.name == name)
    {
        return Err(ServiceError::Conflict(format!(
            "segment name {name:?} already exists in network {network_id}"
        )));
    }
    let cidr: Ipv4Cidr = req
        .cidr
        .parse()
        .map_err(|e| ServiceError::InvalidCidr(format!("{}: {e}", req.cidr)))?;
    let candidate = Segment {
        id: SegmentId("candidate".to_string()),
        network_id: network.id.clone(),
        name: name.clone(),
        cidr,
        status: SegmentStatus::Active,
        created_at: now(),
    };
    candidate
        .validate_cidr(network.overlay_cidr)
        .map_err(|e| ServiceError::InvalidCidr(e.to_string()))?;
    if state
        .segments(&network_id)
        .iter()
        .any(|segment| segment.cidr == cidr)
    {
        return Err(ServiceError::Conflict(format!(
            "cidr {cidr} is already used by an existing segment in network {network_id}"
        )));
    }

    state.route_seq += 1;
    let segment = Segment {
        id: SegmentId(format!("seg-{network_id}-{}", state.route_seq)),
        network_id: domain_network_id,
        name,
        cidr,
        status: SegmentStatus::Active,
        created_at: now(),
    };
    state
        .segments
        .entry(network_id.clone())
        .or_default()
        .push(segment.clone());
    let revision_id = record_revision(state, &network_id)?;
    Ok(to_segment_view(&segment, revision_id))
}

pub fn list_segments(
    state: &MeshState,
    network_id: &str,
) -> Result<Vec<SegmentView>, ServiceError> {
    state.network(network_id)?;
    Ok(state
        .segments(network_id)
        .iter()
        .map(|segment| {
            let (revision_id, _) = current_revision_ref(state, network_id);
            to_segment_view(segment, revision_id)
        })
        .collect())
}

fn to_segment_view(segment: &Segment, revision_id: u64) -> SegmentView {
    SegmentView {
        id: segment.id.to_string(),
        network_id: segment.network_id.to_string(),
        name: segment.name.clone(),
        cidr: segment.cidr.to_string(),
        status: segment.status.as_str().to_string(),
        created_at: segment.created_at.clone(),
        revision_id,
    }
}

fn segment_by_id<'a>(
    state: &'a MeshState,
    network_id: &'a str,
    segment_id: &str,
) -> Result<&'a Segment, ServiceError> {
    state.network(network_id)?;
    state
        .segments(network_id)
        .iter()
        .find(|segment| segment.id.to_string() == segment_id)
        .ok_or_else(|| {
            ServiceError::SegmentNotFound(format!("{segment_id} in network {network_id}"))
        })
}

/// A newly created grant is Pending: only one-way trust that has been explicitly applied enters the desired hash.
pub fn create_segment_grant(
    state: &mut MeshState,
    network_id: &str,
    req: CreateSegmentGrantRequest,
) -> Result<SegmentGrantView, ServiceError> {
    let network = state.network(network_id)?;
    let domain_network_id = network.id.clone();
    let source = segment_by_id(state, network_id, &req.source_segment_id)?;
    let source_id = source.id.clone();
    let destination = segment_by_id(state, network_id, &req.destination_segment_id)?;
    let destination_id = destination.id.clone();
    if source_id == destination_id {
        return Err(ServiceError::InvalidInput(
            "source and destination segments must differ".into(),
        ));
    }
    if state.segment_grants(network_id).iter().any(|grant| {
        grant.status != SegmentGrantStatus::Revoked
            && grant.source_segment_id == source_id
            && grant.destination_segment_id == destination_id
    }) {
        return Err(ServiceError::Conflict(format!(
            "an active grant already exists from segment {} to segment {}",
            source_id, destination_id
        )));
    }

    state.route_seq += 1;
    let grant = SegmentGrantBuilder::new(
        SegmentGrantId(format!("sg-{}", state.route_seq)),
        domain_network_id,
        source_id.clone(),
        destination_id.clone(),
        now(),
    )
    .build();
    state
        .grants
        .entry(network_id.to_string())
        .or_default()
        .push(grant.clone());
    let revision_id = record_revision(state, network_id)?;
    Ok(to_segment_grant_view(
        state,
        network_id,
        &grant,
        revision_id,
    ))
}

pub fn list_segment_grants(
    state: &MeshState,
    network_id: &str,
) -> Result<Vec<SegmentGrantView>, ServiceError> {
    state.network(network_id)?;
    let (revision_id, _) = current_revision_ref(state, network_id);
    Ok(state
        .segment_grants(network_id)
        .iter()
        .map(|grant| to_segment_grant_view(state, network_id, grant, revision_id))
        .collect())
}

/// Explicitly approve a Pending grant: only afterwards does it enter plan compilation and desired_config_hash v4.
pub fn apply_segment_grant(
    state: &mut MeshState,
    network_id: &str,
    grant_id: &str,
) -> Result<SegmentGrantView, ServiceError> {
    state.network(network_id)?;
    let target_index = state
        .grants
        .get(network_id)
        .and_then(|grants| {
            grants
                .iter()
                .position(|grant| grant.id.to_string() == grant_id)
        })
        .ok_or_else(|| {
            ServiceError::SegmentGrantNotFound(format!("{grant_id} in network {network_id}"))
        })?;
    if state.grants[network_id][target_index].status != SegmentGrantStatus::Pending {
        return Err(ServiceError::Conflict(format!(
            "segment grant {} is {}, only pending grants can be applied",
            grant_id,
            state.grants[network_id][target_index].status.as_str()
        )));
    }
    state.grants.get_mut(network_id).expect("checked")[target_index].status =
        SegmentGrantStatus::Applied;
    let target = state.grants[network_id][target_index].clone();
    let revision_id = record_revision(state, network_id)?;
    Ok(to_segment_grant_view(
        state,
        network_id,
        &target,
        revision_id,
    ))
}

/// Revoke one-way trust; revoking twice is a 409 and produces no no-op revision.
pub fn revoke_segment_grant(
    state: &mut MeshState,
    network_id: &str,
    grant_id: &str,
) -> Result<SegmentGrantView, ServiceError> {
    state.network(network_id)?;
    let target_index = state
        .grants
        .get(network_id)
        .and_then(|grants| {
            grants
                .iter()
                .position(|grant| grant.id.to_string() == grant_id)
        })
        .ok_or_else(|| {
            ServiceError::SegmentGrantNotFound(format!("{grant_id} in network {network_id}"))
        })?;
    let mut target = state.grants[network_id][target_index].clone();
    target
        .revoke(now())
        .map_err(|e| ServiceError::Conflict(e.to_string()))?;
    state.grants.get_mut(network_id).expect("checked")[target_index] = target.clone();
    let revision_id = record_revision(state, network_id)?;
    Ok(to_segment_grant_view(
        state,
        network_id,
        &target,
        revision_id,
    ))
}

fn to_segment_grant_view(
    state: &MeshState,
    network_id: &str,
    grant: &SegmentGrant,
    revision_id: u64,
) -> SegmentGrantView {
    let (_, apply_status) = current_revision_ref(state, network_id);
    SegmentGrantView {
        id: grant.id.to_string(),
        network_id: grant.network_id.to_string(),
        source_segment_id: grant.source_segment_id.to_string(),
        destination_segment_id: grant.destination_segment_id.to_string(),
        status: grant.status.as_str().to_string(),
        created_at: grant.created_at.clone(),
        revoked_at: grant.revoked_at.clone(),
        revision_id,
        apply_status,
    }
}

/// Create a per-host all-port forward: write "alias /32 -> target /32" as a single atomic unit.
///
/// Host Forward adds no new port/firewall model: `/32` makes every port of TCP/UDP/ICMP and
/// every protocol go through the existing LAN Route + Alias NETMAP path; deleting the route/alias unit deletes everything.
pub fn create_host_forward(
    state: &mut MeshState,
    network_id: &str,
    req: CreateHostForwardRequest,
) -> Result<HostForwardView, ServiceError> {
    state.network(network_id)?;
    let target = Ipv4Cidr::new(req.target_ipv4, 32)
        .map_err(|e| ServiceError::InvalidCidr(format!("{}/32: {e}", req.target_ipv4)))?;
    let alias_cidr = Ipv4Cidr::new(req.alias_ipv4, 32)
        .map_err(|e| ServiceError::InvalidCidr(format!("{}/32: {e}", req.alias_ipv4)))?;
    check_new_forward_prefix(state, network_id, alias_cidr)?;
    check_local_alias_prefix(state, network_id, target)?;
    let translation_mode = match req.translation_mode.as_deref() {
        None | Some("dnat_snat") => TranslationMode::DnatSnat,
        Some("dnat_only") => TranslationMode::DnatOnly,
        Some(other) => {
            return Err(ServiceError::InvalidInput(format!(
                "translation_mode must be \"dnat_snat\" or \"dnat_only\", got {other:?}"
            )));
        }
    };
    let overlay = state.network(network_id)?.overlay_cidr;
    if target.overlaps(&overlay) || alias_cidr.overlaps(&overlay) {
        return Err(ServiceError::RouteConflict(format!(
            "host forward target {target} or alias {alias_cidr} overlaps overlay {overlay}"
        )));
    }
    for existing in state
        .lan_routes
        .get(network_id)
        .map(Vec::as_slice)
        .unwrap_or(&[])
    {
        if existing.destination_cidr.overlaps(&target) {
            return Err(ServiceError::RouteConflict(format!(
                "host forward target {target} overlaps existing route {} ({})",
                existing.id, existing.destination_cidr
            )));
        }
    }

    let gateway = DeviceId(req.gateway_device_id.clone());
    let device = state
        .registry
        .find_by_id(&gateway)
        .ok_or_else(|| ServiceError::DeviceNotFound(req.gateway_device_id.clone()))?;
    if device.network_id.to_string() != network_id {
        return Err(ServiceError::DeviceNotFound(req.gateway_device_id));
    }
    if !device.is_active() {
        return Err(ServiceError::Conflict(format!(
            "gateway device {} is not active",
            device.id
        )));
    }

    let route = LanRoute {
        id: LanRouteId(format!("rt-{}", state.route_seq + 1)),
        network_id: meshlet_domain::NetworkId(network_id.to_string()),
        gateway_device_id: gateway,
        destination_cidr: target,
        route_mode: RouteMode::Alias,
        return_path_mode: ReturnPathMode::ControlledSnat,
        status: DesiredStateStatus::Pending,
        created_at: now(),
    };
    let alias = AliasMapping::new(
        AliasMappingId(format!("al-{}", state.route_seq + 2)),
        meshlet_domain::NetworkId(network_id.to_string()),
        route.id.clone(),
        alias_cidr,
        target,
        translation_mode,
    )
    .map_err(|e| ServiceError::InvalidInput(e.to_string()))?;

    state.route_seq += 2;

    state
        .lan_routes
        .entry(network_id.to_string())
        .or_default()
        .push(route);
    state
        .aliases
        .entry(network_id.to_string())
        .or_default()
        .push(alias.clone());
    let revision_id = record_revision(state, network_id)?;
    Ok(to_host_forward_view(state, network_id, &alias, revision_id))
}

/// Host Forward list = all current Alias units with a /32 target (real LAN segments are still shown
/// on the existing Alias page, keeping the two semantics out of the same table).
pub fn list_host_forwards(
    state: &MeshState,
    network_id: &str,
) -> Result<Vec<HostForwardView>, ServiceError> {
    state.network(network_id)?;
    let routes: HashMap<String, &LanRoute> = state
        .lan_routes
        .get(network_id)
        .map(|routes| {
            routes
                .iter()
                .map(|route| (route.id.to_string(), route))
                .collect()
        })
        .unwrap_or_default();
    let mut views = state
        .aliases
        .get(network_id)
        .map(|aliases| {
            aliases
                .iter()
                .filter_map(|alias| {
                    let route = routes.get(&alias.lan_route_id.to_string())?;
                    if route.destination_cidr.prefix_len() != 32 {
                        return None;
                    }
                    let (_, apply_status) = current_revision_ref(state, network_id);
                    Some(HostForwardView {
                        id: alias.id.to_string(),
                        network_id: alias.network_id.to_string(),
                        gateway_device_id: route.gateway_device_id.to_string(),
                        target_ipv4: alias.target_cidr.network().to_string(),
                        alias_ipv4: alias.alias_cidr.network().to_string(),
                        translation_mode: alias.translation_mode.as_str().to_string(),
                        status: alias.status.as_str().to_string(),
                        revision_id: 0,
                        apply_status,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    views.sort_by_key(|view| view.alias_ipv4.clone());
    Ok(views)
}

/// Delete the alias id of a Host Forward; the bound route is removed together with it via the existing ownership unit.
pub fn delete_host_forward(
    state: &mut MeshState,
    network_id: &str,
    alias_id: &str,
) -> Result<(String, String), ServiceError> {
    delete_alias(state, network_id, alias_id)
}

fn to_alias_view(
    state: &MeshState,
    network_id: &str,
    alias: &AliasMapping,
    revision_id: u64,
) -> AliasView {
    let (_, apply_status) = current_revision_ref(state, network_id);
    AliasView {
        id: alias.id.to_string(),
        network_id: alias.network_id.to_string(),
        lan_route_id: alias.lan_route_id.to_string(),
        alias_cidr: alias.alias_cidr.to_string(),
        target_cidr: alias.target_cidr.to_string(),
        translation_mode: alias.translation_mode.as_str().to_string(),
        status: alias.status.as_str().to_string(),
        revision_id,
        apply_status,
    }
}

fn to_host_forward_view(
    state: &MeshState,
    network_id: &str,
    alias: &AliasMapping,
    revision_id: u64,
) -> HostForwardView {
    let (_, apply_status) = current_revision_ref(state, network_id);
    let target_ipv4 = alias.target_cidr.network().to_string();
    let alias_ipv4 = alias.alias_cidr.network().to_string();
    HostForwardView {
        id: alias.id.to_string(),
        network_id: alias.network_id.to_string(),
        gateway_device_id: state
            .lan_routes
            .get(network_id)
            .and_then(|routes| routes.iter().find(|route| route.id == alias.lan_route_id))
            .map(|route| route.gateway_device_id.to_string())
            .unwrap_or_default(),
        target_ipv4,
        alias_ipv4,
        translation_mode: alias.translation_mode.as_str().to_string(),
        status: alias.status.as_str().to_string(),
        revision_id,
        apply_status,
    }
}

/// Revoke a device (peer revocation, the control-plane part of §11.5): the status becomes `Revoked` (offline) and a
/// new revision is recorded — a revoked device does not enter the desired-config hash. Invalidation of the agent credential is done by the handler outside the lock.
pub fn revoke_device(
    state: &mut MeshState,
    network_id: &str,
    device_id: &str,
) -> Result<RevisionRef, ServiceError> {
    state.network(network_id)?;
    let revoked_id = {
        let device = state
            .registry
            .find_by_id_mut(&DeviceId(device_id.to_string()))
            .ok_or_else(|| ServiceError::DeviceNotFound(device_id.to_string()))?;
        if device.network_id.to_string() != network_id {
            return Err(ServiceError::DeviceNotFound(device_id.to_string()));
        }
        device
            .revoke(now())
            .map_err(|e| ServiceError::Conflict(e.to_string()))?;
        device.id.clone()
    };
    // §11.5: revocation must remove the LAN routes published by that device, so the desired config is not left with routes pointing
    // at a revoked Peer (AllowedIPs derivation would keep treating it as a remote segment and keep distributing it).
    // §12.6 ownership cleanup: remove the Alias mappings bound to those routes along with them (no orphan translations).
    let orphaned: Vec<String> = state
        .lan_routes
        .get(network_id)
        .map(|routes| {
            routes
                .iter()
                .filter(|r| r.gateway_device_id == revoked_id)
                .map(|r| r.id.to_string())
                .collect()
        })
        .unwrap_or_default();
    if let Some(routes) = state.lan_routes.get_mut(network_id) {
        routes.retain(|r| r.gateway_device_id != revoked_id);
    }
    if let Some(aliases) = state.aliases.get_mut(network_id) {
        aliases.retain(|a| !orphaned.contains(&a.lan_route_id.to_string()));
    }
    let revision_id = record_revision(state, network_id)?;
    Ok(RevisionRef {
        revision_id,
        apply_status: meshlet_domain::ApplyStatus::Pending.as_str().to_string(),
    })
}

/// Set device labels (MT-005): full replacement (PUT semantics). Labels are routing metadata,
/// not part of the desired config — no revision is recorded and no backend apply is triggered; persisting is done by the caller
/// through [crate::persist::commit_device_labels]. The device must belong to that network.
pub fn set_device_labels(
    state: &mut MeshState,
    network_id: &str,
    device_id: &str,
    labels: BTreeMap<String, String>,
) -> Result<Device, ServiceError> {
    state.network(network_id)?;
    let device = state
        .registry
        .find_by_id_mut(&DeviceId(device_id.to_string()))
        .ok_or_else(|| ServiceError::DeviceNotFound(device_id.to_string()))?;
    if device.network_id.to_string() != network_id {
        return Err(ServiceError::DeviceNotFound(device_id.to_string()));
    }
    device.labels = labels;
    Ok(device.clone())
}

/// The network's current revision reference (reuses the network-view semantics: 0/`none` when there is no revision).
pub fn current_revision_ref(state: &MeshState, network_id: &str) -> (u64, String) {
    state
        .ledger
        .current(&meshlet_domain::NetworkId(network_id.to_string()))
        .map(|r| (r.revision, r.apply_status.as_str().to_string()))
        .unwrap_or((0, "none".to_string()))
}

fn to_route_view(
    state: &MeshState,
    network_id: &str,
    route: &LanRoute,
    revision_id: u64,
) -> RouteView {
    let (_, apply_status) = current_revision_ref(state, network_id);
    RouteView {
        id: route.id.to_string(),
        network_id: route.network_id.to_string(),
        gateway_device_id: route.gateway_device_id.to_string(),
        destination_cidr: route.destination_cidr.to_string(),
        route_mode: route.route_mode.as_str().to_string(),
        return_path_mode: route.return_path_mode.as_str().to_string(),
        status: route.status.as_str().to_string(),
        revision_id,
        apply_status,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn fingerprint_of(public_key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(public_key.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn to_network_view(state: &MeshState, n: &Network) -> NetworkView {
    // Current desired revision = the latest non-rolled-back revision (ADR-009: display follows application status).
    let current = state
        .ledger
        .current(&meshlet_domain::NetworkId(n.id.0.clone()));
    NetworkView {
        id: n.id.to_string(),
        name: n.name.clone(),
        overlay_cidr: n.overlay_cidr.to_string(),
        status: match n.status {
            meshlet_domain::NetworkStatus::Active => "active",
            meshlet_domain::NetworkStatus::Deleting => "deleting",
        }
        .to_string(),
        created_at: n.created_at.clone(),
        revision_id: current.map(|r| r.revision).unwrap_or(0),
        apply_status: current
            .map(|r| r.apply_status.as_str().to_string())
            .unwrap_or_else(|| "none".to_string()),
    }
}

fn to_device_view(
    d: &Device,
    now: &Timestamp,
    thresholds: &meshlet_domain::PresenceThresholds,
    direct: Option<&DeviceDirectState>,
    direct_links: Vec<DirectLinkStatus>,
    diagnostics: Option<NetworkDiagnostics>,
) -> DeviceView {
    let presence = evaluate_presence(d, now, thresholds);
    let observed_endpoint = direct
        .and_then(|s| s.observed_endpoint())
        .map(|(ip, port)| format!("{ip}:{port}"));
    let public_endpoint = direct
        .and_then(|s| s.public_endpoint())
        .map(|c| format!("{}:{}", c.ip, c.port));
    DeviceView {
        id: d.id.to_string(),
        network_id: d.network_id.to_string(),
        name: d.name.clone(),
        virtual_ipv4: d.virtual_ipv4,
        public_key: d.public_key.clone(),
        fingerprint: fingerprint_of(&d.public_key),
        status: match d.status {
            meshlet_domain::DeviceStatus::Pending => "pending",
            meshlet_domain::DeviceStatus::Active => "active",
            meshlet_domain::DeviceStatus::Revoked => "revoked",
        }
        .to_string(),
        created_at: d.created_at.clone(),
        approved_at: d.approved_at.clone(),
        last_seen_at: d.last_seen_at.clone(),
        online_state: presence.state.as_str().to_string(),
        presence_source: presence.source.as_str().to_string(),
        dataplane_evidence: d.dataplane_evidence.clone(),
        direct_links,
        observed_endpoint,
        public_endpoint,
        diagnostics,
        labels: d.labels.clone(),
    }
}
