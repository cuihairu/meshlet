//! In-memory MeshState aggregate and persistence-facing accessors.

use meshlet_domain::{
    AliasMapping, DesiredStateStatus, Device, DeviceDirectState, DeviceId, DeviceRegistration,
    DeviceRegistry, Invite, Ipam, LanRoute, Network, Segment, SegmentGrant,
};
use std::collections::{BTreeMap, HashMap};

use meshlet_network::NetworkDiagnostics;

use crate::service::error::ServiceError;

#[derive(Clone)]
pub struct MeshState {
    pub(crate) deployments: HashMap<String, crate::revision::Deployment>,
    pub(crate) networks: HashMap<String, Network>,
    /// Invites are indexed by token digest (§11.3: redemption locates by digest, never exposing the raw token).
    pub(crate) invites: HashMap<String, Invite>,
    pub(crate) ipams: HashMap<String, Ipam>,
    /// Device registry (`pub(crate)`: the agent heartbeat needs to read a device's network membership).
    pub(crate) registry: DeviceRegistry,
    /// LAN routes (Phase 3 control plane: add/remove lands in state first, application awaits the backend, ADR-005).
    pub(crate) lan_routes: HashMap<String, Vec<LanRoute>>,
    /// Alias mappings (Phase 4 control plane: one-to-one equal-length prefixes,
    /// ADR-006; ownership of the NAT rule — deletion cleans up the whole unit
    /// (alias + bound route), while the kernel rule is executed by the backend
    /// during a revision apply).
    pub(crate) aliases: HashMap<String, Vec<AliasMapping>>,
    /// Service publish objects (R-06: PortForward / HTTP route / probe / DNS
    /// record, indexed by network). Filtered per device when building the plan
    /// (`crate::publish`); they stop taking effect once the device is revoked.
    pub(crate) publishes: HashMap<String, crate::publish::PublishCatalog>,
    /// Segment trust groups (ADR-012), restored for startup validation and
    /// policy-plan work that follows.
    pub(crate) segments: HashMap<String, Vec<Segment>>,
    /// Directed segment grants (ADR-012), restored with segments.
    pub(crate) grants: HashMap<String, Vec<SegmentGrant>>,
    /// Route id sequence (globally monotonic; deleted ids are never reused).
    pub(crate) route_seq: u64,
    /// Publish object id sequence (`pf-` / `hr-` / `pb-` / `dn-` share one
    /// monotonic sequence; the prefixes differ so they cannot collide;
    /// persisted to `mesh_meta.publish_seq`, and deleted ids are never reused).
    publish_seq: u64,
    /// Online determination window (§12.4; defaults in
    /// [meshlet_domain::PresenceThresholds]). `pub(crate)`: the §12.7
    /// diagnostics items 4/8 judge handshake/report freshness against the same
    /// window.
    pub(crate) presence_thresholds: meshlet_domain::PresenceThresholds,
    /// Desired-config revision bookkeeping (ADR-009 state machine, §10).
    pub(crate) ledger: meshlet_domain::ConfigLedger,
    /// Bootstrap tokens (indexed by token digest; same digest-index discipline as invites, §11.3).
    pub(crate) bootstrap_tokens: std::collections::HashMap<String, meshlet_domain::BootstrapToken>,
    /// Bootstrap token sequence (`bt-N`, persisted to `mesh_meta`; deleted ids are never reused).
    pub(crate) bootstrap_seq: u64,
    /// Registration request sequence (`dev-reg-N`, persisted to `mesh_meta`;
    /// deleted ids are never reused). Its prefix does not collide with `bt-`, so
    /// each sequence being monotonic on its own is sufficient — no shared
    /// counter. The pending requests themselves live inside `registry`
    /// ([DeviceRegistry]).
    pub(crate) registration_seq: u64,
    /// §12 P2P direct-connect candidates (**in-memory state**, transient
    /// advisory data): re-reported on every heartbeat, so it is not persisted —
    /// persisting would only add staleness risk (after a disconnect, an old
    /// candidate would still be treated as valid by peers). The observed source
    /// address comes from the connection socket (public candidate), and LAN
    /// addresses are reported in the agent heartbeat. A `BTreeMap` is used to
    /// stay consistent with the domain-layer `peer_endpoints_for` (deterministic
    /// ordering).
    pub(crate) direct_states: BTreeMap<DeviceId, DeviceDirectState>,
    /// Each node's real hostname (**in-memory state**, same discipline as
    /// `direct_states`): reported in the agent heartbeat, and the default alias
    /// source for SSH alias distribution (hostname > peer name); not persisted —
    /// the next heartbeat after a hub restart restores it.
    pub(crate) device_hostnames: BTreeMap<DeviceId, String>,
    /// R-DIAG network diagnostics three snapshots (**in-memory state**, same
    /// discipline as `direct_states`): re-reported on every heartbeat and not
    /// persisted — persisting would only add staleness risk. A `None` report
    /// (collection failed) removes the entry.
    pub(crate) diagnostics: BTreeMap<DeviceId, NetworkDiagnostics>,
    /// Tasks (MT-002: dispatch → ack → run → result receipt, with the id as the
    /// idempotency key). Persisted under the same discipline as config revisions
    /// (a restart recovers the task queue, so re-dispatch after a disconnect
    /// loses nothing and duplicates nothing).
    pub(crate) tasks: HashMap<String, crate::task::TaskRecord>,
    /// Task id sequence (`task-{seq}`, persisted to `mesh_meta.task_seq`;
    /// deleted ids are never reused; an explicit idempotency id does not consume
    /// the sequence).
    pub(crate) task_seq: u64,
}

impl MeshState {
    pub fn new(presence_thresholds: meshlet_domain::PresenceThresholds) -> Self {
        Self {
            deployments: HashMap::new(),
            networks: HashMap::new(),
            invites: HashMap::new(),
            ipams: HashMap::new(),
            registry: DeviceRegistry::new(),
            lan_routes: HashMap::new(),
            aliases: HashMap::new(),
            publishes: HashMap::new(),
            segments: HashMap::new(),
            grants: HashMap::new(),
            route_seq: 0,
            publish_seq: 0,
            presence_thresholds,
            ledger: meshlet_domain::ConfigLedger::new(),
            bootstrap_tokens: HashMap::new(),
            bootstrap_seq: 0,
            registration_seq: 0,
            direct_states: BTreeMap::new(),
            device_hostnames: BTreeMap::new(),
            diagnostics: BTreeMap::new(),
            tasks: HashMap::new(),
            task_seq: 0,
        }
    }

    pub(crate) fn network(&self, id: &str) -> Result<&Network, ServiceError> {
        self.networks
            .get(id)
            .ok_or_else(|| ServiceError::NetworkNotFound(id.to_string()))
    }

    // -- Persistence support (§17.3) -------------------------------------------
    // Write path: after the handler finishes the state change inside the lock,
    // these read-only accessors extract the rows that need persisting (cloned),
    // and SQLite is written outside the lock. Startup path: `restore_*` pours
    // the DB rows back into state.

    /// Network row (shared by persistence/rebuild; returns `None` when absent).
    pub(crate) fn network_row(&self, id: &str) -> Option<&Network> {
        self.networks.get(id)
    }

    /// Network hub address (the first IPAM address; used for dataplane wiring, returns `None` when absent).
    pub(crate) fn hub_address(&self, id: &str) -> Option<std::net::Ipv4Addr> {
        self.ipams.get(id).map(|ipam| ipam.hub_address())
    }

    /// Invite row (located by token digest; enroll writes `used_count` back through it after redemption).
    pub(crate) fn invite_by_hash(&self, token_hash: &str) -> Option<&Invite> {
        self.invites.get(token_hash)
    }

    /// All invites (startup rebuild).
    pub(crate) fn invites(&self) -> impl Iterator<Item = &Invite> {
        self.invites.values()
    }

    /// Current route id sequence (persisted to `mesh_meta`; never resets to zero and never reissues numbers across restarts).
    pub(crate) fn route_seq(&self) -> u64 {
        self.route_seq
    }

    /// Current publish object id sequence (persisted to `mesh_meta`; never resets to zero and never reissues numbers across restarts).
    pub(crate) fn publish_seq(&self) -> u64 {
        self.publish_seq
    }

    /// Current task id sequence (persisted to `mesh_meta.task_seq`; never resets to zero and never reissues numbers across restarts).
    pub(crate) fn task_seq(&self) -> u64 {
        self.task_seq
    }

    pub(crate) fn set_task_seq(&mut self, seq: u64) {
        self.task_seq = seq;
    }

    pub(crate) fn set_publish_seq(&mut self, seq: u64) {
        self.publish_seq = seq;
    }

    /// Current bootstrap token sequence (persisted to `mesh_meta`).
    pub(crate) fn bootstrap_seq(&self) -> u64 {
        self.bootstrap_seq
    }

    pub(crate) fn set_bootstrap_seq(&mut self, seq: u64) {
        self.bootstrap_seq = seq;
    }

    /// Current registration request sequence (persisted to `mesh_meta`).
    pub(crate) fn registration_seq(&self) -> u64 {
        self.registration_seq
    }

    pub(crate) fn set_registration_seq(&mut self, seq: u64) {
        self.registration_seq = seq;
    }

    pub(crate) fn registration_count(&self) -> usize {
        self.registry.registrations().len()
    }

    pub(crate) fn segment_count(&self) -> usize {
        self.segments.values().map(Vec::len).sum()
    }

    pub(crate) fn segments(&self, network_id: &str) -> &[Segment] {
        self.segments
            .get(network_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub(crate) fn segment_grants(&self, network_id: &str) -> &[SegmentGrant] {
        self.grants
            .get(network_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub(crate) fn segment_grant_count(&self) -> usize {
        self.grants.values().map(Vec::len).sum()
    }

    /// Startup rebuild: pour back one pending registration request (it does not enter IPAM or the desired config).
    pub(crate) fn restore_registration(
        &mut self,
        r: DeviceRegistration,
    ) -> Result<(), ServiceError> {
        self.registry
            .add_registration(r)
            .map_err(ServiceError::from)
    }

    /// Startup rebuild (§17.3): pour back one network and its IPAM (the hub is
    /// recomputed and addresses are kept one by one — a revoked device's virtual
    /// IP still occupies its slot, matching runtime semantics).
    pub(crate) fn restore_network(&mut self, network: Network) -> Result<(), ServiceError> {
        let hub = network
            .overlay_cidr
            .iter_usable()
            .next()
            .expect("overlay has at least one usable address");
        let ipam = Ipam::new(network.overlay_cidr, hub)
            .map_err(|e| ServiceError::Internal(e.to_string()))?;
        let id = network.id.to_string();
        self.networks.insert(id.clone(), network);
        self.ipams.insert(id, ipam);
        Ok(())
    }

    /// Startup rebuild: pour back one device (IPAM keeps its virtual IP; the registry dedupes as usual).
    pub(crate) fn restore_device(&mut self, device: Device) -> Result<(), ServiceError> {
        let segments = self
            .segments
            .get(&device.network_id.to_string())
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let network = self
            .networks
            .get(&device.network_id.to_string())
            .ok_or_else(|| ServiceError::Internal("network missing for device restore".into()))?;
        meshlet_domain::validate_device_segment(
            device.virtual_ipv4,
            &device.network_id,
            &device.segment_id,
            network.overlay_cidr,
            segments,
        )
        .map_err(|e| ServiceError::Internal(e.to_string()))?;
        let ipam = self
            .ipams
            .get_mut(&device.network_id.to_string())
            .ok_or_else(|| ServiceError::Internal("ipam missing for restore".to_string()))?;
        ipam.allocate_specific(device.virtual_ipv4)
            .map_err(|e| ServiceError::Internal(e.to_string()))?;
        self.registry.add(device).map_err(ServiceError::from)
    }

    /// Startup rebuild: pour back one LAN route.
    pub(crate) fn restore_route(&mut self, route: LanRoute) {
        self.lan_routes
            .entry(route.network_id.to_string())
            .or_default()
            .push(route);
    }

    /// Startup rebuild: pour back one Alias mapping.
    pub(crate) fn restore_alias(&mut self, alias: AliasMapping) {
        self.aliases
            .entry(alias.network_id.to_string())
            .or_default()
            .push(alias);
    }

    pub(crate) fn restore_segment(&mut self, segment: Segment) -> Result<(), ServiceError> {
        let network = self
            .networks
            .get(&segment.network_id.to_string())
            .ok_or_else(|| ServiceError::Internal("network missing for segment restore".into()))?;
        segment
            .validate_cidr(network.overlay_cidr)
            .map_err(|e| ServiceError::Internal(e.to_string()))?;
        self.segments
            .entry(segment.network_id.to_string())
            .or_default()
            .push(segment);
        Ok(())
    }

    pub(crate) fn restore_segment_grant(
        &mut self,
        grant: SegmentGrant,
    ) -> Result<(), ServiceError> {
        let segments = self
            .segments
            .get(&grant.network_id.to_string())
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if !segments
            .iter()
            .any(|segment| segment.id == grant.source_segment_id)
            || !segments
                .iter()
                .any(|segment| segment.id == grant.destination_segment_id)
        {
            return Err(ServiceError::Internal(
                "segment grant references an unknown segment".into(),
            ));
        }
        self.grants
            .entry(grant.network_id.to_string())
            .or_default()
            .push(grant);
        Ok(())
    }

    /// Startup rebuild: pour back one invite (digest indexed; revoked/exhausted state is preserved as usual).
    pub(crate) fn restore_invite(&mut self, invite: Invite) {
        self.invites.insert(invite.token_hash.clone(), invite);
    }

    /// Startup rebuild: restore the route id sequence (deleted ids are never reused).
    pub(crate) fn set_route_seq(&mut self, seq: u64) {
        self.route_seq = seq;
    }

    // -- Startup summary counts (for BootState logging / test assertions) ------

    pub(crate) fn network_count(&self) -> usize {
        self.networks.len()
    }

    pub(crate) fn device_count(&self) -> usize {
        self.registry.devices().len()
    }

    pub(crate) fn route_count(&self) -> usize {
        self.lan_routes.values().map(Vec::len).sum()
    }

    pub(crate) fn alias_count(&self) -> usize {
        self.aliases.values().map(Vec::len).sum()
    }

    /// For startup rebuild: every registered route id (used to detect orphan Alias rows).
    pub(crate) fn bound_route_ids(&self) -> std::collections::HashSet<String> {
        self.lan_routes
            .values()
            .flat_map(|rs| rs.iter().map(|r| r.id.to_string()))
            .collect()
    }

    pub(crate) fn invite_count(&self) -> usize {
        self.invites.len()
    }

    pub(crate) fn revision_count(&self) -> usize {
        self.networks
            .keys()
            .map(|id| {
                self.ledger
                    .revisions(&meshlet_domain::NetworkId(id.clone()))
                    .len()
            })
            .sum()
    }
}

/// Network existence check (for reuse by other modules; a missing network → 404).
pub fn require_network(state: &MeshState, network_id: &str) -> Result<(), ServiceError> {
    state.network(network_id).map(|_| ())
}

/// Result of settling desired-item status: the route/mapping ids whose status
/// **changed**, together with the new status (for persistence).
#[derive(Debug, Default, Clone)]
pub struct DesiredStateSettle {
    pub routes: Vec<(String, DesiredStateStatus)>,
    pub aliases: Vec<(String, DesiredStateStatus)>,
}

/// Converge the outcome of one apply / rollback into each desired item's
/// `status` (the route/mapping layer mirror of §10.1's "writing to the DB is
/// not the same as being in effect").
///
/// - `applied = true` (the backend successfully pushed the config into the
///   kernel): routes whose gateway device is Active move to `Applied`, and the
///   aliases bound to them move to `Applied` in step — only now are these
///   prefixes genuinely usable by the agent dataplane
///   ([`meshlet_domain::peer_routes`] adopts only `Applied`);
/// - The gateway device is not Active (no peer to send to), or the apply failed
///   / was rolled back: move to `Failed` — the failure stays visible, and the
///   agent plan drops these prefixes, so it does not keep forwarding under a
///   config that never took effect;
/// - Unchanged status is not reported (an idempotent replay produces no
///   pointless writes to the DB).
pub fn settle_desired_state(
    state: &mut MeshState,
    network_id: &str,
    applied: bool,
) -> DesiredStateSettle {
    settle_desired_with_status(
        state,
        network_id,
        if applied {
            DesiredStateStatus::Applied
        } else {
            DesiredStateStatus::Failed
        },
    )
}

pub fn settle_desired_with_status(
    state: &mut MeshState,
    network_id: &str,
    status: DesiredStateStatus,
) -> DesiredStateSettle {
    let mut settle = DesiredStateSettle::default();
    // First compute each route's gateway availability and target status under an immutable borrow, then write everything back in one pass.
    let wanted: Vec<(String, bool, DesiredStateStatus)> = state
        .lan_routes
        .get(network_id)
        .map(|routes| {
            routes
                .iter()
                .map(|r| {
                    let gateway_ready = state
                        .registry
                        .find_by_id(&r.gateway_device_id)
                        .map(|d| d.is_active())
                        .unwrap_or(false);
                    let want = if gateway_ready {
                        status
                    } else {
                        DesiredStateStatus::Failed
                    };
                    (r.id.to_string(), r.status == want, want)
                })
                .collect()
        })
        .unwrap_or_default();
    if let Some(routes) = state.lan_routes.get_mut(network_id) {
        for (id, _, want) in &wanted {
            if let Some(route) = routes.iter_mut().find(|r| r.id.to_string() == *id) {
                if route.status != *want {
                    route.status = *want;
                    settle.routes.push((id.clone(), *want));
                }
            }
        }
    }
    // An Alias follows its bound route: if the route is in effect the mapping is in effect, otherwise the mapping is `Failed` (the translation was never pushed).
    let route_status: HashMap<String, DesiredStateStatus> = state
        .lan_routes
        .get(network_id)
        .map(|routes| {
            routes
                .iter()
                .map(|r| (r.id.to_string(), r.status))
                .collect()
        })
        .unwrap_or_default();
    if let Some(aliases) = state.aliases.get_mut(network_id) {
        for alias in aliases.iter_mut() {
            let want = match route_status.get(&alias.lan_route_id.to_string()) {
                Some(status) => *status,
                _ => DesiredStateStatus::Failed,
            };
            if alias.status != want {
                alias.status = want;
                settle.aliases.push((alias.id.to_string(), want));
            }
        }
    }
    settle
}

impl Default for MeshState {
    fn default() -> Self {
        Self::new(meshlet_domain::PresenceThresholds::default())
    }
}
