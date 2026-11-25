//! In-memory records for published objects (the shared shape of the DB rows,
//! the in-memory state and the device plan).

use crate::service::MeshState;
use meshlet_publish::health::{HealthState, ProbeTarget};
use meshlet_publish::{AuthorizationPolicy, ForwardProtocol};

/// L4 port forward: `policy` goes into the plan as-is (consumed directly by
/// [`meshlet_publish`] on the agent side); in the DB, CIDRs and tokens are
/// stored as JSON.
#[derive(Debug, Clone)]
pub struct PublishForward {
    pub id: String,
    pub network_id: String,
    pub device_id: String,
    pub protocol: ForwardProtocol,
    pub listener_address: std::net::SocketAddr,
    pub backend_address: std::net::SocketAddr,
    pub policy: AuthorizationPolicy,
    pub enabled: bool,
    pub created_at: String,
}

/// HTTP route: `(hostname, path_prefix)` is unique within a network.
#[derive(Debug, Clone)]
pub struct PublishHttpRoute {
    pub id: String,
    pub network_id: String,
    pub device_id: String,
    pub hostname: String,
    pub path_prefix: String,
    pub backend_address: std::net::SocketAddr,
    pub listener_address: std::net::SocketAddr,
    pub policy: AuthorizationPolicy,
    pub tls_passthrough: bool,
    pub created_at: String,
}

/// Health probe: flat fields (one-to-one with the DB columns), assembled into
/// a [`ProbeTarget`] by `target()`; the most recent result lives in memory
/// (`last_*`) and is updated after the agent reports in.
#[derive(Debug, Clone)]
pub struct PublishProbe {
    pub id: String,
    pub network_id: String,
    pub device_id: String,
    pub target: ProbeTarget,
    pub interval_secs: u64,
    pub enabled: bool,
    pub created_at: String,
    pub last_state: Option<HealthState>,
    pub last_checked_at: Option<String>,
    pub last_detail: Option<String>,
}

impl PublishProbe {
    pub fn target(&self) -> ProbeTarget {
        self.target.clone()
    }
}

/// Split-horizon DNS record: `name` must fall inside the device socket's
/// `internal_suffix` (domain-layer validation); one
/// `(bind_address, internal_suffix)` per device.
#[derive(Debug, Clone)]
pub struct PublishDnsRecord {
    pub id: String,
    pub network_id: String,
    pub device_id: String,
    pub name: String,
    pub address: std::net::Ipv4Addr,
    pub ttl: u32,
    pub priority: u16,
    pub bind_address: std::net::SocketAddr,
    pub internal_suffix: String,
    pub created_at: String,
}

/// All published objects of one network. Loaded back by `persist::load` at
/// startup, filtered per device when building the plan.
#[derive(Debug, Clone, Default)]
pub struct PublishCatalog {
    pub forwards: Vec<PublishForward>,
    pub http_routes: Vec<PublishHttpRoute>,
    pub probes: Vec<PublishProbe>,
    pub dns_records: Vec<PublishDnsRecord>,
}

impl MeshState {
    /// Startup restore: load back one published object (foreign keys are already
    /// enforced in the DB, so the network/device must exist).
    pub(crate) fn restore_publish_forward(&mut self, forward: PublishForward) {
        self.publishes
            .entry(forward.network_id.clone())
            .or_default()
            .forwards
            .push(forward);
    }

    pub(crate) fn restore_publish_http_route(&mut self, route: PublishHttpRoute) {
        self.publishes
            .entry(route.network_id.clone())
            .or_default()
            .http_routes
            .push(route);
    }

    pub(crate) fn restore_publish_probe(&mut self, probe: PublishProbe) {
        self.publishes
            .entry(probe.network_id.clone())
            .or_default()
            .probes
            .push(probe);
    }

    pub(crate) fn restore_publish_dns_record(&mut self, record: PublishDnsRecord) {
        self.publishes
            .entry(record.network_id.clone())
            .or_default()
            .dns_records
            .push(record);
    }
}

/// For the startup summary: total number of published objects (the sum of the
/// four kinds).
pub(crate) fn publish_object_count(state: &MeshState) -> usize {
    state
        .publishes
        .values()
        .map(|c| c.forwards.len() + c.http_routes.len() + c.probes.len() + c.dns_records.len())
        .sum()
}
