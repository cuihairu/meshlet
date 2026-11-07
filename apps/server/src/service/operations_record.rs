//! Desired-config revision bookkeeping shared by resource operations.

use meshlet_domain::Device;

use crate::service::{error::ServiceError, shared::now, state::MeshState};

/// Record a desired-config revision from the current network snapshot.
pub(crate) fn record_revision(
    state: &mut MeshState,
    network_id: &str,
) -> Result<u64, ServiceError> {
    let overlay = state.network(network_id)?.overlay_cidr;
    let ipam = state
        .ipams
        .get(network_id)
        .ok_or_else(|| ServiceError::Internal("ipam missing".to_string()))?;
    let devices: Vec<Device> = state
        .registry
        .devices()
        .iter()
        .filter(|d| d.network_id.to_string() == network_id)
        .cloned()
        .collect();
    let routes = state
        .lan_routes
        .get(network_id)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let aliases = state
        .aliases
        .get(network_id)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let hash = meshlet_domain::desired_config_hash(
        &overlay,
        ipam.hub_address(),
        &devices,
        routes,
        aliases,
        state.segment_grants(network_id),
    );
    Ok(state.ledger.record(
        &meshlet_domain::NetworkId(network_id.to_string()),
        hash,
        now(),
    ))
}
