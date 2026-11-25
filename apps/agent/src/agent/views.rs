//! Direct peer views.

use std::collections::BTreeMap;

use meshlet_domain::DirectLinkStatus;
use meshlet_network::dial::DirectPeerView;

/// Candidate set + link status -> direct peer view (pure function, testable).
/// Candidates that are direct or pending-handshake take the link status; candidates
/// without a path (absent from the link status) are marked `hub_relay` (dialable target).
pub(super) fn direct_peer_views(
    wanted: &[meshlet_domain::PeerEndpoints],
    links: &[DirectLinkStatus],
) -> Vec<DirectPeerView> {
    let by_key: BTreeMap<&str, &DirectLinkStatus> =
        links.iter().map(|l| (l.public_key.as_str(), l)).collect();
    wanted
        .iter()
        .map(|c| {
            let link = by_key.get(c.public_key.as_str());
            DirectPeerView {
                name: c.name.clone(),
                device_id: c.device_id.to_string(),
                virtual_ipv4: c.virtual_ipv4,
                public_key: c.public_key.clone(),
                mode: link
                    .map(|l| l.connection_mode.clone())
                    .unwrap_or_else(|| "hub_relay".into()),
                rtt_ms: link.and_then(|l| l.rtt_ms),
                rtt_source: link.and_then(|l| l.rtt_source.clone()),
                endpoint: link.map(|l| l.endpoint.clone()).unwrap_or_default(),
                last_handshake_at: link.and_then(|l| l.last_handshake_at),
            }
        })
        .collect()
}
