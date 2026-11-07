//! Direct peer views.

use std::collections::BTreeMap;

use meshlet_domain::DirectLinkStatus;
use meshlet_network::dial::DirectPeerView;

/// 候选集 + 链路状态 → 直连对端视图（纯函数，可测）。候选已直连/待握手取
/// 链路状态；候选无路径（不在链路状态里）标 `hub_relay`（可拨号目标）。
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
