//! Handshake age projection.

use std::collections::BTreeMap;

use meshlet_network::NetworkDiagnostics;

/// Diagnostic dump -> handshake age (pure function): translate each peer's
/// most-recent-handshake Unix seconds from `wg dump` into "seconds ago". Rows
/// with `last_handshake <= 0` (never handshook) or later than the current clock
/// (clock rolled back) are dropped - missing evidence is never invented.
pub(super) fn dump_handshake_ages(
    net: Option<&NetworkDiagnostics>,
    now_secs: u64,
) -> BTreeMap<String, u64> {
    let Some(net) = net else {
        return BTreeMap::new();
    };
    net.wg
        .iter()
        .filter(|p| p.last_handshake > 0 && p.last_handshake <= now_secs)
        .map(|p| (p.public_key.clone(), now_secs - p.last_handshake))
        .collect()
}
