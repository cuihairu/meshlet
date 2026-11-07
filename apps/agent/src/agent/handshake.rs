//! Handshake age projection.

use std::collections::BTreeMap;

use meshlet_network::NetworkDiagnostics;

/// 诊断 dump → 握手年龄（纯函数）：`wg dump` 每 peer 的最近握手 Unix 秒翻译
/// 成「距今秒」。`last_handshake <= 0`（从未握手）或晚于当前时钟（时钟回拨）
/// 的行丢弃——证据缺失不臆造。
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
