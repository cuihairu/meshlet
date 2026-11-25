//! Diagnostics carrier types (R-DIAG, split out from lib.rs): the Serde types
//! behind structured diagnostic snapshots; the crate root re-exports them to
//! keep the `meshlet_network::{NetworkDiagnostics, ...}` path intact.

/// Network diagnostics information surface (R-DIAG, 2026-11-01 user directive):
/// **structured** carriers for three kinds of snapshot — the agent's local route
/// table, the interface inventory, and wg-mlt readings. The agent collects them
/// (per-platform [crate::NetworkBackend] implementations; on Linux the existing
/// `ip route` / `wg show dump` parsers are reused, not rewritten) and reports
/// them to the server with the heartbeat; the console diagnostics page and the
/// CLI `meshlet agent diag` render from them.
///
/// Discipline shared with [crate::NetworkSnapshot]: real state that cannot be read
/// is reported as `None` / an empty array (missing evidence stays visible);
/// never guess a default value.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct NetworkDiagnostics {
    /// Collection time (agent-local ISO-8601); `None` = collection incomplete.
    pub collected_at: Option<String>,
    /// Full route tables (raw Linux `ip route show table all` / Windows `route print`).
    /// Kept verbatim so it can be diffed line by line against the real routing table;
    /// empty = not obtained.
    pub route_table: Vec<String>,
    /// Interface inventory (name + IPv4 address/prefix + state + MTU).
    pub interfaces: Vec<InterfaceDiagnostic>,
    /// wg-mlt interface readings (`wg show dump` parsed; one entry per peer).
    pub wg: Vec<WgPeerDiagnostic>,
}

/// One interface diagnostic entry (R-DIAG "interface inventory: includes address/state/MTU").
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct InterfaceDiagnostic {
    pub name: String,
    /// IPv4 address (dotted notation); empty string when there is no IPv4 address.
    pub ipv4: String,
    /// Prefix length (0–32); `None` when not obtained.
    pub prefix: Option<u8>,
    /// `up` / `down` / `unknown` (on Linux from the `ip link` UP flag, on
    /// Windows from the InterfaceOperationalStatus of `Get-NetIPConfiguration`).
    pub state: String,
    /// Interface MTU (bytes); `None` = not obtained.
    pub mtu: Option<u32>,
}

/// One wg-mlt interface reading (R-DIAG "wg show: peer/handshake/traffic").
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct WgPeerDiagnostic {
    pub public_key: String,
    /// Peer endpoint (`ip:port`); empty = not configured.
    pub endpoint: String,
    /// Peer AllowedIPs (comma-separated CIDR string).
    pub allowed_ips: String,
    /// Most recent handshake time (Unix seconds); 0 = no handshake ever.
    pub last_handshake: u64,
    /// Cumulative received bytes (`transfer-rx`).
    pub rx_bytes: u64,
    /// Cumulative sent bytes (`transfer-tx`).
    pub tx_bytes: u64,
}
