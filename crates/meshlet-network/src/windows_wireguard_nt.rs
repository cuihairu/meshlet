//! wireguard-nt embedded bindings — plan layer ([ADR-008](../../../docs/decisions/adr-008-windows-network-backend.md)
//! review candidate model, pre-work before the spike described in the
//! [analysis doc](../../../docs/design/userspace-wireguard-analysis.md)).
//!
//! Target model: drop the `wireguard.exe` tunnel service layer (one
//! `WireGuardTunnel$<name>` Windows service per tunnel) and let a single
//! agent process create N WireGuardNT adapters directly via
//! `wireguard_nt::Adapter::create` — **one adapter per network**
//! (`wg-mlt-<handle>`). The cost of many networks drops from one Windows
//! service to one Rust object, which eliminates service singleton
//! contention (analysis doc §1.2: a later-installed service's conf
//! overwrites an earlier service's peer table, and 51820 collides on bind).
//!
//! Layering (same discipline as [windows_tunnel]):
//!
//! - **Plan layer** (compiles and unit-tests on any platform): the pure
//!   conversion [TunnelConfig] -> [NtInterfacePlan] plus name/port
//!   guarding ([nt_interface_plan]).
//! - **Apply-spec layer** (compiles and unit-tests on any platform):
//!   [NtInterfacePlan] -> [NtApplySpec] — keys base64-decoded to 32
//!   bytes, MTU guarding, and `private_key: None` passed through
//!   untouched ([nt_apply_spec]).
//! - **`#[cfg(windows)]` execution layer**: dll loading ([nt_dll_path])
//!   and [NtRuntime] — open-or-create adapter, `set_config` -> `up` ->
//!   address + route assembly -> `get_config` read-back (the sequence
//!   verified by the on-machine PoC, wgnt-step12-2026-11-21 8/8 PASS).
//!   The host CI does not run Windows tests; this layer is compile-
//!   verified through windows-gnu cross clippy/check, and the field
//!   mapping stays a mechanical transcription (all semantic decisions
//!   happen in the spec layer).
//!
//! Premise (recorded with the ADR-008 review): wireguard.dll **must ship
//! with meshlet** (the official WireGuard for Windows install does not
//! include the dll; the tunnel is statically linked into the exe). See
//! [nt_dll_candidates] for the candidate search order; binding crate
//! 0.5.0 against the official wireguard-nt 1.1 amd64 dll works on a real
//! machine (PoC evidence, driver version 65537). The backend wiring batch
//! has already hooked this module into [crate::windows] backend
//! dispatch (when `tunnel_backend = "nt"` it assembles through
//! [NtRuntime]; the default remains the service model) — the three
//! production hosts still run the wireguard.exe service model, and the
//! switch waits on PoC acceptance plus user sign-off.
//!
//! Discipline (carried from [windows_tunnel] / ADR-010):
//!
//! - **fail closed (port)**: reject when [TunnelConfig::listen_port] is
//!   `None` — wireguard-nt's `SetInterface.listen_port: None` does not
//!   mean "let the OS pick a port" but **falls back to default 51820**
//!   (evidenced in the crate field docs), which will collide across
//!   multiple networks; ports must be explicitly assigned by the agent
//!   per network (analysis doc §2.5), and the effective value is judged
//!   by the `Adapter::get_config()` read-back (report the read-back
//!   value, never the requested one). See [nt_listen_port].
//! - **fail closed (peer)**: `SetPeer.endpoint` is a mandatory
//!   `SocketAddr` (no room for Option), so a peer without an endpoint or
//!   with an unparseable one is rejected outright; a
//!   `persistent_keepalive_secs` beyond the `u16` ceiling is rejected
//!   (`SetPeer.keep_alive: Option<u16>`), never silently truncated.
//! - **name guarding**: the adapter name is `wg-mlt-<handle>`, total
//!   length <=15 (the same rule as the Linux-side iface ceiling,
//!   symmetric across platforms, see [nt_adapter_name]); the character
//!   whitelist matches the Linux-side `apply_tunnel_sync` (alphanumerics
//!   and `_-`). Note that the wireguard-nt crate's own `MAX_NAME` is
//!   256 (at the UTF-16 encoding layer), not this constraint — this
//!   constraint comes from the generic network interface name ceiling.
//! - **private key boundary (ADR-010)**: [NtInterfacePlan::private_key]
//!   only passes through [TunnelConfig::private_key] (`None` = keep the
//!   existing key, idempotent re-apply, isomorphic to the `None` contract
//!   of the Linux-side `apply_tunnel_sync`); the hand-written
//!   [std::fmt::Debug] impl redacts the key field, so plan objects can
//!   safely enter logs. The driver semantics of
//!   `SetInterface.private_key: None` are anchored from the crate
//!   source: `set_config` assembles a **bit flag** (`None` -> the
//!   `HAS_PRIVATE_KEY` bit is not set -> the driver keeps the existing
//!   private key without clearing it) — the spec layer
//!   [nt_apply_spec] anchors that contract with a `None -> None`
//!   pass-through test; **the on-machine behaviour-anchoring PoC remains
//!   a prerequisite for the backend wiring batch** (a todo do-not-enter
//!   clause), and until then `NtRuntime` is not in production dispatch.
//! - **MTU**: wireguard-nt's `SetInterface` has no MTU field; the crate's
//!   `set_default_route` **hardcodes the adapter `NlMtu` to 1420**
//!   (evidenced in source). The spec layer guards on that: a plan MTU
//!   that is not `None` and is not 1420 is rejected outright
//!   ([NT_INTERFACE_MTU]) — never silently apply 1420 and pretend the
//!   plan was honored. meshlet's default plan MTU happens to be 1420
//!   ([crate::DEFAULT_TUNNEL_MTU]); a non-1420 plan (such as PPPoE 1412)
//!   is explicitly rejected on this path rather than misconfigured.
//!   Assembling the MTU to the plan value requires calling
//!   `SetIpInterfaceEntry` yourself, which is work for a later batch and
//!   out of scope here.

use crate::windows_console::NoWindowCommand;
use crate::NetworkError;
use crate::TunnelConfig;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use meshlet_domain::Ipv4Cidr;
use std::fmt;
use std::net::SocketAddr;

/// Adapter name prefix: `wg-mlt-` + the network handle.
const ADAPTER_NAME_PREFIX: &str = "wg-mlt-";
/// Upper bound on the total adapter name length (prefix included). Same
/// value as the Linux-side `apply_tunnel_sync` iface name ceiling, for
/// cross-platform symmetry.
const ADAPTER_NAME_MAX: usize = 15;

/// wireguard-nt plan-layer error: the rejection reasons for the name,
/// port, and peer conversion guards.
///
/// When the execution layer (a later batch) lowers these into
/// [`crate::NetworkError`], it maps per variant; the plan layer keeps
/// its own type so execution semantics do not pollute plan semantics.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NtPlanError {
    #[error("adapter handle is empty")]
    AdapterNameEmpty,
    #[error("adapter name too long: {len} > {max} (prefix {ADAPTER_NAME_PREFIX:?} + handle)")]
    AdapterNameTooLong { len: usize, max: usize },
    #[error("adapter handle has invalid character at {pos}: allowed [A-Za-z0-9_-]")]
    AdapterNameInvalidChar { pos: usize },
    #[error(
        "listen_port is required: wireguard-nt None falls back to default 51820 (port collision across networks)"
    )]
    ListenPortMissing,
    #[error("peer {index}: endpoint is required (SetPeer.endpoint is a mandatory SocketAddr)")]
    PeerEndpointMissing { index: usize },
    #[error("peer {index}: endpoint not parseable as SocketAddr: {raw}")]
    PeerEndpointInvalid { index: usize, raw: String },
    #[error("peer {index}: keepalive {value} exceeds u16 range of SetPeer.keep_alive")]
    PeerKeepAliveTooLarge { index: usize, value: u32 },
}

impl From<NtPlanError> for crate::NetworkError {
    /// Plan-layer guard rejection -> apply rejection (semantics unchanged:
    /// an invalid plan is a rejection, never a silent correction). The
    /// backend dispatch folds this in with `?`.
    fn from(error: NtPlanError) -> Self {
        crate::NetworkError::ApplyRejected(error.to_string())
    }
}

/// wireguard-nt plan for a single peer (the pre-execution transformation
/// of [PeerConfig]).
///
/// Fields correspond one-to-one with wireguard-nt `SetPeer` (public key
/// and keepalive still in plan-layer form: base64 `String` /
/// `Option<u16>`; the binary `[u8; 32]` conversion is deferred to the
/// cfg(windows) execution layer — key bytes should only exist at the
/// moment of execution).
#[derive(Clone, PartialEq, Eq)]
pub struct NtPeerPlan {
    /// Peer public key (base64).
    pub public_key: String,
    /// The peer's UDP-reachable endpoint. **Required** (`SetPeer.endpoint`
    /// is not an Option); missing values are rejected in
    /// [nt_interface_plan].
    pub endpoint: SocketAddr,
    /// AllowedIPs (kept consistent with the target routes, §7.2).
    pub allowed_ips: Vec<Ipv4Cidr>,
    /// Persistent keepalive in seconds; `None` = do not send one.
    pub keep_alive: Option<u16>,
}

impl fmt::Debug for NtPeerPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtPeerPlan")
            .field("public_key", &self.public_key)
            .field("endpoint", &self.endpoint)
            .field("allowed_ips", &self.allowed_ips)
            .field("keep_alive", &self.keep_alive)
            .finish()
    }
}

/// wireguard-nt adapter plan for a single network: the execution form of
/// a [TunnelConfig] after guarding.
///
/// Private key boundary (ADR-010): [private_key](NtInterfacePlan::private_key)
/// exists only locally in the agent; the [Debug](std::fmt::Debug) impl
/// redacts it, so plan objects can safely enter logs.
#[derive(Clone, PartialEq, Eq)]
pub struct NtInterfacePlan {
    /// WireGuardNT adapter name (`wg-mlt-<handle>`, <=15, see
    /// [nt_adapter_name]). One adapter per network — the cure for service
    /// singleton contention.
    pub adapter_name: String,
    /// Explicitly assigned UDP listen port (**not an Option**, see
    /// [nt_listen_port]). The effective value is judged by the execution
    /// layer's `get_config()` read-back.
    pub listen_port: u16,
    /// Interface address (assembled via IP Helper on the Windows side, not
    /// a `SetInterface` field).
    pub address: std::net::Ipv4Addr,
    /// Interface address prefix length.
    pub address_prefix: u8,
    /// MTU intent (`SetInterface` has no such field; the execution layer
    /// assembles it via Windows APIs).
    pub mtu: Option<u32>,
    /// Private key (base64). `None` = keep the existing key (idempotent
    /// re-apply); **redacted by Debug**, never enters logs.
    pub private_key: Option<String>,
    /// Peer plans.
    pub peers: Vec<NtPeerPlan>,
}

impl fmt::Debug for NtInterfacePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtInterfacePlan")
            .field("adapter_name", &self.adapter_name)
            .field("listen_port", &self.listen_port)
            .field("address", &self.address)
            .field("address_prefix", &self.address_prefix)
            .field("mtu", &self.mtu)
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "<redacted>"),
            )
            .field("peers", &self.peers)
            .finish()
    }
}

/// Adapter name guard: `wg-mlt-<handle>`, total length <=15, character
/// whitelist `[A-Za-z0-9_-]` (only the handle part is validated; the
/// prefix is a constant and always valid).
///
/// Fail closed: an empty handle, an over-long total name, or any
/// out-of-whitelist character is rejected. The whitelist matches the
/// Linux-side `apply_tunnel_sync` iface name validation so plan objects
/// keep consistent semantics across platforms.
pub fn nt_adapter_name(handle: &str) -> Result<String, NtPlanError> {
    if handle.is_empty() {
        return Err(NtPlanError::AdapterNameEmpty);
    }
    for (pos, ch) in handle.chars().enumerate() {
        let ok = ch.is_ascii_alphanumeric() || ch == '_' || ch == '-';
        if !ok {
            return Err(NtPlanError::AdapterNameInvalidChar { pos });
        }
    }
    let name = format!("{ADAPTER_NAME_PREFIX}{handle}");
    if name.len() > ADAPTER_NAME_MAX {
        return Err(NtPlanError::AdapterNameTooLong {
            len: name.len(),
            max: ADAPTER_NAME_MAX,
        });
    }
    Ok(name)
}

/// FNV-1a 32-bit (deterministic, dependency-free): short hash for
/// deriving adapter handles.
fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &byte in bytes {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// Production interface name -> adapter handle (<=8 chars, see
/// [nt_adapter_name]).
///
/// Network interface names (`[dataplane] interface`, e.g. the 14-char
/// `meshlet-overlay`) often exceed the adapter handle ceiling (after the
/// `wg-mlt-` prefix only 8 chars remain), so they cannot be used as the
/// handle directly — they must be compressed deterministically: stable
/// across processes and restarts (otherwise restart cannot find the
/// original adapter and creates a duplicate), and distinct interface
/// names must not collapse onto the same handle.
///
/// Rule: keep whitelist characters `[A-Za-z0-9_-]` and replace the rest
/// with `-`; names <=8 chars are used as-is; longer names take the first
/// 4 chars plus the low 16 bits of the full-name FNV-1a as 4 hex digits
/// (8 chars total). The result may be empty (empty interface name) —
/// [nt_adapter_name] fails closed on that.
pub fn nt_adapter_handle(interface: &str) -> String {
    let sanitized: String = interface
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if sanitized.len() <= 8 {
        return sanitized;
    }
    let prefix: String = sanitized.chars().take(4).collect();
    let hash = fnv1a32(interface.as_bytes()) & 0xffff;
    format!("{prefix}{hash:04x}")
}

/// Listen port guard: `None` is rejected.
///
/// wireguard-nt's `SetInterface.listen_port: None` falls back to the
/// default 51820 (evidenced in the crate field docs) — it is not "let
/// the OS pick a port"; with multiple networks a second adapter would
/// inevitably collide on bind (same root as the 0xc0000022 seen in the
/// service model era). Ports must be explicitly assigned by the agent
/// per network.
pub fn nt_listen_port(listen_port: Option<u16>) -> Result<u16, NtPlanError> {
    listen_port.ok_or(NtPlanError::ListenPortMissing)
}

/// Peer plan conversion: `PeerConfig` -> [NtPeerPlan], fail closed.
///
/// - endpoint missing / unparseable -> reject (`SetPeer.endpoint` is
///   mandatory);
/// - keepalive beyond `u16` -> reject (never silently truncated);
/// - `allowed_ips` passed through (IPv4 CIDRs are already canonical).
fn nt_peer_plan(peer: &crate::PeerConfig, index: usize) -> Result<NtPeerPlan, NtPlanError> {
    let endpoint = match peer.endpoint.as_deref() {
        None => return Err(NtPlanError::PeerEndpointMissing { index }),
        Some(raw) => {
            raw.trim()
                .parse::<SocketAddr>()
                .map_err(|_| NtPlanError::PeerEndpointInvalid {
                    index,
                    raw: raw.to_string(),
                })?
        }
    };
    let keep_alive = match peer.persistent_keepalive_secs {
        None => None,
        Some(v) if v <= u16::MAX as u32 => Some(v as u16),
        Some(v) => return Err(NtPlanError::PeerKeepAliveTooLarge { index, value: v }),
    };
    Ok(NtPeerPlan {
        public_key: peer.public_key.clone(),
        endpoint,
        allowed_ips: peer.allowed_ips.clone(),
        keep_alive,
    })
}

/// Plan conversion: [TunnelConfig] -> [NtInterfacePlan] (pure function,
/// works on any platform).
///
/// Fully fail closed: a `None` port is rejected, missing/bad peer
/// endpoints are rejected, out-of-range keepalive is rejected, and an
/// invalid adapter name is rejected (the `handle` input goes through
/// [nt_adapter_name]). `private_key`/`mtu`/`address` pass through with
/// [TunnelConfig] semantics (`None` private key = keep the existing
/// key).
pub fn nt_interface_plan(
    tunnel: &TunnelConfig,
    handle: &str,
) -> Result<NtInterfacePlan, NtPlanError> {
    let adapter_name = nt_adapter_name(handle)?;
    let listen_port = nt_listen_port(tunnel.listen_port)?;
    let peers = tunnel
        .peers
        .iter()
        .enumerate()
        .map(|(index, peer)| nt_peer_plan(peer, index))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(NtInterfacePlan {
        adapter_name,
        listen_port,
        address: tunnel.address,
        address_prefix: tunnel.address_prefix,
        mtu: tunnel.mtu,
        private_key: tunnel.private_key.clone(),
        peers,
    })
}

// ---------------------------------------------------------------------------
// Apply-spec layer: NtInterfacePlan -> NtApplySpec (compiles and unit-tests
// on any platform).
// ---------------------------------------------------------------------------

/// The value the wireguard-nt crate's `set_default_route` hardcodes for
/// the adapter `NlMtu` (evidenced in source). The apply-spec layer
/// rejects a plan MTU that differs from it; see [nt_apply_spec].
pub const NT_INTERFACE_MTU: u32 = 1420;

/// WireGuard key length in bytes (Curve25519): base64 decoding must
/// produce exactly this length.
const KEY_LEN: usize = 32;

/// base64 key -> 32 bytes. The plan layer holds both public and private
/// keys as base64 strings (isomorphic to the `wg` tool) while the driver
/// API takes `[u8; 32]` — a decode failure or wrong length is rejected
/// outright, never silently truncated or zero-padded.
fn nt_decode_key(raw: &str, what: &str) -> Result<[u8; KEY_LEN], crate::NetworkError> {
    let decoded = BASE64.decode(raw.trim()).map_err(|e| {
        crate::NetworkError::ApplyRejected(format!("{what}: base64 decode failed: {e}"))
    })?;
    decoded.try_into().map_err(|v: Vec<u8>| {
        crate::NetworkError::ApplyRejected(format!(
            "{what}: decoded to {} bytes, expected {KEY_LEN}",
            v.len()
        ))
    })
}

/// Apply spec for a single peer: a neutral form corresponding one-to-one
/// with wireguard-nt `SetPeer` fields (public key already decoded to
/// bytes; preshared_key is unused and always None).
#[derive(Clone, PartialEq, Eq)]
pub struct NtApplyPeerSpec {
    /// Peer public key (32 bytes, base64 already decoded).
    pub public_key: [u8; KEY_LEN],
    /// Peer UDP endpoint (already guarded as mandatory by the plan layer).
    pub endpoint: SocketAddr,
    /// AllowedIPs (canonical `Ipv4Cidr`, the direct source of driver
    /// route targets).
    pub allowed_ips: Vec<Ipv4Cidr>,
    /// Persistent keepalive in seconds; `None` = do not send one.
    pub keep_alive: Option<u16>,
}

impl fmt::Debug for NtApplyPeerSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Public keys are safe for logs (identity fields); there is no key
        // material to redact — the same policy as NtPeerPlan.
        f.debug_struct("NtApplyPeerSpec")
            .field("public_key", &BASE64.encode(self.public_key))
            .field("endpoint", &self.endpoint)
            .field("allowed_ips", &self.allowed_ips)
            .field("keep_alive", &self.keep_alive)
            .finish()
    }
}

/// Apply spec for a single adapter: a neutral form corresponding one-to-
/// one with wireguard-nt `SetInterface` fields. **All semantic decisions
/// (key decoding, MTU guarding, `None` pass-through) are completed in this
/// layer and anchored by host CI unit tests**; assembling `SetInterface`
/// on cfg(windows) is reduced to a mechanical transcription.
#[derive(Clone, PartialEq, Eq)]
pub struct NtApplySpec {
    /// Explicit listen port (the plan layer already guarantees it is not
    /// `None`).
    pub listen_port: u16,
    /// Private key (32 bytes). `None` = **passed through untouched** to
    /// the driver's bit-flag semantics — the `HAS_PRIVATE_KEY` bit stays
    /// unset so the driver keeps the existing private key (the idempotent
    /// re-apply contract, see the module docs private key boundary).
    pub private_key: Option<[u8; KEY_LEN]>,
    /// Peer specs.
    pub peers: Vec<NtApplyPeerSpec>,
}

impl fmt::Debug for NtApplySpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtApplySpec")
            .field("listen_port", &self.listen_port)
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "<redacted>"),
            )
            .field("peers", &self.peers)
            .finish()
    }
}

/// Plan -> apply spec (pure function, works on any platform):
///
/// - public/private keys are base64-decoded; a failure rejects
///   ([nt_decode_key]);
/// - `private_key: None` is passed through untouched (anchoring the
///   driver's bit-level keep semantics);
/// - **MTU guard**: a plan `mtu` that is not `None` and is not
///   [NT_INTERFACE_MTU] is rejected — the crate's address/route assembly
///   hardcodes NlMtu to 1420, so silently accepting a non-1420 plan
///   would be a misconfiguration (see the module docs MTU entry).
pub fn nt_apply_spec(plan: &NtInterfacePlan) -> Result<NtApplySpec, crate::NetworkError> {
    if let Some(mtu) = plan.mtu {
        if mtu != NT_INTERFACE_MTU {
            return Err(crate::NetworkError::ApplyRejected(format!(
                "plan mtu {mtu} != wireguard-nt pinned interface mtu {NT_INTERFACE_MTU}: \
                 the nt path cannot honor a custom mtu yet"
            )));
        }
    }
    let private_key = match plan.private_key.as_deref() {
        None => None,
        Some(raw) => Some(nt_decode_key(raw, "tunnel private_key")?),
    };
    let peers = plan
        .peers
        .iter()
        .enumerate()
        .map(|(index, peer)| {
            Ok(NtApplyPeerSpec {
                public_key: nt_decode_key(&peer.public_key, &format!("peer {index} public_key"))?,
                endpoint: peer.endpoint,
                allowed_ips: peer.allowed_ips.clone(),
                keep_alive: peer.keep_alive,
            })
        })
        .collect::<Result<Vec<_>, crate::NetworkError>>()?;
    Ok(NtApplySpec {
        listen_port: plan.listen_port,
        private_key,
        peers,
    })
}

// ---------------------------------------------------------------------------
// Read-only snapshot layer (cross-platform pure structs; the cfg(windows)
// execution layer builds them from get_config read-backs).
// ---------------------------------------------------------------------------

/// Snapshot reading for a single peer (the read-only view of a
/// [WireguardInterface] read-back).
///
/// The public key stays in byte form — base64 encode/decode belongs to
/// the diagnostics surface (the backend wiring converts to
/// [crate::PeerObserved]), the same boundary discipline as the spec
/// layer's "key bytes exist only at the moment of execution".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtPeerSnapshot {
    /// Peer public key (32 bytes, verbatim from the read-back).
    pub public_key: [u8; 32],
    /// AllowedIPs (canonical from the read-back; V6 entries are dropped
    /// at construction — this layer never sets V6, so seeing one is an
    /// anomaly and dropping it self-heals).
    pub allowed_ips: Vec<Ipv4Cidr>,
}

/// Read-only snapshot for a single adapter (input for inspect / drift
/// reconciliation, [NtRuntime::snapshot]).
///
/// **No MTU or interface address fields** — wireguard-nt `get_config`
/// only reads back listen_port/private_key/public_key/peers (evidenced
/// in the registry source), so MTU and address readings do not exist on
/// [WireguardInterface]. Reconciliation treats those two dimensions as
/// "missing evidence means no verdict" ([crate::device_plan_matches]
/// ④/⑥ only judge when a reading exists) instead of creating a replay
/// loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtAdapterSnapshot {
    /// Effective listen port read back (judge the effective value by the
    /// read-back, not the requested one).
    pub listen_port: u16,
    /// Local public key read back (fingerprint used by reconciliation to
    /// detect "the local private key was swapped").
    pub public_key: [u8; 32],
    /// Peer readings.
    pub peers: Vec<NtPeerSnapshot>,
}

// ---------------------------------------------------------------------------
// dll search order (cross-platform pure function + cfg(windows) concrete
// resolution).
// ---------------------------------------------------------------------------

/// Environment variable override for the dll search (the same entry point
/// used by troubleshooting and the on-machine PoC).
pub const NT_DLL_ENV: &str = "MESHLET_WIREGUARD_NT_DLL";

/// `C:\ProgramData\meshlet\wireguard.dll` — the fixed location in the
/// deploy staging layout.
const NT_DLL_PROGRAMDATA: &str = r"C:\ProgramData\meshlet\wireguard.dll";

/// dll candidate search order (pure function): environment variable
/// override -> the directory next to the exe (MSI/zip layout with the
/// agent binary) -> the ProgramData staging location.
///
/// Candidates only define an **order**, not existence — real-machine
/// resolution ([nt_dll_path]) takes the first candidate that exists, and
/// when none exists it reports the full candidate list (so
/// troubleshooting need not consult the source).
pub fn nt_dll_candidates(
    env_value: Option<&str>,
    exe_dir: Option<&std::path::Path>,
) -> Vec<std::path::PathBuf> {
    let mut candidates = Vec::new();
    if let Some(env) = env_value.map(str::trim).filter(|s| !s.is_empty()) {
        candidates.push(std::path::PathBuf::from(env));
    }
    if let Some(dir) = exe_dir {
        candidates.push(dir.join("wireguard.dll"));
    }
    candidates.push(std::path::PathBuf::from(NT_DLL_PROGRAMDATA));
    candidates
}

// ---------------------------------------------------------------------------
// nt adapter OS alias resolution (cross-platform pure function + real-
// machine PowerShell query).
//
// Evidence for item 1 of the seven-item acceptance
// (wgnt-seven-item-2026-11-21.md): the OS-level InterfaceAlias that
// wireguard-nt gives an adapter is the driver's fixed name `WireGuard`;
// the tunnel name `wg-mlt-<handle>` appears only in InterfaceDescription
// (`<adapter_name> Tunnel`). So no `-InterfaceAlias` / `InterfaceAlias ==`
// match may use `wg-mlt-<handle>` or the managed interface name directly —
// the OS Name must be looked up via InterfaceDescription. Never hardcode
// `WireGuard` (the crate default name, but matching must not depend on
// it).
// ---------------------------------------------------------------------------

/// Look up the OS interface name (Name) from
/// `Get-NetAdapter | Select Name,InterfaceDescription | ConvertTo-Json`
/// output by matching InterfaceDescription.
///
/// Matching rule: InterfaceDescription is an **ASCII case-insensitive**
/// exact match for `"<adapter_name> Tunnel"` (the wireguard-nt naming
/// convention; evidence in the module header). Returns the matching
/// `Name`; malformed JSON / no match -> `None` (the caller handles it
/// under fail-closed semantics, never silently falling through).
/// PowerShell emits a single object as an object and multiple as an
/// array — both are normalized via `Value` (the same pattern as
/// `parse_lan_ip_json`); malformed entries are skipped without blocking
/// later matches.
pub fn os_alias_from_adapter_enum_json(json: &str, adapter_name: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let entries: Vec<&serde_json::Value> = match &value {
        serde_json::Value::Array(items) => items.iter().collect(),
        serde_json::Value::Object(_) => vec![&value],
        _ => return None,
    };
    let needle = format!("{adapter_name} Tunnel");
    for entry in entries {
        let Some(name) = entry.get("Name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(desc) = entry.get("InterfaceDescription").and_then(|v| v.as_str()) else {
            continue;
        };
        if desc.eq_ignore_ascii_case(&needle) {
            return Some(name.to_string());
        }
    }
    None
}

/// Resolve the nt adapter's OS interface name on a real machine: enumerate
/// via `Get-NetAdapter` (field names are English and locale-independent)
/// then look up by InterfaceDescription
/// ([os_alias_from_adapter_enum_json]).
///
/// Fail closed: command failure / adapter missing / malformed JSON ->
/// `Err(ApplyRejected)` (the caller never continues with a wrong name;
/// failing the whole apply is preferable). Effective only on a real
/// Windows machine; compiles cross-platform (the host CI runs windows-gnu
/// cross validation).
pub fn resolve_nt_os_alias(adapter_name: &str) -> Result<String, NetworkError> {
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-NetAdapter | Select-Object Name,InterfaceDescription | \
             ConvertTo-Json -Compress",
        ])
        .no_window()
        .output()
        .map_err(|error| NetworkError::Io(format!("spawn powershell (Get-NetAdapter): {error}")))?;
    if !output.status.success() {
        return Err(NetworkError::ApplyRejected(format!(
            "Get-NetAdapter failed: {}",
            crate::windows_console::decode_output(&output.stderr)
        )));
    }
    let json = crate::windows_console::decode_output(&output.stdout);
    os_alias_from_adapter_enum_json(&json, adapter_name).ok_or_else(|| {
        NetworkError::ApplyRejected(format!(
            "no nt adapter with InterfaceDescription '{adapter_name} Tunnel' in \
             Get-NetAdapter output (is the wireguard-nt adapter up?)"
        ))
    })
}

#[cfg(windows)]
mod exec {
    //! cfg(windows) execution layer: dll loading and [NtRuntime]. All
    //! semantic decisions are completed in the layers above; this module
    //! is reduced to assembly and error mapping. The host CI compile-
    //! verifies it via windows-gnu cross clippy/check (it does not run
    //! tests).

    use super::{
        nt_apply_spec, nt_dll_candidates, NtAdapterSnapshot, NtApplySpec, NtPeerSnapshot, BASE64,
        NT_DLL_ENV,
    };
    use crate::NetworkError;
    use base64::Engine;
    use meshlet_domain::Ipv4Cidr;
    use std::collections::{BTreeMap, HashMap};
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// Adapter pool name (same as the wireguard-nt official example/PoC).
    const NT_ADAPTER_POOL: &str = "WireGuard";

    /// Resolve the dll path on a real machine: see [super::nt_dll_candidates]
    /// for the candidate order and take the first existing file; `None`
    /// when none exists (the caller reports the candidate list).
    pub fn nt_dll_path() -> Option<PathBuf> {
        let env_value = std::env::var_os(NT_DLL_ENV).map(|v| v.to_string_lossy().into_owned());
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(std::path::Path::to_path_buf));
        nt_dll_candidates(env_value.as_deref(), exe_dir.as_deref())
            .into_iter()
            .find(|p| p.is_file())
    }

    /// wireguard-nt crate error -> [NetworkError]: permission errors
    /// (`PermissionDenied`, typically driver install without elevation)
    /// map to InsufficientPrivileges and the rest to Io — so the agent
    /// side can read out directly whether to elevate or to fix the
    /// environment.
    fn nt_map_err(op: &str, err: wireguard_nt::Error) -> NetworkError {
        let denied = match &err {
            wireguard_nt::Error::Driver(e) | wireguard_nt::Error::Windows(_, e) => {
                e.kind() == std::io::ErrorKind::PermissionDenied
            }
            _ => false,
        };
        if denied {
            NetworkError::InsufficientPrivileges(format!("{op}: {err}"))
        } else {
            NetworkError::Io(format!("{op}: {err}"))
        }
    }

    /// Apply spec -> crate `SetInterface` (mechanical transcription, no
    /// semantic decisions).
    ///
    /// `allowed_ips` builds `Ipv4Net` from canonical
    /// [meshlet_domain::Ipv4Cidr] (host bits always zero; deserialization
    /// rejects non-canonical values) — `Ipv4Net::new` can only fail for
    /// prefix > 32, which the domain type already excludes, so the
    /// `expect` is unreachable.
    fn nt_set_interface(spec: &NtApplySpec) -> wireguard_nt::SetInterface {
        wireguard_nt::SetInterface {
            listen_port: Some(spec.listen_port),
            public_key: None,
            private_key: spec.private_key,
            peers: spec
                .peers
                .iter()
                .map(|peer| wireguard_nt::SetPeer {
                    public_key: Some(peer.public_key),
                    preshared_key: None,
                    keep_alive: peer.keep_alive,
                    endpoint: peer.endpoint,
                    allowed_ips: peer
                        .allowed_ips
                        .iter()
                        .map(|cidr| {
                            ipnet::IpNet::V4(
                                ipnet::Ipv4Net::new(cidr.network(), cidr.prefix_len())
                                    .expect("canonical Ipv4Cidr prefix <= 32"),
                            )
                        })
                        .collect(),
                })
                .collect(),
        }
    }

    /// Open-or-create: try `Adapter::open` first (an idempotent open for
    /// an already-existing adapter), and fall back to `Adapter::create`
    /// (a random GUID within the pool) on failure.
    fn nt_open_or_create(
        wireguard: &wireguard_nt::Wireguard,
        adapter_name: &str,
    ) -> Result<wireguard_nt::Adapter, NetworkError> {
        wireguard_nt::Adapter::open(wireguard, adapter_name)
            .or_else(|_| {
                wireguard_nt::Adapter::create(wireguard, NT_ADAPTER_POOL, adapter_name, None)
            })
            .map_err(|e| nt_map_err(&format!("open or create adapter {adapter_name}"), e))
    }

    /// wireguard-nt runtime: **persistently holds** handles to created
    /// adapters for the lifetime of the agent process (the crate's
    /// `Adapter` `Drop` -> `WireGuardCloseAdapter` removes the adapter —
    /// if the handle is not held, the adapter disappears as soon as apply
    /// finishes; the PoC's zero-residue exit is exactly that semantics).
    ///
    /// Assembled through the `nt` dispatch of the [crate::windows]
    /// backend (when `tunnel_backend = "nt"`,
    /// [crate::windows::WindowsNetworkBackend] holds this runtime; the
    /// default service model does not take this path).
    pub struct NtRuntime {
        wireguard: wireguard_nt::Wireguard,
        dll_path: PathBuf,
        /// Adapter name -> persistent handle. apply reuses a held handle
        /// (`Adapter` is not Clone, and reopening a second handle only to
        /// Drop it would manufacture churn).
        adapters: Mutex<HashMap<String, wireguard_nt::Adapter>>,
    }

    impl NtRuntime {
        /// Load wireguard.dll and establish the runtime. See
        /// [super::nt_dll_candidates] for the dll candidate order; when
        /// no candidate exists, report Io carrying the full candidate
        /// list.
        pub fn load() -> Result<Self, NetworkError> {
            let dll_path = nt_dll_path().ok_or_else(|| {
                let env_value = std::env::var_os(NT_DLL_ENV)
                    .map(|v| v.to_string_lossy().into_owned());
                let exe_dir = std::env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(std::path::Path::to_path_buf));
                let searched = nt_dll_candidates(env_value.as_deref(), exe_dir.as_deref())
                    .iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("; ");
                NetworkError::Io(format!(
                    "wireguard.dll not found (ship it beside the agent exe or set {NT_DLL_ENV}); searched: {searched}"
                ))
            })?;
            // SAFETY: the path comes from the fixed candidate order or a
            // controlled environment variable (the module docs shipping
            // discipline), loaded the same way as the PoC.
            let wireguard = unsafe { wireguard_nt::load_from_path(&dll_path) }
                .map_err(|e| NetworkError::Io(format!("load wireguard.dll: {e}")))?;
            Ok(Self {
                wireguard,
                dll_path,
                adapters: Mutex::new(HashMap::new()),
            })
        }

        /// The dll path actually loaded (for diagnostics).
        pub fn dll_path(&self) -> &std::path::Path {
            &self.dll_path
        }

        /// Apply the plan: open-or-create -> `set_config` (replaces the
        /// peer table wholesale; the crate always includes `REPLACE_PEERS`)
        /// -> `up` (the socket is created in the up state; the PoC shows
        /// there is no handshake unless up) -> one-shot address +
        /// allowed_ips route assembly -> `get_config` read-back.
        ///
        /// Returns the **read-back** listen port (plan-layer discipline:
        /// judge the effective value by the read-back, not the requested
        /// one). The assembly sequence matches PoC wg-nt-poc verbatim (the
        /// sequence that passed 8/8 on a real machine).
        pub fn apply(&self, plan: &super::NtInterfacePlan) -> Result<u16, NetworkError> {
            let spec = nt_apply_spec(plan)?;
            let set_interface = nt_set_interface(&spec);
            let addr_net = ipnet::Ipv4Net::new(plan.address, plan.address_prefix)
                .map_err(|_| NetworkError::ApplyRejected("interface address prefix > 32".into()))?;
            let mut adapters = self.adapters.lock().unwrap_or_else(|p| p.into_inner());
            let adapter = match adapters.get_mut(&plan.adapter_name) {
                Some(held) => held,
                None => {
                    let created = nt_open_or_create(&self.wireguard, &plan.adapter_name)?;
                    adapters.insert(plan.adapter_name.clone(), created);
                    adapters
                        .get_mut(&plan.adapter_name)
                        .expect("adapter inserted above")
                }
            };
            adapter
                .set_config(&set_interface)
                .map_err(|e| nt_map_err("adapter set_config", e))?;
            adapter.up().map_err(|e| nt_map_err("adapter up", e))?;
            // Address assignment carries host bits (the interface address
            // 10.x.y.z itself), while route targets come from canonical
            // allowed_ips (host bits always zero) — both constraints are
            // guaranteed by upstream types, so no trunc is needed here
            // (the PoC's trunc lesson was that host bits entering
            // CreateIpForwardEntry2 raise error 87, which a canonical
            // CIDR can never trigger).
            adapter
                .set_default_route(&[ipnet::IpNet::V4(addr_net)], &set_interface)
                .map_err(|e| nt_map_err("assign address and routes", e))?;
            let readback = adapter.get_config();
            Ok(readback.listen_port)
        }

        /// Remove an adapter: take it out of the handle table and Drop it
        /// (-> `WireGuardCloseAdapter`; the adapter dies with its
        /// handle). Returns `false` when it does not exist.
        pub fn remove(&self, adapter_name: &str) -> bool {
            self.adapters
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(adapter_name)
                .is_some()
        }

        /// Names of adapters with currently held handles (for diagnostics;
        /// emitted in stable sorted order).
        pub fn adapter_names(&self) -> Vec<String> {
            let mut names = self
                .adapters
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .keys()
                .cloned()
                .collect::<Vec<_>>();
            names.sort();
            names
        }

        /// `get_config` read-back snapshot for a held adapter (the nt
        /// backend's inspect input). Returns `None` when the adapter is
        /// not held (after a process restart the adapter dies with its
        /// handle, and `tunnel_exists=false` lets reconcile replay it).
        pub fn inspect(&self, adapter_name: &str) -> Option<NtAdapterSnapshot> {
            let adapters = self.adapters.lock().unwrap_or_else(|p| p.into_inner());
            let config = adapters.get(adapter_name)?.get_config();
            Some(NtAdapterSnapshot {
                listen_port: config.listen_port,
                public_key: config.public_key,
                peers: config
                    .peers
                    .iter()
                    .map(|peer| NtPeerSnapshot {
                        public_key: peer.public_key,
                        allowed_ips: peer
                            .allowed_ips
                            .iter()
                            .filter_map(ipnet_v4_to_cidr)
                            .collect(),
                    })
                    .collect(),
            })
        }

        /// Peer handshake ages for a held adapter (public key -> seconds
        /// since handshake, input to the P2P direct-connect decision).
        /// Same semantics as `wg show <if> latest-handshakes` (the
        /// [crate] parser's policy: rows that never handshook or show a
        /// clock going backwards are dropped — missing evidence is not
        /// invented). Returns an error when the adapter is not held (the
        /// direct-connect decision then treats it as no data rather than
        /// pretending).
        pub fn handshake_ages(
            &self,
            adapter_name: &str,
        ) -> Result<BTreeMap<String, u64>, NetworkError> {
            let adapters = self.adapters.lock().unwrap_or_else(|p| p.into_inner());
            let adapter = adapters.get(adapter_name).ok_or_else(|| {
                NetworkError::Io(format!("no held wireguard-nt adapter {adapter_name}"))
            })?;
            let config = adapter.get_config();
            let now = std::time::SystemTime::now();
            Ok(config
                .peers
                .iter()
                .filter_map(|peer| {
                    let last = peer.last_handshake?;
                    let age = now.duration_since(last).ok()?.as_secs();
                    Some((BASE64.encode(peer.public_key), age))
                })
                .collect())
        }
    }

    /// `ipnet::IpNet` -> canonical [Ipv4Cidr] (meshlet is IPv4-only for
    /// now: V6 routes do not appear on the nt path, so filter them
    /// directly).
    fn ipnet_v4_to_cidr(net: &ipnet::IpNet) -> Option<Ipv4Cidr> {
        match net {
            ipnet::IpNet::V4(v4) => Ipv4Cidr::from_host_address(v4.network(), v4.prefix_len()).ok(),
            ipnet::IpNet::V6(_) => None,
        }
    }
}

#[cfg(windows)]
pub use exec::{nt_dll_path, NtRuntime};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PeerConfig;

    fn tunnel() -> TunnelConfig {
        TunnelConfig {
            name: "net-a".into(),
            address: "10.99.1.1".parse().unwrap(),
            address_prefix: 24,
            listen_port: Some(51821),
            peers: vec![peer("pub-a", Some("100.64.0.2:51820"))],
            mtu: Some(1380),
            private_key: Some("secret-key-material".into()),
        }
    }

    fn peer(public_key: &str, endpoint: Option<&str>) -> PeerConfig {
        PeerConfig {
            public_key: public_key.into(),
            allowed_ips: vec!["10.99.2.0/24".parse().unwrap()],
            endpoint: endpoint.map(str::to_string),
            persistent_keepalive_secs: Some(25),
        }
    }

    #[test]
    fn adapter_name_accepts_handle_up_to_15_total() {
        // 7-char prefix + 8-char handle = 15, exactly at the limit.
        assert_eq!(nt_adapter_name("abcdefgh").unwrap(), "wg-mlt-abcdefgh");
        assert_eq!(nt_adapter_name("net1").unwrap(), "wg-mlt-net1");
    }

    #[test]
    fn adapter_name_rejects_oversize_empty_and_bad_chars() {
        // 7 + 9 = 16 > 15.
        assert_eq!(
            nt_adapter_name("abcdefghi"),
            Err(NtPlanError::AdapterNameTooLong { len: 16, max: 15 })
        );
        assert_eq!(nt_adapter_name(""), Err(NtPlanError::AdapterNameEmpty));
        assert_eq!(
            nt_adapter_name("net a"),
            Err(NtPlanError::AdapterNameInvalidChar { pos: 3 })
        );
        // Neither dot nor slash is in the whitelist (path separators never
        // enter interface names).
        assert!(matches!(
            nt_adapter_name("net.a"),
            Err(NtPlanError::AdapterNameInvalidChar { pos: 3 })
        ));
        assert!(matches!(
            nt_adapter_name("net/a"),
            Err(NtPlanError::AdapterNameInvalidChar { pos: 3 })
        ));
    }

    #[test]
    fn adapter_handle_passes_short_names_through() {
        // Names <=8 chars pass through unchanged (no hash distortion,
        // friendly to diagnostics).
        assert_eq!(nt_adapter_handle("meshlet"), "meshlet");
        assert_eq!(nt_adapter_handle("meshlet2"), "meshlet2");
        // Out-of-whitelist characters are replaced with `-`.
        assert_eq!(nt_adapter_handle("mesh.let"), "mesh-let");
        // Empty interface name -> empty handle (nt_adapter_name fails
        // closed on it).
        assert_eq!(nt_adapter_handle(""), "");
    }

    #[test]
    fn adapter_handle_compresses_long_names_deterministically() {
        // Production interface name, 14 chars > 8: compresses to a 4-char
        // prefix + 4 hex hash digits = 8.
        let handle = nt_adapter_handle("meshlet-overlay");
        assert_eq!(
            handle.len(),
            8,
            "long interface must compress to 8 chars: {handle}"
        );
        assert!(
            handle.starts_with("mesh"),
            "prefix preserves the leading chars: {handle}"
        );
        assert!(
            handle
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
            "handle chars must stay in the whitelist: {handle}"
        );
        // Deterministic: same input always yields the same output (stable
        // across restarts so restart does not re-create).
        assert_eq!(nt_adapter_handle("meshlet-overlay"), handle);
        // The full name enters the hash: long names differing only in a
        // suffix do not collapse.
        assert_ne!(
            nt_adapter_handle("meshlet-overlay-1"),
            nt_adapter_handle("meshlet-overlay-2")
        );
        // The compressed adapter name (wg-mlt- + handle) lands exactly at
        // <=15.
        let name = nt_adapter_name(&handle).unwrap();
        assert_eq!(
            name.len(),
            15,
            "compressed adapter name sits at the 15-char limit: {name}"
        );
    }

    #[test]
    fn listen_port_requires_explicit_value() {
        assert_eq!(nt_listen_port(Some(51821)).unwrap(), 51821);
        assert_eq!(nt_listen_port(None), Err(NtPlanError::ListenPortMissing));
    }

    #[test]
    fn interface_plan_maps_fields_and_guards_peers() {
        let plan = nt_interface_plan(&tunnel(), "net-a").unwrap();
        assert_eq!(plan.adapter_name, "wg-mlt-net-a");
        assert_eq!(plan.listen_port, 51821);
        assert_eq!(
            plan.address,
            "10.99.1.1".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(plan.address_prefix, 24);
        assert_eq!(plan.mtu, Some(1380));
        assert_eq!(plan.private_key.as_deref(), Some("secret-key-material"));
        assert_eq!(plan.peers.len(), 1);
        assert_eq!(plan.peers[0].public_key, "pub-a");
        assert_eq!(
            plan.peers[0].endpoint,
            "100.64.0.2:51820".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(plan.peers[0].keep_alive, Some(25));
    }

    #[test]
    fn interface_plan_fails_closed_on_missing_port_and_bad_peers() {
        let mut t = tunnel();
        t.listen_port = None;
        assert_eq!(
            nt_interface_plan(&t, "net-a"),
            Err(NtPlanError::ListenPortMissing)
        );

        let mut t = tunnel();
        t.peers[0].endpoint = None;
        assert_eq!(
            nt_interface_plan(&t, "net-a"),
            Err(NtPlanError::PeerEndpointMissing { index: 0 })
        );

        let mut t = tunnel();
        t.peers[0].endpoint = Some("not-an-endpoint".into());
        assert_eq!(
            nt_interface_plan(&t, "net-a"),
            Err(NtPlanError::PeerEndpointInvalid {
                index: 0,
                raw: "not-an-endpoint".into()
            })
        );

        // Keepalive out of range: u32 65536 cannot fit into u16
        // SetPeer.keep_alive.
        let mut t = tunnel();
        t.peers[0].persistent_keepalive_secs = Some(65_536);
        assert_eq!(
            nt_interface_plan(&t, "net-a"),
            Err(NtPlanError::PeerKeepAliveTooLarge {
                index: 0,
                value: 65_536
            })
        );

        // Adapter name guarding runs before peer validation.
        assert!(matches!(
            nt_interface_plan(&tunnel(), "bad handle"),
            Err(NtPlanError::AdapterNameInvalidChar { pos: 3 })
        ));

        // An empty peers list is legal (an unloaded plan when the hub has
        // not issued peers).
        let mut t = tunnel();
        t.peers.clear();
        assert!(nt_interface_plan(&t, "net-a").unwrap().peers.is_empty());
    }

    #[test]
    fn interface_plan_debug_redacts_private_key() {
        let plan = nt_interface_plan(&tunnel(), "net-a").unwrap();
        let rendered = format!("{plan:?}");
        assert!(!rendered.contains("secret-key-material"));
        assert!(rendered.contains("<redacted>"));
        // Peer plans carry no key material (public keys, endpoints, and
        // allowed_ips are all loggable).
        let peer_rendered = format!("{:?}", plan.peers[0]);
        assert!(peer_rendered.contains("pub-a"));
    }

    #[test]
    fn keepalive_boundary_values_pass() {
        // The u16 ceiling passes exactly, with no silent truncation.
        let mut t = tunnel();
        t.peers[0].persistent_keepalive_secs = Some(u16::MAX as u32);
        let plan = nt_interface_plan(&t, "net-a").unwrap();
        assert_eq!(plan.peers[0].keep_alive, Some(u16::MAX));
    }

    // ----- apply-spec layer -----

    fn valid_key_bytes(seed: u8) -> String {
        BASE64.encode([seed; 32])
    }

    /// Spec-layer fixture: the plan-layer default is `mtu: Some(1380)`
    /// while the spec-layer guard demands 1420 — pin everything to
    /// [NT_INTERFACE_MTU] and let individual tests override it.
    fn spec_tunnel() -> TunnelConfig {
        let mut t = tunnel();
        t.mtu = Some(NT_INTERFACE_MTU);
        t
    }

    #[test]
    fn apply_spec_decodes_keys_and_maps_peers() {
        let mut t = spec_tunnel();
        t.private_key = Some(valid_key_bytes(1));
        t.peers[0].public_key = valid_key_bytes(2);
        let plan = nt_interface_plan(&t, "net-a").unwrap();
        let spec = nt_apply_spec(&plan).unwrap();
        assert_eq!(spec.listen_port, 51821);
        assert_eq!(spec.private_key, Some([1u8; 32]));
        assert_eq!(spec.peers.len(), 1);
        assert_eq!(spec.peers[0].public_key, [2u8; 32]);
        assert_eq!(spec.peers[0].keep_alive, Some(25));
        assert_eq!(
            spec.peers[0].endpoint,
            "100.64.0.2:51820".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn apply_spec_passes_private_key_none_through_untouched() {
        // Anchoring: None -> None passed through untouched. wireguard-nt
        // `set_config` assembles bit flags (None -> the HAS_PRIVATE_KEY
        // bit is not set -> the driver keeps the existing private key,
        // evidenced in the crate source) — the first link in making the
        // idempotent re-apply contract hold across platforms; the
        // on-machine behaviour-anchoring PoC is a prerequisite for the
        // backend wiring batch (a todo do-not-enter clause).
        let mut t = spec_tunnel();
        t.private_key = None;
        t.peers[0].public_key = valid_key_bytes(2);
        let plan = nt_interface_plan(&t, "net-a").unwrap();
        let spec = nt_apply_spec(&plan).unwrap();
        assert!(spec.private_key.is_none());
    }

    #[test]
    fn apply_spec_rejects_undecodable_keys() {
        // Non-base64 / wrong length / empty string; private keys follow
        // the same rule as peer public keys.
        let mut t = spec_tunnel();
        t.private_key = Some("not-base64!!".into());
        t.peers[0].public_key = valid_key_bytes(2);
        let plan = nt_interface_plan(&t, "net-a").unwrap();
        assert!(matches!(
            nt_apply_spec(&plan),
            Err(crate::NetworkError::ApplyRejected(msg))
                if msg.contains("private_key") && msg.contains("base64")
        ));

        let mut t = spec_tunnel();
        t.private_key = Some(valid_key_bytes(1));
        t.peers[0].public_key = BASE64.encode([9u8; 4]); // valid base64, wrong length
        let plan = nt_interface_plan(&t, "net-a").unwrap();
        assert!(matches!(
            nt_apply_spec(&plan),
            Err(crate::NetworkError::ApplyRejected(msg))
                if msg.contains("peer 0") && msg.contains("expected 32")
        ));

        let mut t = spec_tunnel();
        t.private_key = Some("   ".into()); // empty after trimming
        t.peers[0].public_key = valid_key_bytes(2);
        let plan = nt_interface_plan(&t, "net-a").unwrap();
        assert!(matches!(
            nt_apply_spec(&plan),
            Err(crate::NetworkError::ApplyRejected(_))
        ));
    }

    #[test]
    fn apply_spec_pins_mtu_to_the_crate_hardcoded_1420() {
        // The crate's set_default_route hardcodes NlMtu=1420: a non-1420
        // plan is rejected explicitly (plans such as PPPoE 1412 are
        // simply unusable on the nt path); never silently apply 1420.
        let mut t = tunnel();
        t.private_key = Some(valid_key_bytes(1));
        t.peers[0].public_key = valid_key_bytes(2);
        t.mtu = Some(1380);
        let plan = nt_interface_plan(&t, "net-a").unwrap();
        assert!(matches!(
            nt_apply_spec(&plan),
            Err(crate::NetworkError::ApplyRejected(msg)) if msg.contains("1380")));

        // Both `None` (following the crate's 1420) and an explicit 1420
        // pass.
        for mtu in [None, Some(NT_INTERFACE_MTU)] {
            let mut t = spec_tunnel();
            t.private_key = Some(valid_key_bytes(1));
            t.peers[0].public_key = valid_key_bytes(2);
            t.mtu = mtu;
            let plan = nt_interface_plan(&t, "net-a").unwrap();
            assert!(nt_apply_spec(&plan).is_ok(), "mtu {mtu:?} should pass");
        }
    }

    #[test]
    fn apply_spec_debug_redacts_private_key() {
        let mut t = spec_tunnel();
        t.private_key = Some(valid_key_bytes(7));
        t.peers[0].public_key = valid_key_bytes(2);
        let plan = nt_interface_plan(&t, "net-a").unwrap();
        let spec = nt_apply_spec(&plan).unwrap();
        let rendered = format!("{spec:?}");
        assert!(
            !rendered.contains(&valid_key_bytes(7)),
            "raw key must not leak"
        );
        assert!(rendered.contains("<redacted>"));
    }

    // ----- dll candidate order -----

    #[test]
    fn dll_candidates_order_env_exe_then_programdata() {
        let env = Some("/srv/override/wireguard.dll");
        let exe_dir = Some(std::path::Path::new(r"C:\Program Files\Meshlet"));
        let got = nt_dll_candidates(env, exe_dir);
        assert_eq!(got.len(), 3);
        assert_eq!(
            got[0],
            std::path::PathBuf::from("/srv/override/wireguard.dll")
        );
        assert_eq!(
            got[1],
            std::path::Path::new(r"C:\Program Files\Meshlet").join("wireguard.dll")
        );
        assert_eq!(
            got[2],
            std::path::PathBuf::from(r"C:\ProgramData\meshlet\wireguard.dll")
        );

        // A blank environment variable does not enter the candidate list;
        // when the exe dir is absent only ProgramData remains as a
        // fallback.
        assert_eq!(
            nt_dll_candidates(Some("  "), None),
            vec![std::path::PathBuf::from(
                r"C:\ProgramData\meshlet\wireguard.dll"
            )]
        );
        assert_eq!(nt_dll_candidates(None, None).len(), 1);
    }

    // ----- nt adapter OS alias resolution (regression test for item 1 of
    // the seven-item acceptance) -----

    #[test]
    fn os_alias_matches_by_interface_description_case_insensitive() {
        // Real-machine shape (wgnt-seven-item-2026-11-21.md): the OS Name
        // is the driver's default `WireGuard`, and the tunnel name appears
        // only in InterfaceDescription.
        let json = r#"[
            {"Name":"Ethernet","InterfaceDescription":"Intel(R) Ethernet Connection"},
            {"Name":"WireGuard","InterfaceDescription":"wg-mlt-wg-mdc44 Tunnel"}
        ]"#;
        assert_eq!(
            os_alias_from_adapter_enum_json(json, "wg-mlt-wg-mdc44"),
            Some("WireGuard".to_string())
        );
        // Case-insensitive (the casing the OS provides is not trusted as
        // a premise).
        let upper = r#"[{"Name":"WireGuard","InterfaceDescription":"WG-MLT-WG-MDC44 TUNNEL"}]"#;
        assert_eq!(
            os_alias_from_adapter_enum_json(upper, "wg-mlt-wg-mdc44"),
            Some("WireGuard".to_string())
        );
    }

    #[test]
    fn os_alias_survives_noise_and_malformed_entries() {
        // Noise rows from other adapters plus a malformed entry (missing
        // InterfaceDescription) do not block later matches.
        let json = r#"[
            {"Name":"Ethernet"},
            {"Name":"Hyper-V","InterfaceDescription":"Microsoft Hyper-V Virtual Ethernet Adapter"},
            {"Name":"WireGuard","InterfaceDescription":"wg-mlt-a1b2 Tunnel"}
        ]"#;
        assert_eq!(
            os_alias_from_adapter_enum_json(json, "wg-mlt-a1b2"),
            Some("WireGuard".to_string())
        );
    }

    #[test]
    fn os_alias_single_object_and_fail_closed_on_miss() {
        // PowerShell single-object output (not an array).
        let single = r#"{"Name":"WireGuard","InterfaceDescription":"wg-mlt-net1 Tunnel"}"#;
        assert_eq!(
            os_alias_from_adapter_enum_json(single, "wg-mlt-net1"),
            Some("WireGuard".to_string())
        );
        // No match -> None (the caller fails closed).
        assert_eq!(
            os_alias_from_adapter_enum_json(single, "wg-mlt-other"),
            None
        );
        // Malformed JSON / a non-object array element / neither object nor
        // array -> None.
        assert_eq!(
            os_alias_from_adapter_enum_json("not json", "wg-mlt-net1"),
            None
        );
        assert_eq!(
            os_alias_from_adapter_enum_json(r#"[42]"#, "wg-mlt-net1"),
            None
        );
        assert_eq!(os_alias_from_adapter_enum_json(r#"3"#, "wg-mlt-net1"), None);
    }
}
