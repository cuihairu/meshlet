//! The boringtun embedded userspace backend — the plan layer (sourced from the
//! [analysis document](../../../docs/design/userspace-wireguard-analysis.md);
//! the meshlet data plane moves from the kernel WireGuard to the boringtun
//! userspace protocol).
//!
//! Target model: run the WireGuard userspace protocol on macOS with boringtun
//! (Cloudflare), replacing the kernel WireGuard module. **The Intel mac choice
//! is pinned** (the user decided on 2026-11-22: `x86_64-apple-darwin` is
//! officially supported; gotatun/wireguard-go are out).
//!
//! Layering (the same discipline as [crate::windows_wireguard_nt]):
//!
//! **Plan layer** (compiles and unit-tests on any platform): the pure
//! conversion [TunnelConfig] -> [BtInterfacePlan] plus the utun naming/port/MTU
//! guards ([bt_interface_plan]).
//!
//! **Command plan** (compiles and unit-tests on any platform):
//! [BtInterfacePlan] -> `Vec<[crate::macos::backend::BtCommand]>`
//! (ifconfig/route/MTU — the utun is a **dummy device** whose IP/routes are
//! self-managed, see `bt_apply_commands` in [crate::macos]).
//!
//! **`#[cfg(target_os = "macos")]` execution layer**: spawns boringtun-cli —
//! bring up the utun and attach the `/var/run/wireguard/*.sock` UAPI, then run
//! the command executor (see [crate::macos::backend]). The host CI does not
//! run macOS tests; this layer is verified by the
//! `x86_64-apple-darwin` cross check compile.
//!
//! Path selection (decision ②-3): **PATH B — spawn boringtun-cli + wg.sock
//! UAPI**, not library-level embedding (PATH A). Reason: the boringtun 0.7.1
//! library is a WireGuard protocol library (the `noise`/`x25519` modules) and
//! **does not provide a macOS utun device abstraction** (the `device` feature
//! goes through socket2, not utun ioctls) — PATH A would require meshlet to
//! build its own utun ioctls plus a protocol event loop and thread lifecycle
//! management, far beyond the scope of this batch (test pins); PATH B has
//! boringtun-cli bring up the utun and expose the UAPI socket, and meshlet
//! configures keys/peers through the standard `wg` tool and the dummy device's
//! IP/routes through `ifconfig`/`route`; the command executor and the
//! reconciliation model are carried over from the linux backend. **The
//! boringtun crate dependency is therefore not added** (PATH B only depends on
//! the `boringtun-cli` binary at runtime; packaging belongs to the ⑤ real
//! machine batch).
//!
//! Discipline (inheriting [crate::windows_wireguard_nt] / ADR-010):
//!
//! - **fail closed (port)**: [TunnelConfig::listen_port] being `None` is
//!   refused — boringtun/utun need an explicit port, and `None` falling back to
//!   the default 51820 must collide across multiple networks (the same root as
//!   back in the service-model era). See [bt_listen_port].
//! - **fail closed (peer)**: the peer `endpoint` is a mandatory `SocketAddr`
//!   (no room for an Option); missing or unparseable values are always refused;
//!   `persistent_keepalive_secs` beyond the `u16` upper bound is refused, never
//!   silently truncated.
//! - **naming guard**: the utun name must be `utun` (let the kernel choose) or
//!   `utun<digits>` (`utun[0-9]+`, such as `utun5`); everything else is
//!   refused. A macOS utun is a kernel-managed dummy device, and its name can
//!   only be allocated by the kernel or given explicitly.
//! - **private key boundary (ADR-010)**: [BtInterfacePlan::private_key] only
//!   passes through [TunnelConfig::private_key] (`None` = keep the existing key,
//!   idempotent re-application); the hand-written [std::fmt::Debug]
//!   implementation redacts the private key field — the plan object can safely
//!   enter logs.
//! - **MTU**: guarded by [BT_INTERFACE_MTU] — a plan `mtu` that is not `None`
//!   and is not 1420 is always refused (the same rule as NT); meshlet's default
//!   plan MTU happens to be 1420 ([crate::DEFAULT_TUNNEL_MTU]).

use crate::NetworkError;
use crate::TunnelConfig;
use meshlet_domain::Ipv4Cidr;
use std::fmt;
use std::net::SocketAddr;

/// boringtun plan-layer error: the rejection reasons of the naming/port/peer
/// conversion guards.
///
/// The execution layer (a later batch) maps variants when it lands in
/// [`crate::NetworkError`]; the plan layer stands as its own type first so that
/// execution semantics cannot pollute plan semantics (the same convention as
/// NT).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BtPlanError {
    #[error("utun interface name is empty")]
    UtunNameEmpty,
    #[error(
        "utun interface name {name:?} invalid: must be 'utun' (kernel picks) or 'utun<digits>'"
    )]
    UtunNameInvalid { name: String },
    #[error(
        "listen_port is required: boringtun/utun needs an explicit port (None falls back to default 51820, port collision across networks)"
    )]
    ListenPortMissing,
    #[error(
        "peer {index}: endpoint is required (boringtun peer endpoint is a mandatory SocketAddr)"
    )]
    PeerEndpointMissing { index: usize },
    #[error("peer {index}: endpoint not parseable as SocketAddr: {raw}")]
    PeerEndpointInvalid { index: usize, raw: String },
    #[error("peer {index}: keepalive {value} exceeds u16 range of persistent_keepalive_secs")]
    PeerKeepAliveTooLarge { index: usize, value: u32 },
    #[error(
        "mtu {mtu} unsupported: boringtun path only accepts {expected} (same rule as wireguard-nt)"
    )]
    MtuUnsupported { mtu: u32, expected: u32 },
}

impl From<BtPlanError> for NetworkError {
    /// A plan-layer guard rejection -> an application rejection (the semantics
    /// are unchanged: an invalid plan is a rejection, never a silent
    /// correction). The backend dispatch absorbs it directly with `?`.
    fn from(error: BtPlanError) -> Self {
        NetworkError::ApplyRejected(error.to_string())
    }
}

/// The boringtun plan for a single peer (the pre-conversion to the execution
/// form of [crate::PeerConfig]).
///
/// The fields mirror the standard `wg` configuration surface (structurally
/// identical to the boringtun-cli UAPI): the public key/keepalive keep the
/// plan-layer form (a base64 `String` / `Option<u16>`), and the binary
/// conversion is left to the execution layer — key bytes should only exist at
/// the moment of execution.
#[derive(Clone, PartialEq, Eq)]
pub struct BtPeerPlan {
    /// The peer public key (base64).
    pub public_key: String,
    /// The peer's UDP-reachable endpoint. **Mandatory**; a missing value is
    /// refused at [bt_interface_plan].
    pub endpoint: SocketAddr,
    /// AllowedIPs (matching the target routes, §7.2).
    pub allowed_ips: Vec<Ipv4Cidr>,
    /// Persistent keepalive seconds; `None` = do not send.
    pub keep_alive: Option<u16>,
}

impl fmt::Debug for BtPeerPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BtPeerPlan")
            .field("public_key", &self.public_key)
            .field("endpoint", &self.endpoint)
            .field("allowed_ips", &self.allowed_ips)
            .field("keep_alive", &self.keep_alive)
            .finish()
    }
}

/// The boringtun plan for a single network: the execution form of
/// [TunnelConfig] after the guards.
///
/// Private key boundary (ADR-010): [private_key](BtInterfacePlan::private_key)
/// exists only locally on the agent; the [Debug](std::fmt::Debug)
/// implementation redacts it, so the plan object can safely enter logs.
#[derive(Clone, PartialEq, Eq)]
pub struct BtInterfacePlan {
    /// The utun interface name (`utun` lets the kernel choose, or an explicit
    /// `utun<digits>`; see [bt_utun_name]). The execution layer resolves the
    /// actual name through `WG_TUN_NAME_FILE` when it is `utun`.
    pub interface_name: String,
    /// The explicitly allocated UDP listen port (**not an Option**; see
    /// [bt_listen_port]).
    pub listen_port: u16,
    /// The interface address.
    pub address: std::net::Ipv4Addr,
    /// The interface address prefix length.
    pub address_prefix: u8,
    /// The MTU intent (guarded by [BT_INTERFACE_MTU]; assembled by the
    /// execution layer through `ifconfig`).
    pub mtu: Option<u32>,
    /// The private key (base64). `None` = keep the existing key (idempotent
    /// re-application); **redacted in Debug**, never entering logs.
    pub private_key: Option<String>,
    /// The peer plans.
    pub peers: Vec<BtPeerPlan>,
}

impl fmt::Debug for BtInterfacePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BtInterfacePlan")
            .field("interface_name", &self.interface_name)
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

/// The boringtun interface MTU guard value (the same rule as NT): meshlet's
/// default plan MTU happens to be 1420 ([crate::DEFAULT_TUNNEL_MTU]), and this
/// path currently accepts only 1420 — a non-1420 plan (such as PPPoE 1412) is
/// explicitly refused rather than silently coerced to 1420 and pretending it
/// is satisfied.
pub const BT_INTERFACE_MTU: u32 = 1420;

/// The utun interface name guard: `utun` (let the kernel choose) or
/// `utun<digits>` (such as `utun5`).
///
/// fail closed: an empty string, a non-`utun` prefix, and any non-digit
/// characters after the prefix are all refused. A macOS utun is a
/// kernel-managed dummy device and its name can only be allocated by the kernel
/// or given explicitly — no arbitrary string is accepted.
pub fn bt_utun_name(requested: &str) -> Result<String, BtPlanError> {
    if requested.is_empty() {
        return Err(BtPlanError::UtunNameEmpty);
    }
    let rest = requested
        .strip_prefix("utun")
        .ok_or_else(|| BtPlanError::UtunNameInvalid {
            name: requested.to_string(),
        })?;
    if !rest.is_empty() && !rest.chars().all(|c| c.is_ascii_digit()) {
        return Err(BtPlanError::UtunNameInvalid {
            name: requested.to_string(),
        });
    }
    Ok(requested.to_string())
}

/// The listen port guard: `None` is refused.
///
/// boringtun/utun need an explicit port; `None` falling back to the default
/// 51820 must collide on the second interface across multiple networks (the
/// same root as the 0xc0000022 of the service-model era). The agent must
/// allocate the port explicitly per network.
pub fn bt_listen_port(listen_port: Option<u16>) -> Result<u16, BtPlanError> {
    listen_port.ok_or(BtPlanError::ListenPortMissing)
}

/// The peer plan conversion: `PeerConfig` -> [BtPeerPlan], fail closed.
///
/// - A missing or unparseable endpoint -> refused (the boringtun peer endpoint
///   is mandatory);
/// - A keepalive beyond `u16` -> refused (never silently truncated);
/// - `allowed_ips` passes through (the IPv4 CIDR is already normalized).
fn bt_peer_plan(peer: &crate::PeerConfig, index: usize) -> Result<BtPeerPlan, BtPlanError> {
    let endpoint = match peer.endpoint.as_deref() {
        None => return Err(BtPlanError::PeerEndpointMissing { index }),
        Some(raw) => {
            raw.trim()
                .parse::<SocketAddr>()
                .map_err(|_| BtPlanError::PeerEndpointInvalid {
                    index,
                    raw: raw.to_string(),
                })?
        }
    };
    let keep_alive = match peer.persistent_keepalive_secs {
        None => None,
        Some(v) if v <= u16::MAX as u32 => Some(v as u16),
        Some(v) => return Err(BtPlanError::PeerKeepAliveTooLarge { index, value: v }),
    };
    Ok(BtPeerPlan {
        public_key: peer.public_key.clone(),
        endpoint,
        allowed_ips: peer.allowed_ips.clone(),
        keep_alive,
    })
}

/// The plan conversion: [TunnelConfig] -> [BtInterfacePlan] (a pure function,
/// any platform).
///
/// Fail closed across the board: a `None` port is refused, a missing or
/// malformed peer endpoint is refused, an out-of-range keepalive is refused,
/// an illegal utun name is refused ([bt_utun_name]), and an MTU other than
/// [BT_INTERFACE_MTU] is refused. `private_key`/`address` and the rest pass
/// through with the [TunnelConfig] semantics (a `None` private key = keep the
/// existing key).
pub fn bt_interface_plan(
    tunnel: &TunnelConfig,
    interface_name: &str,
) -> Result<BtInterfacePlan, BtPlanError> {
    let interface_name = bt_utun_name(interface_name)?;
    let listen_port = bt_listen_port(tunnel.listen_port)?;
    if let Some(mtu) = tunnel.mtu.filter(|mtu| *mtu != BT_INTERFACE_MTU) {
        return Err(BtPlanError::MtuUnsupported {
            mtu,
            expected: BT_INTERFACE_MTU,
        });
    }
    let peers = tunnel
        .peers
        .iter()
        .enumerate()
        .map(|(index, peer)| bt_peer_plan(peer, index))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BtInterfacePlan {
        interface_name,
        listen_port,
        address: tunnel.address,
        address_prefix: tunnel.address_prefix,
        mtu: tunnel.mtu,
        private_key: tunnel.private_key.clone(),
        peers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PeerConfig;

    /// A legal baseline plan: an explicit port, an MTU exactly at the guard
    /// value, and complete peer endpoints.
    fn tunnel() -> TunnelConfig {
        TunnelConfig {
            name: "net-a".into(),
            address: "10.240.0.7".parse().unwrap(),
            address_prefix: 16,
            listen_port: Some(51821),
            peers: vec![peer("pub-a", Some("100.64.0.2:51820"))],
            mtu: Some(BT_INTERFACE_MTU),
            private_key: Some("secret-key-material".into()),
        }
    }

    fn peer(public_key: &str, endpoint: Option<&str>) -> PeerConfig {
        PeerConfig {
            public_key: public_key.into(),
            allowed_ips: vec!["10.240.0.8/32".parse().unwrap()],
            endpoint: endpoint.map(str::to_string),
            persistent_keepalive_secs: Some(25),
        }
    }

    fn plan() -> BtInterfacePlan {
        bt_interface_plan(&tunnel(), "utun").unwrap()
    }

    /// ④ pin: the utun name whitelist — both `utun` (kernel picks) and
    /// `utun<digits>` are legal.
    #[test]
    fn utun_name_accepts_bare_and_numbered() {
        assert_eq!(bt_utun_name("utun").unwrap(), "utun");
        assert_eq!(bt_utun_name("utun0").unwrap(), "utun0");
        assert_eq!(bt_utun_name("utun12").unwrap(), "utun12");
    }

    /// ④ pin: anything off the whitelist is refused (including trailing
    /// non-digits after the prefix, case, and leading/trailing whitespace).
    #[test]
    fn utun_name_rejects_empty_nonprefix_and_trailing_junk() {
        assert_eq!(bt_utun_name(""), Err(BtPlanError::UtunNameEmpty));
        for bad in ["wg0", "tun5", "utun5x", "utun-1", "UTUN5", "utun ", " utun"] {
            assert_eq!(
                bt_utun_name(bad),
                Err(BtPlanError::UtunNameInvalid {
                    name: bad.to_string()
                }),
                "{bad:?} must be rejected"
            );
        }
    }

    /// ④ pin: the MTU guard — 1420 passes, the rest (1412/1500/900) are
    /// refused, never silently coerced.
    #[test]
    fn mtu_guard_accepts_1420_and_rejects_others() {
        let guard = |got: u32| {
            let mut tunnel = tunnel();
            tunnel.mtu = Some(got);
            bt_interface_plan(&tunnel, "utun")
        };
        assert_eq!(guard(BT_INTERFACE_MTU).unwrap().mtu, Some(1420));
        // `None` = unspecified, passed through (not guarded, and no default
        // filled in).
        let mut bare = tunnel();
        bare.mtu = None;
        assert_eq!(bt_interface_plan(&bare, "utun").unwrap().mtu, None);
        for mtu in [1412u32, 1500, 900] {
            assert_eq!(
                guard(mtu),
                Err(BtPlanError::MtuUnsupported {
                    mtu,
                    expected: BT_INTERFACE_MTU,
                }),
                "mtu {mtu} must be rejected, not coerced to 1420"
            );
        }
    }

    /// ④ pin: a `None` listen_port is fail-closed (refused, never falling back
    /// to the default 51820).
    #[test]
    fn listen_port_none_is_rejected() {
        assert_eq!(bt_listen_port(None), Err(BtPlanError::ListenPortMissing));
        assert_eq!(bt_listen_port(Some(51821)), Ok(51821));
        let mut tunnel = tunnel();
        tunnel.listen_port = None;
        assert_eq!(
            bt_interface_plan(&tunnel, "utun"),
            Err(BtPlanError::ListenPortMissing)
        );
    }

    /// ④ pin: a missing or malformed peer endpoint is refused.
    #[test]
    fn peer_endpoint_missing_or_invalid_is_rejected() {
        let mut tunnel = tunnel();
        tunnel.peers = vec![peer("pub-a", None)];
        assert_eq!(
            bt_interface_plan(&tunnel, "utun"),
            Err(BtPlanError::PeerEndpointMissing { index: 0 })
        );
        tunnel.peers = vec![peer("pub-a", Some("not-an-address"))];
        assert_eq!(
            bt_interface_plan(&tunnel, "utun"),
            Err(BtPlanError::PeerEndpointInvalid {
                index: 0,
                raw: "not-an-address".to_string(),
            })
        );
    }

    /// ④ pin: an out-of-range keepalive is refused (never truncated), an
    /// in-range one is kept, and `None` passes through.
    #[test]
    fn keepalive_over_u16_is_rejected_not_truncated() {
        let mut tunnel = tunnel();
        // Out of range is refused (never truncated).
        let mut p = peer("pub-a", Some("100.64.0.2:51820"));
        p.persistent_keepalive_secs = Some(u16::MAX as u32 + 1);
        tunnel.peers = vec![p];
        assert_eq!(
            bt_interface_plan(&tunnel, "utun"),
            Err(BtPlanError::PeerKeepAliveTooLarge {
                index: 0,
                value: u16::MAX as u32 + 1,
            })
        );
        // Within the upper bound the original value is kept (no truncation,
        // no amplification).
        let mut p = peer("pub-a", Some("100.64.0.2:51820"));
        p.persistent_keepalive_secs = Some(u16::MAX as u32);
        tunnel.peers = vec![p];
        assert_eq!(
            bt_interface_plan(&tunnel, "utun").unwrap().peers[0].keep_alive,
            Some(u16::MAX)
        );
        // `None` passes through (no keepalive sent).
        let mut p = peer("pub-a", Some("100.64.0.2:51820"));
        p.persistent_keepalive_secs = None;
        tunnel.peers = vec![p];
        assert_eq!(
            bt_interface_plan(&tunnel, "utun").unwrap().peers[0].keep_alive,
            None
        );
    }

    /// ④ pin: the plan object carries the address/prefix/port/peers (including
    /// the `utun` name passed through as-is).
    #[test]
    fn interface_plan_carries_address_port_and_peers() {
        let plan = plan();
        assert_eq!(plan.interface_name, "utun");
        assert_eq!(plan.listen_port, 51821);
        assert_eq!(plan.address.to_string(), "10.240.0.7");
        assert_eq!(plan.address_prefix, 16);
        assert_eq!(plan.private_key.as_deref(), Some("secret-key-material"));
        assert_eq!(plan.peers.len(), 1);
        assert_eq!(plan.peers[0].public_key, "pub-a");
        assert_eq!(plan.peers[0].endpoint.to_string(), "100.64.0.2:51820");
        assert_eq!(plan.peers[0].keep_alive, Some(25));
    }

    /// ④ pin: the private key is redacted in Debug output (ADR-010) —
    /// `<redacted>` is present and not one byte of the key appears.
    #[test]
    fn debug_output_never_leaks_private_key_bytes() {
        let key = "super-secret-base64-material";
        let mut tunnel = tunnel();
        tunnel.private_key = Some(key.to_string());
        let plan = bt_interface_plan(&tunnel, "utun").unwrap();
        let rendered = format!("{plan:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(
            !rendered.contains(key),
            "private key bytes leaked into Debug: {rendered}"
        );
    }

    /// ④ pin: a `private_key: None` passes through (an idempotent re-application
    /// keeps the existing key).
    #[test]
    fn private_key_none_passes_through() {
        let mut tunnel = tunnel();
        tunnel.private_key = None;
        assert_eq!(
            bt_interface_plan(&tunnel, "utun").unwrap().private_key,
            None
        );
    }

    /// ④ pin: a plan-layer guard rejection -> [`NetworkError::ApplyRejected`]
    /// (the backend dispatch absorbs it with `?`, without downgrading the
    /// semantics).
    #[test]
    fn plan_error_maps_to_apply_rejected() {
        for error in [
            BtPlanError::UtunNameEmpty,
            BtPlanError::ListenPortMissing,
            BtPlanError::MtuUnsupported {
                mtu: 1412,
                expected: BT_INTERFACE_MTU,
            },
        ] {
            assert!(
                matches!(
                    NetworkError::from(error.clone()),
                    NetworkError::ApplyRejected(_)
                ),
                "{error:?} must map to ApplyRejected"
            );
        }
    }
}
