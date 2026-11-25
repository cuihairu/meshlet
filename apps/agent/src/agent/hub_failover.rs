//! Hub multi-endpoint failover (UI batch B3 / the remaining item of the todo "close out the four UI points").
//!
//! `[dataplane] hub_endpoint` now supports comma-separated multiple endpoints ([`crate::agent::agent::DataplaneConfig::hub_endpoints`]).
//! The server plan leaves the hub peer's endpoint empty (§16.4: the server does not know the
//! agent's network location), so the agent fills it from local configuration to be able to initiate
//! the handshake. With multiple endpoints: when the incumbent endpoint's handshake with the hub
//! times out (or never handshakes past the grace period), rotate to the next candidate and re-deliver
//! - a hub entry-address change (VPS migration / a spare hub) self-heals with no agent config edit.
//!
//! Health criterion = the kernel handshake age of the hub peer (plan tunnel.peers[0]; the server plan
//! always has a single hub peer) ([`meshlet_network`] backends' `handshake_ages_sync`):
//! - `Some(age)` with `age <= stale` -> the incumbent is healthy, keep it;
//! - `Some(age)` with `age > stale` -> the incumbent is dead, rotate (the hub's persistent
//!   keepalive is forced >= 25s, [`enforce_hub_keepalive`], so a healthy handshake never stalls and
//!   a stale age means the path is broken - a reliable criterion);
//! - `None` (never handshook) -> give one grace period after a rotation to await the first handshake,
//!   and only rotate once the grace expires without one - this avoids a spurious rotation on a fresh
//!   start and endless fast churn over all-dead endpoints.
//!
//! The rotation result lands in `{state_dir}/hub-endpoint.json` ([`HubEndpointLedger`], the same
//! ledger style as `direct-port.json`): `index` (the current candidate index) +
//! `selected_at_ms` (the rotation time, the grace-period basis). Single/zero endpoints write no ledger
//! (behavior identical to the old version, no new file).

/// The incumbent hub endpoint is deemed "dead" and rotated once its handshake age exceeds this many
/// seconds. The hub keepalive is raised to 25s ([`meshlet_network::HUB_KEEPALIVE_SECS`]), so a healthy
/// handshake must refresh within 25s; 60s = 2.4 keepalive periods, leaving ample margin for a broken
/// path and never misjudging a healthy handshake.
pub(super) const HUB_HANDSHAKE_STALE_SECS: u64 = 60;

/// Endpoint ledger path: `{state_dir}/hub-endpoint.json`.
pub(super) fn ledger_path(state_dir: &str) -> std::path::PathBuf {
    std::path::Path::new(state_dir).join("hub-endpoint.json")
}

/// Hub endpoint selection ledger (`hub-endpoint.json`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct HubEndpointLedger {
    /// The currently selected `hub_endpoints()` candidate index.
    pub index: usize,
    /// The rotation/selection time (Unix milliseconds; the grace-period basis).
    pub selected_at_ms: u64,
}

/// Read the ledger: missing/corrupt is treated as "no ledger" (`None`, reconverging next round; corrupt
/// data is never taken as the incumbent selection).
pub(super) fn load(state_dir: &str) -> Option<HubEndpointLedger> {
    let raw = std::fs::read_to_string(ledger_path(state_dir)).ok()?;
    serde_json::from_str::<HubEndpointLedger>(&raw).ok()
}

/// Write the ledger (a failure is only logged by the caller: the ledger is an anti-churn optimization and must not block the dataplane).
pub(super) fn save(state_dir: &str, ledger: &HubEndpointLedger) -> Result<(), String> {
    let path = ledger_path(state_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let raw =
        serde_json::to_string(ledger).map_err(|e| format!("serialize hub-endpoint ledger: {e}"))?;
    std::fs::write(&path, raw).map_err(|e| format!("write {}: {e}", path.display()))
}

/// One hub endpoint selection decision ([`decide`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HubDecision {
    /// The selected candidate index (`0..configured.len()`).
    pub index: usize,
    /// The selected endpoint (`configured[index]`).
    pub endpoint: String,
    /// The caller should persist the ledger (a rotation or a first-time preference).
    pub save: bool,
    /// A rotation happened: the caller should force a re-apply (the new endpoint must be pushed into the kernel).
    pub rotate: bool,
    /// The ledger to persist (valid when `save == true`).
    pub ledger: HubEndpointLedger,
}

/// Hub endpoint selection (pure function, testable). Failover only when `configured.len() > 1`;
/// a single endpoint always selects `index 0` with no change (`save=false, rotate=false`, same as the old behavior).
///
/// - `current`: the previous round's ledger (`None` = first round);
/// - `hub_age`: the hub peer's handshake age in seconds (`None` = no handshake yet);
/// - `now_ms`: the current Unix milliseconds (for grace timing);
/// - `stale_secs`: the handshake-staleness threshold for declaring death ([`HUB_HANDSHAKE_STALE_SECS`]);
/// - `grace_ms`: the grace period after a rotation while awaiting the first handshake (when there is none).
pub(super) fn decide(
    configured: &[String],
    current: Option<&HubEndpointLedger>,
    hub_age: Option<u64>,
    now_ms: u64,
    stale_secs: u64,
    grace_ms: u64,
) -> HubDecision {
    debug_assert!(!configured.is_empty(), "caller gates on non-empty");
    if configured.len() == 1 {
        // Single endpoint: always select it, zero state, zero rotation - the old behavior is unchanged byte for byte.
        return HubDecision {
            index: 0,
            endpoint: configured[0].clone(),
            save: false,
            rotate: false,
            ledger: HubEndpointLedger {
                index: 0,
                selected_at_ms: now_ms,
            },
        };
    }

    let current_index = current.map(|l| l.index.min(configured.len() - 1));
    let (index, rotate) = match current {
        // First round: start from the first candidate (the grace is timed from now; the startup apply carries it down).
        None => (0, false),
        Some(ledger) => {
            let cur = ledger.index.min(configured.len() - 1);
            match hub_age {
                // The incumbent is healthy: keep it (grace timing untouched, only the age criterion counts).
                Some(age) if age <= stale_secs => (cur, false),
                // The incumbent is dead (stale): rotate to the next one (wrapping around).
                Some(_) => ((cur + 1) % configured.len(), true),
                // No handshake yet: after a rotation allow the grace period to await the first handshake, and rotate only if the grace expires without one.
                None => {
                    if now_ms.saturating_sub(ledger.selected_at_ms) > grace_ms {
                        ((cur + 1) % configured.len(), true)
                    } else {
                        (cur, false)
                    }
                }
            }
        }
    };
    // The ledger is written only when the selection really changes (first-time preference / rotation); keeping the
    // incumbent never writes to disk - the 30s poll must not create write churn.
    let save = current_index != Some(index);
    HubDecision {
        index,
        endpoint: configured[index].clone(),
        save,
        rotate,
        ledger: HubEndpointLedger {
            index,
            selected_at_ms: now_ms,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eps(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn ledger(index: usize, at: u64) -> HubEndpointLedger {
        HubEndpointLedger {
            index,
            selected_at_ms: at,
        }
    }

    #[test]
    fn single_endpoint_never_rotates_and_saves_nothing() {
        let d = decide(&eps(&["a:51820"]), None, None, 0, 60, 90_000);
        assert_eq!(d.index, 0);
        assert_eq!(d.endpoint, "a:51820");
        assert!(!d.save);
        assert!(!d.rotate);

        // Even a dead incumbent does not rotate (there is no second candidate); zero state.
        let d = decide(
            &eps(&["a:51820"]),
            Some(&ledger(0, 0)),
            Some(9999),
            0,
            60,
            90_000,
        );
        assert!(!d.rotate);
        assert!(!d.save);
    }

    #[test]
    fn fresh_handshake_keeps_current() {
        let cur = ledger(1, 10_000);
        // The incumbent is healthy (age <= 60): keep index 1, no ledger write, no rotation.
        let d = decide(
            &eps(&["a:51820", "b:51821"]),
            Some(&cur),
            Some(12),
            20_000,
            60,
            90_000,
        );
        assert_eq!(d.index, 1);
        assert_eq!(d.endpoint, "b:51821");
        assert!(!d.rotate);
        assert!(!d.save);
    }

    #[test]
    fn stale_handshake_rotates_to_next_and_wraps() {
        // The incumbent is dead (age 61 > 60): rotate to the next candidate, wrapping around.
        let cur = ledger(0, 10_000);
        let d = decide(
            &eps(&["a:51820", "b:51821", "c:51822"]),
            Some(&cur),
            Some(61),
            20_000,
            60,
            90_000,
        );
        assert_eq!(d.index, 1);
        assert_eq!(d.endpoint, "b:51821");
        assert!(d.rotate);
        assert!(d.save);
        assert_eq!(d.ledger.index, 1);
        assert_eq!(d.ledger.selected_at_ms, 20_000);

        // The last candidate dies: wrap around to 0.
        let cur = ledger(2, 10_000);
        let d = decide(
            &eps(&["a:51820", "b:51821", "c:51822"]),
            Some(&cur),
            Some(61),
            20_000,
            60,
            90_000,
        );
        assert_eq!(d.index, 0);
        assert_eq!(d.endpoint, "a:51820");
        assert!(d.rotate);
    }

    #[test]
    fn no_handshake_rotates_only_after_grace() {
        let eps = eps(&["a:51820", "b:51821"]);
        // Still within the grace after a rotation (< 90s): keep it, no rotation.
        let cur = ledger(1, 10_000);
        let d = decide(&eps, Some(&cur), None, 50_000, 60, 90_000);
        assert_eq!(d.index, 1);
        assert!(!d.rotate);

        // Past the grace with still no handshake: rotate.
        let d = decide(&eps, Some(&cur), None, 110_000, 60, 90_000);
        assert_eq!(d.index, 0);
        assert!(d.rotate);

        // First round with no handshake (fresh start): start from candidate 0, timing the grace from now.
        let d = decide(&eps, None, None, 30_000, 60, 90_000);
        assert_eq!(d.index, 0);
        assert!(!d.rotate);
        assert!(d.save);
        assert_eq!(d.ledger.selected_at_ms, 30_000);
    }

    #[test]
    fn ledger_round_trips_through_the_state_file() {
        let dir = std::env::temp_dir().join(format!("meshlet-hub-fo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let dir_str = dir.to_str().unwrap();
        assert_eq!(load(dir_str), None);
        let l = ledger(2, 123_456_789);
        save(dir_str, &l).unwrap();
        assert_eq!(load(dir_str), Some(l));
        // A corrupt file -> None (reconverge next round).
        std::fs::write(ledger_path(dir_str), "not json").unwrap();
        assert_eq!(load(dir_str), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
