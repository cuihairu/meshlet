//! Reconciliation decisions (**pure logic**: never touches the kernel, unit-testable without
//! privileges). The agent only consumes the structured plan published by the server (§16.4);
//! the question is "replay now or not": - the desired config hash changed (the server has a
//! new revision) → apply; - no local ledger (first install / state file lost) → apply; -
//! actual kernel objects don't match the expectation (tunnel gone / a route missing / a NAT
//! rule gone) → apply — exactly the fix path for "tunnel vanished after a host reboot while
//! the ledger still says applied" (TODO #32); - none of the above → don't apply (replay only
//! on change, §10.1 — idempotent and leaves the live network undisturbed). NAT cleanup goes
//! by the **ownership comment** (`meshlet alias {id}`, §12.6): only units installed per the
//! ledger and absent from the plan are removed — never touches non-Meshlet rules, never
//! deletes rules still in the plan.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use meshlet_network::nat::NatRule;
use meshlet_network::{DevicePlan, NetworkSnapshot};
use serde::{Deserialize, Serialize};

/// Ledger state file (`{state_dir}/applied.json`): a summary of the plan
/// last **actually applied successfully**. A corrupt or missing file is
/// treated as "no ledger" (triggering a replay instead of pretending it is
/// applied).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentState {
    /// Applied `desired_config_hash` (same source as revision bookkeeping).
    pub desired_config_hash: String,
    /// Applied tunnel address (`a.b.c.d`): direct evidence whether the
    /// tunnel is still the same one.
    #[serde(default)]
    pub tunnel_address: String,
    /// Applied route destination prefixes.
    #[serde(default)]
    pub routes: Vec<String>,
    /// Applied NAT rule fingerprint set (`chain|match|action|owner`,
    /// order-independent) — a mismatch with the plan triggers a whole-unit
    /// cleanup by ownership comment + re-issue.
    #[serde(default)]
    pub nat_rules: Vec<String>,
    /// Applied NAT ownership units (`meshlet alias {id}`): the precise
    /// cleanup key when a mapping is deleted.
    #[serde(default)]
    pub nat_owners: Vec<String>,
    /// Time of the last successful apply (ISO-8601 UTC, for troubleshooting;
    /// does not affect decisions).
    #[serde(default)]
    pub applied_at: String,
    /// WireGuard public-key fingerprint of this host at apply time (derived
    /// via `wg pubkey`; BUG② fix). Drift detection uses it to recognize a
    /// hand-rebuilt tunnel where the peers happen to match the plan but the
    /// local private key was swapped. Older ledgers lack the field (empty
    /// string = don't judge; naturally filled after one replay).
    #[serde(default)]
    pub local_public_key: String,
    /// The full plan last applied to the kernel. It is the rollback source for
    /// a failed transition; older ledgers without this field replay safely.
    #[serde(default)]
    pub last_good_plan: Option<DevicePlan>,
}

/// Ledger path: `{state_dir}/applied.json`.
pub fn state_path(state_dir: &str) -> PathBuf {
    Path::new(state_dir).join("applied.json")
}

impl AgentState {
    /// Build an "applied" ledger from a plan (written only after a
    /// successful apply).
    pub fn from_plan(plan: &DevicePlan) -> Self {
        Self {
            desired_config_hash: plan.desired_config_hash.clone(),
            tunnel_address: plan.tunnel.address.to_string(),
            routes: prefixes(plan.routes.iter().map(|r| r.destination)),
            nat_rules: rule_signatures(&plan.nat_rules),
            nat_owners: owners(&plan.nat_rules),
            applied_at: now(),
            local_public_key: String::new(),
            last_good_plan: Some(plan.clone()),
        }
    }

    /// Read the ledger (missing or corrupt → default empty ledger; callers
    /// replay accordingly).
    pub fn load(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))
    }

    /// Atomic persist: write a temp file then rename — a killed process never
    /// leaves half a JSON behind.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        }
        let tmp = path.with_extension("json.tmp");
        let body = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&tmp, body).map_err(|e| format!("write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("rename into {}: {e}", path.display()))?;
        Ok(())
    }
}

/// Whether a replay is needed + the reason (observable, not just yes/no).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Whether the kernel must be replayed.
    pub needs_apply: bool,
    /// Why (observable, logged).
    pub reason: Reason,
}

/// Replay reason: any one of these forces a replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// No change needed (replay only on change, §10.1).
    UpToDate,
    /// Desired config hash changed: the server has a new revision.
    DesiredConfigChanged,
    /// No local ledger (first install / state file lost).
    NoLocalLedger,
    /// Actual kernel objects don't match the ledger: tunnel/route/NAT drift
    /// or loss (TODO #32).
    KernelDrift,
    /// Hub multi-endpoint failover: the active endpoint died, rotate to the
    /// next candidate (replay the tunnel).
    HubEndpointRotated,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::UpToDate => "up_to_date",
            Reason::DesiredConfigChanged => "desired_config_changed",
            Reason::NoLocalLedger => "no_local_ledger",
            Reason::KernelDrift => "kernel_drift",
            Reason::HubEndpointRotated => "hub_endpoint_rotated",
        }
    }
}
///
/// Reconcile: ledger vs actual kernel vs server expectation.
///
/// `extra_peer_keys`: public keys of P2P direct peers (§12) — added/removed separately by the agent's direct manager, not part of the server plan;
/// their presence is **not** drift (pure gain, and neither is their absence —
/// direct state converges via the manager itself; the plan is never replayed
/// repeatedly just because "the direct peer isn't added yet").
///
/// Order of judgment: desired hash first (a real change gets reported as one),
/// then the ledger, then kernel drift.
pub fn needs_apply(
    state: &AgentState,
    snapshot: &NetworkSnapshot,
    plan: &DevicePlan,
    extra_peer_keys: &BTreeSet<String>,
) -> Decision {
    let reason = if state.desired_config_hash.is_empty() {
        Reason::NoLocalLedger
    } else if state.desired_config_hash != plan.desired_config_hash {
        Reason::DesiredConfigChanged
    } else if drifted(state, snapshot, plan, extra_peer_keys) {
        Reason::KernelDrift
    } else {
        Reason::UpToDate
    };
    Decision {
        needs_apply: reason != Reason::UpToDate,
        reason,
    }
}

/// Kernel state versus desired drift (identity-level, not count-level).
///
/// Every item is judged by **object identity**, not counts — "same count"
/// does not mean "same identity":
/// - Tunnel: absent, or the adapter's actual address differs from the
///   expectation → drift (an interface vanishing after reboot is routine;
///   the ledger address and plan address go stale from the same source — the
///   actual kernel reading is the truth);
/// - Local private key: the applied public key recorded in the ledger
///   differs from the local public key read from the kernel dump → drift
///   (a hand-rekeyed tunnel must be replayed to correct even if the peers
///   happen to match the plan, BUG②);
/// - Peers: expected vs actual compared item by item on the `public key →
///   allowed-ips` set. One missing (peer hand-deleted), one extra (an extra
///   meshlet peer on the managed interface), or widened allowed-ips — all
///   three are drift;
/// - Routes: an expected destination prefix not installed, or a
///   Meshlet-marked but no-longer-expected route on the managed interface →
///   drift (unmarked routes belong to others and never enter the observed
///   set);
/// - NAT: expected vs actual compared exactly as rule fingerprint sets
///   (claimed via ownership comments; both sides empty after a reboot
///   flushed iptables also counts as consistent).
fn drifted(
    state: &AgentState,
    snapshot: &NetworkSnapshot,
    plan: &DevicePlan,
    extra_peer_keys: &BTreeSet<String>,
) -> bool {
    if !snapshot.tunnel_exists || snapshot.forwarding_enabled != Some(true) {
        return true;
    }
    if !state.tunnel_address.is_empty() && state.tunnel_address != plan.tunnel.address.to_string() {
        return true;
    }
    // Adapter actual address (BUG②): kernel reading differs from the plan
    // (hand-readdressed / half-failed apply) → drift. The old check compared
    // "ledger address vs plan address", both stale (same source), so a manual
    // tunnel readdressing went unseen; this compares the **actual kernel
    // reading**. A missing reading (None) is not judged — missing evidence
    // neither pretends consistency nor enters a replay loop.
    if let Some(actual) = snapshot.tunnel_address {
        if actual != plan.tunnel.address {
            return true;
        }
    }
    // Local private-key fingerprint (BUG②): the ledger recorded the public
    // key at apply time, and the local public key read from the kernel dump
    // differs → someone swapped the private key (hand rebuild / key-rotation
    // bypass); must replay to correct. The classic misjudgment — peer set
    // happens to match the plan (UpToDate, skip apply, report applied success
    // while the kernel is unchanged) — is exactly this missing check. Not
    // judged when the ledger has no fingerprint (older ledger) or the reading
    // is missing.
    if !state.local_public_key.is_empty() {
        if let Some(actual) = &snapshot.local_public_key {
            if actual != &state.local_public_key {
                return true;
            }
        }
    }
    // MTU: explicitly configured in the plan but the kernel reading differs →
    // drift (correction of hand edits / half-failed applies). When the plan
    // sets no MTU, don't judge: the kernel default or an admin's deliberate
    // setting is not a plan violation.
    if plan.tunnel.mtu.is_some() && snapshot.tunnel_mtu != plan.tunnel.mtu {
        return true;
    }
    // Peer identity (not counts): compare public key → allowed-ips item by
    // item on both sides. Same count but a substituted peer, or a widened
    // allowed-ips on some peer, forces a corrective replay just like "one
    // peer missing". Peers on the managed interface are all Meshlet-owned,
    // but P2P direct peers (`extra_peer_keys`) are added/removed separately
    // by the manager — their presence is not drift.
    let ips = |cidrs: &[meshlet_domain::Ipv4Cidr]| -> BTreeSet<String> {
        cidrs.iter().map(ToString::to_string).collect()
    };
    let expected_peers = plan
        .tunnel
        .peers
        .iter()
        .map(|peer| (peer.public_key.clone(), ips(&peer.allowed_ips)))
        .collect::<BTreeMap<_, _>>();
    let observed_peers = snapshot
        .peers
        .iter()
        .map(|peer| (peer.public_key.clone(), ips(&peer.allowed_ips)))
        .collect::<BTreeMap<_, _>>();
    // Plan peers must correspond one-to-one with the kernel (direct peers
    // are excluded from the plan-side comparison).
    for (key, wanted_ips) in &expected_peers {
        if observed_peers.get(key) != Some(wanted_ips) {
            return true;
        }
    }
    // The kernel must not contain a peer that is neither in the plan nor in
    // the direct keep set (unmanaged object → drift). A missing keep-set
    // direct peer is not drift (the manager adds it back) — avoids a loop.
    if observed_peers
        .keys()
        .any(|key| !expected_peers.contains_key(key) && !extra_peer_keys.contains(key))
    {
        return true;
    }
    // Route comparison only applies to backends where routes are issued
    // independently of peers (service model: netsh applies plan.routes
    // separately). Backends that assemble routes from peer allowed-ips (nt
    // model: adapter set_default_route) skip this — routes are fully
    // determined by the peer identity-level comparison above (public key →
    // allowed-ips item by item); judging "out-of-plan routes" by plan.routes
    // on top would permanently flag the hub `/16` as drift on leaf nodes with
    // `routes=[]`, looping KernelDrift replays every round (2026-11-22 imac,
    // confirmed: 185 hits on the pre boundary with the old binary).
    if !snapshot.routes_from_peers {
        let installed: BTreeSet<String> = snapshot
            .installed_routes
            .iter()
            .map(|c| c.to_string())
            .collect();
        let missing = plan
            .routes
            .iter()
            .map(|r| r.destination.to_string())
            .any(|d| !installed.contains(&d));
        if missing {
            return true;
        }
        // A route previously installed by the same interface but no longer
        // desired is Meshlet-owned drift. Applying routes then removes it
        // without sweeping connected or foreign paths.
        let extra = snapshot.installed_routes.iter().any(|installed| {
            !plan
                .routes
                .iter()
                .any(|route| &route.destination == installed)
        });
        if extra {
            return true;
        }
    }
    // NAT identity: exact comparison of rule fingerprint sets (not "are
    // there any NAT rules"). A missing DNAT/SNAT that should be installed, or
    // an extra rule under a Meshlet comment (issue paths only add, never
    // remove; leftover old unit), both force a replay; NAT gone from the plan
    // while Meshlet rules remain in the kernel (gateway demoted, mapping
    // deleted but cleanup failed) hits too. The observed set only contains
    // rules claimed by the comment prefix — non-meshlet rules are invisible
    // here and never judged as drift.
    let expected_nat: BTreeSet<String> =
        plan.nat_rules.iter().map(|rule| rule.signature()).collect();
    let observed_nat: BTreeSet<String> = snapshot.nat_rules.iter().cloned().collect();
    expected_nat != observed_nat
}

/// NAT units to clean up by ownership comment before this replay (§12.6 /
/// precise cleanup).
///
/// The criterion is **whether the rule set is still consistent**, not
/// "whether the owner is still there":
/// - installed per the ledger, whole mapping gone from the plan → clean up
///   all rules of that owner;
/// - mapping still there but the rule set changed (translation mode
///   `dnat_snat` ↔ `dnat_only` etc.) → likewise clean the whole unit first,
///   then [`apply_device_plan_sync`] re-issues per the plan, avoiding stale
///   rules (the backend's issue path only adds, never removes; leftovers are
///   never discovered automatically).
///
/// Rules are deleted only by the `meshlet alias {id}` comment; non-Meshlet
/// rules are never touched.
pub fn stale_owners(
    state: &AgentState,
    plan: &DevicePlan,
    kernel_owners: &[String],
    ledger_present: bool,
) -> Vec<String> {
    if !ledger_present {
        return kernel_owners.to_vec();
    }
    if rule_signatures(&plan.nat_rules) == state.nat_rules {
        // Rule sets consistent: leave all owned rules alone (idempotent,
        // §10.3).
        return Vec::new();
    }
    // When the ledger is lost/corrupt, the kernel's existing Meshlet
    // ownership inventory is the authoritative source: enumerate all rule
    // owners carrying a `meshlet alias *` comment, exclude units still
    // expected by the plan, and clean up the rest; non-Meshlet rules are
    // never touched.
    let planned: std::collections::BTreeSet<_> = owners(&plan.nat_rules).into_iter().collect();
    let kernel_only: std::collections::BTreeSet<_> = kernel_owners.iter().cloned().collect();
    if state.nat_owners.is_empty() {
        return kernel_only.into_iter().collect();
    }
    let stale = kernel_only
        .difference(&planned)
        .cloned()
        .collect::<Vec<_>>();
    if !stale.is_empty() {
        return stale;
    }
    // Rule set changed but the kernel has no extra objects: clear the whole
    // old unit recorded in the ledger, then re-issue from the plan — the
    // add-only issue path never discovers "the old rules should no longer
    // exist" on its own.
    state.nat_owners.clone()
}

/// Fingerprint set of the plan's NAT rules (`chain|dest|action|ownership|
/// source|incoming interface`, deduplicated and order-independent): an equal
/// set means the kernel rules need no refresh. Fingerprints come from
/// [`NatRule::signature`] — the kernel-side parsed fingerprints share the same
/// shape, so both sides compare as sets.
fn rule_signatures(rules: &[NatRule]) -> Vec<String> {
    rules
        .iter()
        .map(|r| r.signature())
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect()
}

/// Set of NAT ownership units in the plan (deduplicated, sorted,
/// deterministic).
fn owners(rules: &[NatRule]) -> Vec<String> {
    rules
        .iter()
        .map(|r| r.owner.clone())
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect()
}

fn prefixes(dests: impl Iterator<Item = meshlet_domain::Ipv4Cidr>) -> Vec<String> {
    dests.map(|c| c.to_string()).collect()
}
fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// ---------------------------------------------------------------------------
// Tests (pure logic, no kernel/network needed)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use meshlet_domain::Ipv4Cidr;
    use meshlet_network::nat::{NatAction, NatChain};
    use meshlet_network::{PeerConfig, PeerObserved, RouteConfig, TunnelConfig};
    use std::net::Ipv4Addr;

    /// Test convenience wrapper: cases that don't care about direct peers use
    /// an empty keep set.
    fn apply(state: &AgentState, snapshot: &NetworkSnapshot, plan: &DevicePlan) -> Decision {
        needs_apply(state, snapshot, plan, &BTreeSet::new())
    }

    fn plan(hash: &str, with_nat: bool) -> DevicePlan {
        DevicePlan {
            desired_revision: 0,
            hub_port: None,
            tunnel: TunnelConfig {
                name: "wg0".into(),
                address: "10.240.0.7".parse().unwrap(),
                address_prefix: 16,
                listen_port: None,
                peers: vec![PeerConfig {
                    public_key: "hub-pub".into(),
                    allowed_ips: vec!["10.240.0.0/16".parse::<Ipv4Cidr>().unwrap()],
                    endpoint: None,
                    persistent_keepalive_secs: None,
                }],
                mtu: None,
                private_key: None,
            },
            routes: vec![RouteConfig {
                destination: "192.168.9.0/24".parse().unwrap(),
                interface: "wg0".into(),
                gateway: Some("10.240.0.2".parse::<Ipv4Addr>().unwrap()),
            }],
            nat_rules: if with_nat {
                vec![
                    NatRule {
                        source_cidr: None,
                        incoming_interface: None,
                        chain: NatChain::Prerouting,
                        match_dest: "10.241.9.0/24".parse().unwrap(),
                        action: NatAction::NetMap {
                            to: "192.168.9.0/24".parse().unwrap(),
                        },
                        owner: "meshlet alias al-1".into(),
                    },
                    NatRule {
                        source_cidr: None,
                        incoming_interface: None,
                        chain: NatChain::Postrouting,
                        match_dest: "192.168.9.0/24".parse().unwrap(),
                        action: NatAction::SnatToGatewayLan,
                        owner: "meshlet alias al-1".into(),
                    },
                ]
            } else {
                Vec::new()
            },
            hub_address: None,
            publish: None,
            ssh_config: None,
            desired_config_hash: hash.into(),
        }
    }

    /// Kernel snapshot consistent with the plan ("installed as planned").
    /// Peer identity, routes and NAT fingerprints are all **derived from the
    /// plan** rather than hand-written lookalikes — snapshot and plan are
    /// supposed to share a source, and hand-written values drift quietly
    /// (exactly what the old, replaced test did).
    fn healthy(plan: &DevicePlan) -> NetworkSnapshot {
        NetworkSnapshot {
            tunnel_exists: true,
            forwarding_enabled: Some(true),
            peers: plan
                .tunnel
                .peers
                .iter()
                .map(|peer| PeerObserved {
                    public_key: peer.public_key.clone(),
                    allowed_ips: peer.allowed_ips.clone(),
                })
                .collect(),
            installed_routes: plan.routes.iter().map(|route| route.destination).collect(),
            nat_rules: plan.nat_rules.iter().map(|rule| rule.signature()).collect(),
            tunnel_mtu: Some(1420),
            local_public_key: None,
            tunnel_address: Some(plan.tunnel.address),
            tunnel_listen_port: plan.tunnel.listen_port,
            routes_from_peers: false,
        }
    }

    fn state_of(plan: &DevicePlan) -> AgentState {
        AgentState::from_plan(plan)
    }

    #[test]
    fn up_to_date_plan_is_not_reapplied() {
        let p = plan("hash-a", true);
        let d = apply(&state_of(&p), &healthy(&p), &p);
        assert!(!d.needs_apply);
        assert_eq!(d.reason, Reason::UpToDate);
        assert_eq!(d.reason.as_str(), "up_to_date");
    }

    #[test]
    fn missing_ledger_triggers_apply() {
        // First install: no ledger must replay; "memory is empty" must not be
        // read as already-applied.
        let p = plan("hash-a", false);
        let d = apply(&AgentState::default(), &healthy(&p), &p);
        assert!(d.needs_apply);
        assert_eq!(d.reason, Reason::NoLocalLedger);
    }

    #[test]
    fn new_server_revision_triggers_apply() {
        let old = plan("hash-a", false);
        let new = plan("hash-b", false);
        let d = apply(&state_of(&old), &healthy(&new), &new);
        assert!(d.needs_apply);
        assert_eq!(d.reason, Reason::DesiredConfigChanged);
    }

    #[test]
    fn host_reboot_losing_the_tunnel_triggers_replay() {
        // TODO #32: ledger says hash-a, the kernel interface is gone (host
        // reboot) → must replay.
        let p = plan("hash-a", false);
        let rebooted = NetworkSnapshot {
            tunnel_exists: false,
            ..healthy(&p)
        };
        let d = apply(&state_of(&p), &rebooted, &p);
        assert!(d.needs_apply, "a vanished tunnel must be replayed");
        assert_eq!(d.reason, Reason::KernelDrift);
    }

    #[test]
    fn peer_consistent_but_local_key_rotated_is_drift() {
        // BUG② regression (second item of todo.md "Windows deployment
        // findings"): a hand-rebuilt tunnel whose peers happen to match the
        // plan but whose local private key was swapped → previously judged
        // UpToDate and skipped apply (reported applied success while the
        // kernel was unchanged); now must judge KernelDrift.
        let p = plan("hash-a", false);
        let mut state = state_of(&p);
        state.local_public_key = "K".repeat(43) + "=";

        // Peers match, local public key differs → drift.
        let mut hand_rebuilt = healthy(&p);
        hand_rebuilt.local_public_key = Some("M".repeat(43) + "=");
        assert_eq!(apply(&state, &hand_rebuilt, &p).reason, Reason::KernelDrift);

        // Local public key matches (kernel after a normal re-apply) → no
        // drift.
        let mut matching = healthy(&p);
        matching.local_public_key = Some(state.local_public_key.clone());
        assert!(!apply(&state, &matching, &p).needs_apply);

        // Missing reading (dump unreadable) → don't judge (missing evidence
        // must not enter a replay loop).
        let mut unreadable = healthy(&p);
        unreadable.local_public_key = None;
        assert!(!apply(&state, &unreadable, &p).needs_apply);

        // Old ledger (no fingerprint field) → don't judge; naturally filled
        // after one replay.
        let old_ledger = state_of(&p); // local_public_key defaults to empty
        assert!(!apply(&old_ledger, &hand_rebuilt, &p).needs_apply);
    }

    #[test]
    fn adapter_address_different_from_plan_is_drift() {
        // // BUG② regression: a manual tunnel readdressed (peers match). The old // check compared "ledger address vs plan address" (stale, same
        // source); an actual-kernel-reading mismatch must now be caught.
        let p = plan("hash-a", false);
        let state = state_of(&p);
        let mut moved = healthy(&p);
        moved.tunnel_address = Some("10.240.0.99".parse().unwrap());
        assert_eq!(apply(&state, &moved, &p).reason, Reason::KernelDrift);

        // Missing reading → don't judge.
        let mut unreadable = healthy(&p);
        unreadable.tunnel_address = None;
        assert!(!apply(&state, &unreadable, &p).needs_apply);
    }

    #[test]
    fn missing_route_peer_or_nat_counts_as_drift() {
        let p = plan("hash-a", true);
        let state = state_of(&p);

        let no_route = NetworkSnapshot {
            installed_routes: Vec::new(),
            ..healthy(&p)
        };
        assert_eq!(apply(&state, &no_route, &p).reason, Reason::KernelDrift);

        let no_nat = NetworkSnapshot {
            nat_rules: Vec::new(),
            ..healthy(&p)
        };
        assert_eq!(apply(&state, &no_nat, &p).reason, Reason::KernelDrift);

        let no_peer = NetworkSnapshot {
            peers: Vec::new(),
            ..healthy(&p)
        };
        assert_eq!(apply(&state, &no_peer, &p).reason, Reason::KernelDrift);
    }

    #[test]
    fn nt_peer_implied_routes_are_not_route_drift() {
        // Under the nt model (wireguard-nt adapter set_default_route), kernel
        // routes are assembled entirely from peer allowed-ips; plan.routes is
        // not issued via a separate path. Drift detection therefore skips the
        // plan.routes comparison — the hub `/16` must not be judged an
        // out-of-plan route just because it isn't in plan.routes (a replay
        // loop every round on leaf nodes with routes=[]; 2026-11-22 imac,
        // confirmed: KernelDrift hit the pre boundary 185 times on the old
        // binary).
        let mut p = plan("hash-a", false);
        p.routes = Vec::new(); // leaf node: no explicit route plan (imac has routes=[])
        let state = state_of(&p);
        let peer_routes: Vec<Ipv4Cidr> = p.tunnel.peers[0].allowed_ips.clone();
        assert!(
            !peer_routes.is_empty(),
            "test plan must carry peer allowed-ips to model the nt route set"
        );

        // nt semantics: installed routes = peer allowed-ips (hub `/16`);
        // skipping the plan.routes comparison → no drift (converges after the
        // fix).
        let nt_snapshot = NetworkSnapshot {
            installed_routes: peer_routes.clone(),
            routes_from_peers: true,
            ..healthy(&p)
        };
        assert_eq!(apply(&state, &nt_snapshot, &p).reason, Reason::UpToDate);

        // The same snapshot judged under service-model semantics (routes
        // independent of peers, compared against plan.routes): the hub `/16`
        // isn't in the empty plan.routes → out-of-plan route → must be drift.
        // This is the pre-fix reality (routes_from_peers not yet introduced),
        // kept as a regression guard for the fix.
        let service_snapshot = NetworkSnapshot {
            installed_routes: peer_routes,
            routes_from_peers: false,
            ..healthy(&p)
        };
        assert_eq!(
            apply(&state, &service_snapshot, &p).reason,
            Reason::KernelDrift
        );
    }

    #[test]
    fn direct_peer_in_the_keep_set_is_not_drift_but_its_absence_is_not_either() {
        // §12: direct peers are added/removed separately by the agent's direct
        // manager. During plan-replay reconciliation:
        // - present in the kernel → not drift (kept, no replay triggered);
        // - absent from the kernel → also not drift (the manager adds it back
        //   — a drift-triggered replay would not install the direct peer
        //   anyway, deadlocking in "replay can't fix it").
        let p = plan("hash-a", false);
        let state = state_of(&p);
        let direct_key = "direct-peer-pubkey==".to_string();

        let with_direct = NetworkSnapshot {
            peers: vec![
                PeerObserved {
                    public_key: p.tunnel.peers[0].public_key.clone(),
                    allowed_ips: p.tunnel.peers[0].allowed_ips.clone(),
                },
                PeerObserved {
                    public_key: direct_key.clone(),
                    allowed_ips: vec!["10.240.0.9/32".parse().unwrap()],
                },
            ],
            ..healthy(&p)
        };
        let keep: BTreeSet<String> = [direct_key.clone()].into_iter().collect();
        assert!(
            !needs_apply(&state, &with_direct, &p, &keep).needs_apply,
            "a kept direct peer must not read as drift"
        );

        // An extra peer outside the keep set is still drift (unmanaged
        // object).
        let keep: BTreeSet<String> = BTreeSet::new();
        assert_eq!(
            needs_apply(&state, &with_direct, &p, &keep).reason,
            Reason::KernelDrift
        );

        // A direct peer declared in the keep set but absent from the kernel:
        // not drift (the manager is responsible for adding it).
        let keep: BTreeSet<String> = [direct_key].into_iter().collect();
        assert!(!needs_apply(&state, &healthy(&p), &p, &keep).needs_apply);
    }

    #[test]
    fn a_substituted_or_extra_peer_is_drift_with_an_equal_count() {
        // Same count, different identity (a peer swapped on the managed
        // interface) → must replay. The old check only looked at
        // `peer_count` and judged such injections "not drifted" — exactly why
        // identity-level comparison was introduced.
        let p = plan("hash-a", false);
        let swapped = NetworkSnapshot {
            peers: vec![PeerObserved {
                public_key: "somebody-else".into(),
                allowed_ips: vec!["10.240.0.0/16".parse().unwrap()],
            }],
            ..healthy(&p)
        };
        assert_eq!(
            apply(&state_of(&p), &swapped, &p).reason,
            Reason::KernelDrift
        );
        // No substitution, just one extra peer: peers on this interface are
        // all Meshlet-owned, so an extra one is drift (it equally bypassed
        // the misplaced peer_count check).
        let extra = {
            let mut snapshot = healthy(&p);
            snapshot.peers.push(PeerObserved {
                public_key: "lurker".into(),
                allowed_ips: vec!["10.240.0.9/32".parse().unwrap()],
            });
            snapshot
        };
        assert_eq!(apply(&state_of(&p), &extra, &p).reason, Reason::KernelDrift);
    }

    #[test]
    fn peer_allowed_ips_widened_is_drift_and_order_is_ignored() {
        // Same identity, widened allowed-ips (allowing the whole range) →
        // must replay to correct.
        let p = plan("hash-a", false);
        let widened = NetworkSnapshot {
            peers: vec![PeerObserved {
                public_key: "hub-pub".into(),
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            }],
            ..healthy(&p)
        };
        assert_eq!(
            apply(&state_of(&p), &widened, &p).reason,
            Reason::KernelDrift
        );

        // Same set, different order is not drift (kernel enumeration order is
        // not ours to dictate).
        let mut multi = plan("hash-a", false);
        multi.tunnel.peers[0].allowed_ips = vec![
            "10.240.0.0/16".parse().unwrap(),
            "192.168.9.0/24".parse().unwrap(),
        ];
        let reordered = NetworkSnapshot {
            peers: vec![PeerObserved {
                public_key: multi.tunnel.peers[0].public_key.clone(),
                allowed_ips: vec![
                    "192.168.9.0/24".parse().unwrap(),
                    "10.240.0.0/16".parse().unwrap(),
                ],
            }],
            ..healthy(&multi)
        };
        assert!(!apply(&state_of(&multi), &reordered, &multi).needs_apply);
    }

    #[test]
    fn missing_or_extra_nat_fingerprint_is_drift() {
        // One missing: DNAT hand-deleted while SNAT remains → set mismatch.
        // The old `nat_rules_present` boolean judged this "not drifted" — one
        // rule present was taken as all present.
        let p = plan("hash-a", true);
        let mut dnat_missing = healthy(&p);
        dnat_missing.nat_rules = vec![p.nat_rules[1].signature()];
        assert_eq!(
            apply(&state_of(&p), &dnat_missing, &p).reason,
            Reason::KernelDrift
        );

        // One extra: the issue path only adds, never removes, so leftover
        // rules from an old mapping unit must be detected (they will not
        // vanish on their own).
        let mut stale_rule = p.nat_rules[0].clone();
        stale_rule.match_dest = "10.241.8.0/24".parse().unwrap();
        stale_rule.action = NatAction::NetMap {
            to: "192.168.8.0/24".parse().unwrap(),
        };
        stale_rule.owner = "meshlet alias al-0".into();
        let mut extra_rule = healthy(&p);
        extra_rule.nat_rules.push(stale_rule.signature());
        assert_eq!(
            apply(&state_of(&p), &extra_rule, &p).reason,
            Reason::KernelDrift
        );
    }

    #[test]
    fn orphan_nat_rules_on_a_demoted_gateway_are_drift() {
        // NAT gone from the plan (gateway demoted / mapping deleted) while
        // Meshlet-commented rules remain in the kernel → must replay to run
        // the ownership cleanup. The old logic waved "no NAT in plan" through,
        // leaving leftovers until someone cleaned them by hand.
        let p = plan("hash-a", false);
        let orphan = NatRule {
            source_cidr: None,
            incoming_interface: None,
            chain: NatChain::Postrouting,
            match_dest: "192.168.9.0/24".parse().unwrap(),
            action: NatAction::SnatToGatewayLan,
            owner: "meshlet alias al-1".into(),
        };
        let mut leftover = healthy(&p);
        leftover.nat_rules = vec![orphan.signature()];
        assert_eq!(
            apply(&state_of(&p), &leftover, &p).reason,
            Reason::KernelDrift
        );
    }

    #[test]
    fn planned_mtu_mismatch_counts_as_drift() {
        // Kernel reading differs from the plan (hand edit / half-failed
        // apply) → must replay to correct (#51).
        let mut p = plan("hash-a", false);
        p.tunnel.mtu = Some(1380);

        let wrong = NetworkSnapshot {
            tunnel_mtu: Some(1420),
            ..healthy(&p)
        };
        assert_eq!(apply(&state_of(&p), &wrong, &p).reason, Reason::KernelDrift);

        let matching = NetworkSnapshot {
            tunnel_mtu: Some(1380),
            ..healthy(&p)
        };
        assert!(!apply(&state_of(&p), &matching, &p).needs_apply);
    }

    #[test]
    fn kernel_mtu_is_not_judged_when_plan_leaves_it_unset() {
        // Plan sets no MTU: whatever the kernel reads is fine (the 1420
        // default or a deliberate admin setting).
        let p = plan("hash-a", false);
        let other = NetworkSnapshot {
            tunnel_mtu: Some(1300),
            ..healthy(&p)
        };
        assert!(!apply(&state_of(&p), &other, &p).needs_apply);
    }

    #[test]
    fn no_nat_in_plan_does_not_require_nat_rules_in_kernel() {
        // Non-gateway device: the kernel has no Meshlet NAT rules by design;
        // not drift.
        let p = plan("hash-a", false);
        let no_nat = NetworkSnapshot {
            nat_rules: Vec::new(),
            ..healthy(&p)
        };
        assert!(!apply(&state_of(&p), &no_nat, &p).needs_apply);
    }

    #[test]
    fn stale_owners_covers_removed_and_changed_mappings() {
        let p = plan("hash-a", true);
        let state = state_of(&p);
        assert!(
            stale_owners(&state, &p, &[], true).is_empty(),
            "an unchanged plan has nothing stale"
        );

        // Mapping deleted (whole-unit cleanup, §12.6): empty rule set → clean
        // up all ledger units.
        let mut without_alias = p.clone();
        without_alias.nat_rules.clear();
        assert_eq!(
            stale_owners(&state, &without_alias, &state.nat_owners, true),
            vec!["meshlet alias al-1"]
        );

        // Another mapping takes over: clean up the old unit; the new unit is
        // issued with the plan.
        let mut other = p.clone();
        other.nat_rules[0].owner = "meshlet alias al-2".into();
        other.nat_rules[1].owner = "meshlet alias al-2".into();
        assert_eq!(
            stale_owners(&state, &other, &state.nat_owners, true),
            vec!["meshlet alias al-1"]
        );

        // // Mapping still there but a rule is gone (dnat_snat → dnat_only): the // issue path only
        // adds, so clean first, then refresh — otherwise old // rules linger (anything outside the
        // whitelist is never touched). let mut dnat_only = p.clone();
        let mut dnat_only = p.clone();
        dnat_only.nat_rules.pop();
        assert_eq!(
            stale_owners(&state, &dnat_only, &state.nat_owners, true),
            vec!["meshlet alias al-1"]
        );

        // Reordering is not a change (the fingerprint set is
        // order-independent).
        let mut reordered = p.clone();
        reordered.nat_rules.reverse();
        assert!(stale_owners(&state, &reordered, &state.nat_owners, true).is_empty());
    }

    #[test]
    fn missing_or_corrupt_ledger_uses_kernel_inventory() {
        let mut p = plan("hash-a", false);
        p.nat_rules.clear();
        assert_eq!(
            stale_owners(
                &AgentState::default(),
                // &p, &["meshlet alias kept".into(), "meshlet alias old".into()],
                &p,
                &["meshlet alias kept".into(), "meshlet alias old".into()],
                false
            ),
            [
                "meshlet alias kept".to_string(),
                "meshlet alias old".to_string(),
            ]
        );
    }

    #[test]
    fn state_round_trips_through_the_state_file() {
        let p = plan("hash-a", true);
        let state = state_of(&p);
        let dir = std::env::temp_dir().join("meshlet-agent-state-test");
        let path = state_path(dir.to_str().unwrap());
        std::fs::remove_file(&path).ok();

        state.save(&path).expect("save state");
        let loaded = AgentState::load(&path).expect("load state");
        // assert_eq!(loaded, state); assert_eq!(loaded.desired_config_hash, "hash-a");
        assert_eq!(loaded, state);
        assert_eq!(loaded.desired_config_hash, "hash-a");
        assert_eq!(loaded.nat_owners, vec!["meshlet alias al-1"]);
        assert_eq!(loaded.routes, vec!["192.168.9.0/24"]);
        assert_eq!(loaded.nat_rules.len(), 2, "one fingerprint per rule");
        assert!(
            loaded
                .nat_rules
                .iter()
                .all(|f| f.contains("meshlet alias al-1")),
            "fingerprints carry the ownership comment: {:?}",
            loaded.nat_rules
        );
        // // The plan carries no private key: the ledger will not accidentally
        // persist one either.
        assert!(!state.tunnel_address.contains("key"));

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn corrupt_state_file_reads_as_empty_ledger() {
        // A corrupt ledger is treated as "no ledger" (triggering a replay);
        // the agent must neither stall nor pretend the plan is applied.
        let dir = std::env::temp_dir().join("meshlet-agent-state-corrupt");
        std::fs::create_dir_all(&dir).unwrap();
        let path = state_path(dir.to_str().unwrap());
        std::fs::write(&path, "{not json").unwrap();
        let loaded = AgentState::load(&path).unwrap_or_default();
        assert_eq!(loaded, AgentState::default());
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }
}
