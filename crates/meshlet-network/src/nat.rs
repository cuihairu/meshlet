//! NAT rule planning ([archive §9.4–§9.5](../../../docs/review/chatgpt-2026-10-13.md),
//! [ADR-006](../../../docs/decisions/adr-006-alias-prefix-nat.md)).
//!
//! This module is **pure planning**: it deterministically derives the gateway-side NAT rules
//! that should exist from an `AliasMapping`, without executing any iptables call. Execution
//! (pushing/removing rules) follows the revision apply into the network backend
//! ([ADR-007](../../../docs/decisions/adr-007-linux-network-backend.md)); until the dataplane is
//! wired up, apply fails deterministically and visibly (§10.3, no pretending to succeed).
//!
//! Translation happens on the **target LAN gateway** (§9.4): the gateway knows the real LAN exit
//! and reaches the target host directly, while the VPS only forwards by prefix (no need to build
//! overlapping routes for every remote LAN on the VPS).

use meshlet_domain::{AliasMapping, Ipv4Cidr, TranslationMode};

/// NAT table chains: destination rewrite before the routing decision (PREROUTING), source rewrite
/// before the packet leaves the gateway (POSTROUTING).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatChain {
    Prerouting,
    Postrouting,
}

impl NatChain {
    /// The iptables chain name (for rendering).
    pub fn as_str(self) -> &'static str {
        match self {
            NatChain::Prerouting => "PREROUTING",
            NatChain::Postrouting => "POSTROUTING",
        }
    }
}

/// Rule action. Serialized as snake_case (plans go out over the agent API, so the field shape
/// matches the rest of the control-plane snake_case contract: `{"net_map":{"to":"…"}}` / `"snat_to_gateway_lan"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatAction {
    /// 1:1 equal-length prefix rewrite (iptables `NETMAP` semantics). ADR-006's equal-length
    /// constraint guarantees a one-to-one address mapping between the alias and target sides (the
    /// same offset math as `AliasMapping::translate`).
    NetMap { to: Ipv4Cidr },
    /// Controlled SNAT to the gateway's own LAN address (§9.5 default compatibility mode). The
    /// address is resolved by the gateway at execution time — the mapping itself carries no
    /// gateway LAN address.
    SnatToGatewayLan,
}

/// A single planned NAT rule.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NatRule {
    #[serde(default)]
    pub source_cidr: Option<Ipv4Cidr>,
    #[serde(default)]
    pub incoming_interface: Option<String>,
    pub chain: NatChain,
    /// Matches on the **destination** prefix: DNAT matches the alias prefix; controlled SNAT matches
    /// the target prefix (i.e. traffic already DNAT-rewritten to the real LAN destination and about
    /// to enter the LAN).
    pub match_dest: Ipv4Cidr,
    pub action: NatAction,
    /// Ownership comment (§12.6 cleanup targeting): `meshlet alias {id}` — when a mapping or the whole
    /// unit is removed, Meshlet-owned rules are matched and removed exactly by comment; non-Meshlet
    /// rules are never touched.
    pub owner: String,
}

impl NatRule {
    /// Rule identity fingerprint (`chain|dest|action|owner|source|in-iface`), independent of the
    /// gateway LAN address. The plan side and the kernel side ([crate::linux] parsing the iptables
    /// `-S` output) produce strings of the same shape, so the two sides can be compared as exact sets.
    ///
    /// The fingerprint only reflects the **fields the kernel actually renders** (see
    /// [`Self::iptables_args`]): `-i` renders only for PREROUTING; on a POSTROUTING rule
    /// `incoming_interface` is inert metadata and the fingerprint always records `none` — otherwise
    /// the plan side carries an interface while the kernel side does not, the same rule fingerprints
    /// differently on each side and is misjudged as an out-of-plan extra object.
    ///
    /// Optional fields render as the bare CIDR Display string and defaults as `none` — the kernel
    /// side reads bare strings off the command line anyway; `{:?}` would print internal struct
    /// fields and never match.
    ///
    /// The ledger (`nat_rules` in `applied.json`) is only ever compared against another fingerprint
    /// of the same plan, never against the kernel side, so a convention change here triggers at
    /// most one idempotent replay.
    pub fn signature(&self) -> String {
        let action = match self.action {
            NatAction::NetMap { to } => format!("net_map:{to}"),
            NatAction::SnatToGatewayLan => "snat_to_gateway_lan".to_string(),
        };
        let source = self
            .source_cidr
            .map_or_else(|| "none".to_string(), |cidr| cidr.to_string());
        let interface = match self.chain {
            NatChain::Prerouting => self
                .incoming_interface
                .clone()
                .unwrap_or_else(|| "none".to_string()),
            NatChain::Postrouting => "none".to_string(),
        };
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.chain.as_str(),
            self.match_dest,
            action,
            self.owner,
            source,
            interface
        )
    }

    /// Render as iptables arguments (everything except `-t nat`; unit tests and the future executor
    /// share this one rendering so plan and execution cannot drift). `gateway_lan_addr` is consumed
    /// by [NatAction::SnatToGatewayLan]; NETMAP rules do not read it.
    pub fn iptables_args(&self, gateway_lan_addr: std::net::Ipv4Addr) -> Vec<String> {
        let mut args = vec![
            "-A".into(),
            self.chain.as_str().into(),
            "-d".into(),
            self.match_dest.to_string(),
        ];
        if let Some(source) = self.source_cidr {
            args.extend(["-s".into(), source.to_string()]);
        }
        if self.chain == NatChain::Prerouting {
            if let Some(interface) = &self.incoming_interface {
                args.extend(["-i".into(), interface.clone()]);
            }
        }
        match self.action {
            NatAction::NetMap { to } => {
                args.extend(["-j".into(), "NETMAP".into(), "--to".into(), to.to_string()]);
            }
            NatAction::SnatToGatewayLan => {
                args.extend([
                    "-j".into(),
                    "SNAT".into(),
                    "--to-source".into(),
                    gateway_lan_addr.to_string(),
                ]);
            }
        }
        args.extend([
            "-m".into(),
            "comment".into(),
            "--comment".into(),
            self.owner.clone(),
        ]);
        args
    }
}

/// Plan gateway-side NAT rules from an Alias mapping (§9.4–§9.5):
///
/// - **DNAT is always present**: `PREROUTING NETMAP alias → target` — a client visits the Alias
///   address and the gateway rewrites the destination to the real LAN prefix (equal-length,
///   one-to-one);
/// - `dnat_snat` (the default compatibility mode) adds a controlled `POSTROUTING` SNAT: Alias
///   traffic entering the LAN gets its source rewritten to the gateway LAN address — LAN hosts
///   reply without needing a return route pointing at the gateway, at the cost of the LAN side
///   losing sight of the original source address (a limitation stated in §9.5; the console shows
///   the mode alongside the mapping);
/// - `dnat_only` adds no SNAT (keeps the original source address): it requires the LAN to have a
///   return route pointing at the gateway (`dual_route` semantics), or responses are lost.
///
/// Rule order is deterministic (DNAT first, SNAT after); the ownership comment carries the mapping id.
pub fn alias_nat_rules(alias: &AliasMapping) -> Vec<NatRule> {
    let owner = format!("meshlet alias {}", alias.id);
    let mut rules = vec![NatRule {
        source_cidr: None,
        incoming_interface: None,
        chain: NatChain::Prerouting,
        match_dest: alias.alias_cidr,
        action: NatAction::NetMap {
            to: alias.target_cidr,
        },
        owner: owner.clone(),
    }];
    if alias.translation_mode == TranslationMode::DnatSnat {
        rules.push(NatRule {
            source_cidr: None,
            incoming_interface: None,
            chain: NatChain::Postrouting,
            match_dest: alias.target_cidr,
            action: NatAction::SnatToGatewayLan,
            owner,
        });
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshlet_domain::{AliasMappingId, LanRouteId, NetworkId};

    fn mapping(mode: TranslationMode) -> AliasMapping {
        AliasMapping::new(
            AliasMappingId("al-7".into()),
            NetworkId("n-1".into()),
            LanRouteId("rt-3".into()),
            "10.241.1.0/24".parse().unwrap(),
            "192.168.1.0/24".parse().unwrap(),
            mode,
        )
        .unwrap()
    }

    #[test]
    fn dnat_only_plans_a_single_prerouting_netmap() {
        // §9.4: DNAT is always present and executes on the target LAN gateway.
        let rules = alias_nat_rules(&mapping(TranslationMode::DnatOnly));
        assert_eq!(rules.len(), 1);
        let dnat = &rules[0];
        assert_eq!(dnat.chain, NatChain::Prerouting);
        assert_eq!(dnat.match_dest.to_string(), "10.241.1.0/24");
        assert_eq!(
            dnat.action,
            NatAction::NetMap {
                to: "192.168.1.0/24".parse().unwrap()
            }
        );
        // Original source address preserved: no SNAT rule (requires the dual_route return route).
        assert!(!rules.iter().any(|r| r.chain == NatChain::Postrouting));
    }

    #[test]
    fn dnat_snat_adds_controlled_postrouting_snat() {
        // §9.5 default compatibility mode: Alias traffic entering the LAN is controlled-SNATed to the gateway LAN address.
        let rules = alias_nat_rules(&mapping(TranslationMode::DnatSnat));
        assert_eq!(rules.len(), 2);
        // Deterministic order: DNAT first.
        assert_eq!(rules[0].chain, NatChain::Prerouting);
        let snat = &rules[1];
        assert_eq!(snat.chain, NatChain::Postrouting);
        // SNAT matches the target prefix — traffic just DNAT-rewritten and about to enter the LAN.
        assert_eq!(snat.match_dest.to_string(), "192.168.1.0/24");
        assert_eq!(snat.action, NatAction::SnatToGatewayLan);
    }

    #[test]
    fn every_rule_carries_the_alias_ownership_comment() {
        // §12.6: when a mapping is deleted, Meshlet-owned rules are cleaned up exactly by comment.
        for mode in [TranslationMode::DnatOnly, TranslationMode::DnatSnat] {
            for rule in alias_nat_rules(&mapping(mode)) {
                assert_eq!(rule.owner, "meshlet alias al-7");
            }
        }
    }

    #[test]
    fn planning_is_deterministic() {
        let alias = mapping(TranslationMode::DnatSnat);
        assert_eq!(alias_nat_rules(&alias), alias_nat_rules(&alias));
    }

    #[test]
    fn overlay_traffic_matches_no_rule_so_sources_stay_original() {
        // §7.4: ordinary overlay device-to-device traffic keeps its original source address — blanket-SNATing
        // the whole overlay network to the VPS address is forbidden. The planning layer guarantees this
        // structurally: rules match on the **destination** prefix, which can only be the alias or the
        // real LAN (target) subnet; traffic destined inside the overlay matches no rule and passes through as-is.
        let overlay: Ipv4Cidr = "10.240.0.0/16".parse().unwrap();
        for mode in [TranslationMode::DnatOnly, TranslationMode::DnatSnat] {
            let rules = alias_nat_rules(&mapping(mode));

            // No rule's match prefix overlaps the overlay subnet (the "blanket-SNAT the whole
            // overlay network" rule shape does not exist).
            for rule in &rules {
                assert!(
                    !overlay.overlaps(&rule.match_dest),
                    "rule must not match overlay destinations: {rule:?}"
                );
            }
            // Overlay destination addresses match no rule at all.
            for dest in ["10.240.0.5", "10.240.200.9"] {
                let ip = dest.parse::<std::net::Ipv4Addr>().unwrap();
                assert!(
                    !rules.iter().any(|r| r.match_dest.contains(ip)),
                    "overlay dest {dest} must match no NAT rule"
                );
            }
            // Alias destinations do match a rule — translation targets only Alias traffic.
            let alias_dest = "10.241.1.5".parse::<std::net::Ipv4Addr>().unwrap();
            assert!(
                rules.iter().any(|r| r.match_dest.contains(alias_dest)),
                "alias destination must match a rule"
            );
        }
    }

    #[test]
    fn iptables_rendering_matches_the_plan() {
        // Plan and rendering share one structure: whatever a rule contains, the rendering pushes.
        let gw: std::net::Ipv4Addr = "192.168.1.1".parse().unwrap();
        let rules = alias_nat_rules(&mapping(TranslationMode::DnatSnat));
        let (dnat, snat) = (&rules[0], &rules[1]);

        let expected: Vec<String> = [
            "-A",
            "PREROUTING",
            "-d",
            "10.241.1.0/24",
            "-j",
            "NETMAP",
            "--to",
            "192.168.1.0/24",
            "-m",
            "comment",
            "--comment",
            "meshlet alias al-7",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(dnat.iptables_args(gw), expected);

        let expected: Vec<String> = [
            "-A",
            "POSTROUTING",
            "-d",
            "192.168.1.0/24",
            "-j",
            "SNAT",
            "--to-source",
            "192.168.1.1",
            "-m",
            "comment",
            "--comment",
            "meshlet alias al-7",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(snat.iptables_args(gw), expected);
    }
}
