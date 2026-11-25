//! R-01 pure-logic planner (chapter 4 of target-architecture): touches no database, runs no system commands, holds no keys.
//! Takes an immutable snapshot as input and emits a deterministic plan; see docs/design/r01-domain-model.md for the revision state machine.

pub mod outbox;

pub use outbox::{Outbox, OutboxEntry, OutboxError, OutboxStatus, RevisionReceipt};

use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevisionStatus {
    Pending,
    Preparing,
    Applying,
    Succeeded,
    Failed,
    RollingBack,
    RolledBack,
}

impl RevisionStatus {
    /// Legal transition table: the single Applied state is dropped (review 3.2); after a failure only rollback is allowed, no jump straight to success (decision 6).
    pub fn can_transition_to(self, next: RevisionStatus) -> bool {
        use RevisionStatus::*;
        matches!(
            (self, next),
            (Pending, Preparing)
                | (Preparing, Applying)
                | (Preparing, Failed)
                | (Applying, Succeeded)
                | (Applying, Failed)
                | (Failed, RollingBack)
                | (RollingBack, RolledBack)
                | (RollingBack, Failed)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverlayAddress(pub [u8; 4]);

#[derive(Debug, Clone)]
pub struct NetworkSnapshot {
    pub network_id: String,
    /// Joined device -> overlay address (desired-state, input only)
    pub attachments: BTreeMap<String, OverlayAddress>,
    pub lan_prefixes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanOp {
    PublishLanRoute {
        prefix: String,
        owner_device: String,
        metric: u32,
    },
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub network_id: String,
    /// Deterministic once sorted (same input always yields the same output, review 4.3)
    pub ops: Vec<PlanOp>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    InvalidPrefix(String),
    PrefixOverlap(String),
}

fn parse_prefix(p: &str) -> Result<(u32, u32), PlanError> {
    let bad = || PlanError::InvalidPrefix(p.to_string());
    let (ip, mask) = p.split_once('/').ok_or_else(bad)?;
    let octets: Vec<u8> = ip
        .split('.')
        .map(|x| x.parse::<u8>().map_err(|_| bad()))
        .collect::<Result<_, _>>()?;
    if octets.len() != 4 {
        return Err(bad());
    }
    let mask: u8 = mask.parse().map_err(|_| bad())?;
    if mask > 32 {
        return Err(bad());
    }
    let ip = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
    let m = if mask == 0 {
        0
    } else {
        u32::MAX << (32 - mask)
    };
    Ok((ip & m, m))
}

fn overlaps(a: (u32, u32), b: (u32, u32)) -> bool {
    a.0 & b.1 == b.0 & a.1
}

/// Conflict check that is global and independent of creation order (review 4.2): every pair of prefixes is compared.
pub fn check_prefix_conflicts(prefixes: &[String]) -> Result<(), PlanError> {
    let parsed = prefixes
        .iter()
        .map(|p| parse_prefix(p).map(|v| (p, v)))
        .collect::<Result<Vec<_>, _>>()?;
    for i in 0..parsed.len() {
        for j in (i + 1)..parsed.len() {
            if overlaps(parsed[i].1, parsed[j].1) {
                return Err(PlanError::PrefixOverlap(format!(
                    "{} vs {}",
                    parsed[i].0, parsed[j].0
                )));
            }
        }
    }
    Ok(())
}

/// Deterministic LAN route plan: conflict check first, then publish in lexicographic (prefix, owner) order.
pub fn plan_lan_routes(snapshot: &NetworkSnapshot) -> Result<Plan, PlanError> {
    check_prefix_conflicts(&snapshot.lan_prefixes)?;
    let mut owners: Vec<&String> = snapshot.attachments.keys().collect();
    owners.sort();
    let mut prefixes = snapshot.lan_prefixes.clone();
    prefixes.sort();
    let mut ops = Vec::new();
    if let Some(owner) = owners.first() {
        for prefix in &prefixes {
            ops.push(PlanOp::PublishLanRoute {
                prefix: prefix.clone(),
                owner_device: (*owner).clone(),
                metric: 100,
            });
        }
    }
    Ok(Plan {
        network_id: snapshot.network_id.clone(),
        ops,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use RevisionStatus::*;

    #[test]
    fn transition_lifecycle_is_legal() {
        assert!(Pending.can_transition_to(Preparing));
        assert!(!Pending.can_transition_to(Succeeded));
        assert!(!Failed.can_transition_to(Succeeded));
        assert!(Failed.can_transition_to(RollingBack));
    }

    #[test]
    fn conflicts_are_order_independent() {
        let a = vec!["10.0.0.0/8".to_string(), "10.1.0.0/16".to_string()];
        let b = vec!["10.1.0.0/16".to_string(), "10.0.0.0/8".to_string()];
        assert!(check_prefix_conflicts(&a).is_err());
        assert!(check_prefix_conflicts(&b).is_err());
        assert!(check_prefix_conflicts(&["10.0.0.0/8".into(), "11.0.0.0/8".into()]).is_ok());
    }

    #[test]
    fn plan_is_deterministic() {
        let mut attachments = BTreeMap::new();
        attachments.insert("dev-b".to_string(), OverlayAddress([10, 200, 0, 2]));
        attachments.insert("dev-a".to_string(), OverlayAddress([10, 200, 0, 1]));
        let snap = NetworkSnapshot {
            network_id: "n1".to_string(),
            attachments,
            lan_prefixes: vec!["192.168.1.0/24".to_string()],
        };
        let p1 = plan_lan_routes(&snap).unwrap();
        let p2 = plan_lan_routes(&snap).unwrap();
        assert_eq!(p1.ops, p2.ops);
        match &p1.ops[0] {
            PlanOp::PublishLanRoute { owner_device, .. } => assert_eq!(owner_device, "dev-a"),
        }
    }
}
