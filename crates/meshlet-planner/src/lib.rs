//! R-01 纯逻辑规划器（target-architecture 第四章）：不落库、不执行系统命令、不持密钥。
//! 输入不可变快照，输出确定性计划；修订状态机见 docs/design/r01-domain-model.md。

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
    /// 合法迁移表：弃单一 Applied（评审 3.2）；失败后只能回滚，不许直通成功（决策 6）。
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
    /// 已入网设备 -> overlay 地址（期望态纯输入）
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
    /// 排序后即确定性（同输入必同输出，评审 4.3）
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

/// 全局且与创建顺序无关的冲突检查（评审 4.2）：任意两前缀两两比对。
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

/// 确定性 LAN 路由计划：先冲突检查，再按 (prefix, owner) 字典序发布。
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
