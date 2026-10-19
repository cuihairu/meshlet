//! 配置状态机与版本簿记（[存档 §10](../../docs/review/chatgpt-2026-10-13.md)、
//! [ADR-009](../../docs/decisions/adr-009-config-revision-rollback.md)）。
//!
//! 「数据库写入成功 ≠ WireGuard/路由/NAT 已生效」（§10.1）：期望配置的每次
//! 变更先生成新的 [`ConfigRevision`]（`Pending`，只代表 DB 已写入），再由
//! backend 显式应用到实际环境后才算 `Applied`；应用失败必须把错误写入修订
//! 记录（`Failed` + `error_summary`），**结果不确定时同样进入失败态、不得
//! 假装成功**（§10.3）。控制台以应用状态为准，不以 DB 写入为准。
//!
//! 应用幂等（§10.3）：同一版本重复应用结果一致——已 `Applied` 的修订直接返回，
//! 不再调用 backend；失败版本不允许原地重试（重试 = 以相同哈希记录新修订，
//! 保持状态机严格）；回滚只针对**当前**（最新未回滚的）`Failed` 修订
//! （`Applied` 的撤销走前滚新版本；被更新修订取代的失败修订拒绝回滚，
//! §10.4 不交叉破坏）。

use crate::cidr::Ipv4Cidr;
use crate::entities::{
    AliasMapping, ApplyStatus, ConfigRevision, Device, DeviceStatus, LanRoute, NetworkId,
    RevisionError, Timestamp,
};
use crate::segments::SegmentGrant;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::Ipv4Addr;

// ---------------------------------------------------------------------------
// 期望配置哈希
// ---------------------------------------------------------------------------

/// 期望配置哈希（ADR-009 `desired_config_hash`）：对 overlay 网段、hub 地址、
/// 全部 **Active** 设备、全部 LAN 路由与全部 Alias 映射的确定性序列化取
/// SHA-256。顺序不敏感（设备按虚拟 IP、路由按目的网段、Alias 按前缀排序）；
/// `Pending`/`Revoked` 设备不入配置故不参与哈希；路由/Alias 删除即出哈希。
/// 标签随输入集演进（v2 = 加入路由行，v3 = 加入 Alias 行，v4 = 加入 Applied
/// Segment Grant 行），避免跨版本哈希误判相等。
pub fn desired_config_hash(
    overlay_cidr: &Ipv4Cidr,
    hub: Ipv4Addr,
    devices: &[Device],
    routes: &[LanRoute],
    aliases: &[AliasMapping],
    segment_grants: &[SegmentGrant],
) -> String {
    let mut lines = vec![
        "meshlet-desired-v4".to_string(),
        format!("overlay={overlay_cidr}"),
        format!("hub={hub}"),
    ];
    let mut active: Vec<&Device> = devices
        .iter()
        .filter(|d| d.status == DeviceStatus::Active)
        .collect();
    active.sort_by_key(|d| d.virtual_ipv4);
    for d in active {
        lines.push(format!(
            "device name={} vip={} pubkey={}",
            d.name, d.virtual_ipv4, d.public_key
        ));
    }
    let mut sorted_routes: Vec<&LanRoute> = routes.iter().collect();
    sorted_routes.sort_by(|a, b| (&a.destination_cidr, &a.id).cmp(&(&b.destination_cidr, &b.id)));
    for r in sorted_routes {
        lines.push(format!(
            "route dst={} gw={} mode={} return={}",
            r.destination_cidr,
            r.gateway_device_id,
            r.route_mode.as_str(),
            r.return_path_mode.as_str()
        ));
    }
    let mut sorted_aliases: Vec<&AliasMapping> = aliases.iter().collect();
    sorted_aliases.sort_by(|a, b| (&a.alias_cidr, &a.id).cmp(&(&b.alias_cidr, &b.id)));
    for a in sorted_aliases {
        lines.push(format!(
            "alias prefix={} target={} route={} mode={}",
            a.alias_cidr,
            a.target_cidr,
            a.lan_route_id,
            a.translation_mode.as_str()
        ));
    }
    let mut sorted_grants: Vec<&SegmentGrant> = segment_grants
        .iter()
        .filter(|g| g.status == crate::segments::SegmentGrantStatus::Applied)
        .collect();
    sorted_grants.sort_by(|a, b| {
        (&a.source_segment_id, &a.destination_segment_id, &a.id).cmp(&(
            &b.source_segment_id,
            &b.destination_segment_id,
            &b.id,
        ))
    });
    for g in sorted_grants {
        lines.push(format!(
            "segment-grant src={} dst={}",
            g.source_segment_id, g.destination_segment_id
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(lines.join("\n").as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// ---------------------------------------------------------------------------
// 应用后端
// ---------------------------------------------------------------------------

/// 把期望配置应用到实际网络环境的后端（WireGuard/路由/NAT 的 OS 侧执行者）。
///
/// 实现纪律（§10.3、ADR-007）：
/// - 幂等：重复应用同一版本不得破坏网络；
/// - 结果不确定（如 applying 中途失联、无法确认接口状态）也必须返回 `Err`，
///   **不得返回 `Ok` 假装成功**；
/// - 只操作 Meshlet 自有对象，不得清空系统路由。
pub trait ConfigApplyBackend {
    /// Inspect and repair the last confirmed plan without publishing pending edits.
    fn reconcile(&mut self) -> Result<(), String> {
        Err("backend recovery is not configured".into())
    }
    fn apply(&mut self, revision: &ConfigRevision) -> Result<(), String>;
    /// 回滚一个 `Failed` 修订：只删除/恢复 Meshlet 自有对象。
    fn rollback(&mut self, revision: &ConfigRevision) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// 版本簿记
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    #[error("revision {revision} not found in network {network_id}")]
    RevisionNotFound { network_id: String, revision: u64 },
    /// 回滚目标已被更新修订取代（§10.4）：被取代的失败修订从未生效，按其
    /// 意图回滚会交叉触碰更新修订所拥有的对象——重试路径是对当前修订操作
    /// 或前滚记录新修订。
    #[error(
        "revision {revision} superseded by {latest} in network {network_id}; \
            roll back the current revision or record a new one"
    )]
    SupersededRevision {
        network_id: String,
        revision: u64,
        latest: u64,
    },
    #[error(transparent)]
    IllegalTransition(#[from] RevisionError),
}

/// 每网络配置修订簿记（ADR-009）：版本号网络内严格单调递增（§10.4 的版本
/// 顺序——同一网络的配置修改串行化即由「先记录修订、再应用修订」保证）。
#[derive(Debug, Clone, Default)]
pub struct ConfigLedger {
    revisions: HashMap<NetworkId, Vec<ConfigRevision>>,
}

impl ConfigLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// 记录一次期望配置变更：版本号 = 该网络上一版本 + 1，初始状态
    /// `Pending`（此时只完成了 DB 写入，**尚未生效**）。
    pub fn record(
        &mut self,
        network_id: &NetworkId,
        desired_config_hash: String,
        now: Timestamp,
    ) -> u64 {
        let revisions = self.revisions.entry(network_id.clone()).or_default();
        let revision = revisions.last().map(|r| r.revision + 1).unwrap_or(1);
        revisions.push(ConfigRevision::new(
            network_id.clone(),
            revision,
            desired_config_hash,
            now,
        ));
        revision
    }

    /// 某网络的全部修订（按版本号升序；未知网络返回空切片）。
    pub fn revisions(&self, network_id: &NetworkId) -> &[ConfigRevision] {
        self.revisions
            .get(network_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// 单个修订。
    pub fn get(&self, network_id: &NetworkId, revision: u64) -> Option<&ConfigRevision> {
        self.revisions(network_id)
            .iter()
            .find(|r| r.revision == revision)
    }

    /// 当前期望修订 = 最新一个未回滚的修订（控制台以此为准，§10.1）。
    pub fn current(&self, network_id: &NetworkId) -> Option<&ConfigRevision> {
        self.revisions(network_id)
            .iter()
            .rev()
            .find(|r| r.apply_status != ApplyStatus::RolledBack)
    }

    /// 应用一个修订：`pending → applying → applied | failed`。
    ///
    /// - 已 `Applied`：幂等返回，**不再调用 backend**（§10.3 重复应用不破坏
    ///   网络）；
    /// - backend 失败（含结果不确定）：进入 `Failed` 并记录 `error_summary`，
    ///   返回更新后的修订——调用方必须向控制台暴露该失败，不得吞掉；
    /// - 其余非法跃迁（如对 `Failed` 原地重试）返回
    ///   [`LedgerError::IllegalTransition`]，重试路径是记录新修订。
    pub fn apply(
        &mut self,
        network_id: &NetworkId,
        revision: u64,
        backend: &mut dyn ConfigApplyBackend,
        now: Timestamp,
    ) -> Result<ConfigRevision, LedgerError> {
        // 先做只读判定：未知修订 / 已生效版本的幂等重放都不需要可变借用。
        match self.get(network_id, revision) {
            None => {
                return Err(LedgerError::RevisionNotFound {
                    network_id: network_id.to_string(),
                    revision,
                })
            }
            Some(r) if r.apply_status == ApplyStatus::Applied => return Ok(r.clone()),
            Some(_) => {}
        }
        if let Some(latest) = self.current(network_id) {
            if latest.revision != revision {
                return Err(LedgerError::SupersededRevision {
                    network_id: network_id.to_string(),
                    revision,
                    latest: latest.revision,
                });
            }
        }
        let r = self.get_mut(network_id, revision).unwrap();
        if r.apply_status == ApplyStatus::Pending {
            r.transition(ApplyStatus::Applying)?;
        }
        match backend.apply(r) {
            Ok(()) => {
                r.transition(ApplyStatus::Applied)?;
                r.applied_at = Some(now);
                r.error_summary = None;
            }
            Err(summary) => {
                // 失败（含不确定结果）显式落态：error_summary 可诊断（§12.2）。
                r.transition(ApplyStatus::Failed)?;
                r.error_summary = Some(summary);
            }
        }
        Ok(self.get(network_id, revision).cloned().unwrap())
    }

    /// A provisional kernel success is not committed until its outcome is durable.
    /// Correct it to an explicit failure when persistence of that outcome fails.
    pub fn mark_apply_unconfirmed(&mut self, network_id: &NetworkId, revision: u64, error: String) {
        if let Some(r) = self.get_mut(network_id, revision) {
            if matches!(r.apply_status, ApplyStatus::Applied | ApplyStatus::Applying) {
                r.apply_status = ApplyStatus::Failed;
                r.applied_at = None;
                r.error_summary = Some(error);
            }
        }
    }

    /// Keep a rollback unconfirmed when its durable outcome cannot be committed.
    pub fn mark_rollback_unconfirmed(
        &mut self,
        network_id: &NetworkId,
        revision: u64,
        error: String,
    ) {
        if let Some(r) = self.get_mut(network_id, revision) {
            if matches!(
                r.apply_status,
                ApplyStatus::RolledBack | ApplyStatus::RollbackPending
            ) {
                r.apply_status = ApplyStatus::RollbackPending;
                let prior = r.error_summary.take().unwrap_or_default();
                r.error_summary = Some(format!("{prior}; {error}"));
            }
        }
    }

    /// 回滚一个 `Failed` 修订：`failed → rollback_pending → rolled_back`。
    /// 回滚动作同样交给 backend；上次回滚未确认（`RollbackPending`）允许重试，
    /// 已 `RolledBack` 的修订幂等返回。回滚成功后当前期望修订自然回落到更早
    /// 的未回滚修订（见 [`Self::current`]）。
    ///
    /// 只允许回滚**当前**（最新未回滚的）修订：被更新修订取代的 `Failed`
    /// 修订从未生效，按其意图回滚会交叉触碰更新修订拥有的对象（§10.4），
    /// 返回 [`LedgerError::SupersededRevision`]。
    pub fn rollback(
        &mut self,
        network_id: &NetworkId,
        revision: u64,
        backend: &mut dyn ConfigApplyBackend,
    ) -> Result<ConfigRevision, LedgerError> {
        // 先做只读判定：未知修订 / 幂等重放 / 非法跃迁都不需要可变借用。
        match self.get(network_id, revision) {
            None => {
                return Err(LedgerError::RevisionNotFound {
                    network_id: network_id.to_string(),
                    revision,
                })
            }
            Some(r) => match r.apply_status {
                ApplyStatus::RolledBack => return Ok(r.clone()), // 幂等
                // Failed 正常进入回滚；RollbackPending 是上次回滚未确认的重试入口。
                ApplyStatus::Failed | ApplyStatus::RollbackPending => {}
                other => {
                    return Err(LedgerError::IllegalTransition(
                        RevisionError::IllegalTransition {
                            from: other,
                            to: ApplyStatus::RollbackPending,
                        },
                    ))
                }
            },
        }
        // 取代检查（§10.4 交叉破坏）：只回滚当前修订。
        if let Some(latest) = self.current(network_id) {
            if latest.revision != revision {
                return Err(LedgerError::SupersededRevision {
                    network_id: network_id.to_string(),
                    revision,
                    latest: latest.revision,
                });
            }
        }
        let r = self.get_mut(network_id, revision).unwrap();
        if r.apply_status == ApplyStatus::Failed {
            r.transition(ApplyStatus::RollbackPending)?;
        }
        match backend.rollback(r) {
            Ok(()) => {
                r.transition(ApplyStatus::RolledBack)?;
            }
            Err(err) => {
                // 回滚失败：留在 RollbackPending（明确未完成），保留原失败
                // 诊断并追加回滚错误——状态可区分，失败可见。
                let mut msg = r.error_summary.take().unwrap_or_default();
                if !msg.is_empty() {
                    msg.push_str("; ");
                }
                msg.push_str("rollback failed: ");
                msg.push_str(&err);
                r.error_summary = Some(msg);
            }
        }
        Ok(self.get(network_id, revision).cloned().unwrap())
    }

    /// 装载持久化的修订（§17.3 启动重建）：按网络分组、版本号升序灌入，
    /// 版本序列与 DB 逐字一致——后续 [`Self::record`] 从最后一条继续递增，
    /// 不重号。调用方（boot）应保证同一网络内版本号无重复。
    pub fn restore(&mut self, revisions: Vec<ConfigRevision>) {
        let mut grouped: HashMap<NetworkId, Vec<ConfigRevision>> = HashMap::new();
        for r in revisions {
            grouped.entry(r.network_id.clone()).or_default().push(r);
        }
        for (network_id, mut rs) in grouped {
            rs.sort_by_key(|r| r.revision);
            self.revisions.insert(network_id, rs);
        }
    }

    /// Replace the stored conclusion for an already selected revision after an
    /// isolated apply/rollback task completes. Callers must still hold the
    /// network revision lock so concurrent tasks cannot overwrite each other.
    pub fn restore_revision(&mut self, revision: ConfigRevision) {
        let network_revisions = self
            .revisions
            .entry(revision.network_id.clone())
            .or_default();
        if let Some(existing) = network_revisions
            .iter_mut()
            .find(|r| r.revision == revision.revision)
        {
            *existing = revision;
        }
    }

    pub fn reserve_apply(&mut self, network_id: &NetworkId, revision: u64) -> bool {
        self.get_mut(network_id, revision)
            .filter(|r| r.apply_status == ApplyStatus::Pending)
            .is_some_and(|r| {
                r.apply_status = ApplyStatus::Applying;
                true
            })
    }

    pub fn reserve_rollback(&mut self, network_id: &NetworkId, revision: u64) -> bool {
        self.get_mut(network_id, revision)
            .filter(|r| r.apply_status == ApplyStatus::Failed)
            .is_some_and(|r| {
                r.apply_status = ApplyStatus::RollbackPending;
                true
            })
    }

    /// §10.3 中断收敛（§17.3 重启恢复）：进程重启后，停在 `Applying` 的修订
    /// 结果不可知——一律落 `Failed` 并记录中断诊断，**不得假装成功**。
    /// `RollbackPending` 保留（回滚未确认、可重试）；`Applied`/`RolledBack`
    /// 是终态，不动。返回被收敛修订的身份，供调用方回写持久层。
    pub fn interrupt_applying(&mut self, error_summary: &str) -> Vec<(NetworkId, u64)> {
        let mut converged = Vec::new();
        for (network_id, revisions) in self.revisions.iter_mut() {
            for r in revisions.iter_mut() {
                if r.apply_status == ApplyStatus::Applying
                    && r.transition(ApplyStatus::Failed).is_ok()
                {
                    r.error_summary = Some(error_summary.to_string());
                    converged.push((network_id.clone(), r.revision));
                }
            }
        }
        converged
    }

    fn get_mut(&mut self, network_id: &NetworkId, revision: u64) -> Option<&mut ConfigRevision> {
        self.revisions
            .get_mut(network_id)
            .and_then(|rs| rs.iter_mut().find(|r| r.revision == revision))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::{
        AliasMappingId, DesiredStateStatus, DeviceId, LanRouteId, ReturnPathMode, RouteMode,
        TranslationMode,
    };

    const T0: &str = "2026-10-14T08:00:00Z";
    const T1: &str = "2026-10-14T08:01:00Z";
    const T2: &str = "2026-10-14T08:02:00Z";

    fn net(id: &str) -> NetworkId {
        NetworkId(id.into())
    }

    struct OkBackend;

    impl ConfigApplyBackend for OkBackend {
        fn apply(&mut self, _r: &ConfigRevision) -> Result<(), String> {
            Ok(())
        }
        fn rollback(&mut self, _r: &ConfigRevision) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn backend_recovery_default_fails_closed_until_configured() {
        let mut unconfigured = OkBackend;
        assert_eq!(
            unconfigured.reconcile().unwrap_err(),
            "backend recovery is not configured"
        );

        struct ConfiguredBackend;

        impl ConfigApplyBackend for ConfiguredBackend {
            fn apply(&mut self, _r: &ConfigRevision) -> Result<(), String> {
                Ok(())
            }

            fn rollback(&mut self, _r: &ConfigRevision) -> Result<(), String> {
                Ok(())
            }

            fn reconcile(&mut self) -> Result<(), String> {
                Ok(())
            }
        }

        assert!(ConfiguredBackend.reconcile().is_ok());
    }

    struct BrokenBackend {
        apply_error: String,
        rollback_error: String,
    }

    impl BrokenBackend {
        fn new(apply_error: &str, rollback_error: &str) -> Self {
            Self {
                apply_error: apply_error.into(),
                rollback_error: rollback_error.into(),
            }
        }
    }

    impl ConfigApplyBackend for BrokenBackend {
        fn apply(&mut self, _r: &ConfigRevision) -> Result<(), String> {
            Err(self.apply_error.clone())
        }
        fn rollback(&mut self, _r: &ConfigRevision) -> Result<(), String> {
            Err(self.rollback_error.clone())
        }
    }

    struct CountingBackend {
        calls: u32,
    }

    impl ConfigApplyBackend for CountingBackend {
        fn apply(&mut self, _r: &ConfigRevision) -> Result<(), String> {
            self.calls += 1;
            Ok(())
        }
        fn rollback(&mut self, _r: &ConfigRevision) -> Result<(), String> {
            self.calls += 1;
            Ok(())
        }
    }

    #[test]
    fn revisions_are_monotonic_per_network_and_independent_across_networks() {
        let mut l = ConfigLedger::new();
        let (a, b) = (net("net-a"), net("net-b"));
        assert_eq!(l.record(&a, "h1".into(), T0.into()), 1);
        assert_eq!(l.record(&a, "h2".into(), T0.into()), 2);
        // 另一网络独立计数（§10.4 版本顺序按网络隔离）。
        assert_eq!(l.record(&b, "h1".into(), T0.into()), 1);
        assert_eq!(l.current(&a).unwrap().revision, 2);
        assert_eq!(l.get(&a, 1).unwrap().desired_config_hash, "h1");
        assert_eq!(l.get(&b, 1).unwrap().desired_config_hash, "h1");
    }

    #[test]
    fn recorded_revision_is_pending_without_applied_at_or_error() {
        // 验收基线：DB 写入 ≠ 显示生效——新修订不得宣称 Applied。
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h".into(), T0.into());
        let r = l.current(&id).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::Pending);
        assert!(r.applied_at.is_none());
        assert!(r.error_summary.is_none());
    }

    #[test]
    fn apply_success_transitions_to_applied_and_sets_applied_at() {
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h".into(), T0.into());
        let r = l.apply(&id, 1, &mut OkBackend, T1.into()).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::Applied);
        assert_eq!(r.applied_at.as_deref(), Some(T1));
        assert!(r.error_summary.is_none());
    }

    #[test]
    fn apply_failure_is_visible_in_failed_state_with_verbatim_summary() {
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h".into(), T0.into());
        let mut backend = BrokenBackend::new("wg setconf exit 1: line 3 invalid", "unused");
        let r = l.apply(&id, 1, &mut backend, T1.into()).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::Failed);
        assert!(r.applied_at.is_none());
        assert_eq!(
            r.error_summary.as_deref(),
            Some("wg setconf exit 1: line 3 invalid")
        );
    }

    #[test]
    fn uncertain_backend_outcome_lands_in_failed_not_applied() {
        // §10.3：结果不确定时进入明确的失败状态，不得假装成功。
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h".into(), T0.into());
        let mut backend =
            BrokenBackend::new("result unknown: connection lost while applying", "unused");
        let r = l.apply(&id, 1, &mut backend, T1.into()).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::Failed);
        assert_eq!(
            r.error_summary.as_deref(),
            Some("result unknown: connection lost while applying")
        );
    }

    #[test]
    fn uncertain_durable_outcomes_stay_explicitly_unconfirmed() {
        let mut ledger = ConfigLedger::new();
        let network = net("net-1");
        ledger.record(&network, "h1".into(), T0.into());
        ledger
            .apply(&network, 1, &mut OkBackend, T1.into())
            .unwrap();
        ledger.mark_apply_unconfirmed(&network, 1, "apply commit io failed".into());
        let revision = ledger.get(&network, 1).unwrap().clone();
        assert_eq!(revision.apply_status, ApplyStatus::Failed);
        assert_eq!(revision.applied_at, None);
        assert_eq!(
            revision.error_summary.as_deref(),
            Some("apply commit io failed")
        );

        ledger.mark_rollback_unconfirmed(&network, 1, "pending state ignored".into());
        assert_eq!(
            ledger.get(&network, 1).unwrap().apply_status,
            ApplyStatus::Failed
        );

        let rollback = ledger.rollback(&network, 1, &mut OkBackend).unwrap();
        assert_eq!(rollback.apply_status, ApplyStatus::RolledBack);
        ledger.mark_rollback_unconfirmed(&network, 1, "rollback commit io failed".into());
        let revision = ledger.get(&network, 1).unwrap();
        assert_eq!(revision.apply_status, ApplyStatus::RollbackPending);
        assert_eq!(
            revision.error_summary.as_deref(),
            Some("apply commit io failed; rollback commit io failed")
        );

        ledger.mark_apply_unconfirmed(&network, 99, "missing".into());
        ledger.mark_rollback_unconfirmed(&network, 99, "missing".into());
    }

    #[test]
    fn unknown_or_superseded_revisions_are_refused_before_touching_backends() {
        let mut ledger = ConfigLedger::new();
        let network = net("net-1");
        ledger.record(&network, "h1".into(), T0.into());
        ledger
            .apply(
                &network,
                1,
                &mut BrokenBackend::new("apply failed", "unused"),
                T1.into(),
            )
            .unwrap();
        let mut backend = CountingBackend { calls: 0 };

        assert!(matches!(
            ledger.apply(&network, 404, &mut backend, T1.into()),
            Err(LedgerError::RevisionNotFound { revision: 404, .. })
        ));
        assert!(matches!(
            ledger.rollback(&network, 404, &mut backend),
            Err(LedgerError::RevisionNotFound { revision: 404, .. })
        ));

        ledger.record(&network, "h1".into(), T1.into());
        assert!(matches!(
            ledger.apply(&network, 1, &mut backend, T2.into()),
            Err(LedgerError::SupersededRevision {
                revision: 1,
                latest: 2,
                ..
            })
        ));

        ledger
            .apply(
                &network,
                2,
                &mut BrokenBackend::new("apply failed", "unused"),
                T2.into(),
            )
            .unwrap();
        assert_eq!(backend.calls, 0);
        assert!(matches!(
            ledger.rollback(&network, 1, &mut backend),
            Err(LedgerError::SupersededRevision {
                revision: 1,
                latest: 2,
                ..
            })
        ));
        assert_eq!(backend.calls, 0);
    }

    #[test]
    fn reapplying_applied_revision_is_idempotent_and_skips_backend() {
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h".into(), T0.into());
        let mut backend = CountingBackend { calls: 0 };
        let first = l.apply(&id, 1, &mut backend, T1.into()).unwrap();
        assert_eq!(first.apply_status, ApplyStatus::Applied);
        // 重放同一版本：不再调用 backend，applied_at 不变。
        let second = l.apply(&id, 1, &mut backend, T2.into()).unwrap();
        assert_eq!(backend.calls, 1);
        assert_eq!(second.apply_status, ApplyStatus::Applied);
        assert_eq!(second.applied_at.as_deref(), Some(T1));
    }

    #[test]
    fn reapplying_failed_revision_is_rejected_new_revision_is_the_retry_path() {
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h".into(), T0.into());
        let mut backend = BrokenBackend::new("boom", "unused");
        l.apply(&id, 1, &mut backend, T1.into()).unwrap();
        // 原地重试被状态机拒绝……
        let err = l.apply(&id, 1, &mut backend, T2.into()).unwrap_err();
        assert!(matches!(err, LedgerError::IllegalTransition(_)));
        // ……重试 = 以相同哈希记录新修订。
        let rev2 = l.record(&id, "h".into(), T2.into());
        assert_eq!(rev2, 2);
        assert_eq!(l.current(&id).unwrap().apply_status, ApplyStatus::Pending);
    }

    #[test]
    fn apply_of_unknown_revision_is_not_found() {
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        let err = l.apply(&id, 7, &mut OkBackend, T1.into()).unwrap_err();
        assert_eq!(
            err,
            LedgerError::RevisionNotFound {
                network_id: "net-1".into(),
                revision: 7
            }
        );
    }

    #[test]
    fn failed_revision_can_be_rolled_back_and_current_falls_back() {
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h1".into(), T0.into());
        l.record(&id, "h2".into(), T0.into());
        let mut backend = BrokenBackend::new("boom", "unused");
        l.apply(&id, 2, &mut backend, T1.into()).unwrap();
        let r = l.rollback(&id, 2, &mut OkBackend).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::RolledBack);
        // 回滚后当前期望回落到更早的未回滚修订。
        assert_eq!(l.current(&id).unwrap().revision, 1);
        assert_eq!(l.current(&id).unwrap().apply_status, ApplyStatus::Pending);
    }

    #[test]
    fn rollback_is_restricted_to_failed_revisions() {
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h".into(), T0.into());
        // Pending 不允许回滚（Applied 的撤销走前滚新版本，ADR-009）。
        let err = l.rollback(&id, 1, &mut OkBackend).unwrap_err();
        assert!(matches!(err, LedgerError::IllegalTransition(_)));
        // Applied 是终态，同样不允许回滚。
        l.apply(&id, 1, &mut OkBackend, T1.into()).unwrap();
        let err = l.rollback(&id, 1, &mut OkBackend).unwrap_err();
        assert!(matches!(err, LedgerError::IllegalTransition(_)));
    }

    #[test]
    fn failed_rollback_stays_rollback_pending_with_combined_summary_and_can_retry() {
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h".into(), T0.into());
        let mut broken = BrokenBackend::new("apply boom", "interface meshlet0 missing");
        l.apply(&id, 1, &mut broken, T1.into()).unwrap();
        // 回滚失败：留在 RollbackPending，诊断合并（原失败 + 回滚错误）。
        let r = l.rollback(&id, 1, &mut broken).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::RollbackPending);
        let summary = r.error_summary.as_deref().unwrap();
        assert!(summary.contains("apply boom"));
        assert!(summary.contains("rollback failed: interface meshlet0 missing"));
        // 重试回滚成功 → RolledBack。
        let r = l.rollback(&id, 1, &mut OkBackend).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::RolledBack);
    }

    #[test]
    fn rolling_back_a_rolled_back_revision_is_idempotent() {
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h".into(), T0.into());
        let mut broken = BrokenBackend::new("boom", "unused");
        l.apply(&id, 1, &mut broken, T1.into()).unwrap();
        l.rollback(&id, 1, &mut OkBackend).unwrap();
        // 幂等：不报错、状态不变、不调用 backend。
        let mut backend = CountingBackend { calls: 0 };
        let r = l.rollback(&id, 1, &mut backend).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::RolledBack);
        assert_eq!(backend.calls, 0);
    }

    #[test]
    fn fully_rolled_back_network_has_no_current_revision() {
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h".into(), T0.into());
        let mut broken = BrokenBackend::new("boom", "unused");
        l.apply(&id, 1, &mut broken, T1.into()).unwrap();
        l.rollback(&id, 1, &mut OkBackend).unwrap();
        assert!(l.current(&id).is_none());
    }

    #[test]
    fn rollback_of_superseded_failed_revision_is_rejected() {
        // §10.4 交叉破坏防线：被更新修订取代的 Failed 修订从未生效，按其
        // 意图回滚会触碰更新修订拥有的对象。
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        l.record(&id, "h1".into(), T0.into());
        let mut broken = BrokenBackend::new("boom", "unused");
        l.apply(&id, 1, &mut broken, T1.into()).unwrap();

        // 取代者是 Pending：回滚旧失败修订被拒。
        l.record(&id, "h2".into(), T2.into());
        assert_eq!(
            l.rollback(&id, 1, &mut OkBackend).unwrap_err(),
            LedgerError::SupersededRevision {
                network_id: "net-1".into(),
                revision: 1,
                latest: 2,
            }
        );
        // 取代者是 Applied：同样被拒（Applied 的撤销走前滚新版本）。
        let mut l2 = ConfigLedger::new();
        l2.record(&id, "h1".into(), T0.into());
        l2.apply(&id, 1, &mut broken, T1.into()).unwrap();
        l2.record(&id, "h2".into(), T2.into());
        l2.apply(&id, 2, &mut OkBackend, T2.into()).unwrap();
        assert!(matches!(
            l2.rollback(&id, 1, &mut OkBackend).unwrap_err(),
            LedgerError::SupersededRevision { .. }
        ));
        // 当前（最新）失败修订仍可正常回滚——限制不是全禁。
        let mut l3 = ConfigLedger::new();
        l3.record(&id, "h1".into(), T0.into());
        l3.apply(&id, 1, &mut broken, T1.into()).unwrap();
        l3.record(&id, "h2".into(), T2.into());
        l3.apply(&id, 2, &mut broken, T2.into()).unwrap();
        let r = l3.rollback(&id, 2, &mut OkBackend).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::RolledBack);
        // 级联：回滚掉最新后，更早的失败修订成为当前，可继续回滚。
        let r = l3.rollback(&id, 1, &mut OkBackend).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::RolledBack);
    }

    /// 记录 backend 收到的每次调用（修订身份），用于断言回滚边界。
    #[derive(Default)]
    struct RecordingBackend {
        applied: Vec<(String, u64)>,
        rolled_back: Vec<(String, u64)>,
    }

    impl ConfigApplyBackend for RecordingBackend {
        fn apply(&mut self, r: &ConfigRevision) -> Result<(), String> {
            self.applied.push((r.network_id.to_string(), r.revision));
            Err("recorded failure".into())
        }
        fn rollback(&mut self, r: &ConfigRevision) -> Result<(), String> {
            self.rolled_back
                .push((r.network_id.to_string(), r.revision));
            Ok(())
        }
    }

    #[test]
    fn rollback_backend_receives_only_the_failed_revision() {
        // §10.3 / ADR-007：回滚以**该失败修订**为边界——backend 只收到这个
        // 修订的身份（network_id + revision），从不收到其他修订或任何
        // 「清空全部」指令；ledger 层钉死这条契约。
        let mut l = ConfigLedger::new();
        let (a, b) = (net("net-a"), net("net-b"));
        l.record(&a, "ha1".into(), T0.into());
        l.record(&b, "hb1".into(), T0.into());
        l.record(&a, "ha2".into(), T1.into());
        let mut backend = RecordingBackend::default();

        // net-a rev2 应用失败；回滚它。
        l.apply(&a, 2, &mut backend, T2.into()).unwrap();
        let r = l.rollback(&a, 2, &mut backend).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::RolledBack);

        assert_eq!(backend.applied, vec![("net-a".into(), 2)]);
        // 恰好一次回滚调用，目标就是失败修订本身——不是 rev1、不是 net-b。
        assert_eq!(backend.rolled_back, vec![("net-a".into(), 2)]);
    }

    #[test]
    fn restore_replays_revisions_and_continues_numbering() {
        // §17.3 启动重建：持久化的修订逐字灌回，后续 record 接续递增不重号。
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        let r1 = ConfigRevision::new(id.clone(), 1, "h1".into(), T0.into());
        let mut r2 = ConfigRevision::new(id.clone(), 2, "h2".into(), T1.into());
        r2.apply_status = ApplyStatus::Applied;
        r2.applied_at = Some(T2.into());
        l.restore(vec![r2.clone(), r1.clone()]); // 乱序输入也按版本号归位
        assert_eq!(l.revisions(&id), &[r1, r2]);
        assert_eq!(l.current(&id).unwrap().desired_config_hash, "h2");
        // 重启后新变更：版本号从 3 续起。
        assert_eq!(l.record(&id, "h3".into(), T2.into()), 3);
    }

    #[test]
    fn interrupted_applying_lands_failed_with_summary() {
        // §10.3：停在 applying 的修订结果不可知 → 落 failed + 中断诊断。
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        let mk = |rev: u64, status: ApplyStatus| {
            let mut r = ConfigRevision::new(id.clone(), rev, format!("h{rev}"), T0.into());
            r.apply_status = status;
            r
        };
        l.restore(vec![
            mk(1, ApplyStatus::Applied),
            mk(2, ApplyStatus::Applying),
            mk(3, ApplyStatus::RollbackPending),
        ]);
        let converged = l.interrupt_applying("interrupted: process restarted while applying");
        assert_eq!(converged, vec![(id.clone(), 2)]);
        assert_eq!(
            l.get(&id, 2).unwrap().apply_status,
            ApplyStatus::Failed,
            "uncertain outcome must not pretend success"
        );
        assert_eq!(
            l.get(&id, 2).unwrap().error_summary.as_deref(),
            Some("interrupted: process restarted while applying")
        );
        // 终态与回滚未确认态不受影响。
        assert_eq!(l.get(&id, 1).unwrap().apply_status, ApplyStatus::Applied);
        assert_eq!(
            l.get(&id, 3).unwrap().apply_status,
            ApplyStatus::RollbackPending
        );
        // 幂等：再次收敛不再命中任何修订。
        assert!(l.interrupt_applying("again").is_empty());
    }

    #[test]
    fn interrupted_applying_can_be_rolled_back_after_restart() {
        // 收敛后的 failed 修订仍是合法回滚入口（rollback 重试语义不变）。
        let mut l = ConfigLedger::new();
        let id = net("net-1");
        let mut r = ConfigRevision::new(id.clone(), 1, "h".into(), T0.into());
        r.apply_status = ApplyStatus::Applying;
        l.restore(vec![r]);
        l.interrupt_applying("interrupted");
        let r = l.rollback(&id, 1, &mut OkBackend).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::RolledBack);
    }

    #[test]
    fn concurrent_record_assigns_unique_contiguous_revisions() {
        // §10.4 版本顺序：并发记录（调用方持网络级互斥）下版本号唯一、
        // 连续、严格递增——不交叉、不丢号、不重号。
        use std::sync::{Arc, Mutex};
        const THREADS: u64 = 8;
        const PER_THREAD: u64 = 25;

        let ledger = Arc::new(Mutex::new(ConfigLedger::new()));
        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let ledger = Arc::clone(&ledger);
                std::thread::spawn(move || {
                    let mut mine = Vec::new();
                    for i in 0..PER_THREAD {
                        let rev = ledger.lock().unwrap().record(
                            &net("net-1"),
                            format!("h-{t}-{i}"),
                            T0.into(),
                        );
                        mine.push(rev);
                    }
                    mine
                })
            })
            .collect();
        let mut all = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(all.len() as u64, THREADS * PER_THREAD);
        all.sort_unstable();
        let expected: Vec<u64> = (1..=THREADS * PER_THREAD).collect();
        assert_eq!(all, expected, "unique, contiguous, strictly increasing");

        let guard = ledger.lock().unwrap();
        let numbers: Vec<u64> = guard
            .revisions(&net("net-1"))
            .iter()
            .map(|r| r.revision)
            .collect();
        assert_eq!(numbers, expected);
    }

    // -- desired_config_hash ------------------------------------------------

    fn device(name: &str, ip: &str, status: DeviceStatus) -> Device {
        Device {
            id: crate::entities::DeviceId(name.into()),
            network_id: net("net-1"),
            name: name.into(),
            virtual_ipv4: ip.parse().unwrap(),
            public_key: format!("pub-{name}"),
            platform: crate::entities::Platform::Linux,
            status,
            last_seen_at: None,
            last_handshake_at: None,
            last_report_at: None,
            dataplane_evidence: None,
            created_at: T0.into(),
            approved_at: None,
            segment_id: crate::SegmentId("seg-net-1".into()),
            revoked_at: None,
        }
    }

    fn grant(status: crate::segments::SegmentGrantStatus) -> SegmentGrant {
        SegmentGrant {
            id: crate::SegmentGrantId("sg-1".into()),
            network_id: net("net-1"),
            source_segment_id: crate::SegmentId("seg-src".into()),
            destination_segment_id: crate::SegmentId("seg-dst".into()),
            status,
            created_at: T0.into(),
            revoked_at: None,
        }
    }

    #[test]
    fn desired_config_hash_includes_only_applied_segment_grants() {
        let overlay: Ipv4Cidr = "10.240.0.0/16".parse().unwrap();
        let hub: Ipv4Addr = "10.240.0.1".parse().unwrap();
        let base = desired_config_hash(&overlay, hub, &[], &[], &[], &[]);

        let pending = grant(crate::segments::SegmentGrantStatus::Pending);
        let revoked = grant(crate::segments::SegmentGrantStatus::Revoked);
        assert_eq!(
            desired_config_hash(&overlay, hub, &[], &[], &[], &[pending]),
            base
        );
        assert_eq!(
            desired_config_hash(&overlay, hub, &[], &[], &[], &[revoked]),
            base
        );

        let mut applied = grant(crate::segments::SegmentGrantStatus::Applied);
        let with_applied =
            desired_config_hash(&overlay, hub, &[], &[], &[], std::slice::from_ref(&applied));
        assert_ne!(with_applied, base);

        let mut other = grant(crate::segments::SegmentGrantStatus::Applied);
        other.id = crate::SegmentGrantId("sg-2".into());
        assert_eq!(
            desired_config_hash(
                &overlay,
                hub,
                &[],
                &[],
                &[],
                &[applied.clone(), other.clone()]
            ),
            desired_config_hash(&overlay, hub, &[], &[], &[], &[other, applied.clone()])
        );

        applied.status = crate::segments::SegmentGrantStatus::Revoked;
        applied.revoked_at = Some(T1.into());
        assert_eq!(
            desired_config_hash(&overlay, hub, &[], &[], &[], &[applied]),
            base
        );
    }

    #[test]
    fn desired_config_hash_is_deterministic_and_device_order_insensitive() {
        let overlay: Ipv4Cidr = "10.240.0.0/16".parse().unwrap();
        let hub: Ipv4Addr = "10.240.0.1".parse().unwrap();
        let d1 = device("alpha", "10.240.0.2", DeviceStatus::Active);
        let d2 = device("beta", "10.240.0.3", DeviceStatus::Active);
        let h1 = desired_config_hash(&overlay, hub, &[d1.clone(), d2.clone()], &[], &[], &[]);
        let h2 = desired_config_hash(&overlay, hub, &[d2, d1], &[], &[], &[]);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn desired_config_hash_tracks_active_config_only() {
        let overlay: Ipv4Cidr = "10.240.0.0/16".parse().unwrap();
        let hub: Ipv4Addr = "10.240.0.1".parse().unwrap();
        let alpha = device("alpha", "10.240.0.2", DeviceStatus::Active);
        let base = desired_config_hash(&overlay, hub, std::slice::from_ref(&alpha), &[], &[], &[]);

        // 新设备加入 → 哈希变化。
        let beta = device("beta", "10.240.0.3", DeviceStatus::Active);
        assert_ne!(
            desired_config_hash(&overlay, hub, &[alpha.clone(), beta], &[], &[], &[],),
            base
        );

        // 改名 → 哈希变化（期望配置含设备名）。
        let mut renamed = alpha.clone();
        renamed.name = "alpha-2".into();
        assert_ne!(
            desired_config_hash(&overlay, hub, &[renamed], &[], &[], &[]),
            base
        );

        // 撤销（Revoked）→ 与无任何设备时一致（不入配置）。
        let mut revoked = alpha.clone();
        revoked.status = DeviceStatus::Revoked;
        assert_eq!(
            desired_config_hash(&overlay, hub, &[revoked], &[], &[], &[]),
            desired_config_hash(&overlay, hub, &[], &[], &[], &[])
        );

        // overlay 或 hub 变化 → 哈希变化。
        let other_overlay: Ipv4Cidr = "172.30.0.0/16".parse().unwrap();
        assert_ne!(
            desired_config_hash(
                &other_overlay,
                hub,
                std::slice::from_ref(&alpha),
                &[],
                &[],
                &[],
            ),
            base
        );
        let other_hub: Ipv4Addr = "10.240.0.254".parse().unwrap();
        assert_ne!(
            desired_config_hash(&overlay, other_hub, &[alpha], &[], &[], &[]),
            base
        );
    }

    fn route(dst: &str, gw: &str, mode: RouteMode) -> LanRoute {
        LanRoute {
            id: LanRouteId(format!("rt-{dst}-{gw}-{mode:?}")),
            network_id: NetworkId("net-1".into()),
            gateway_device_id: DeviceId(gw.into()),
            destination_cidr: dst.parse().unwrap(),
            route_mode: mode,
            return_path_mode: ReturnPathMode::DualRoute,
            status: DesiredStateStatus::Pending,
            created_at: T0.into(),
        }
    }

    fn alias(id: &str, alias_cidr: &str, target_cidr: &str, route_id: &str) -> AliasMapping {
        AliasMapping::new(
            AliasMappingId(id.into()),
            net("net-1"),
            LanRouteId(route_id.into()),
            alias_cidr.parse().unwrap(),
            target_cidr.parse().unwrap(),
            TranslationMode::DnatSnat,
        )
        .unwrap()
    }

    #[test]
    fn desired_config_hash_includes_routes_order_insensitively() {
        let overlay: Ipv4Cidr = "10.240.0.0/16".parse().unwrap();
        let hub: Ipv4Addr = "10.240.0.1".parse().unwrap();
        let a = route("192.168.1.0/24", "dev-1", RouteMode::Direct);
        let b = route("192.168.2.0/24", "dev-2", RouteMode::Alias);

        // 路由纳入期望配置。
        assert_ne!(
            desired_config_hash(&overlay, hub, &[], std::slice::from_ref(&a), &[], &[]),
            desired_config_hash(&overlay, hub, &[], &[], &[], &[])
        );
        // 顺序不敏感。
        assert_eq!(
            desired_config_hash(&overlay, hub, &[], &[a.clone(), b.clone()], &[], &[],),
            desired_config_hash(&overlay, hub, &[], &[b.clone(), a.clone()], &[], &[]),
        );
        // 返回路径模式 / 路由模式参与哈希。
        let mut snat = route("192.168.1.0/24", "dev-1", RouteMode::Direct);
        snat.return_path_mode = ReturnPathMode::ControlledSnat;
        assert_ne!(
            desired_config_hash(&overlay, hub, &[], std::slice::from_ref(&snat), &[], &[],),
            desired_config_hash(&overlay, hub, &[], std::slice::from_ref(&a), &[], &[],)
        );
        // 删除路由（不出现在输入里）→ 哈希不同于含路由时。
        let with_route = desired_config_hash(&overlay, hub, &[], &[a], &[], &[]);
        assert_ne!(
            with_route,
            desired_config_hash(&overlay, hub, &[], &[], &[], &[])
        );
    }

    #[test]
    fn desired_config_hash_includes_aliases_order_insensitively() {
        let overlay: Ipv4Cidr = "10.240.0.0/16".parse().unwrap();
        let hub: Ipv4Addr = "10.240.0.1".parse().unwrap();
        let a1 = alias("al-1", "10.241.1.0/24", "192.168.1.0/24", "rt-1");
        let a2 = alias("al-2", "10.241.2.0/24", "192.168.2.0/24", "rt-2");

        // Alias 纳入期望配置。
        let base = desired_config_hash(&overlay, hub, &[], &[], &[], &[]);
        assert_ne!(
            desired_config_hash(&overlay, hub, &[], &[], std::slice::from_ref(&a1), &[]),
            base
        );
        // 顺序不敏感。
        assert_eq!(
            desired_config_hash(&overlay, hub, &[], &[], &[a1.clone(), a2.clone()], &[],),
            desired_config_hash(&overlay, hub, &[], &[], &[a2.clone(), a1.clone()], &[])
        );
        // 前缀或绑定路由变化 → 哈希变化。
        let other = alias("al-1", "10.241.9.0/24", "192.168.9.0/24", "rt-1");
        assert_ne!(
            desired_config_hash(&overlay, hub, &[], &[], std::slice::from_ref(&other), &[],),
            desired_config_hash(&overlay, hub, &[], &[], std::slice::from_ref(&a1), &[],)
        );
        // 删除 Alias → 哈希回到 base。
        assert_eq!(desired_config_hash(&overlay, hub, &[], &[], &[], &[]), base);
    }
}
