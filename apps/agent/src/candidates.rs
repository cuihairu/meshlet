//! 端点候选表（FLIP-001 候选表纳管 roaming 面）：服务端下发面（`Config`）+
//! 内核 roaming 观测面（`Roaming`）+ 探测证实可达面（`Discovered`）三类来源，
//! agent 侧合并成「有效候选集」供 SEL-001 探测与直连状态机消费。
//!
//! 为什么：内核 wg roaming 是「对端换了网 / 新 face 可用」的最强证据（内核
//! 收到新源面的合法认证包即漫游 endpoint），但这类面常不在服务端候选表——
//! 旧路径只在直连态经记忆面（`last_direct`）被动跟随，回中继后证据随
//! `wg set peer` 移除而丢失，promote 只能回头选配置面等它劣化（fliploop
//! 实锤的翻转环根源，见 docs/acceptance-evidence/fliploop-imac-2026-11-14.md）。
//! 候选表把 roaming 面持久为带 `last_seen` 的表项：回中继后 SEL-001 仍持续
//! 探测它，promote 选路时它与其他面同台竞争（劣化过滤照旧）——健康面胜出，
//! 而不是盯单一配置面等它劣化再回中继。
//!
//! 来源语义（[`FaceSource`]）：
//! - `Config`：服务端候选集下发（权威，不过期，随每轮对账保鲜）；
//! - `Roaming`：内核 `wg dump` 观测到对端 endpoint（[`Self::ROAMING_TTL_SECS`]
//!   内无新观测即过期——对端离开该网后旧面不再误导选路）；
//! - `Discovered`：roaming 面被 SEL-001 窗口证实健康（执行层升级），同样
//!   按 `last_seen` 过期（探测线程持续对它采样即持续保鲜）。
//!
//! 纯逻辑、无 IO：内核观测由执行层喂（`wg dump` endpoint），探测证实由
//! SEL-001 窗口判定（见 `crate::probe::face_healthy`）。

use std::collections::BTreeMap;

use meshlet_domain::{EndpointCandidate, PeerEndpoints};

/// 候选面来源。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FaceSource {
    /// 服务端候选集下发（权威，不过期）。
    Config,
    /// 内核 roaming 观测（TTL 内有效）。
    Roaming,
    /// SEL-001 窗口证实的健康 roaming 面（TTL 内有效）。
    Discovered,
}

impl FaceSource {
    /// 展示 / 决策日志用小写标识。
    pub fn as_str(self) -> &'static str {
        match self {
            FaceSource::Config => "config",
            FaceSource::Roaming => "roaming",
            FaceSource::Discovered => "discovered",
        }
    }
}

/// roaming / discovered 面的 TTL（秒）：30min。内核对活跃路径每对账周期
/// （30s）刷新观测，正常情况下永不触界；TTL 只负责回收「对端已离开该网」
/// 的陈旧面——30min 足够跨多轮探测仍留有证据，又不至于无限期误导选路。
pub const ROAMING_TTL_SECS: u64 = 1_800;

/// 一个候选表项：来源 + 最近证据时刻（Unix 秒）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaceEntry {
    pub source: FaceSource,
    pub last_seen_secs: u64,
}

/// 端点候选表：`(对端公钥, 候选)` → 表项。
#[derive(Debug, Default)]
pub struct CandidateTable {
    entries: BTreeMap<(String, EndpointCandidate), FaceEntry>,
}

impl CandidateTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// 服务端候选集同步：全部 config 面插入 / 保鲜（已有 roaming /
    /// discovered 表项的同面升级为 Config——服务端口径是权威来源）。
    pub fn sync_config(&mut self, wanted: &[PeerEndpoints], now_secs: u64) {
        for peer in wanted {
            for candidate in &peer.endpoints {
                self.entries.insert(
                    (peer.public_key.clone(), *candidate),
                    FaceEntry {
                        source: FaceSource::Config,
                        last_seen_secs: now_secs,
                    },
                );
            }
        }
    }

    /// 内核 roaming 观测：对端 endpoint 灌入候选表。返回是否为**新面**
    /// （此前无此 (公钥, 候选) 表项）——新面 = 换网信号，执行层据此触发
    /// 立即探测（不等 30s 节流）。已知面只刷新 `last_seen`（活跃路径
    /// 永不过期），来源不降级（Config/discovered 保持）。
    pub fn observe_roaming(
        &mut self,
        public_key: &str,
        candidate: EndpointCandidate,
        now_secs: u64,
    ) -> bool {
        match self.entries.get_mut(&(public_key.to_string(), candidate)) {
            Some(entry) => {
                entry.last_seen_secs = now_secs;
                false
            }
            None => {
                self.entries.insert(
                    (public_key.to_string(), candidate),
                    FaceEntry {
                        source: FaceSource::Roaming,
                        last_seen_secs: now_secs,
                    },
                );
                true
            }
        }
    }

    /// 探测证实升级：roaming 面 SEL-001 窗口健康 → `Discovered`（并保鲜）。
    /// Config 面不受影响；已 discovered 的只刷新 `last_seen`。
    pub fn mark_discovered(
        &mut self,
        public_key: &str,
        candidate: EndpointCandidate,
        now_secs: u64,
    ) {
        if let Some(entry) = self.entries.get_mut(&(public_key.to_string(), candidate)) {
            if entry.source == FaceSource::Roaming {
                entry.source = FaceSource::Discovered;
            }
            entry.last_seen_secs = now_secs;
        }
    }

    /// 过期回收：roaming / discovered 面超过 [`Self::ROAMING_TTL_SECS`] 无新
    /// 证据（内核观测或探测采样）即移除；config 面不过期（服务端权威）。
    pub fn expire(&mut self, now_secs: u64) {
        self.entries.retain(|_, entry| {
            entry.source == FaceSource::Config
                || now_secs.saturating_sub(entry.last_seen_secs) <= ROAMING_TTL_SECS
        });
    }

    /// 回收不在候选集里的对端（撤销 / 下线 / 换段）。
    pub fn retain_peers(&mut self, wanted: &[PeerEndpoints]) {
        let live: std::collections::BTreeSet<&str> =
            wanted.iter().map(|p| p.public_key.as_str()).collect();
        self.entries
            .retain(|(key, _), _| live.contains(key.as_str()));
    }

    /// 合并为有效候选集：服务端候选顺序在前（原序），表内新增面按
    /// `(ip, port)` 排序追加（确定性）。同面去重（服务端候选优先保留）。
    pub fn merge_into(&self, wanted: &[PeerEndpoints]) -> Vec<PeerEndpoints> {
        wanted
            .iter()
            .map(|peer| {
                let mut endpoints: Vec<_> = peer.endpoints.to_vec();
                let mut extra: Vec<_> = self
                    .entries
                    .keys()
                    .filter(|(key, candidate)| {
                        key == &peer.public_key && !endpoints.contains(candidate)
                    })
                    .map(|(_, candidate)| *candidate)
                    .collect();
                extra.sort_by_key(|c| (c.ip, c.port));
                endpoints.extend(extra);
                PeerEndpoints {
                    device_id: peer.device_id.clone(),
                    public_key: peer.public_key.clone(),
                    virtual_ipv4: peer.virtual_ipv4,
                    name: peer.name.clone(),
                    endpoints,
                }
            })
            .collect()
    }

    /// 某对端的全部表项（候选 + 来源），按候选排序（确定性）。
    pub fn faces(&self, public_key: &str) -> Vec<(EndpointCandidate, FaceSource)> {
        self.entries
            .iter()
            .filter(|((key, _), _)| key == public_key)
            .map(|((_, candidate), entry)| (*candidate, entry.source))
            .collect()
    }

    /// 全部 roaming 表项（探测证实升级的迭代输入）。
    pub fn roaming_faces(&self) -> Vec<(String, EndpointCandidate)> {
        self.entries
            .iter()
            .filter(|(_, entry)| entry.source == FaceSource::Roaming)
            .map(|((key, candidate), _)| (key.clone(), *candidate))
            .collect()
    }

    /// 探测证据刷新（FLIP-001）：探测窗口健康的表项保鲜（`last_seen` 前移）
    /// 且 roaming 面升级 `Discovered`。这是 discovered 面在回中继后的续命
    /// 机制——内核观测已断（peer 被移出），SEL-001 持续答话即持续保鲜；健康
    /// 集之外的面不动（TTL 到期自然回收）。Config 面来源不变（权威不过期）。
    pub fn refresh_probe_evidence(
        &mut self,
        healthy: &std::collections::BTreeSet<(String, EndpointCandidate)>,
        now_secs: u64,
    ) {
        for (public_key, candidate) in healthy {
            self.mark_discovered(public_key, *candidate, now_secs);
        }
    }

    /// 表项总数（诊断 / 测试）。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// 恢复门 bypass 判定（FLIP-001，纯函数）：候选表里该对端存在「探测证实
/// 健康」的面 → `true`（不 hold_relay 等门，本轮直接放行状态机 promote）。
/// `healthy` 是探测运行时的健康面集合（[`crate::probe::ProbeRuntime::healthy_faces`]）。
pub fn has_probe_healthy_face(
    public_key: &str,
    table_faces: &[(EndpointCandidate, FaceSource)],
    healthy: &std::collections::BTreeSet<(String, EndpointCandidate)>,
) -> bool {
    table_faces
        .iter()
        .any(|(candidate, _)| healthy.contains(&(public_key.to_string(), *candidate)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshlet_domain::EndpointKind;

    fn lan(ip: &str, port: u16) -> EndpointCandidate {
        EndpointCandidate {
            ip: ip.parse().unwrap(),
            port,
            kind: EndpointKind::Lan,
        }
    }

    fn public(ip: &str, port: u16) -> EndpointCandidate {
        EndpointCandidate {
            ip: ip.parse().unwrap(),
            port,
            kind: EndpointKind::Public,
        }
    }

    fn peer(key: &str, endpoints: &[EndpointCandidate]) -> PeerEndpoints {
        PeerEndpoints {
            device_id: meshlet_domain::DeviceId("dev".into()),
            public_key: key.into(),
            virtual_ipv4: "10.240.0.3".parse().unwrap(),
            name: String::new(),
            endpoints: endpoints.to_vec(),
        }
    }

    #[test]
    fn sync_config_marks_and_refreshes_config_faces() {
        let mut table = CandidateTable::new();
        let wanted = vec![peer("pk", &[lan("192.168.1.50", 51820)])];
        table.sync_config(&wanted, 100);
        assert_eq!(
            table.faces("pk"),
            vec![(lan("192.168.1.50", 51820), FaceSource::Config)]
        );
        // 再同步（下一轮对账）保鲜，不过期。
        table.sync_config(&wanted, 100_000);
        table.expire(100_000 + ROAMING_TTL_SECS + 1);
        assert_eq!(table.len(), 1, "config face never expires");
    }

    #[test]
    fn observe_roaming_flags_new_face_only_once() {
        let mut table = CandidateTable::new();
        assert!(
            table.observe_roaming("pk", lan("192.168.5.11", 51820), 100),
            "first kernel observation is a new face"
        );
        assert!(
            !table.observe_roaming("pk", lan("192.168.5.11", 51820), 130),
            "known face observation refreshes, not a change"
        );
    }

    #[test]
    fn roaming_face_expires_after_ttl_but_refresh_keeps_it() {
        let mut table = CandidateTable::new();
        table.observe_roaming("pk", lan("192.168.5.11", 51820), 100);
        table.expire(100 + ROAMING_TTL_SECS);
        assert_eq!(table.len(), 1, "within TTL");
        table.expire(100 + ROAMING_TTL_SECS + 1);
        assert!(table.is_empty(), "stale roaming face expires");
        // 活跃路径每周期刷新 → 永不过期。
        table.observe_roaming("pk", lan("192.168.5.11", 51820), 100);
        for t in 1..=10u64 {
            table.observe_roaming("pk", lan("192.168.5.11", 51820), 100 + t * 200);
        }
        table.expire(100 + 10 * 200 + ROAMING_TTL_SECS);
        assert_eq!(table.len(), 1, "actively refreshed face survives");
    }

    #[test]
    fn discovered_upgrade_then_expiry() {
        let mut table = CandidateTable::new();
        table.observe_roaming("pk", public("203.0.113.9", 51820), 100);
        table.mark_discovered("pk", public("203.0.113.9", 51820), 110);
        assert_eq!(
            table.faces("pk"),
            vec![(public("203.0.113.9", 51820), FaceSource::Discovered)]
        );
        table.mark_discovered("pk", public("203.0.113.9", 51820), 120);
        assert_eq!(
            table.faces("pk"),
            vec![(public("203.0.113.9", 51820), FaceSource::Discovered)]
        );
        table.expire(120 + ROAMING_TTL_SECS + 1);
        assert!(table.is_empty(), "discovered faces expire like roaming");
    }

    #[test]
    fn config_authority_upgrades_roaming_entry() {
        let mut table = CandidateTable::new();
        table.observe_roaming("pk", lan("192.168.1.50", 51820), 100);
        table.sync_config(&[peer("pk", &[lan("192.168.1.50", 51820)])], 130);
        assert_eq!(
            table.faces("pk"),
            vec![(lan("192.168.1.50", 51820), FaceSource::Config)],
            "server-known face upgrades to config authority"
        );
    }

    #[test]
    fn merge_into_appends_table_only_faces_sorted_and_dedupes() {
        let mut table = CandidateTable::new();
        let wanted = vec![peer(
            "pk",
            &[public("203.0.113.5", 51820), lan("192.168.1.9", 51820)],
        )];
        table.sync_config(&wanted, 100);
        table.observe_roaming("pk", lan("192.168.1.2", 51820), 110);
        table.observe_roaming("pk", lan("192.168.1.7", 51820), 110);
        let merged = table.merge_into(&wanted);
        assert_eq!(
            merged[0].endpoints,
            vec![
                public("203.0.113.5", 51820),
                lan("192.168.1.9", 51820),
                // 表内新增面按 (ip, port) 追加，确定性。
                lan("192.168.1.2", 51820),
                lan("192.168.1.7", 51820),
            ]
        );
    }

    #[test]
    fn retain_peers_drops_entries_of_peers_outside_candidate_set() {
        let mut table = CandidateTable::new();
        table.observe_roaming("pk-a", lan("192.168.1.2", 51820), 100);
        table.observe_roaming("pk-b", lan("192.168.1.3", 51820), 100);
        table.retain_peers(&[peer("pk-a", &[])]);
        assert_eq!(table.faces("pk-a").len(), 1);
        assert!(table.faces("pk-b").is_empty(), "left the candidate set");
    }

    /// 探测证据刷新：健康面保鲜（TTL 续命）+ roaming → discovered 升级；
    /// 不健康的面不动（TTL 到期回收）。
    #[test]
    fn refresh_probe_evidence_keeps_healthy_faces_alive() {
        let mut table = CandidateTable::new();
        table.observe_roaming("pk", lan("192.168.1.2", 51820), 100);
        table.observe_roaming("pk", lan("192.168.1.3", 51820), 100);
        let mut healthy = std::collections::BTreeSet::new();
        healthy.insert(("pk".to_string(), lan("192.168.1.2", 51820)));
        // 每 200s 刷一次健康证据（探测 5s 一轮的加速模拟）：远超 TTL 仍活着。
        for round in 0..20u64 {
            table.refresh_probe_evidence(&healthy, 100 + (round + 1) * 200);
        }
        table.expire(100 + 20 * 200 + ROAMING_TTL_SECS);
        assert_eq!(table.faces("pk").len(), 1, "healthy face kept alive");
        assert_eq!(
            table.faces("pk")[0].1,
            FaceSource::Discovered,
            "roaming upgraded to discovered by probe evidence"
        );
        // 不健康面（.3 无探测证据）早已过期。
        assert!(
            !table
                .faces("pk")
                .iter()
                .any(|(c, _)| *c == lan("192.168.1.3", 51820)),
            "unprobed face expired"
        );
    }

    /// bypass 判定：表内面 ∩ 探测健康集非空才放行；表外面（健康窗口残留）
    /// 与不健康的表面都不放行。
    #[test]
    fn has_probe_healthy_face_requires_table_and_probe_agreement() {
        let face_a = lan("192.168.1.2", 51820);
        let face_b = lan("192.168.1.3", 51820);
        let faces = vec![(face_a, FaceSource::Roaming)];
        let mut healthy = std::collections::BTreeSet::new();
        healthy.insert(("pk".to_string(), face_a));
        assert!(super::has_probe_healthy_face("pk", &faces, &healthy));
        // 该面不健康 → 不放行。
        assert!(!super::has_probe_healthy_face(
            "pk",
            &faces,
            &std::collections::BTreeSet::new()
        ));
        // 健康的面不在表内（过期残留窗口）→ 不放行。
        healthy.clear();
        healthy.insert(("pk".to_string(), face_b));
        assert!(!super::has_probe_healthy_face("pk", &faces, &healthy));
        // 别的 peer 的健康面 → 不放行。
        healthy.insert(("other".to_string(), face_a));
        assert!(!super::has_probe_healthy_face("pk", &faces, &healthy));
    }
}
