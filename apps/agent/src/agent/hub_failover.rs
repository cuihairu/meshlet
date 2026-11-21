//! hub 多端点 failover（UI 批 B3 / todo「UI 四项收口」剩项）。
//!
//! `[dataplane] hub_endpoint` 现支持逗号分隔多端点（[`crate::agent::agent::DataplaneConfig::hub_endpoints`]）。
//! 服务端计划把 hub peer 的 endpoint 留空（§16.4：服务端不知道 agent 的
//! 网络位置），agent 用本地配置填充才能主动握手。多端点时：现役端点与 hub
//! 的握手超时（或从不握手超过宽限），就轮换到下一个候选并重新下发——hub
//! 入口地址变更（VPS 迁移 / 备用 hub）无需改 agent 配置即可自愈。
//!
//! 健康判据 = hub peer（计划 tunnel.peers[0]，服务端计划恒为单 hub peer）
//! 的内核握手年龄（[`meshlet_network`] 各后端 `handshake_ages_sync`）：
//! - `Some(age)` 且 `age <= stale` → 现役健康，保持；
//! - `Some(age)` 且 `age > stale` → 现役死亡，轮换（hub 的 persistent
//!   keepalive 被强制 ≥ 25s，[`enforce_hub_keepalive`]，健康握手不会断更，
//!   超龄即路径已断，是可靠判据）；
//! - `None`（从不握手）→ 给轮换后一次宽限（grace）等首个握手，超宽限仍无
//!   握手才轮换——避免 fresh start 误轮换与全死端点无限快速 churn。
//!
//! 轮换结果落 `{state_dir}/hub-endpoint.json`（[`HubEndpointLedger`]，与
//! `direct-port.json` 同一账本风格）：`index`（当前候选下标）+
//! `selected_at_ms`（轮换时刻，grace 计时基准）。单/零端点不落账本
//! （行为与旧版完全一致，零新文件）。

/// 现役 hub 端点握手年龄超此秒数判为「死亡」→ 轮换。hub keepalive 被抬到
/// 25s（[`meshlet_network::HUB_KEEPALIVE_SECS`]），健康握手 25s 内必更新；
/// 60s = 2.4 个 keepalive 周期，路径断了的余量给足，绝不误判健康握手。
pub(super) const HUB_HANDSHAKE_STALE_SECS: u64 = 60;

/// 端点账本路径：`{state_dir}/hub-endpoint.json`。
pub(super) fn ledger_path(state_dir: &str) -> std::path::PathBuf {
    std::path::Path::new(state_dir).join("hub-endpoint.json")
}

/// hub 端点选择账本（`hub-endpoint.json`）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct HubEndpointLedger {
    /// 当前选中的 `hub_endpoints()` 候选下标。
    pub index: usize,
    /// 轮换/选定时刻（Unix 毫秒；grace 计时基准）。
    pub selected_at_ms: u64,
}

/// 读账本：缺失/损坏按「无账本」处理（`None`，下一轮重新收敛；绝不拿坏
/// 数据当现役选择）。
pub(super) fn load(state_dir: &str) -> Option<HubEndpointLedger> {
    let raw = std::fs::read_to_string(ledger_path(state_dir)).ok()?;
    serde_json::from_str::<HubEndpointLedger>(&raw).ok()
}

/// 写账本（失败只由调用方记日志：账本是防 churn 优化，不阻塞数据面）。
pub(super) fn save(state_dir: &str, ledger: &HubEndpointLedger) -> Result<(), String> {
    let path = ledger_path(state_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let raw =
        serde_json::to_string(ledger).map_err(|e| format!("serialize hub-endpoint ledger: {e}"))?;
    std::fs::write(&path, raw).map_err(|e| format!("write {}: {e}", path.display()))
}

/// 一次 hub 端点选择决策（[`decide`]）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HubDecision {
    /// 选中的候选下标（`0..configured.len()`）。
    pub index: usize,
    /// 选中的端点（`configured[index]`）。
    pub endpoint: String,
    /// 调用方应持久化账本（轮换或首选定）。
    pub save: bool,
    /// 轮换发生：调用方应强制重新 apply（新端点需下到内核）。
    pub rotate: bool,
    /// 要落盘的账本（`save == true` 时有效）。
    pub ledger: HubEndpointLedger,
}

/// hub 端点选择（纯函数，可测）。仅当 `configured.len() > 1` 才做 failover；
/// 单端点恒选 `index 0`、零改动（`save=false, rotate=false`，行为与旧版一致）。
///
/// - `current`：上一轮账本（`None` = 首轮）；
/// - `hub_age`：hub peer 握手年龄秒（`None` = 尚无握手）；
/// - `now_ms`：当前 Unix 毫秒（grace 计时）；
/// - `stale_secs`：握手超龄判死阈值（[`HUB_HANDSHAKE_STALE_SECS`]）；
/// - `grace_ms`：轮换后等待首个握手的宽限（`None` 握手时）。
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
        // 单端点：恒选它，零状态、零轮换——旧行为逐字节不变。
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
        // 首轮：从第一个候选起（grace 从现在计时；启动 apply 会带它下去）。
        None => (0, false),
        Some(ledger) => {
            let cur = ledger.index.min(configured.len() - 1);
            match hub_age {
                // 现役健康：保持（grace 计时不动，只认年龄判据）。
                Some(age) if age <= stale_secs => (cur, false),
                // 现役死亡（超龄）：轮换下一个（回绕）。
                Some(_) => ((cur + 1) % configured.len(), true),
                // 尚无握手：轮换后给 grace 等首个握手，超宽限仍无才轮换。
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
    // 只在选择真的变化时落账本（首选定/轮换）；保持现役绝不写盘——30s 轮询
    // 不得制造写盘 churn。
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

        // 即使现役死亡也不轮换（无第二候选）；零状态。
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
        // 现役健康（年龄 ≤ 60）：保持下标 1，不落账本不轮换。
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
        // 现役死亡（年龄 61 > 60）：轮换到下一个候选，回绕。
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

        // 最后一个候选死亡：回绕到 0。
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
        // 轮换后尚在 grace（< 90s）：保持，不轮换。
        let cur = ledger(1, 10_000);
        let d = decide(&eps, Some(&cur), None, 50_000, 60, 90_000);
        assert_eq!(d.index, 1);
        assert!(!d.rotate);

        // 超宽限仍无握手：轮换。
        let d = decide(&eps, Some(&cur), None, 110_000, 60, 90_000);
        assert_eq!(d.index, 0);
        assert!(d.rotate);

        // 首轮无握手（fresh start）：从候选 0 起，grace 计时从现在。
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
        // 损坏文件 → None（下一轮重新收敛）。
        std::fs::write(ledger_path(dir_str), "not json").unwrap();
        assert_eq!(load(dir_str), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
