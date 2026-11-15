//! demote backoff（FLIP-002 保底）：连续 demote 后对 promote 侧做指数退避
//! 冷却——第 N 次连续 demote 的 promote 冷却 = `base × 2^(N-1)`，封顶 `cap`；
//! 链路持续健康（连续 M 轮有探测健康面证据，M = `recovery_confirmations`）
//! 即清零计数。
//!
//! 为什么：SEL-003 劣化门 + 恢复门防抖了「单拍瞬态」，但当劣化源持续存在
//! （如 JMrE 24h 窗口 262 个 promote→demote 环、中位 1.48min），旧路径每
//! 恢复门放行就立刻在同一个面上再翻一拍——backoff 把重试间隔指数拉开
//! （30s → 1min → 2min → … → cap 15min），劣化面上的无效重试从「分钟级
//! 循环」退化为「个位数尝试」，等 FLIP-001 候选表给出健康面后自然收敛。
//!
//! 边界（任务书）：backoff **只作用 promote 侧**——SEL-003 的劣化判定与
//! demote 动作完全不受影响（探测该报劣化还报，灵敏度不放松）；域层在
//! hold_relay 之后检查抑制表，抑制期间保持中继并留 defer 决策记录。
//!
//! 纯逻辑、无 IO：时间由调用方传入（毫秒），测试可注入任意时钟。

use std::collections::BTreeMap;

/// 单对端的退避状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BackoffState {
    /// 连续 demote 次数（本轮冷却链条内；健康清零时整条删除）。
    demotes: u32,
    /// 连续健康轮数（note_health 驱动；不健康即清零）。
    health_streak: u32,
    /// 抑制截止时刻（Unix 毫秒）。
    suppress_until_ms: u64,
}

/// demote backoff 状态机：对端公钥 → 退避状态。
#[derive(Debug)]
pub struct DemoteBackoff {
    base_ms: u64,
    cap_ms: u64,
    confirmations: u32,
    state: BTreeMap<String, BackoffState>,
}

impl DemoteBackoff {
    /// 新建退避器。`base_ms` 下限 1；`cap_ms` 下限 `base_ms`；
    /// `confirmations` 下限 1（钳制，非法配置不 panic）。
    pub fn new(base_ms: u64, cap_ms: u64, confirmations: u32) -> Self {
        let base_ms = base_ms.max(1);
        Self {
            base_ms,
            cap_ms: cap_ms.max(base_ms),
            confirmations: confirmations.max(1),
            state: BTreeMap::new(),
        }
    }

    /// 第 N 次连续 demote 的冷却时长（毫秒）：`base × 2^(N-1)` 封顶 `cap`。
    /// `base > cap >> exp` 即说明 `base << exp` 已达/超出 cap（含 u64 高位
    /// 绕回——`checked_shl` 只查移位量溢出，不查值溢出）→ 直接取 cap。
    fn delay_ms(&self, demotes: u32) -> u64 {
        let exponent = demotes.saturating_sub(1).min(62);
        if exponent > 0 && self.base_ms > self.cap_ms >> exponent {
            self.cap_ms
        } else {
            self.base_ms << exponent
        }
    }

    /// 记录一次 demote：连续计数 +1、健康轮清零、抑制截止 = now + 冷却时长。
    pub fn on_demote(&mut self, public_key: &str, now_ms: u64) {
        let demotes = {
            let entry = self
                .state
                .entry(public_key.to_string())
                .or_insert(BackoffState {
                    demotes: 0,
                    health_streak: 0,
                    suppress_until_ms: 0,
                });
            entry.demotes = entry.demotes.saturating_add(1);
            entry.health_streak = 0;
            entry.demotes
        };
        let delay = self.delay_ms(demotes);
        let entry = self
            .state
            .get_mut(public_key)
            .expect("entry just inserted above");
        entry.suppress_until_ms = now_ms.saturating_add(delay);
    }

    /// 记录一轮健康证据：`healthy` = 该对端本轮有探测健康面（FLIP-001
    /// 健康面集合任一命中）。连续 `confirmations` 轮健康 → 整条退避清零
    /// （下次 demote 从 base 重新起步）；一轮不健康 → 健康轮清零（连续性
    /// 打破），demote 计数与当前抑制保持。无退避状态时 no-op。
    pub fn note_health(&mut self, public_key: &str, healthy: bool, _now_ms: u64) {
        let Some(state) = self.state.get_mut(public_key) else {
            return;
        };
        if healthy {
            state.health_streak = state.health_streak.saturating_add(1);
            if state.health_streak >= self.confirmations {
                self.state.remove(public_key);
            }
        } else {
            state.health_streak = 0;
        }
    }

    /// 该对端当前是否处于抑制期（是 → 返回 defer 决策记录用的理由串）。
    pub fn suppress_reason(&self, public_key: &str, now_ms: u64) -> Option<String> {
        let state = self.state.get(public_key)?;
        if now_ms >= state.suppress_until_ms {
            return None;
        }
        let cooling_secs = (state.suppress_until_ms - now_ms).div_ceil(1000);
        Some(format!(
            "promote deferred: demote backoff ({} consecutive demote(s), cooling {}s more; FLIP-002)",
            state.demotes, cooling_secs
        ))
    }

    /// 当前全部抑制中的对端 → 理由（域层 `suppress_promote` 参数的输入；
    /// 单快照构建，避免逐对端重复扫描）。
    pub fn suppress_map(&self, now_ms: u64) -> BTreeMap<String, String> {
        self.state
            .iter()
            .filter(|(_, state)| now_ms < state.suppress_until_ms)
            .map(|(key, state)| {
                let cooling_secs = (state.suppress_until_ms - now_ms).div_ceil(1000);
                (
                    key.clone(),
                    format!(
                        "promote deferred: demote backoff ({} consecutive demote(s), cooling {}s more; FLIP-002)",
                        state.demotes, cooling_secs
                    ),
                )
            })
            .collect()
    }

    /// 回收不在候选集里的对端（撤销 / 下线后状态清理）。
    pub fn retain(&mut self, keys: &[String]) {
        let live: std::collections::BTreeSet<&str> = keys.iter().map(String::as_str).collect();
        self.state.retain(|key, _| live.contains(key.as_str()));
    }

    /// 是否有退避状态（诊断 / 测试）。
    pub fn is_empty(&self) -> bool {
        self.state.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // base 30s / cap 15min / 3 轮健康清零 —— 全部默认值的加速等价测试口径。
    fn backoff() -> DemoteBackoff {
        DemoteBackoff::new(30_000, 900_000, 3)
    }

    #[test]
    fn delay_grows_exponentially_then_caps() {
        let b = backoff();
        assert_eq!(b.delay_ms(1), 30_000, "1st demote: base");
        assert_eq!(b.delay_ms(2), 60_000, "2nd: base × 2");
        assert_eq!(b.delay_ms(3), 120_000, "3rd: base × 4");
        assert_eq!(b.delay_ms(4), 240_000, "4th: base × 8");
        // 封顶：base × 32 = 960_000ms 已超 15min，压到 900_000ms。
        assert_eq!(b.delay_ms(6), 900_000, "capped below base × 32");
        assert_eq!(b.delay_ms(7), 900_000, "cap reached");
        assert_eq!(b.delay_ms(100), 900_000, "far beyond cap");
    }

    #[test]
    fn on_demote_suppresses_for_the_backoff_window() {
        let mut b = backoff();
        b.on_demote("pk", 1_000);
        assert!(b.suppress_reason("pk", 1_000).is_some(), "suppressed now");
        assert!(b.suppress_reason("pk", 30_999).is_some(), "still within 30s");
        assert!(
            b.suppress_reason("pk", 31_000).is_none(),
            "cooldown expired at base × 1"
        );
    }

    #[test]
    fn consecutive_demotes_stretch_and_restart_window() {
        let mut b = backoff();
        b.on_demote("pk", 0);
        b.on_demote("pk", 5_000); // 冷却期内又 demote（promote 被抑制，但劣化侧照常）
        assert!(
            b.suppress_reason("pk", 5_000)
                .unwrap()
                .contains("2 consecutive"),
            "reason counts consecutive demotes"
        );
        assert!(b.suppress_reason("pk", 5_000 + 60_000 - 1).is_some());
        assert!(b.suppress_reason("pk", 5_000 + 60_000).is_none(), "2nd window = 60s");
    }

    #[test]
    fn health_confirmations_clear_backoff_fully() {
        let mut b = backoff();
        b.on_demote("pk", 0);
        b.on_demote("pk", 1_000); // demotes=2，冷却 60s
        // 2 轮健康（< confirmations=3）→ 仍抑制。
        b.note_health("pk", true, 2_000);
        b.note_health("pk", true, 3_000);
        assert!(b.suppress_reason("pk", 2_000).is_some(), "not yet cleared");
        // 第 3 轮健康 → 整条清零：立即不再抑制，下次 demote 从 base 重来。
        b.note_health("pk", true, 4_000);
        assert!(b.suppress_reason("pk", 4_000).is_none(), "cleared by 3 healthy rounds");
        assert!(b.is_empty(), "state fully removed");
        b.on_demote("pk", 5_000);
        assert!(b.suppress_reason("pk", 5_000 + 29_999).is_some());
        assert!(
            b.suppress_reason("pk", 5_000 + 30_000).is_none(),
            "restarts at base, not at the old 2nd-demote level"
        );
    }

    #[test]
    fn unhealthy_round_breaks_health_streak_but_keeps_suppression() {
        let mut b = backoff();
        b.on_demote("pk", 0);
        b.note_health("pk", true, 1_000);
        b.note_health("pk", true, 2_000);
        b.note_health("pk", false, 3_000); // 连续性打破
        b.note_health("pk", true, 4_000);
        b.note_health("pk", true, 5_000);
        assert!(
            b.suppress_reason("pk", 5_000).is_some(),
            "2+1 healthy rounds < 3 confirmations; suppression holds"
        );
    }

    #[test]
    fn note_health_without_state_is_noop() {
        let mut b = backoff();
        b.note_health("pk", true, 0);
        b.note_health("pk", false, 1_000);
        assert!(b.is_empty(), "no backoff state was created");
    }

    #[test]
    fn retain_drops_departed_peers() {
        let mut b = backoff();
        b.on_demote("pk-a", 0);
        b.on_demote("pk-b", 0);
        b.retain(&["pk-a".to_string()]);
        assert!(b.suppress_reason("pk-a", 0).is_some());
        assert!(b.suppress_reason("pk-b", 0).is_none(), "departed peer reclaimed");
    }

    #[test]
    fn constructor_clamps_invalid_values() {
        let b = DemoteBackoff::new(0, 0, 0);
        assert_eq!(b.delay_ms(1), 1, "base clamped to 1ms");
        let b = DemoteBackoff::new(60_000, 30_000, 0);
        assert_eq!(b.delay_ms(1), 60_000, "cap raised to base");
        assert_eq!(b.delay_ms(2), 60_000, "cap == base means constant delay");
    }
}
