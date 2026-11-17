//! SEL-001 候选端点探测运行时：独立线程按 `interval_secs`（默认 5s）对每
//! peer 的全部候选端点发 ICMP 轻量探测，维护 RTT / 丢包 / 抖动滑动窗口。
//!
//! 为什么是独立线程而不是搭 agent 主循环：主循环节拍是 `poll_interval_secs`
//! （默认 30s），探测周期（任务书默认 5s）比它密；且一次探测是 `ping` 子进程
//! （最长等 1s），绝不该把数据面循环拖慢。
//!
//! 零控制面负载（任务书）：候选集复用 30s 直连对账拉到的列表（心跳同步的
//! 数据），探测线程绝不请求 server。缓存由 [`reconcile`](crate::agent::Agent)
//! 刷新，对端下线后最迟一个对账周期内停止探测。
//!
//! 统计供 SEL-002（评分 / 迟滞切换）与 SEL-004（console 展示）消费；SEL-001
//! 阶段以 debug 日志呈现（5s 一条，默认日志级别下不刷屏）。

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use meshlet_config::ProbeConfig;
use meshlet_domain::{EndpointCandidate, PeerEndpoints};
use meshlet_network::probe::{
    default_transport, is_degraded, probe_round, ProbeSample, ProbeTarget, ProbeTracker,
    ProbeWindow, SwitchDecision, SwitchGate, LAST_LOST_TOLERANCE,
};

/// 探测运行时：一个后台线程 + 候选缓存（reconcile 写 / 探测线程读）+
/// 统计跟踪器（探测线程写 / agent 读快照）。
///
/// `Drop` 只置停止位不 `join`：线程最长一个周期（默认 5s）后自行退出，持有
/// 的是 `Arc` 克隆、内存安全；join 会让 agent 关闭（以及测试的构造 / 丢弃）
/// 白白等满一个周期。
pub struct ProbeRuntime {
    cache: Arc<Mutex<Vec<PeerEndpoints>>>,
    tracker: Arc<Mutex<ProbeTracker>>,
    /// SEL-002 迟滞闸：agent 主循环只读评估结果，状态由 `evaluate_switch`
    /// 就地推进（短临界区，探测线程不触碰）。
    gate: Arc<Mutex<SwitchGate>>,
    /// SEL-003 时延劣化阈值（毫秒，`ProbeConfig::degrade_rtt_ms`）：窗口
    /// RTT 中位数 ≥ 此值判劣化（is_degraded 时延维度的配置入口）。
    degrade_rtt_ms: u64,
    /// SEL-003 丢包尖峰阈值（`ProbeConfig::loss_spike`）：窗口丢包率 ≥ 此值
    /// 判劣化（is_degraded 丢包维度的配置入口；默认 0.2，见其文档）。
    loss_spike: f64,
    /// SEL-003 年轻窗口豁免下限（`ProbeConfig::degrade_min_samples`，方案 1）：
    /// 窗口样本 < 此值不判劣化。
    degrade_min_samples: usize,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl ProbeRuntime {
    /// 起探测线程；`enabled = false` 时为冷启动（无线程、零开销；缓存与
    /// 快照接口照常可用）。
    pub fn start(config: &ProbeConfig) -> Self {
        let cache = Arc::new(Mutex::new(Vec::new()));
        let tracker = Arc::new(Mutex::new(ProbeTracker::new(config.window)));
        let gate = Arc::new(Mutex::new(SwitchGate::new(
            config.switch_required,
            config.switch_margin,
            config.switch_cooldown_secs.saturating_mul(1000),
        )));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = if config.enabled {
            let cache = Arc::clone(&cache);
            let tracker = Arc::clone(&tracker);
            let stop = Arc::clone(&stop);
            let interval = Duration::from_secs(config.interval_secs.max(1));
            Some(
                std::thread::Builder::new()
                    .name("meshlet-probe".into())
                    .spawn(move || loop {
                        std::thread::sleep(interval);
                        if stop.load(Ordering::Relaxed) {
                            return;
                        }
                        let peers = lock(&cache).clone();
                        if peers.is_empty() {
                            // 无候选（直连关 / 无对端）：本轮 no-op，不动窗口。
                            continue;
                        }
                        let mut tracker = lock(&tracker);
                        let round = probe_round(&mut tracker, &peers, default_transport);
                        tracing::debug!(
                            peers = peers.len(),
                            issued = round.issued,
                            lost = round.lost,
                            "candidate probe round finished"
                        );
                    })
                    .expect("spawn the candidate probe thread"),
            )
        } else {
            None
        };
        Self {
            cache,
            tracker,
            gate,
            degrade_rtt_ms: config.degrade_rtt_ms,
            loss_spike: config.loss_spike,
            degrade_min_samples: config.degrade_min_samples,
            stop,
            handle,
        }
    }

    /// 刷新候选集（`reconcile_direct` 每 30s 调用；空列表 = 清空缓存，探测
    /// 线程下一轮起 no-op）。
    pub fn update_candidates(&self, peers: &[PeerEndpoints]) {
        *lock(&self.cache) = peers.to_vec();
    }

    /// 当前全部目标的窗口快照（SEL-002 / SEL-004 消费；克隆小map，目标数 =
    /// peers × 候选数）。
    pub fn snapshot(&self) -> BTreeMap<ProbeTarget, ProbeWindow> {
        lock(&self.tracker).windows().clone()
    }

    /// SEL-002：评估某对端是否该把直连 endpoint 切换到更优候选。
    ///
    /// 读窗口快照并推进迟滞闸（[`SwitchGate::evaluate`]）。`current` = 当前
    /// 已下发的直连候选；`None` = 尚无直连路径（初始选择不由本闸负责）。
    /// 返回切换决策（含理由），由调用方执行 `wg set endpoint` 并记录事件。
    /// 切换宽限（方案 1）在闸内判定：宽限期内一律 `None`。
    pub fn evaluate_switch(
        &self,
        peer: &str,
        current: Option<EndpointCandidate>,
    ) -> Option<SwitchDecision> {
        self.evaluate_switch_at(peer, current, now_ms())
    }

    /// [`Self::evaluate_switch`] 的时钟注入版（测试用虚拟时间）。
    fn evaluate_switch_at(
        &self,
        peer: &str,
        current: Option<EndpointCandidate>,
        now_ms: u64,
    ) -> Option<SwitchDecision> {
        let snapshot = self.snapshot();
        lock(&self.gate).evaluate(peer, current, &snapshot, now_ms)
    }

    /// SEL-003：从窗口快照推导各对端**当前直连路径**是否劣化（丢包尖峰/
    /// 超时/RTT 深劣化）。公钥 → 劣化布尔。
    ///
    /// 只评估 `current` 给出的现役 endpoint（`wg` 实际下发的直连候选）的
    /// 窗口：候选列表里其余候选（公网 NAT / 异网 LAN 常年 ICMP 不达）与
    /// 现役路径无关——2026-11-13 真死复验实锤「任一候选劣化 → 整 peer
    /// 劣化」会把健康直连永久误降级。探测关 / 无窗口 → 空 map（不武断
    /// 回中继）。
    pub fn degraded_map(
        &self,
        current: &BTreeMap<String, EndpointCandidate>,
    ) -> BTreeMap<String, bool> {
        self.degraded_map_at(current, now_ms())
    }

    /// [`Self::degraded_map`] 的时钟注入版（测试用虚拟时间）。
    ///
    /// 切换宽限（方案 1）：对端处于宽限期内 → 跳过劣化判定（禁对现路径判
    /// 劣化——刚切换的路径窗口未立起来，宽限内由闸 shield，真死由握手
    /// classify 兜底）。
    fn degraded_map_at(
        &self,
        current: &BTreeMap<String, EndpointCandidate>,
        now_ms: u64,
    ) -> BTreeMap<String, bool> {
        let snapshot = self.snapshot();
        let gate = lock(&self.gate);
        let mut map = BTreeMap::new();
        for (public_key, candidate) in current {
            if gate.in_cooldown(public_key, now_ms) {
                continue;
            }
            let Some(window) = snapshot.get(&(public_key.clone(), *candidate)) else {
                continue;
            };
            if is_degraded(
                window,
                self.degrade_rtt_ms,
                self.loss_spike,
                self.degrade_min_samples,
            ) {
                map.insert(public_key.clone(), true);
            }
        }
        map
    }

    /// promote 偏好健康面（2026-11-14 巡检单 nov14-1410）：当前探测窗口
    /// 劣化的 (public_key, candidate) 面集合，供晋升选路前置过滤（劣化面
    /// 上 re-promote 只会立刻再降级——930f137 决策日志实录的 demote→记忆
    /// 面回拨→再降级翻转循环）。
    ///
    /// 口径与 [`Self::degraded_map`] 同源（is_degraded 同一判定）：无基线
    /// （全 Lost / 无采样）不判——不武断封掉没探测过的面；探测关 → 空集合
    /// （过滤整体失效，行为与旧版一致）。
    pub fn degraded_faces(&self) -> BTreeSet<(String, EndpointCandidate)> {
        let snapshot = self.snapshot();
        let mut set = BTreeSet::new();
        for ((public_key, candidate), window) in snapshot {
            if is_degraded(
                &window,
                self.degrade_rtt_ms,
                self.loss_spike,
                self.degrade_min_samples,
            ) {
                set.insert((public_key, candidate));
            }
        }
        set
    }

    /// 方案 8：切换宽限内的旧 endpoint 一次性回滚。触发证据 = 现路径（上次
    /// 切换的目标面）「由好变坏后持续全暗」——窗口里有 RTT 基线（切换时该
    /// 面必有成功读数才可能被选中）且末尾连续 [`LAST_LOST_TOLERANCE`] 拍
    /// `Lost`；许可与簿记在 [`SwitchGate::rollback`]（宽限内 + 一次性 +
    /// 回滚也过宽限）。无基线（全程 Lost，Windows 防火墙常见）不触发——
    /// 那不是「坏掉了」的证据，且这样的面本就不会成为切换目标。返回旧
    /// endpoint，由调用方 `wg set` 并记录事件。
    pub fn switch_rollback(
        &self,
        peer: &str,
        current: EndpointCandidate,
    ) -> Option<EndpointCandidate> {
        self.switch_rollback_at(peer, current, now_ms())
    }

    /// [`Self::switch_rollback`] 的时钟注入版（测试用虚拟时间）。
    fn switch_rollback_at(
        &self,
        peer: &str,
        current: EndpointCandidate,
        now_ms: u64,
    ) -> Option<EndpointCandidate> {
        let dead = self
            .snapshot()
            .get(&(peer.to_string(), current))
            .is_some_and(|w| {
                w.samples().iter().any(|s| matches!(s, ProbeSample::Rtt(_)))
                    && w.samples()
                        .iter()
                        .rev()
                        .take(LAST_LOST_TOLERANCE)
                        .all(|s| matches!(s, ProbeSample::Lost))
            });
        if !dead {
            return None;
        }
        lock(&self.gate).rollback(peer, current, now_ms)
    }

    /// FLIP-001：某 (公钥, 候选) 面是否有「探测证实的健康」证据——恢复门
    /// bypass 的判据输入（候选表内有健康面 → 不 hold_relay 等门，直接
    /// promote 该面）。
    ///
    /// 口径：窗口非空、**至少一拍 RTT 成功**（正面证据——全程 Lost 的长窗口
    /// 享受无基线豁免不判劣化，但那不是「健康」，只是「未知」，绝不冒充），
    /// 且不劣化（[`is_degraded`] 同一判定）。无窗口 / 无成功采样 → `false`。
    pub fn face_healthy(&self, public_key: &str, candidate: EndpointCandidate) -> bool {
        let snapshot = self.snapshot();
        snapshot
            .get(&(public_key.to_string(), candidate))
            .is_some_and(|w| {
                window_is_healthy(
                    w,
                    self.degrade_rtt_ms,
                    self.loss_spike,
                    self.degrade_min_samples,
                )
            })
    }

    /// FLIP-001：当前全部「探测证实健康」的面的集合（单快照批量判定——
    /// 候选表探测证据刷新与恢复门 bypass 共用一轮读数，避免逐面重复克隆
    /// 快照）。口径同 [`Self::face_healthy`]。
    pub fn healthy_faces(&self) -> BTreeSet<(String, EndpointCandidate)> {
        let snapshot = self.snapshot();
        snapshot
            .into_iter()
            .filter(|(_, w)| {
                window_is_healthy(
                    w,
                    self.degrade_rtt_ms,
                    self.loss_spike,
                    self.degrade_min_samples,
                )
            })
            .map(|(target, _)| target)
            .collect()
    }

    /// 决策日志的判据输入：某对端某候选的探测窗口摘要（如
    /// `23,31,L,L loss=50% med=27ms`；`L` = 丢拍）。探测关 / 无窗口 →
    /// `None`（决策事件里该字段缺席，不冒充「探测过且健康」）。
    pub fn window_summary(&self, public_key: &str, candidate: EndpointCandidate) -> Option<String> {
        let snapshot = self.snapshot();
        let window = snapshot.get(&(public_key.to_string(), candidate))?;
        let samples = window
            .samples()
            .iter()
            .map(|s| match s {
                ProbeSample::Rtt(v) => v.to_string(),
                ProbeSample::Lost => "L".into(),
            })
            .collect::<Vec<_>>()
            .join(",");
        Some(format!(
            "{samples} loss={:.0}% med={:?}ms",
            window.loss_rate() * 100.0,
            window.rtt_ms()
        ))
    }

    /// SEL-004：汇总某对端全部候选端点的详情（端点/RTT/丢包/当前选中与原因）。
    ///
    /// `current_endpoint` = 当前已下发的直连 endpoint（`ip:port`；空 = 未选中）。
    /// 每个候选一条，按 (ip, port) 排序（确定性）；`selected` 标记与现路径匹配
    /// 的候选。探测关 / 无窗口 → 空列表（console 显示「无候选读数」）。
    pub fn candidate_statuses(
        &self,
        peer: &str,
        current_endpoint: &str,
    ) -> Vec<meshlet_domain::DirectCandidateStatus> {
        let snapshot = self.snapshot();
        let mut out: Vec<meshlet_domain::DirectCandidateStatus> = snapshot
            .iter()
            .filter(|((p, _), _)| p == peer)
            .map(|((_, c), w)| {
                let endpoint = format!("{}:{}", c.ip, c.port);
                let selected = endpoint == current_endpoint;
                meshlet_domain::DirectCandidateStatus {
                    endpoint: endpoint.clone(),
                    kind: c.kind.as_str().to_string(),
                    rtt_ms: w.rtt_ms(),
                    loss_rate: w.loss_rate(),
                    selected,
                    reason: if selected {
                        "current".into()
                    } else {
                        "backup".into()
                    },
                }
            })
            .collect();
        out.sort_by(|a, b| a.endpoint.cmp(&b.endpoint));
        out
    }

    /// 探测线程是否在跑（配置开关；关 = 冷启动零开销）。
    pub fn is_enabled(&self) -> bool {
        self.handle.is_some()
    }
}

impl Drop for ProbeRuntime {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // 丢弃 JoinHandle = 分离线程：见结构体文档（不 join 的理由）。
        drop(self.handle.take());
    }
}

/// 当前 Unix 毫秒（无 chrono 依赖；时钟倒退时 0 兜底——宽限判定宁可
/// 放开也不卡死）。
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 上锁并从毒化中恢复：探测线程 panic 不该连带 agent 主循环挂掉（缓存 /
/// 跟踪器都是短临界区，毒化只可能是探测线程已崩——恢复数据继续用）。
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// 「探测证实健康」的窗口口径（FLIP-001）：至少一拍 RTT 成功（正面证据；
/// 全程 Lost 的无基线窗口是「未知」不是「健康」）且不劣化（[`is_degraded`]
/// 同一判定）。空窗口 → `false`。
fn window_is_healthy(
    window: &ProbeWindow,
    degrade_rtt_ms: u64,
    loss_spike: f64,
    min_samples: usize,
) -> bool {
    window
        .samples()
        .iter()
        .any(|s| matches!(s, ProbeSample::Rtt(_)))
        && !is_degraded(window, degrade_rtt_ms, loss_spike, min_samples)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ProbeConfig {
        ProbeConfig {
            enabled: false,
            interval_secs: 5,
            window: 8,
            switch_required: 3,
            switch_margin: 0.30,
            recovery_required: 3,
            degrade_rtt_ms: 800,
            loss_spike: 0.20,
            switch_cooldown_secs: 30,
            degrade_min_samples: 4,
        }
    }

    #[test]
    fn evaluate_switch_requires_gate_and_reports_decision() {
        let rt = ProbeRuntime::start(&config());
        let c1 = EndpointCandidate::lan("192.168.1.50".parse().unwrap(), 51821);
        let c2 = EndpointCandidate::lan("192.168.1.60".parse().unwrap(), 51821);
        // 探测线程关（enabled=false）：手动记录 3 轮窗口，验证迟滞闸。
        {
            let mut tracker = lock(&rt.tracker);
            for _ in 0..3 {
                tracker.record("dev-b", c1, ProbeSample::Rtt(100));
                tracker.record("dev-b", c2, ProbeSample::Rtt(60));
            }
        }
        // 第 1、2 轮不切，第 3 轮切（连续 3 轮）。
        assert!(rt.evaluate_switch("dev-b", Some(c1)).is_none());
        assert!(rt.evaluate_switch("dev-b", Some(c1)).is_none());
        let decision = rt.evaluate_switch("dev-b", Some(c1)).expect("switch");
        assert_eq!(decision.to, c2);
        assert!(decision.reason.contains("3 consecutive"));
        // 切换到 c2 后：现路径最佳 → 不再切换。
        assert!(rt.evaluate_switch("dev-b", Some(c2)).is_none());
    }

    #[test]
    fn evaluate_switch_none_without_current_path() {
        let rt = ProbeRuntime::start(&config());
        // 无现路径（初始选择由 DirectManager 负责）→ 本闸不切。
        assert!(rt.evaluate_switch("dev-b", None).is_none());
    }

    #[test]
    fn degraded_map_marks_peers_with_loss_spike_or_timeout() {
        let rt = ProbeRuntime::start(&config());
        let c1 = EndpointCandidate::lan("192.168.1.50".parse().unwrap(), 51821);
        let c2 = EndpointCandidate::lan("192.168.1.60".parse().unwrap(), 51821);
        {
            let mut tracker = lock(&rt.tracker);
            // dev-b：健康（全 RTT）。dev-c：末尾连续 3 拍超时（劣化；
            // last-Lost 软化后单拍瞬态不再动作）。
            for _ in 0..3 {
                tracker.record("dev-b", c1, ProbeSample::Rtt(10));
            }
            for _ in 0..4 {
                tracker.record("dev-c", c2, ProbeSample::Rtt(10));
            }
            for _ in 0..3 {
                tracker.record("dev-c", c2, ProbeSample::Lost);
            }
        }
        let mut current = BTreeMap::new();
        current.insert("dev-b".to_string(), c1);
        current.insert("dev-c".to_string(), c2);
        let degraded = rt.degraded_map(&current);
        assert!(
            !degraded.get("dev-b").copied().unwrap_or(false),
            "dev-b healthy"
        );
        assert!(
            degraded.get("dev-c").copied().unwrap_or(false),
            "dev-c degraded"
        );
        // 空窗口 → 空 map。
        let empty = ProbeRuntime::start(&config());
        assert!(empty.degraded_map(&current).is_empty());
    }

    /// 时延维度（2026-11-13 残余跟进）：探测全程成功但 RTT 持续深劣化
    /// （真机实录 1715ms probe_ok 钉直连）→ degraded_map 标劣化。
    #[test]
    fn degraded_map_marks_sustained_high_rtt_without_loss() {
        let rt = ProbeRuntime::start(&config());
        let c1 = EndpointCandidate::lan("192.168.1.50".parse().unwrap(), 51821);
        {
            let mut tracker = lock(&rt.tracker);
            // dev-b：持续 ~1715ms（0% 丢）→ 时延劣化。
            for v in [1715u64, 1600, 1800, 1715] {
                tracker.record("dev-b", c1, ProbeSample::Rtt(v));
            }
            // dev-d：健康低 RTT → 不劣化。
            for _ in 0..4 {
                tracker.record("dev-d", c1, ProbeSample::Rtt(9));
            }
        }
        let mut current = BTreeMap::new();
        current.insert("dev-b".to_string(), c1);
        current.insert("dev-d".to_string(), c1);
        let degraded = rt.degraded_map(&current);
        assert!(
            degraded.get("dev-b").copied().unwrap_or(false),
            "sustained 1715ms without loss must degrade"
        );
        assert!(
            !degraded.get("dev-d").copied().unwrap_or(false),
            "dev-d healthy"
        );
    }

    /// 现役路径口径 + 无基线豁免（2026-11-13 SEL-002 真死复验实锤）：只有
    /// 当前 endpoint 的窗口参与判定——备份候选常年 ICMP 不达（公网 NAT /
    /// 异网 LAN）不再拖垮整 peer；全程 Lost 的现役路径无基线也不判劣化
    /// （对端防火墙拦 ICMP，隧道可能健康，真死由握手 classify 兜底）。
    #[test]
    fn degraded_map_scopes_to_current_path_and_requires_baseline() {
        let rt = ProbeRuntime::start(&config());
        let c1 = EndpointCandidate::lan("192.168.1.50".parse().unwrap(), 51821);
        let c2 = EndpointCandidate::lan("192.168.1.60".parse().unwrap(), 51821);
        let c3 = EndpointCandidate::lan("192.168.1.70".parse().unwrap(), 51821);
        {
            let mut tracker = lock(&rt.tracker);
            // c1：现役健康（全 RTT）。c2：备份全程 Lost（NAT 不答 ICMP）。
            // c3：由好变坏（50% 尖峰）。
            for _ in 0..4 {
                tracker.record("dev-b", c1, ProbeSample::Rtt(10));
                tracker.record("dev-b", c2, ProbeSample::Lost);
            }
            tracker.record("dev-b", c3, ProbeSample::Rtt(10));
            tracker.record("dev-b", c3, ProbeSample::Rtt(10));
            tracker.record("dev-b", c3, ProbeSample::Lost);
            tracker.record("dev-b", c3, ProbeSample::Lost);
        }
        let mut current = BTreeMap::new();
        // 现役 = c1：备份 c2/c3 的窗口与现役无关 → 不劣化。
        current.insert("dev-b".to_string(), c1);
        assert!(
            !rt.degraded_map(&current)
                .get("dev-b")
                .copied()
                .unwrap_or(false),
            "healthy current path; backup candidates are irrelevant"
        );
        // 现役 = c3（由好变坏）→ 劣化。
        let mut current = BTreeMap::new();
        current.insert("dev-b".to_string(), c3);
        assert!(
            rt.degraded_map(&current)
                .get("dev-b")
                .copied()
                .unwrap_or(false),
            "current path degraded by loss spike with baseline"
        );
        // 现役 = c2（全程 Lost，无基线）→ 不劣化。
        let mut current = BTreeMap::new();
        current.insert("dev-b".to_string(), c2);
        assert!(
            !rt.degraded_map(&current)
                .get("dev-b")
                .copied()
                .unwrap_or(false),
            "never-answered path has no baseline; handshake classify owns true death"
        );
        // 现役无窗口（刚切路径）→ 不劣化。
        let mut current = BTreeMap::new();
        current.insert("dev-x".to_string(), c1);
        assert!(
            !rt.degraded_map(&current)
                .get("dev-x")
                .copied()
                .unwrap_or(false),
            "no window yet; do not degrade"
        );
    }

    #[test]
    fn candidate_statuses_reports_all_candidates_with_selection() {
        let rt = ProbeRuntime::start(&config());
        let c1 = EndpointCandidate::lan("192.168.1.50".parse().unwrap(), 51821);
        let c2 = EndpointCandidate::lan("192.168.1.60".parse().unwrap(), 51821);
        {
            let mut tracker = lock(&rt.tracker);
            tracker.record("dev-b", c1, ProbeSample::Rtt(10));
            tracker.record("dev-b", c1, ProbeSample::Rtt(12));
            tracker.record("dev-b", c2, ProbeSample::Rtt(40));
            tracker.record("dev-b", c2, ProbeSample::Lost);
        }
        // 当前选中 c1：两个候选都列出，c1 标 selected。
        let statuses = rt.candidate_statuses("dev-b", "192.168.1.50:51821");
        assert_eq!(statuses.len(), 2);
        let c1s = statuses
            .iter()
            .find(|c| c.endpoint == "192.168.1.50:51821")
            .unwrap();
        assert!(c1s.selected);
        assert_eq!(c1s.reason, "current");
        assert_eq!(c1s.rtt_ms, Some(11));
        assert_eq!(c1s.loss_rate, 0.0);
        let c2s = statuses
            .iter()
            .find(|c| c.endpoint == "192.168.1.60:51821")
            .unwrap();
        assert!(!c2s.selected);
        assert_eq!(c2s.reason, "backup");
        assert_eq!(c2s.rtt_ms, Some(40));
        assert_eq!(c2s.loss_rate, 0.5);
        // 其它 peer 候选不影响。
        assert!(rt.candidate_statuses("dev-x", "").is_empty());
    }

    /// 决策日志判据输入（2026-11-14 巡检单）：窗口摘要串带逐拍采样与
    /// loss/med 汇总；无窗口（探测关/未采样）→ None，不冒充「探测过」。
    #[test]
    fn window_summary_reports_samples_and_aggregates_or_none() {
        let rt = ProbeRuntime::start(&config());
        let c1 = EndpointCandidate::lan("192.168.1.50".parse().unwrap(), 51821);
        assert!(rt.window_summary("dev-b", c1).is_none(), "no window yet");
        {
            let mut tracker = lock(&rt.tracker);
            tracker.record("dev-b", c1, ProbeSample::Rtt(23));
            tracker.record("dev-b", c1, ProbeSample::Rtt(31));
            tracker.record("dev-b", c1, ProbeSample::Lost);
            tracker.record("dev-b", c1, ProbeSample::Lost);
        }
        let summary = rt.window_summary("dev-b", c1).expect("summary");
        assert!(summary.starts_with("23,31,L,L"), "summary={summary}");
        assert!(summary.contains("loss=50%"), "summary={summary}");
        assert!(summary.contains("med=Some(27)"), "summary={summary}");
        // 其它 peer 无窗口。
        assert!(rt.window_summary("dev-x", c1).is_none());
    }

    /// promote 偏好健康面的面集合：只收「有基线后劣化」的面；健康面不收、
    /// 全程 Lost 无基线面不收（不武断封面）、探测关（无采样）为空集合。
    #[test]
    fn degraded_faces_marks_baseline_degraded_faces_only() {
        let rt = ProbeRuntime::start(&config());
        let c1 = EndpointCandidate::lan("192.168.1.50".parse().unwrap(), 51821);
        let c2 = EndpointCandidate::lan("192.168.1.60".parse().unwrap(), 51821);
        let c3 = EndpointCandidate::lan("192.168.1.70".parse().unwrap(), 51821);
        {
            let mut tracker = lock(&rt.tracker);
            // dev-b@c1 健康；dev-b@c2 由好变坏（末尾 3 拍连续 Lost）；
            // dev-b@c3 全程 Lost（无基线，真死由握手 classify 兜底）。
            for _ in 0..4 {
                tracker.record("dev-b", c1, ProbeSample::Rtt(10));
                tracker.record("dev-b", c2, ProbeSample::Rtt(10));
                tracker.record("dev-b", c3, ProbeSample::Lost);
            }
            for _ in 0..3 {
                tracker.record("dev-b", c2, ProbeSample::Lost);
            }
        }
        let faces = rt.degraded_faces();
        assert!(
            !faces.contains(&("dev-b".into(), c1)),
            "healthy face not marked"
        );
        assert!(
            faces.contains(&("dev-b".into(), c2)),
            "baseline + tail Lost run marked"
        );
        assert!(
            !faces.contains(&("dev-b".into(), c3)),
            "no-baseline face not marked"
        );
        // 探测关 / 无采样 → 空集合（过滤整体失效 = 旧口径）。
        assert!(ProbeRuntime::start(&config()).degraded_faces().is_empty());
    }

    /// 丢包尖峰阈值收窄的钉子（2026-11-17 用户拍板 50% → 20%，恢复门面）：
    /// 49% 丢包的面在旧阈值下算「探测证实健康」，能作 FLIP-001 bypass 证据
    /// 把恢复门放行、直连拉回劣化面——现在不再判健康；<20%（19%）仍健康。
    #[test]
    fn face_healthy_rejects_49_percent_loss_but_accepts_19_percent() {
        let c1 = EndpointCandidate::lan("192.168.1.50".parse().unwrap(), 51821);
        let c2 = EndpointCandidate::lan("192.168.1.60".parse().unwrap(), 51821);
        // 精确边界需要 100 拍窗口（默认测试窗口 8 装不下 49/100）：window=100。
        let mut cfg = config();
        cfg.window = 100;
        let rt = ProbeRuntime::start(&cfg);
        {
            let mut tracker = lock(&rt.tracker);
            for _ in 0..49 {
                tracker.record("dev-b", c1, ProbeSample::Lost);
            }
            for _ in 0..51 {
                tracker.record("dev-b", c1, ProbeSample::Rtt(10));
            }
            for _ in 0..19 {
                tracker.record("dev-b", c2, ProbeSample::Lost);
            }
            for _ in 0..81 {
                tracker.record("dev-b", c2, ProbeSample::Rtt(10));
            }
        }
        assert!(
            !rt.face_healthy("dev-b", c1),
            "49% loss must not count as probe-healthy (no recovery bypass)"
        );
        assert!(
            rt.face_healthy("dev-b", c2),
            "19% loss stays probe-healthy under the 20% threshold"
        );
        // 同一判定源：劣化映射也把 49% 面判劣化（demote 闸一致）。
        let mut current = BTreeMap::new();
        current.insert("dev-b".to_string(), c1);
        assert!(rt
            .degraded_map(&current)
            .get("dev-b")
            .copied()
            .unwrap_or(false));
    }

    /// 切换宽限钉子（方案 1，2026-11-17）：切换后宽限期内（默认
    /// interval×required×2 = 30s）①禁再切 ②禁对现路径判劣化；宽限一过
    /// 两者恢复常规判定。用户实测 ping 三态横跳的「切换瞬断档」即此真空期
    /// 被闸/劣化判定放大的体感。
    #[test]
    fn switch_grace_blocks_reswitch_and_degrade_marking() {
        let c1 = EndpointCandidate::lan("192.168.1.50".parse().unwrap(), 51821);
        let c2 = EndpointCandidate::lan("192.168.1.60".parse().unwrap(), 51821);
        let c3 = EndpointCandidate::lan("192.168.1.70".parse().unwrap(), 51821);
        let rt = ProbeRuntime::start(&config());
        // 攒 c2 优于 c1 的连续 3 采样 → 在 t0=1_000 触发切换 c1→c2。
        {
            let mut tracker = lock(&rt.tracker);
            for _ in 0..3 {
                tracker.record("dev-b", c1, ProbeSample::Rtt(100));
                tracker.record("dev-b", c2, ProbeSample::Rtt(60));
            }
        }
        assert!(rt.evaluate_switch_at("dev-b", Some(c1), 900).is_none());
        assert!(rt.evaluate_switch_at("dev-b", Some(c1), 950).is_none());
        let decision = rt
            .evaluate_switch_at("dev-b", Some(c1), 1_000)
            .expect("switch at t0");
        assert_eq!(decision.to, c2);
        // 切换后 c2 窗口急转直下（末尾连续 3 拍 Lost，7 拍窗口攒满）且 c3
        // 远优于 c2——宽限内两者都必须被挡住。
        {
            let mut tracker = lock(&rt.tracker);
            for _ in 0..3 {
                tracker.record("dev-b", c2, ProbeSample::Lost);
                tracker.record("dev-b", c3, ProbeSample::Rtt(10));
            }
        }
        let mut current = BTreeMap::new();
        current.insert("dev-b".to_string(), c2);
        // 宽限内（t0+5s）：不判劣化、不再切。
        let map = rt.degraded_map_at(&current, 1_000 + 5_000);
        assert!(
            !map.get("dev-b").copied().unwrap_or(false),
            "degrade marking suppressed within grace"
        );
        assert!(
            rt.evaluate_switch_at("dev-b", Some(c2), 1_000 + 5_000)
                .is_none(),
            "re-switch blocked within grace"
        );
        // 宽限过（t0+31.5s；宽限含端点边界，31_000 仍在宽限内——回滚检查
        // 要落在紧随切换的下一对账轮）：同口径读数恢复动作——劣化命中；
        // 闸须重新攒满连续计数（宽限内冻结评估，streak 从 0 重来），第 3
        // 轮才切。
        let map = rt.degraded_map_at(&current, 1_000 + 31_500);
        assert!(
            map.get("dev-b").copied().unwrap_or(false),
            "degrade acts after grace"
        );
        assert!(
            rt.evaluate_switch_at("dev-b", Some(c2), 1_000 + 31_500)
                .is_none(),
            "streak restarts after grace"
        );
        assert!(
            rt.evaluate_switch_at("dev-b", Some(c2), 1_000 + 31_501)
                .is_none(),
            "streak restarts after grace (2/3)"
        );
        assert!(
            rt.evaluate_switch_at("dev-b", Some(c2), 1_000 + 31_502)
                .is_some(),
            "gate acts after streak refills"
        );
    }

    /// 方案 8 回滚钉子（2026-11-18）：死亡证据 = 现路径窗口有 RTT 基线且
    /// 末尾连续 [`LAST_LOST_TOLERANCE`] 拍全 Lost；许可 = 宽限内 + 一次性
    /// + 目标面匹配（闸层宽限延长语义在 network 侧钉子覆盖）。
    #[test]
    fn switch_rollback_needs_death_evidence_and_is_one_shot() {
        let c1 = EndpointCandidate::lan("192.168.2.50".parse().unwrap(), 51821);
        let c2 = EndpointCandidate::lan("192.168.2.60".parse().unwrap(), 51821);
        let rt = ProbeRuntime::start(&config());
        // 攒 c2 优于 c1 的连续 3 采样 → 在 t0=1_000 触发切换 c1→c2。
        {
            let mut tracker = lock(&rt.tracker);
            for _ in 0..3 {
                tracker.record("dev-b", c1, ProbeSample::Rtt(100));
                tracker.record("dev-b", c2, ProbeSample::Rtt(60));
            }
        }
        assert!(rt.evaluate_switch_at("dev-b", Some(c1), 900).is_none());
        assert!(rt.evaluate_switch_at("dev-b", Some(c1), 950).is_none());
        let decision = rt
            .evaluate_switch_at("dev-b", Some(c1), 1_000)
            .expect("switch at t0");
        assert_eq!(decision.to, c2);

        // 无死亡证据（窗口全是好读数）：宽限内也返回 None。
        assert!(
            rt.switch_rollback_at("dev-b", c2, 1_000 + 5_000).is_none(),
            "healthy window is not rollback evidence"
        );
        // 目标面不匹配（current 不是上次切换的落点）：不回滚。
        assert!(
            rt.switch_rollback_at("dev-b", c1, 1_000 + 5_000).is_none(),
            "rollback only applies to the face the switch landed on"
        );

        // 窗口由好变坏：[R,R,R] + [L,L,L] → 死亡证据齐，宽限内回滚 Some(c1)。
        {
            let mut tracker = lock(&rt.tracker);
            for _ in 0..3 {
                tracker.record("dev-b", c2, ProbeSample::Lost);
            }
        }
        assert_eq!(
            rt.switch_rollback_at("dev-b", c2, 1_000 + 5_000),
            Some(c1),
            "dead target face rolls back to the pre-switch face"
        );

        // 一次性：同一宽限内证据仍在，也只回滚一次。
        assert!(
            rt.switch_rollback_at("dev-b", c2, 1_000 + 6_000).is_none(),
            "rollback is one shot"
        );
        // 宽限过（回滚时刻 5_000 + 30_000）：不再回滚。
        assert!(
            rt.switch_rollback_at("dev-b", c2, 35_001).is_none(),
            "no rollback outside grace"
        );
    }
}
