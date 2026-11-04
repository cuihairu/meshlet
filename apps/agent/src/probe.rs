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

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use meshlet_config::ProbeConfig;
use meshlet_domain::{EndpointCandidate, PeerEndpoints};
use meshlet_network::probe::{
    default_transport, is_degraded, probe_round, ProbeTarget, ProbeTracker, ProbeWindow,
    SwitchDecision, SwitchGate,
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
    pub fn evaluate_switch(
        &self,
        peer: &str,
        current: Option<EndpointCandidate>,
    ) -> Option<SwitchDecision> {
        let snapshot = self.snapshot();
        lock(&self.gate).evaluate(peer, current, &snapshot)
    }

    /// SEL-003：从窗口快照推导各对端是否劣化（丢包尖峰/超时）。
    /// 公钥 → 劣化布尔。探测关 / 无窗口 → 空 map（不武断回中继）。
    pub fn degraded_map(&self) -> BTreeMap<String, bool> {
        let snapshot = self.snapshot();
        let mut map = BTreeMap::new();
        for ((peer, _), window) in &snapshot {
            // 任一候选劣化即标记该对端（直连路径劣化）。
            if is_degraded(window) {
                map.insert(peer.clone(), true);
            }
        }
        map
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

/// 上锁并从毒化中恢复：探测线程 panic 不该连带 agent 主循环挂掉（缓存 /
/// 跟踪器都是短临界区，毒化只可能是探测线程已崩——恢复数据继续用）。
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshlet_network::probe::ProbeSample;

    fn config() -> ProbeConfig {
        ProbeConfig {
            enabled: false,
            interval_secs: 5,
            window: 8,
            switch_required: 3,
            switch_margin: 0.30,
            recovery_required: 3,
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
            // dev-b：健康（全 RTT）。dev-c：末次超时（劣化）。
            for _ in 0..3 {
                tracker.record("dev-b", c1, ProbeSample::Rtt(10));
            }
            tracker.record("dev-c", c2, ProbeSample::Rtt(10));
            tracker.record("dev-c", c2, ProbeSample::Rtt(10));
            tracker.record("dev-c", c2, ProbeSample::Lost);
        }
        let degraded = rt.degraded_map();
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
        assert!(empty.degraded_map().is_empty());
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
}
