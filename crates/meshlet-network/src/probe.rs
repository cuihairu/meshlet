//! SEL-001 候选端点探测层：对每 peer 的全部候选端点发轻量探测，采集
//! RTT / 丢包 / 抖动滑动窗口（[todo.md](../../../todo.md) SEL-001）。
//!
//! 设计要点（与任务书一一对应）：
//! - **候选输入**是 [`meshlet_domain::PeerEndpoints`]（hub 下发的公网 / 局域网
//!   候选），探测层只消费它、不自己拼装；
//! - **窗口统计**（[`ProbeWindow`]）是纯逻辑：保留最近 `capacity` 次探测，
//!   超限逐出最旧，`rtt_ms`（中位数）/ `loss_rate` / `jitter_ms` 全部由窗口
//!   推导，SEL-002 的评分与迟滞切换直接消费；
//! - **传输可注入**（[`probe_round`] 的 `transport` 闭包）：生产走平台默认
//!   [`default_transport`]（Linux 经 `ping` 发 ICMP echo，不新增控制面负载），
//!   netns 集成测试注入「在指定命名空间内 ping」的传输来实测双路径 RTT；
//! - **零控制面负载**：探测周期与心跳 / 派单独立，只复用对端候选集（30s 心跳
//!   同步的数据），绝不因探测额外请求 server。
//!
//! 平台差异收敛在 [`default_transport`]：Linux 真实 ICMP 探测（`ping -c 1
//! -W 1`）；Windows 同口径 ICMP（`ping -n 1 -w 1000`，[`crate::windows_probe`]，
//! 2026-11-13 接线）；其余平台返回 `None`（记为丢包）。

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::Ipv4Addr;

use meshlet_domain::{EndpointCandidate, PeerEndpoints};

// ---------------------------------------------------------------------------
// 窗口统计
// ---------------------------------------------------------------------------

/// 一次探测结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeSample {
    /// 往返时延（毫秒）。
    Rtt(u64),
    /// 探测超时未响应（丢包）。
    Lost,
}

/// 有界滑动窗口：保留最近 `capacity` 次探测，超限逐出最旧。
///
/// 纯统计结构，无 IO；所有读数（RTT / 丢包率 / 抖动）都由窗口内样本推导，
/// 不维护任何外部状态，SEL-002 可直接消费。
#[derive(Debug, Clone)]
pub struct ProbeWindow {
    capacity: usize,
    samples: VecDeque<ProbeSample>,
}

impl ProbeWindow {
    /// 新建窗口。`capacity` 下限 1（空窗口无意义）。
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            samples: VecDeque::new(),
        }
    }

    /// 记录一次探测；窗口已满则逐出最旧样本。
    pub fn record(&mut self, sample: ProbeSample) {
        if self.samples.len() == self.capacity {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    /// 窗口内样本数。
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// 窗口容量（本次探测的样本上限）。
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// 窗口内全部样本（旧 → 新，只读视图）。
    pub fn samples(&self) -> &VecDeque<ProbeSample> {
        &self.samples
    }

    /// 窗口内 RTT 样本的中位数（毫秒）。鲁棒集中趋势：单点尖峰 / 单次丢包
    /// 不把读数带偏，SEL-002 评分以此为主。无 RTT 样本 → `None`。
    pub fn rtt_ms(&self) -> Option<u64> {
        let mut rtts: Vec<u64> = self
            .samples
            .iter()
            .filter_map(|s| match s {
                ProbeSample::Rtt(v) => Some(*v),
                ProbeSample::Lost => None,
            })
            .collect();
        rtts.sort_unstable();
        let n = rtts.len();
        match n {
            0 => None,
            _ if n % 2 == 1 => Some(rtts[n / 2]),
            _ => Some((rtts[n / 2 - 1] + rtts[n / 2]) / 2),
        }
    }

    /// 丢包率（0.0..=1.0）：窗口内 Lost 样本 / 总样本。空窗口 → 0.0。
    pub fn loss_rate(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let lost = self
            .samples
            .iter()
            .filter(|s| **s == ProbeSample::Lost)
            .count();
        lost as f64 / self.samples.len() as f64
    }

    /// 抖动（毫秒）：相邻 RTT 样本绝对差值的均值（RFC 3550 式简单抖动）。
    /// 需要 ≥2 个 RTT 样本，否则 `None`。
    pub fn jitter_ms(&self) -> Option<f64> {
        let rtts: Vec<u64> = self
            .samples
            .iter()
            .filter_map(|s| match s {
                ProbeSample::Rtt(v) => Some(*v),
                ProbeSample::Lost => None,
            })
            .collect();
        if rtts.len() < 2 {
            return None;
        }
        let sum: u64 = rtts.windows(2).map(|w| w[0].abs_diff(w[1])).sum();
        Some(sum as f64 / (rtts.len() - 1) as f64)
    }
}

// ---------------------------------------------------------------------------
// 每目标跟踪器
// ---------------------------------------------------------------------------

/// 探测目标标识：对端 wg 公钥 + 候选端点。
///
/// 公钥是全部消费端的统一键：SEL-003 劣化映射 / [`RecoveryGate`]、SEL-002
/// [`SwitchGate`]、SEL-004 候选详情都按 `PeerEndpoints::public_key` 查窗口
/// （2026-11-13 SEL-002 真死复验实锤：按 device_id 记键使三路消费全部失配，
/// 生产环境劣化/切换/候选详情全盲）。
pub type ProbeTarget = (String, EndpointCandidate);

/// 每 `(peer, candidate)` 一个滑动窗口的跟踪器。
///
/// 候选集来自 30s 心跳同步的对端列表；本跟踪器只增删目标，不发起任何网络
/// 操作（传输由 [`probe_round`] 注入）。
#[derive(Debug, Clone)]
pub struct ProbeTracker {
    capacity: usize,
    windows: BTreeMap<ProbeTarget, ProbeWindow>,
}

impl ProbeTracker {
    /// 新建跟踪器；每个目标窗口容量为 `capacity`（下限 1）。
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            windows: BTreeMap::new(),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// 记录一次探测到目标 `(peer 公钥, candidate)`。
    pub fn record(&mut self, public_key: &str, candidate: EndpointCandidate, sample: ProbeSample) {
        self.windows
            .entry((public_key.to_string(), candidate))
            .or_insert_with(|| ProbeWindow::new(self.capacity))
            .record(sample);
    }

    /// 读目标当前窗口（无记录 → `None`）。
    pub fn window(&self, public_key: &str, candidate: EndpointCandidate) -> Option<&ProbeWindow> {
        self.windows.get(&(public_key.to_string(), candidate))
    }

    /// 当前跟踪目标数（含已无候选的历史目标，[`retain_peers`](Self::retain_peers)
    /// 后仅剩活目标）。
    pub fn len(&self) -> usize {
        self.windows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.windows.is_empty()
    }

    /// 全部目标 → 窗口（只读视图）。
    pub fn windows(&self) -> &BTreeMap<ProbeTarget, ProbeWindow> {
        &self.windows
    }

    /// 忘掉不在当前 peer 集合里的目标：对端下线 / 候选消失 → 统计回收，
    /// 不让死目标拖着旧窗口占用内存（SEL-002 评分为候选集之外的 peer 无意义）。
    pub fn retain_peers(&mut self, peers: &[PeerEndpoints]) {
        let live: BTreeSet<ProbeTarget> = peers
            .iter()
            .flat_map(|p| p.endpoints.iter().map(|c| (p.public_key.clone(), *c)))
            .collect();
        self.windows.retain(|k, _| live.contains(k));
    }
}

// ---------------------------------------------------------------------------
// 一轮探测编排
// ---------------------------------------------------------------------------

/// 一轮探测的概要（日志 / 测试断言用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeRound {
    /// 本轮发出的探测数（peers × 各自候选数）。
    pub issued: usize,
    /// 其中记为丢包（传输返回 `None`）的数量。
    pub lost: usize,
}

/// 对每 peer 的每个候选端点发一次探测并记录进 [`ProbeTracker`]。
///
/// `transport(ip) -> Option<u128>` 实测 RTT（毫秒）：`Some(ms)` 记为
/// [`ProbeSample::Rtt`]，`None`（超时 / 不可达 / 平台不支持）记为
/// [`ProbeSample::Lost`]。ICMP echo 以候选 IP 为目标（端口对 ICMP 无意义，
/// 但端口保留在目标标识里，供后续 UDP / WG 传输区分同一 IP 的不同候选）。
///
/// 先 [`ProbeTracker::retain_peers`] 再探测：本轮 peer 集之外的旧目标立即回收。
pub fn probe_round<F: Fn(Ipv4Addr) -> Option<u128>>(
    tracker: &mut ProbeTracker,
    peers: &[PeerEndpoints],
    transport: F,
) -> ProbeRound {
    tracker.retain_peers(peers);
    let mut issued = 0usize;
    let mut lost = 0usize;
    for peer in peers {
        for candidate in &peer.endpoints {
            let sample = match transport(candidate.ip) {
                Some(ms) => ProbeSample::Rtt(ms.min(u64::MAX as u128) as u64),
                None => {
                    lost += 1;
                    ProbeSample::Lost
                }
            };
            tracker.record(&peer.public_key, *candidate, sample);
            issued += 1;
        }
    }
    ProbeRound { issued, lost }
}

/// 平台默认探测传输：Linux 经 `ping -c 1 -W 1` 发 ICMP echo 实测 RTT（免特权
/// 的 `ping_group_range` 或 root 均可，与 [`crate::linux::run_ping_rtt`] 同源）。
///
/// Windows 经 `ping -n 1 -w 1000` 同口径实测（[`crate::windows_probe`]，P0
/// 接线 2026-11-13：此前非 Linux 一律 `None` 记丢包，主力平台探测全盲）。
/// 其余平台返回 `None`——`probe_round` 记为丢包，绝不假装探测到 RTT。
#[cfg(target_os = "linux")]
pub fn default_transport(ip: Ipv4Addr) -> Option<u128> {
    crate::linux::run_ping_rtt(ip)
}

/// 平台默认探测传输（Windows）：见上方 Linux 版别的文档。
#[cfg(target_os = "windows")]
pub fn default_transport(ip: Ipv4Addr) -> Option<u128> {
    crate::windows_probe::run_ping_rtt(ip)
}

/// 平台默认探测传输（其余平台）：无探测实现，记为丢包（见上方文档）。
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn default_transport(_ip: Ipv4Addr) -> Option<u128> {
    None
}

// ---------------------------------------------------------------------------
// SEL-002 路径评分与迟滞切换（纯逻辑，无 IO）
// ---------------------------------------------------------------------------

/// 丢包重罚系数：`score = rtt_ms * (1 + LOSS_PENALTY * loss_rate)`.
/// RTT 是主导项（毫秒直接作基数），丢包率以乘法放大——10% 丢包把得分
/// 加倍，全丢窗口无 RTT 样本则得分记为 +∞（最差）。丢包重罚保证「丢包尖峰」
/// 的劣化路径不会因中位数 RTT 仍低而被误判为优。
pub const LOSS_PENALTY: f64 = 10.0;

/// 路径得分（SEL-002 评分）：`rtt_ms * (1 + LOSS_PENALTY * loss_rate)`.
///
/// - 空窗口 → `None`（尚无读数，不参与比较）；
/// - 窗口内无 RTT 样本（全丢）→ `Some(+∞)`（最差，任何有 RTT 的路径更优）；
/// - 其余 → `Some(rtt 中位数 * (1 + LOSS_PENALTY * 丢包率))`。
///
/// 越低越好。SEL-002 的迟滞切换直接以此做「新路径优于现路径 ≥30%」判定。
pub fn score(window: &ProbeWindow) -> Option<f64> {
    if window.is_empty() {
        return None;
    }
    match window.rtt_ms() {
        None => Some(f64::INFINITY),
        Some(rtt) => Some(rtt as f64 * (1.0 + LOSS_PENALTY * window.loss_rate())),
    }
}

/// 一次迟滞切换决策（SEL-002）：目标候选 + 人类可读理由（事件记录用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchDecision {
    /// 切换到的候选端点。
    pub to: EndpointCandidate,
    /// 切换理由（如「score 60.0 beats 100.0 by >=30% for 3 consecutive samples」）。
    pub reason: String,
}

/// 迟滞闸（SEL-002）：新路径须**连续** `required` 次采样且得分优于现路径
/// ≥ `margin`（默认 30%）才切换，防抖。纯状态机，无 IO。
///
/// 状态按 `(peer, candidate)` 记录连续更优计数：候选变差 / 现路径重新领先 /
/// 切换目标变化都会清零相应计数，绝不因单次抖动翻转。
#[derive(Debug, Clone)]
pub struct SwitchGate {
    required: usize,
    margin: f64,
    /// `(peer, candidate)` → 连续满足「优于现路径 ≥ margin」的采样数。
    streaks: BTreeMap<ProbeTarget, usize>,
}

impl SwitchGate {
    /// 新建迟滞闸。`required` 下限 1；`margin` 钳制到 `(0.0, 1.0]`。
    pub fn new(required: usize, margin: f64) -> Self {
        Self {
            required: required.max(1),
            margin: margin.clamp(f64::EPSILON, 1.0),
            streaks: BTreeMap::new(),
        }
    }

    pub fn required(&self) -> usize {
        self.required
    }

    pub fn margin(&self) -> f64 {
        self.margin
    }

    /// 评估一轮：给定现路径与全部候选窗口，返回是否切换。
    ///
    /// - `current`：当前选中的候选（`None` = 尚无直连路径，初始选择由
    ///   DirectManager 负责，本闸只做**已建立路径之间的切换**）；
    /// - `windows`：该 peer 的候选 → 窗口快照（[`ProbeTracker::windows`]
    ///   按 peer 公钥过滤后的视图）。
    ///
    /// 返回 `Some(SwitchDecision)` 当且仅当：存在一个候选，其得分严格低于
    /// 现路径得分、且 `得分 <= 现路径得分 * (1 - margin)`，且该候选已连续
    /// `required` 轮满足此条件。达到阈值后重置该候选计数（一次切换一次计数）。
    pub fn evaluate(
        &mut self,
        peer: &str,
        current: Option<EndpointCandidate>,
        windows: &BTreeMap<ProbeTarget, ProbeWindow>,
    ) -> Option<SwitchDecision> {
        let current = current?;
        if windows.is_empty() {
            return None;
        }
        let current_score = windows
            .get(&(peer.to_string(), current))
            .and_then(score)
            .unwrap_or(f64::INFINITY);

        // 最佳候选 = 得分最低者（确定性：得分相同取地址最小者）。
        let mut best_candidate: Option<EndpointCandidate> = None;
        let mut best_score = f64::INFINITY;
        for ((p, c), w) in windows {
            if p != peer {
                continue;
            }
            let s = score(w).unwrap_or(f64::INFINITY);
            let better = match best_candidate {
                None => true,
                Some(bc) => s < best_score || (s == best_score && *c < bc),
            };
            if better {
                best_candidate = Some(*c);
                best_score = s;
            }
        }
        let best_candidate = best_candidate?;

        if best_candidate == current {
            // 现路径仍是最佳：所有候选的连胜计数清零（连续条件被打破）。
            self.streaks.clear();
            return None;
        }

        // 新路径须**严格**更优且优于现路径 ≥ margin（防抖）。
        let improved =
            best_score < current_score && best_score <= current_score * (1.0 - self.margin);
        if !improved {
            self.streaks.remove(&(peer.to_string(), best_candidate));
            return None;
        }

        let key = (peer.to_string(), best_candidate);
        let streak = self.streaks.entry(key.clone()).or_insert(0);
        *streak += 1;
        if *streak >= self.required {
            let reason = format!(
                "score {best_score:.1} beats current {current_score:.1} by >= {:.0}% for {} consecutive samples",
                self.margin * 100.0,
                *streak
            );
            self.streaks.remove(&key);
            Some(SwitchDecision {
                to: best_candidate,
                reason,
            })
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// SEL-003 hub 兜底：直连劣化检测与恢复门（纯逻辑，无 IO）
// ---------------------------------------------------------------------------

/// 丢包尖峰阈值（SEL-003）：窗口丢包率 ≥ 此值视为「丢包尖峰」，立即回中继。
pub const LOSS_SPIKE_THRESHOLD: f64 = 0.5;

/// 直连路径劣化判定（SEL-003）：
/// - 空窗口 → `false`（尚无读数，不武断回中继）；
/// - 窗口内无任何 RTT 样本（全程 `Lost`）→ `false`（无基线豁免，见下）；
/// - 窗口丢包率 ≥ [`LOSS_SPIKE_THRESHOLD`]（丢包尖峰）→ `true`；
/// - 最近一次探测超时（[`ProbeSample::Lost`]，超时）→ `true`；
/// - 窗口 RTT 中位数 ≥ `degrade_rtt_ms`（时延劣化）→ `true`；
/// - 其余 → `false`。
///
/// 任一命中即「立即回中继」：劣化直连路径不再承载流量，hub peer 整段路由
/// 自动接管（/32 直连 peer 移除后最长前缀匹配回落 hub）。恢复须经
/// [`RecoveryGate`] 迟滞切回。
///
/// **时延维度**（2026-11-13 SEL-002 双机验收残余跟进）：此前只有丢包/超时
/// 两条规则——探测全程成功但 RTT 深劣化的路径（真机实录 1715ms `probe_ok`）
/// 永不劣化，直连被「链路活着」的证据钉死。中位数判定天然等价「连续 N 拍
/// 超阈值」：单点/少数尖峰拉不动中位数（防抖），持续深劣化才命中。阈值由
/// agent 配置 `ProbeConfig::degrade_rtt_ms` 下发（默认 800ms，依据见其文档）。
///
/// **无基线豁免**（2026-11-13 SEL-002 imac/openclaw 真死复验实锤）：对端
/// 防火墙拦 ICMP（Windows 默认拦 echo）时探测全程 `Lost`，但 WG 隧道可能
/// 完全健康（内核握手持续续期、7–8ms 实测）——与晋升门槛「ICMP 探测失败
/// 不拦晋升」（Windows 网格防火墙对 wg 接口 100% 丢包取证）同一哲学：没有
/// 「由好变坏」的窗口证据就不判劣化。真死由握手年龄 classify 兜底（超过
/// 健康窗口 → Demote），不依赖探测。
pub fn is_degraded(window: &ProbeWindow, degrade_rtt_ms: u64) -> bool {
    if window.is_empty() {
        return false;
    }
    // 无基线豁免：窗口内无任何成功采样 → 没有基线可比，「丢包尖峰/超时」
    // 无从谈起；真死由握手年龄 classify 兜底。
    let Some(median_rtt) = window.rtt_ms() else {
        return false;
    };
    if window.loss_rate() >= LOSS_SPIKE_THRESHOLD {
        return true;
    }
    if matches!(window.samples().back(), Some(ProbeSample::Lost)) {
        return true;
    }
    median_rtt >= degrade_rtt_ms
}

/// 恢复门（SEL-003）：直连劣化回中继后，须连续 `required` 轮健康才允许
/// 按迟滞闸切回。纯状态机，无 IO。
#[derive(Debug, Clone)]
pub struct RecoveryGate {
    required: usize,
    /// 对端公钥 → 连续健康轮数。
    streaks: BTreeMap<String, usize>,
}

impl RecoveryGate {
    /// 新建恢复门。`required` 下限 1。
    pub fn new(required: usize) -> Self {
        Self {
            required: required.max(1),
            streaks: BTreeMap::new(),
        }
    }

    pub fn required(&self) -> usize {
        self.required
    }

    /// 记录一轮探测结果。`healthy` = 该对端直连路径本轮健康（非劣化）。
    /// 返回 `true` 当且仅当该对端已连续 `required` 轮健康（允许切回）；
    /// 不健康则清零计数（连续条件被打破）。
    pub fn record(&mut self, peer: &str, healthy: bool) -> bool {
        if !healthy {
            self.streaks.remove(peer);
            return false;
        }
        let streak = self.streaks.entry(peer.to_string()).or_insert(0);
        *streak += 1;
        *streak >= self.required
    }

    /// 对端当前是否已恢复（连续 `required` 轮健康）。
    pub fn is_ready(&self, peer: &str) -> bool {
        self.streaks.get(peer).is_some_and(|s| *s >= self.required)
    }

    /// 忘掉不在当前 peer 集合里的对端（下线/撤销后回收计数）。
    pub fn retain(&mut self, peers: &[String]) {
        let live: BTreeSet<&str> = peers.iter().map(|s| s.as_str()).collect();
        self.streaks.retain(|k, _| live.contains(k.as_str()));
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn lan(ip: &str, port: u16) -> EndpointCandidate {
        EndpointCandidate::lan(ip.parse().unwrap(), port)
    }

    fn peer(key: &str, vip: &str, endpoints: &[EndpointCandidate]) -> PeerEndpoints {
        PeerEndpoints {
            device_id: meshlet_domain::DeviceId(key.into()),
            public_key: key.into(),
            virtual_ipv4: vip.parse().unwrap(),
            name: format!("{key}-name"),
            endpoints: endpoints.to_vec(),
        }
    }

    // -- ProbeWindow ---------------------------------------------------------

    #[test]
    fn window_clamps_capacity_to_one() {
        let w = ProbeWindow::new(0);
        assert_eq!(w.capacity(), 1);
    }

    #[test]
    fn window_records_and_evicts_oldest() {
        let mut w = ProbeWindow::new(3);
        w.record(ProbeSample::Rtt(10));
        w.record(ProbeSample::Rtt(20));
        w.record(ProbeSample::Rtt(30));
        assert_eq!(w.len(), 3);
        // 第 4 次逐出最旧（10）。
        w.record(ProbeSample::Rtt(40));
        assert_eq!(w.len(), 3);
        assert_eq!(
            w.samples().iter().copied().collect::<Vec<_>>(),
            vec![
                ProbeSample::Rtt(20),
                ProbeSample::Rtt(30),
                ProbeSample::Rtt(40)
            ]
        );
    }

    #[test]
    fn rtt_median_handles_odd_and_even_counts() {
        let mut w = ProbeWindow::new(8);
        for v in [30, 10, 20] {
            w.record(ProbeSample::Rtt(v));
        }
        // 奇数：排序 10,20,30 → 中位数 20。
        assert_eq!(w.rtt_ms(), Some(20));
        w.record(ProbeSample::Rtt(40));
        // 偶数：10,20,30,40 → 均值 (20+30)/2 = 25。
        assert_eq!(w.rtt_ms(), Some(25));
    }

    #[test]
    fn rtt_median_ignores_lost_samples() {
        let mut w = ProbeWindow::new(8);
        w.record(ProbeSample::Lost);
        w.record(ProbeSample::Rtt(50));
        w.record(ProbeSample::Lost);
        w.record(ProbeSample::Rtt(70));
        // 仅 50,70 → 中位数 60。
        assert_eq!(w.rtt_ms(), Some(60));
    }

    #[test]
    fn rtt_none_when_no_rtt_samples() {
        let mut w = ProbeWindow::new(4);
        w.record(ProbeSample::Lost);
        assert_eq!(w.rtt_ms(), None);
        assert!(ProbeWindow::new(4).rtt_ms().is_none());
    }

    #[test]
    fn loss_rate_counts_lost_over_total() {
        let mut w = ProbeWindow::new(5);
        w.record(ProbeSample::Rtt(10));
        w.record(ProbeSample::Lost);
        w.record(ProbeSample::Rtt(20));
        w.record(ProbeSample::Lost);
        assert_eq!(w.loss_rate(), 0.5);
        // 全丢。
        let mut all = ProbeWindow::new(2);
        all.record(ProbeSample::Lost);
        all.record(ProbeSample::Lost);
        assert_eq!(all.loss_rate(), 1.0);
        // 空窗口 → 0。
        assert_eq!(ProbeWindow::new(2).loss_rate(), 0.0);
    }

    #[test]
    fn jitter_is_mean_abs_diff_of_consecutive_rtts() {
        let mut w = ProbeWindow::new(8);
        for v in [10, 20, 25] {
            w.record(ProbeSample::Rtt(v));
        }
        // 相邻差 |10-20|=10, |20-25|=5 → 均值 7.5。
        assert_eq!(w.jitter_ms(), Some(7.5));
    }

    #[test]
    fn jitter_none_with_fewer_than_two_rtts() {
        let mut w = ProbeWindow::new(4);
        w.record(ProbeSample::Rtt(10));
        assert_eq!(w.jitter_ms(), None);
        w.record(ProbeSample::Lost);
        assert_eq!(w.jitter_ms(), None);
    }

    // -- ProbeTracker --------------------------------------------------------

    #[test]
    fn tracker_records_per_target_independently() {
        let mut t = ProbeTracker::new(4);
        let c1 = lan("192.168.1.50", 51821);
        let c2 = lan("192.168.1.60", 51821);
        t.record("dev-b", c1, ProbeSample::Rtt(11));
        t.record("dev-b", c2, ProbeSample::Lost);
        t.record("dev-b", c1, ProbeSample::Rtt(13));
        assert_eq!(t.len(), 2);
        assert_eq!(t.window("dev-b", c1).unwrap().rtt_ms(), Some(12));
        assert_eq!(t.window("dev-b", c2).unwrap().loss_rate(), 1.0);
        assert!(t.window("dev-x", c1).is_none());
    }

    #[test]
    fn retain_peers_drops_targets_of_removed_peers() {
        let mut t = ProbeTracker::new(4);
        let c1 = lan("192.168.1.50", 51821);
        let c2 = lan("192.168.1.60", 51821);
        t.record("dev-b", c1, ProbeSample::Rtt(11));
        t.record("dev-c", c2, ProbeSample::Rtt(12));
        // 只剩 dev-b：dev-c 的目标被回收。
        t.retain_peers(&[peer("dev-b", "10.240.0.3", &[c1])]);
        assert_eq!(t.len(), 1);
        assert!(t.window("dev-c", c2).is_none());
        assert!(t.window("dev-b", c1).is_some());
    }

    // -- probe_round ---------------------------------------------------------

    #[test]
    fn probe_round_records_rtt_and_lost_via_transport() {
        let mut t = ProbeTracker::new(4);
        let peers = vec![
            peer(
                "dev-b",
                "10.240.0.3",
                &[lan("192.168.1.50", 51821), lan("192.168.1.60", 51821)],
            ),
            peer("dev-c", "10.240.0.4", &[lan("10.0.0.7", 51821)]),
        ];
        // 传输：.50 可达（7ms），.60 与 10.0.0.7 超时。
        let round = probe_round(&mut t, &peers, |ip| match ip.octets()[3] {
            50 => Some(7),
            _ => None,
        });
        assert_eq!(round.issued, 3);
        assert_eq!(round.lost, 2);
        assert_eq!(
            t.window("dev-b", lan("192.168.1.50", 51821))
                .unwrap()
                .rtt_ms(),
            Some(7)
        );
        assert_eq!(
            t.window("dev-b", lan("192.168.1.60", 51821))
                .unwrap()
                .loss_rate(),
            1.0
        );
        assert_eq!(
            t.window("dev-c", lan("10.0.0.7", 51821))
                .unwrap()
                .loss_rate(),
            1.0
        );
    }

    #[test]
    fn probe_round_retains_only_live_peers() {
        let mut t = ProbeTracker::new(4);
        let c1 = lan("192.168.1.50", 51821);
        let c2 = lan("192.168.1.60", 51821);
        let first = vec![peer("dev-b", "10.240.0.3", &[c1, c2])];
        probe_round(&mut t, &first, |_| Some(5));
        assert_eq!(t.len(), 2);
        // 第二轮 dev-b 只剩 c1：c2 的目标被回收。
        let second = vec![peer("dev-b", "10.240.0.3", &[c1])];
        probe_round(&mut t, &second, |_| Some(6));
        assert_eq!(t.len(), 1);
        assert!(t.window("dev-b", c2).is_none());
        assert_eq!(t.window("dev-b", c1).unwrap().rtt_ms(), Some(5));
    }

    /// 窗口必须记在 `public_key` 下（生产里 device_id ≠ public_key 是常态）：
    /// 劣化映射 / 迟滞闸 / 候选详情全部按公钥查窗口（2026-11-13 SEL-002
    /// 真死复验实锤 device_id 记键使三路消费全部失配、生产全盲）。
    #[test]
    fn probe_round_keys_windows_by_public_key() {
        let mut t = ProbeTracker::new(4);
        let c1 = lan("192.168.1.50", 51821);
        let mut p = peer("dev-reg-5", "10.240.0.3", &[c1]);
        p.public_key = "JMrE4SZy-pub".into();
        probe_round(&mut t, &[p], |_| Some(9));
        assert!(t.window("JMrE4SZy-pub", c1).is_some());
        assert!(t.window("dev-reg-5", c1).is_none());
    }

    // -- score ----------------------------------------------------------------

    #[test]
    fn score_uses_rtt_with_loss_penalty_and_penalizes_full_loss() {
        // 无丢包：score = rtt。
        let mut w = ProbeWindow::new(4);
        w.record(ProbeSample::Rtt(100));
        assert_eq!(score(&w), Some(100.0));
        // 50% 丢包：score = 100 * (1 + 10*0.5) = 600。
        let mut half = ProbeWindow::new(4);
        half.record(ProbeSample::Rtt(100));
        half.record(ProbeSample::Lost);
        assert_eq!(score(&half), Some(600.0));
        // 全丢：无 RTT 样本 → +∞（最差）。
        let mut all = ProbeWindow::new(4);
        all.record(ProbeSample::Lost);
        assert_eq!(score(&all), Some(f64::INFINITY));
        // 空窗口 → None（尚无读数）。
        assert_eq!(score(&ProbeWindow::new(4)), None);
    }

    // -- SwitchGate -----------------------------------------------------------

    #[test]
    fn switch_gate_switches_after_required_consecutive_better_samples() {
        let c1 = lan("192.168.1.50", 51821);
        let c2 = lan("192.168.1.60", 51821);
        let mut gate = SwitchGate::new(3, 0.30);
        let mut windows: BTreeMap<ProbeTarget, ProbeWindow> = BTreeMap::new();

        // 前 2 轮：c2 得分 60 vs c1 得分 100，已满足 ≥30% 但未连续满 3 轮。
        for _ in 0..2 {
            windows.clear();
            let mut w1 = ProbeWindow::new(8);
            w1.record(ProbeSample::Rtt(100));
            let mut w2 = ProbeWindow::new(8);
            w2.record(ProbeSample::Rtt(60));
            windows.insert(("dev-b".into(), c1), w1);
            windows.insert(("dev-b".into(), c2), w2);
            assert!(gate.evaluate("dev-b", Some(c1), &windows).is_none());
        }
        // 第 3 轮：连续 3 轮 → 切换。
        windows.clear();
        let mut w1 = ProbeWindow::new(8);
        w1.record(ProbeSample::Rtt(100));
        let mut w2 = ProbeWindow::new(8);
        w2.record(ProbeSample::Rtt(60));
        windows.insert(("dev-b".into(), c1), w1);
        windows.insert(("dev-b".into(), c2), w2);
        let decision = gate.evaluate("dev-b", Some(c1), &windows).expect("switch");
        assert_eq!(decision.to, c2);
        assert!(decision.reason.contains("3 consecutive"));
    }

    #[test]
    fn switch_gate_jitter_does_not_flip() {
        // 抖动场景：c1 与 c2 得分交替领先、差距不足 30% → 永不切换。
        let c1 = lan("192.168.1.50", 51821);
        let c2 = lan("192.168.1.60", 51821);
        let mut gate = SwitchGate::new(3, 0.30);
        for round in 0..20u64 {
            let mut windows: BTreeMap<ProbeTarget, ProbeWindow> = BTreeMap::new();
            // 交替领先但差距仅 10%（不足 30% 迟滞）。
            let (a, b) = if round % 2 == 0 { (100, 90) } else { (90, 100) };
            let mut w1 = ProbeWindow::new(8);
            w1.record(ProbeSample::Rtt(a));
            let mut w2 = ProbeWindow::new(8);
            w2.record(ProbeSample::Rtt(b));
            windows.insert(("dev-b".into(), c1), w1);
            windows.insert(("dev-b".into(), c2), w2);
            assert!(
                gate.evaluate("dev-b", Some(c1), &windows).is_none(),
                "jitter must not flip the path (round {round})"
            );
        }
    }

    #[test]
    fn switch_gate_resets_streak_when_current_is_best_again() {
        let c1 = lan("192.168.1.50", 51821);
        let c2 = lan("192.168.1.60", 51821);
        let mut gate = SwitchGate::new(3, 0.30);
        let mut windows: BTreeMap<ProbeTarget, ProbeWindow> = BTreeMap::new();

        // 2 轮 c2 更好（连续计数=2）。
        for _ in 0..2 {
            windows.clear();
            let mut w1 = ProbeWindow::new(8);
            w1.record(ProbeSample::Rtt(100));
            let mut w2 = ProbeWindow::new(8);
            w2.record(ProbeSample::Rtt(60));
            windows.insert(("dev-b".into(), c1), w1);
            windows.insert(("dev-b".into(), c2), w2);
            assert!(gate.evaluate("dev-b", Some(c1), &windows).is_none());
        }
        // 第 3 轮：c1 回到最佳 → 计数清零，不切换。
        windows.clear();
        let mut w1 = ProbeWindow::new(8);
        w1.record(ProbeSample::Rtt(50));
        let mut w2 = ProbeWindow::new(8);
        w2.record(ProbeSample::Rtt(100));
        windows.insert(("dev-b".into(), c1), w1);
        windows.insert(("dev-b".into(), c2), w2);
        assert!(gate.evaluate("dev-b", Some(c1), &windows).is_none());
        // 再 3 轮 c2 更好：计数从 0 重新开始 → 需满 3 轮。
        for _ in 0..2 {
            windows.clear();
            let mut w1 = ProbeWindow::new(8);
            w1.record(ProbeSample::Rtt(100));
            let mut w2 = ProbeWindow::new(8);
            w2.record(ProbeSample::Rtt(60));
            windows.insert(("dev-b".into(), c1), w1);
            windows.insert(("dev-b".into(), c2), w2);
            assert!(gate.evaluate("dev-b", Some(c1), &windows).is_none());
        }
        windows.clear();
        let mut w1 = ProbeWindow::new(8);
        w1.record(ProbeSample::Rtt(100));
        let mut w2 = ProbeWindow::new(8);
        w2.record(ProbeSample::Rtt(60));
        windows.insert(("dev-b".into(), c1), w1);
        windows.insert(("dev-b".into(), c2), w2);
        assert!(gate.evaluate("dev-b", Some(c1), &windows).is_some());
    }

    #[test]
    fn switch_gate_requires_strict_margin_improvement() {
        // 差距 20%（<30%）：即使连续多轮也不切换。
        let c1 = lan("192.168.1.50", 51821);
        let c2 = lan("192.168.1.60", 51821);
        let mut gate = SwitchGate::new(3, 0.30);
        for _ in 0..5 {
            let mut windows: BTreeMap<ProbeTarget, ProbeWindow> = BTreeMap::new();
            let mut w1 = ProbeWindow::new(8);
            w1.record(ProbeSample::Rtt(100));
            let mut w2 = ProbeWindow::new(8);
            w2.record(ProbeSample::Rtt(80));
            windows.insert(("dev-b".into(), c1), w1);
            windows.insert(("dev-b".into(), c2), w2);
            assert!(gate.evaluate("dev-b", Some(c1), &windows).is_none());
        }
    }

    #[test]
    fn switch_gate_full_loss_makes_that_path_worst() {
        // 现路径全丢（score=+∞），新路径有 RTT → 一次即切换（required=1）。
        let c1 = lan("192.168.1.50", 51821);
        let c2 = lan("192.168.1.60", 51821);
        let mut gate = SwitchGate::new(1, 0.30);
        let mut windows: BTreeMap<ProbeTarget, ProbeWindow> = BTreeMap::new();
        let mut w1 = ProbeWindow::new(8);
        w1.record(ProbeSample::Lost);
        let mut w2 = ProbeWindow::new(8);
        w2.record(ProbeSample::Rtt(40));
        windows.insert(("dev-b".into(), c1), w1);
        windows.insert(("dev-b".into(), c2), w2);
        let decision = gate.evaluate("dev-b", Some(c1), &windows).expect("switch");
        assert_eq!(decision.to, c2);
    }

    // -- SEL-003: is_degraded / RecoveryGate ----------------------------------

    #[test]
    fn degraded_detects_loss_spike_and_timeout() {
        const DEGRADE_RTT_MS: u64 = 800;
        // 丢包尖峰（≥50% 丢包）→ 劣化。
        let mut w = ProbeWindow::new(4);
        w.record(ProbeSample::Rtt(10));
        w.record(ProbeSample::Rtt(10));
        w.record(ProbeSample::Lost);
        w.record(ProbeSample::Lost);
        assert!(is_degraded(&w, DEGRADE_RTT_MS), "50% loss is a spike");
        // 最近一次超时（丢包 <50% 但末次 Lost）→ 劣化。
        let mut t = ProbeWindow::new(4);
        t.record(ProbeSample::Rtt(10));
        t.record(ProbeSample::Rtt(10));
        t.record(ProbeSample::Rtt(10));
        t.record(ProbeSample::Lost);
        assert!(is_degraded(&t, DEGRADE_RTT_MS), "latest timeout degrades");
        // 健康：全 RTT、丢包率低、末次 Rtt → 不劣化。
        let mut ok = ProbeWindow::new(4);
        ok.record(ProbeSample::Rtt(10));
        ok.record(ProbeSample::Rtt(12));
        assert!(!is_degraded(&ok, DEGRADE_RTT_MS));
        // 空窗口（尚无读数）→ 不武断回中继。
        assert!(!is_degraded(&ProbeWindow::new(4), DEGRADE_RTT_MS));
    }

    /// 无基线豁免（2026-11-13 真死复验实锤）：openclaw-win / windows-desktop
    /// 防火墙拦 ICMP，候选窗口全程 Lost，但 WG 隧道健康（握手持续续期）——
    /// 全程 Lost 无「由好变坏」的证据，不判劣化；真死由握手年龄 classify 兜底。
    #[test]
    fn degraded_without_rtt_baseline_stays_healthy() {
        const DEGRADE_RTT_MS: u64 = 800;
        let mut w = ProbeWindow::new(8);
        for _ in 0..8 {
            w.record(ProbeSample::Lost);
        }
        assert!(
            !is_degraded(&w, DEGRADE_RTT_MS),
            "never-answered path has no baseline; handshake classify owns true death"
        );
    }

    /// 时延维度（2026-11-13 残余跟进）：探测全程成功但 RTT 持续深劣化
    /// （真机实录 1715ms `probe_ok` 钉直连）也必须判劣化。中位数判定等价
    /// 「连续 N 拍超阈值」——少数尖峰拉不动中位数（防抖）。
    #[test]
    fn degraded_when_median_rtt_is_sustained_over_threshold() {
        const DEGRADE_RTT_MS: u64 = 800;
        // 持续深劣化：全样本 ≥ 阈值 → 中位数 900/1715 命中。
        let mut bad = ProbeWindow::new(8);
        for v in [900, 1715, 950, 880] {
            bad.record(ProbeSample::Rtt(v));
        }
        assert!(
            is_degraded(&bad, DEGRADE_RTT_MS),
            "sustained 900ms degrades"
        );
        // 边界：中位数恰等于阈值 → 命中（≥ 语义，与丢包尖峰一致）。
        let mut edge = ProbeWindow::new(4);
        edge.record(ProbeSample::Rtt(800));
        edge.record(ProbeSample::Rtt(800));
        assert!(
            is_degraded(&edge, DEGRADE_RTT_MS),
            "median == threshold hits"
        );
        // 少数尖峰拉不动中位数：8 拍里 2 拍 1500ms，中位数仍 ~10ms → 不劣化。
        let mut spiky = ProbeWindow::new(8);
        for _ in 0..6 {
            spiky.record(ProbeSample::Rtt(10));
        }
        spiky.record(ProbeSample::Rtt(1500));
        spiky.record(ProbeSample::Rtt(1500));
        assert!(
            !is_degraded(&spiky, DEGRADE_RTT_MS),
            "minority spikes must not degrade"
        );
        // 多数拍超阈值：[10,900,900,1500] → 中位数 900 ≥ 800 → 持续劣化命中。
        let mut half = ProbeWindow::new(4);
        half.record(ProbeSample::Rtt(10));
        half.record(ProbeSample::Rtt(900));
        half.record(ProbeSample::Rtt(900));
        half.record(ProbeSample::Rtt(1500));
        assert!(
            is_degraded(&half, DEGRADE_RTT_MS),
            "majority sustained degrades"
        );
    }

    #[test]
    fn recovery_gate_requires_consecutive_healthy_rounds() {
        let mut gate = RecoveryGate::new(3);
        // 不健康 → 计数清零，永不 ready。
        assert!(!gate.record("peer-a", false));
        assert!(!gate.is_ready("peer-a"));
        // 连续 3 轮健康 → 第 3 轮 ready。
        assert!(!gate.record("peer-a", true));
        assert!(!gate.record("peer-a", true));
        assert!(gate.record("peer-a", true));
        assert!(gate.is_ready("peer-a"));
        // 一轮不健康 → 计数清零，不再 ready。
        assert!(!gate.record("peer-a", false));
        assert!(!gate.is_ready("peer-a"));
        // 再 2 轮健康仍未满 3。
        assert!(!gate.record("peer-a", true));
        assert!(!gate.record("peer-a", true));
        assert!(!gate.is_ready("peer-a"));
    }

    #[test]
    fn recovery_gate_retains_only_live_peers() {
        let mut gate = RecoveryGate::new(2);
        gate.record("peer-a", true);
        gate.record("peer-b", true);
        gate.record("peer-a", true);
        gate.record("peer-b", true);
        assert!(gate.is_ready("peer-a"));
        assert!(gate.is_ready("peer-b"));
        gate.retain(&["peer-a".to_string()]);
        assert!(gate.is_ready("peer-a"));
        assert!(
            !gate.is_ready("peer-b"),
            "removed peer's streak is reclaimed"
        );
    }
}
