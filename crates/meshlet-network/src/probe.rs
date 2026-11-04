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
//! 平台差异收敛在 [`default_transport`]：Linux 真实 ICMP 探测；非 Linux 返回
//! `None`（记为丢包）——Windows 数据面探测传输随其数据面接线后接入，SEL-001
//! 先以 Linux 为准验收。

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

/// 探测目标标识：对端设备 id + 候选端点。
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

    /// 记录一次探测到目标 `(device_id, candidate)`。
    pub fn record(&mut self, device_id: &str, candidate: EndpointCandidate, sample: ProbeSample) {
        self.windows
            .entry((device_id.to_string(), candidate))
            .or_insert_with(|| ProbeWindow::new(self.capacity))
            .record(sample);
    }

    /// 读目标当前窗口（无记录 → `None`）。
    pub fn window(&self, device_id: &str, candidate: EndpointCandidate) -> Option<&ProbeWindow> {
        self.windows.get(&(device_id.to_string(), candidate))
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
            .flat_map(|p| p.endpoints.iter().map(|c| (p.device_id.to_string(), *c)))
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
            tracker.record(&peer.device_id.to_string(), *candidate, sample);
            issued += 1;
        }
    }
    ProbeRound { issued, lost }
}

/// 平台默认探测传输：Linux 经 `ping -c 1 -W 1` 发 ICMP echo 实测 RTT（免特权
/// 的 `ping_group_range` 或 root 均可，与 [`crate::linux::run_ping_rtt`] 同源）。
///
/// 非 Linux（Windows 数据面探测传输未接线）返回 `None`——`probe_round` 记为
/// 丢包，绝不假装探测到 RTT。SEL-001 以 Linux 为准验收。
#[cfg(target_os = "linux")]
pub fn default_transport(ip: Ipv4Addr) -> Option<u128> {
    crate::linux::run_ping_rtt(ip)
}

/// 平台默认探测传输（非 Linux）：见上方 Linux 版别的文档。
#[cfg(not(target_os = "linux"))]
pub fn default_transport(_ip: Ipv4Addr) -> Option<u128> {
    None
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
}
