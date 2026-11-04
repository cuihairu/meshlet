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
use meshlet_domain::PeerEndpoints;
use meshlet_network::probe::{
    default_transport, probe_round, ProbeTarget, ProbeTracker, ProbeWindow,
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
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl ProbeRuntime {
    /// 起探测线程；`enabled = false` 时为冷启动（无线程、零开销；缓存与
    /// 快照接口照常可用）。
    pub fn start(config: &ProbeConfig) -> Self {
        let cache = Arc::new(Mutex::new(Vec::new()));
        let tracker = Arc::new(Mutex::new(ProbeTracker::new(config.window)));
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
