//! Publish runtime and reconciliation.

use meshlet_publish::{ProbeReport, PublishPlan, Publisher};

use crate::server;

/// 发布运行时（R-06）：一个单 worker 的 tokio runtime 承载
/// [`meshlet_publish::Publisher`] 的监听任务与探针排程；`unreported` 是尚未
/// 送达控制面的探针结果（上报失败保留，下一轮重试）。
///
/// 运行层只由服务端计划驱动（§16.4：不下发命令），失败只记日志——发布问题
/// 绝不打断隧道/路由/NAT 的数据面循环。
pub(super) struct PublishRuntime {
    /// 发布层专用运行时（Agent 主循环是同步线程，没有环境运行时可用）；
    /// 用 `Option` 持有是为了在 `Drop` 里取走它、放到独立线程关闭。
    runtime: Option<tokio::runtime::Runtime>,
    publisher: Publisher,
    unreported: Vec<ProbeReport>,
}

/// 单批上报上限（与控制面 `PublishHealthRequest` 的批上限一致）。
pub(super) const PUBLISH_REPORT_BATCH: usize = 256;

impl PublishRuntime {
    pub(super) fn new() -> Self {
        Self {
            runtime: Some(
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .thread_name("meshlet-publish")
                    .enable_all()
                    .build()
                    .expect("spawn the publish runtime thread"),
            ),
            publisher: Publisher::new(),
            unreported: Vec::new(),
        }
    }

    /// 是否没有任何监听或探针在跑（决定能否跳过 tokio 调用）。
    pub(super) fn is_idle(&self) -> bool {
        self.publisher.is_idle()
    }
}

impl Drop for PublishRuntime {
    fn drop(&mut self) {
        // tokio 不允许在异步上下文里 drop Runtime（关闭时要 block_on）。Agent
        // 主循环是同步线程，但测试/嵌入方可能在 async 上下文里构造并丢弃
        // Agent——把 Runtime 挪到独立线程关闭，任何调用方都不会踩这个坑。
        let Some(runtime) = self.runtime.take() else {
            return;
        };
        let _ = std::thread::Builder::new()
            .name("meshlet-publish-shutdown".into())
            .spawn(move || drop(runtime))
            .map(|handle| {
                let _ = handle.join();
            });
    }
}
impl super::Agent {
    /// 发布段对账（R-06）：把本机监听与探针排程对齐到计划里属于本设备的期望
    /// 发布态。`None`（待审批、无计划）= 全部停用。
    pub(super) fn apply_publish(&mut self, plan: Option<&PublishPlan>) {
        let wanted_empty = plan.map(|plan| plan.is_empty()).unwrap_or(true);
        if wanted_empty && self.publish.is_idle() {
            // 无发布对象且无监听：不起 tokio 任务，保持冷路径零开销。
            return;
        }
        let PublishRuntime {
            runtime,
            publisher,
            unreported: _,
        } = &mut self.publish;
        let events = match runtime
            .as_mut()
            .expect("the publish runtime is alive")
            .block_on(publisher.reconcile(plan))
        {
            Ok(events) => events,
            Err(e) => {
                // 计划自相矛盾：拒绝部分生效，保留现有监听，下一轮重试。
                tracing::warn!(error = %e, "publish plan rejected; keeping current listeners");
                return;
            }
        };
        if !events.is_empty() {
            tracing::info!(
                started = events.started,
                stopped = events.stopped,
                failed = ?events.failed,
                "reconciled the publish plan"
            );
        }
    }

    /// 探针结果上报（R-06）：回收本轮结果并入未送达队列，失败保留重试。
    /// 证据不是配置：上报失败只影响健康可见性，不影响发布监听。
    pub(super) fn report_publish_health(&mut self) {
        let fresh = self.publish.publisher.drain_reports();
        self.publish.unreported.extend(fresh);
        if self.publish.unreported.is_empty() {
            return;
        }
        // 批上限对齐控制面；超出丢弃最旧的（探针会按周期重排，不会永久丢失）。
        let excess = self
            .publish
            .unreported
            .len()
            .saturating_sub(PUBLISH_REPORT_BATCH);
        if excess > 0 {
            self.publish.unreported.drain(..excess);
        }
        if let Err(e) =
            server::report_publish_health(&self.server_url, &self.token, &self.publish.unreported)
        {
            tracing::warn!(
                error = %e,
                count = self.publish.unreported.len(),
                "publish health not delivered"
            );
        } else {
            self.publish.unreported.clear();
        }
    }
}
