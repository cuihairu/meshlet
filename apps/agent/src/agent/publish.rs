//! Publish runtime and reconciliation.

use meshlet_publish::{ProbeReport, PublishPlan, Publisher};

use crate::server;

/// Publish runtime (R-06): a single-worker tokio runtime carries
/// [`meshlet_publish::Publisher`]'s listener tasks and probe scheduling; `unreported` holds probe results not
/// yet delivered to the control plane (kept on report failure, retried next round).
///
/// The runtime layer is driven only by the server plan (§16.4: commands are never issued), and failures only log
/// - publish problems must never interrupt the tunnel/routing/NAT dataplane loop.
pub(super) struct PublishRuntime {
    /// Runtime dedicated to the publish layer (the agent main loop is a synchronous thread with no ambient runtime available);
    /// it is held in an `Option` so `Drop` can take it away and shut it down on a separate thread.
    runtime: Option<tokio::runtime::Runtime>,
    publisher: Publisher,
    unreported: Vec<ProbeReport>,
}

/// Per-batch report cap (matching the control plane's `PublishHealthRequest` batch limit).
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

    /// Whether no listener or probe is running (decides whether the tokio call can be skipped).
    pub(super) fn is_idle(&self) -> bool {
        self.publisher.is_idle()
    }
}

impl Drop for PublishRuntime {
    fn drop(&mut self) {
        // tokio forbids dropping a Runtime from inside an async context (shutdown needs block_on). The agent
        // main loop is a synchronous thread, but tests/embedders may construct and drop the Agent from an async
        // context - shut the Runtime down on a separate thread so no caller hits this pitfall.
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
    /// Publish section reconciliation (R-06): align local listeners and probe scheduling to the plan's
    /// expected publish state for this device. `None` (pending approval, no plan) = disable everything.
    pub(super) fn apply_publish(&mut self, plan: Option<&PublishPlan>) {
        let wanted_empty = plan.map(|plan| plan.is_empty()).unwrap_or(true);
        if wanted_empty && self.publish.is_idle() {
            // Nothing to publish and no listeners: spawn no tokio tasks, keeping the cold path free of overhead.
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
                // The plan is self-contradictory: refuse partial application, keep the existing listeners, and retry next round.
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

    /// Probe result reporting (R-06): collect this round's results into the undelivered queue, keeping failures for retry.
    /// Evidence is not configuration: a report failure only affects health visibility, never the publish listeners.
    pub(super) fn report_publish_health(&mut self) {
        let fresh = self.publish.publisher.drain_reports();
        self.publish.unreported.extend(fresh);
        if self.publish.unreported.is_empty() {
            return;
        }
        // The batch cap matches the control plane; beyond it the oldest entries are dropped (probes reschedule on a cycle, so nothing is lost permanently).
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
