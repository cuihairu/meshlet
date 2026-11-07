//! receipts

use meshlet_network::DevicePlan;

use crate::server;

pub(super) struct PendingReceipt {
    pub(super) plan: meshlet_network::DevicePlan,
    pub(super) error: Option<String>,
}

impl super::Agent {
    pub(super) fn flush_pending_receipts(&mut self) {
        while let Some(receipt) = self.pending_receipts.pop_front() {
            let error = receipt.error.as_deref();
            if let Err(error) =
                server::report_apply(&self.server_url, &self.token, &receipt.plan, error)
            {
                self.pending_receipts.push_front(receipt);
                tracing::warn!(%error, "device apply receipt retry not delivered");
                break;
            }
        }
    }

    pub(super) fn enqueue_receipt(&mut self, plan: DevicePlan, error: Option<String>) {
        if self.pending_receipts.len() == 16 {
            self.pending_receipts.pop_front();
        }
        self.pending_receipts
            .push_back(PendingReceipt { plan, error });
    }
}
