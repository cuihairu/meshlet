//! Periodic agent self-update checks.

use std::time::{Duration, Instant};

use crate::self_update;

impl super::Agent {
    pub(super) fn maybe_self_update(&mut self) {
        if !self.upgrade.enabled {
            return;
        }
        let due = self
            .last_update_check
            .map(|last| last.elapsed() >= Duration::from_secs(self.upgrade.check_interval_secs))
            .unwrap_or_default();
        if !due {
            return;
        }
        self.last_update_check = Some(Instant::now());
        let Ok(manifest) = self_update::fetch_manifest(&self.server_url) else {
            return;
        };
        let Ok(self_update::UpdateCheck::Available(plan)) =
            self_update::plan_update(env!("CARGO_PKG_VERSION"), manifest)
        else {
            return;
        };
        let installed = self_update::install(&plan).and_then(|result| {
            self_update::request_restart(&self.state_dir, &result).map(|_| result)
        });
        if let Ok(result) = installed {
            tracing::info!(
                from_version = %result.from_version,
                to_version = %result.to_version,
                "agent update installed; restart requested"
            );
        }
    }
}
