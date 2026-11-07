//! Best-effort SSH configuration sync.

use meshlet_network::DevicePlan;

impl super::Agent {
    pub(super) fn apply_ssh_sync(&mut self, plan: &DevicePlan) {
        let config = self.ssh_config_sync;
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("."));
        let fallback = crate::ssh_sync::self_host(
            self.device_name.as_deref().unwrap_or("meshlet-node"),
            plan.tunnel.address,
        );
        let hosts = plan
            .ssh_config
            .as_ref()
            .map(crate::ssh_sync::hosts_from_plan);
        let status = crate::ssh_sync::sync(
            &home,
            hosts.as_deref(),
            &fallback,
            config.enabled,
            config.manage_include,
            &self.ssh_sync_status_path,
        );
        if let Some(error) = &status.last_error {
            tracing::warn!(error = %error, "ssh config sync failed");
        }
    }
}
