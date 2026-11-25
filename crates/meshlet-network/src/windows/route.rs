use super::backend::WindowsNetworkBackend;
use crate::windows_console::NoWindowCommand;
use crate::{ApplyResult, NetworkError, RouteConfig};

impl WindowsNetworkBackend {
    pub fn remove_stale_meshlet_routes_sync(
        &self,
        _routes: &[RouteConfig],
    ) -> Result<ApplyResult, NetworkError> {
        Ok(ApplyResult::ok())
    }

    pub fn mtu_probe_sync(&self, target: std::net::Ipv4Addr, payload: u32) -> bool {
        std::process::Command::new("ping")
            .args([
                "-n",
                "1",
                "-f",
                "-l",
                &payload.to_string(),
                &target.to_string(),
            ])
            .no_window()
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    }

    /// Windows has no underlay-MTU reading implementation yet: `None` means
    /// "reading unavailable" and the probe falls back to the default 1392
    /// (lane/dataplane-speed telemetry is Linux-only; on Windows verify by
    /// hand with the documented `New-NetIPInterface`/`netsh`, see
    /// docs/guide/performance.md).
    pub fn underlay_path_mtu_sync(&self) -> Option<u32> {
        None
    }
}
