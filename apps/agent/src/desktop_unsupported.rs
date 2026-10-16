//! Non-Linux desktop placeholder pending the ADR-008 Windows dataplane backend.
//!
//! Shared tray state remains supported; desktop I/O is refused instead of pretending
//! that a D-Bus notification or StatusNotifierItem was published.

use crate::desktop::DesktopPublish;
use crate::tray::{EnvProbe, TrayStatus};

#[derive(Default)]
pub struct DesktopClient;

impl DesktopClient {
    pub fn publish(
        &mut self,
        _status: &TrayStatus,
        _env: &EnvProbe,
        notifications_enabled: bool,
        status_notifier_enabled: bool,
    ) -> DesktopPublish {
        if !notifications_enabled && !status_notifier_enabled {
            return DesktopPublish::Disabled;
        }
        DesktopPublish::Headless
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tray::TrayState;

    #[test]
    fn disabled_configuration_is_reported_without_desktop_io() {
        let mut client = DesktopClient;
        let status = TrayStatus::new(TrayState::Offline, None, "mesh0");

        assert_eq!(
            client.publish(&status, &EnvProbe::default(), false, false),
            DesktopPublish::Disabled
        );
    }

    #[test]
    fn enabled_configuration_reports_headless_not_published() {
        let mut client = DesktopClient;
        let status = TrayStatus::new(TrayState::Online, None, "mesh0");

        assert_eq!(
            client.publish(&status, &EnvProbe::default(), true, true),
            DesktopPublish::Headless
        );
    }
}
