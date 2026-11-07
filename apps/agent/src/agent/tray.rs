//! Data-plane status presentation.
use crate::tray::{TrayState, TrayStatus};

use crate::desktop::{desktop_trigger, DesktopPublish, DesktopTrigger};

impl super::Agent {
    pub fn publish_tray(&self, state: TrayState, virtual_ip: Option<std::net::Ipv4Addr>) {
        let status = TrayStatus::new(
            state,
            self.device_name.as_deref(),
            virtual_ip,
            &self.dataplane.interface,
        );
        if let Err(e) = self.tray.publish(&status) {
            tracing::warn!(
                error = %e,
                state = state.accessible_name(),
                "tray status not published"
            );
        }

        let trigger = desktop_trigger(*self.last_desktop_state.borrow(), state);
        if trigger != DesktopTrigger::Unchanged {
            let env = crate::tray::EnvProbe::from_env();
            let result = self.desktop.borrow_mut().publish(
                &status,
                &env,
                trigger == DesktopTrigger::Changed && self.desktop_config.notifications,
                self.desktop_config.status_notifier_item,
            );
            *self.last_desktop_state.borrow_mut() = Some(state);
            if !matches!(result, DesktopPublish::Published) {
                tracing::debug!(result = ?result, "desktop status not shown");
            }
        }
    }
}
