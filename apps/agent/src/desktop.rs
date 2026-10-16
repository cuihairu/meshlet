//! Desktop integration contracts for tray status publishing.
//!
//! Pure data in this module is testable on every platform; Linux-only D-Bus I/O lives
//! in `dbus.rs` and degrades silently when no session bus or watcher is available.

use crate::tray::{IconSize, TrayState, TrayStatus};

/// The result of trying to expose/publish desktop state. File publication remains
/// independent so a missing desktop never removes the status contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopPublish {
    Disabled,
    Headless,
    NoBus,
    NoWatcher,
    Published,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopTrigger {
    Initial,
    Unchanged,
    Changed,
}

pub fn desktop_trigger(previous: Option<TrayState>, current: TrayState) -> DesktopTrigger {
    match previous {
        None => DesktopTrigger::Initial,
        Some(previous) if previous == current => DesktopTrigger::Unchanged,
        Some(_) => DesktopTrigger::Changed,
    }
}

/// Arguments to `org.freedesktop.Notifications.Notify`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyCall {
    pub app_name: &'static str,
    pub replaces_id: u32,
    pub app_icon: &'static str,
    pub summary: &'static str,
    pub body: String,
    pub actions: Vec<&'static str>,
    pub expire_timeout_ms: i32,
    pub desktop_entry: Option<&'static str>,
}

pub const NOTIFICATION_ID: u32 = 0;

pub fn notify_call(status: &TrayStatus) -> NotifyCall {
    NotifyCall {
        app_name: "Meshlet",
        replaces_id: NOTIFICATION_ID,
        app_icon: "meshlet-status",
        summary: status.state.accessible_name(),
        body: status.tooltip.clone(),
        actions: Vec::new(),
        expire_timeout_ms: 5_000,
        desktop_entry: Some("meshlet-agent"),
    }
}

/// Properties exposed by `org.kde.StatusNotifierItem`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusNotifierProperties {
    pub category: &'static str,
    pub id: String,
    pub title: String,
    pub status: &'static str,
    pub icon_name: &'static str,
    pub icon_pixmap: Vec<IconPixmap>,
    pub tooltip: String,
}

/// ARGB32 pixmap in network byte order. Width/height and bytes are kept separate so
/// the D-Bus adapter can serialize exactly `(iiay)` without hidden conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IconPixmap {
    pub width: i32,
    pub height: i32,
    pub argb: Vec<u8>,
}

pub const STATUS_NOTIFIER_CATEGORY: &str = "Communications";
pub const STATUS_NOTIFIER_ID: &str = "meshlet-agent";

pub fn status_notifier_properties(
    status: &TrayStatus,
    pixmaps: impl IntoIterator<Item = IconSize>,
) -> StatusNotifierProperties {
    let icon_pixmap = pixmaps
        .into_iter()
        .map(|size| {
            let (width, height, rgba) = status.state.icon_rgba(size);
            IconPixmap {
                width: width as i32,
                height: height as i32,
                argb: rgba_to_argb(&rgba),
            }
        })
        .collect();
    StatusNotifierProperties {
        category: STATUS_NOTIFIER_CATEGORY,
        id: STATUS_NOTIFIER_ID.to_owned(),
        title: "Meshlet".to_owned(),
        status: "Active",
        icon_name: "meshlet-status",
        icon_pixmap,
        tooltip: status.tooltip.clone(),
    }
}

pub fn rgba_to_argb(rgba: &[u8]) -> Vec<u8> {
    rgba.as_chunks::<4>()
        .0
        .iter()
        .flat_map(|pixel| [pixel[3], pixel[0], pixel[1], pixel[2]])
        .collect()
}

/// Interface/property/member names checked by tests; typos here fail registration.
pub mod names {
    pub const NOTIFICATIONS_INTERFACE: &str = "org.freedesktop.Notifications";
    pub const NOTIFY_METHOD: &str = "Notify";
    pub const STATUS_NOTIFIER_WATCHER: &str = "org.kde.StatusNotifierWatcher";
    pub const REGISTER_METHOD: &str = "RegisterStatusNotifierItem";
    pub const STATUS_NOTIFIER_ITEM: &str = "org.kde.StatusNotifierItem";
    pub const NOTIFICATION_CLOSED_REASON: i32 = 2;
}

pub fn desktop_result(
    enabled: bool,
    has_desktop: bool,
    bus_available: bool,
    watcher_available: bool,
) -> DesktopPublish {
    match (enabled, has_desktop, bus_available, watcher_available) {
        (false, _, _, _) => DesktopPublish::Disabled,
        (true, false, _, _) => DesktopPublish::Headless,
        (true, true, false, _) => DesktopPublish::NoBus,
        (true, true, true, false) => DesktopPublish::NoWatcher,
        (true, true, true, true) => DesktopPublish::Published,
    }
}

#[allow(dead_code)]
fn tray_state_is_shared(state: TrayState) -> TrayState {
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_call_reuses_shared_tray_copy() {
        let status = TrayStatus::new(TrayState::TunnelDrift, Some("laptop"), "mesh0");
        let call = notify_call(&status);
        assert_eq!(call.app_name, "Meshlet");
        assert_eq!(call.summary, "Meshlet tunnel drift");
        assert_eq!(call.body, status.tooltip);
        assert_eq!(call.expire_timeout_ms, 5_000);
        assert_eq!(call.desktop_entry, Some("meshlet-agent"));
    }

    #[test]
    fn status_notifier_properties_expose_both_shared_pixmaps() {
        let status = TrayStatus::new(TrayState::Offline, None, "mesh0");
        let properties = status_notifier_properties(&status, [IconSize::Px16, IconSize::Px24]);
        assert_eq!(properties.category, "Communications");
        assert_eq!(properties.id, "meshlet-agent");
        assert_eq!(properties.status, "Active");
        assert_eq!(properties.tooltip, status.tooltip);
        assert_eq!(properties.icon_pixmap.len(), 2);
        assert_eq!(properties.icon_pixmap[0].width, 16);
        assert_eq!(properties.icon_pixmap[0].argb.len(), 16 * 16 * 4);
        assert_eq!(properties.icon_pixmap[1].width, 24);
        assert_eq!(properties.icon_pixmap[1].argb.len(), 24 * 24 * 4);
    }

    #[test]
    fn rgba_pixels_convert_to_network_order_argb32() {
        assert_eq!(rgba_to_argb(&[1, 2, 3, 4]), vec![4, 1, 2, 3]);
    }

    #[test]
    fn desktop_results_preserve_safe_degradation_order() {
        assert_eq!(
            desktop_result(false, true, true, true),
            DesktopPublish::Disabled
        );
        assert_eq!(
            desktop_result(true, false, true, true),
            DesktopPublish::Headless
        );
        assert_eq!(
            desktop_result(true, true, false, true),
            DesktopPublish::NoBus
        );
        assert_eq!(
            desktop_result(true, true, true, false),
            DesktopPublish::NoWatcher
        );
        assert_eq!(
            desktop_result(true, true, true, true),
            DesktopPublish::Published
        );
    }

    #[test]
    fn dbus_names_use_registered_specifications() {
        assert_eq!(
            names::NOTIFICATIONS_INTERFACE,
            "org.freedesktop.Notifications"
        );
        assert_eq!(names::NOTIFY_METHOD, "Notify");
        assert_eq!(
            names::STATUS_NOTIFIER_WATCHER,
            "org.kde.StatusNotifierWatcher"
        );
        assert_eq!(names::REGISTER_METHOD, "RegisterStatusNotifierItem");
        assert_eq!(names::STATUS_NOTIFIER_ITEM, "org.kde.StatusNotifierItem");
    }

    #[test]
    fn desktop_trigger_distinguishes_initial_unchanged_and_changed() {
        assert_eq!(
            desktop_trigger(None, TrayState::Online),
            DesktopTrigger::Initial
        );
        assert_eq!(
            desktop_trigger(Some(TrayState::Online), TrayState::Online),
            DesktopTrigger::Unchanged
        );
        assert_eq!(
            desktop_trigger(Some(TrayState::Online), TrayState::Offline),
            DesktopTrigger::Changed
        );
    }
}
