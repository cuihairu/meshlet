//! Linux desktop D-Bus adapter. All failures are non-fatal: the agent loop must not
//! back off because a tray host or notification service is unavailable.

use zbus::{block_on, connection, zvariant};

use crate::desktop::{
    desktop_result, names, notify_call, status_notifier_properties, DesktopPublish, IconPixmap,
    NotifyCall, StatusNotifierProperties,
};
use crate::tray::{EnvProbe, IconSize, TrayStatus};

pub const STATUS_NOTIFIER_PATH: &str = "/org/meshlet/StatusNotifierItem";

#[derive(Default)]
pub struct DesktopClient {
    connection: Option<zbus::Connection>,
    status_notifier_registered: bool,
}

impl DesktopClient {
    #[cfg(target_os = "linux")]
    pub fn publish(
        &mut self,
        status: &TrayStatus,
        env: &EnvProbe,
        notifications_enabled: bool,
        status_notifier_enabled: bool,
    ) -> DesktopPublish {
        if !notifications_enabled && !status_notifier_enabled {
            return DesktopPublish::Disabled;
        }
        if !env.has_desktop_session() {
            return DesktopPublish::Headless;
        }
        if self.connection.is_none() {
            match block_on(async { connection::Builder::session()?.build().await }) {
                Ok(connection) => self.connection = Some(connection),
                Err(error) => {
                    tracing::debug!(error = %error, "desktop session bus unavailable");
                    return DesktopPublish::NoBus;
                }
            }
        }
        let Some(connection) = self.connection.clone() else {
            return DesktopPublish::NoBus;
        };
        if notifications_enabled {
            if let Err(error) = Self::notify(&connection, status) {
                tracing::debug!(error = %error, "desktop notification unavailable");
                return DesktopPublish::NoBus;
            }
        }
        if status_notifier_enabled {
            self.publish_status_notifier(&connection, status)
        } else {
            DesktopPublish::Published
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn publish(
        &mut self,
        _status: &TrayStatus,
        _env: &EnvProbe,
        _notifications_enabled: bool,
        _status_notifier_enabled: bool,
    ) -> DesktopPublish {
        if !notifications_enabled && !status_notifier_enabled {
            return DesktopPublish::Disabled;
        }
        DesktopPublish::Headless
    }

    #[cfg(target_os = "linux")]
    fn notify(connection: &zbus::Connection, status: &TrayStatus) -> zbus::Result<()> {
        let call = notify_call(status);
        block_on(async {
            connection
                .call_method(
                    Some(names::NOTIFICATIONS_INTERFACE),
                    "/org/freedesktop/Notifications",
                    Some(names::NOTIFICATIONS_INTERFACE),
                    names::NOTIFY_METHOD,
                    &(
                        call.app_name,
                        call.replaces_id,
                        call.app_icon,
                        call.summary,
                        call.body.clone(),
                        call.actions.clone(),
                        notify_hints(&call),
                        call.expire_timeout_ms,
                    ),
                )
                .await
                .map(|_| ())
        })
    }

    #[cfg(target_os = "linux")]
    fn publish_status_notifier(
        &mut self,
        connection: &zbus::Connection,
        status: &TrayStatus,
    ) -> DesktopPublish {
        let properties = status_notifier_properties(status, [IconSize::Px16, IconSize::Px24]);
        let is_first_registration = !self.status_notifier_registered;
        let registered = block_on(async {
            let object_server = connection.object_server();
            if is_first_registration {
                object_server
                    .at(STATUS_NOTIFIER_PATH, StatusNotifierItem::new(properties))
                    .await?;
                connection
                    .call_method(
                        Some(names::STATUS_NOTIFIER_WATCHER),
                        "/StatusNotifierWatcher",
                        Some(names::STATUS_NOTIFIER_WATCHER),
                        names::REGISTER_METHOD,
                        &(STATUS_NOTIFIER_PATH),
                    )
                    .await
                    .map(|_| ())
            } else {
                let interface_ref = object_server
                    .interface::<_, StatusNotifierItem>(STATUS_NOTIFIER_PATH)
                    .await?;
                let mut interface = interface_ref.get_mut().await;
                interface.properties = properties;
                interface
                    .icon_name_changed(interface_ref.signal_emitter())
                    .await?;
                interface
                    .icon_pixmap_changed(interface_ref.signal_emitter())
                    .await?;
                interface
                    .tool_tip_changed(interface_ref.signal_emitter())
                    .await?;
                Ok(())
            }
        });
        match registered {
            Ok(()) => {
                self.status_notifier_registered = true;
                DesktopPublish::Published
            }
            Err(error) => {
                tracing::debug!(error = %error, "status notifier watcher unavailable");
                DesktopPublish::NoWatcher
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub fn notify_hints(call: &NotifyCall) -> Vec<(&'static str, zvariant::Value<'_>)> {
    let mut hints = Vec::new();
    if let Some(desktop_entry) = call.desktop_entry {
        hints.push(("desktop-entry", zvariant::Value::new(desktop_entry)));
    }
    hints
}

struct StatusNotifierItem {
    properties: StatusNotifierProperties,
}

#[cfg(target_os = "linux")]
impl StatusNotifierItem {
    fn new(properties: StatusNotifierProperties) -> Self {
        Self { properties }
    }
}

#[cfg(target_os = "linux")]
#[zbus::interface(name = "org.kde.StatusNotifierItem")]
impl StatusNotifierItem {
    #[zbus(property)]
    fn category(&self) -> &str {
        self.properties.category
    }

    #[zbus(property)]
    fn id(&self) -> &str {
        &self.properties.id
    }

    #[zbus(property)]
    fn title(&self) -> &str {
        &self.properties.title
    }

    #[zbus(property)]
    fn status(&self) -> &str {
        self.properties.status
    }

    #[zbus(property)]
    fn icon_name(&self) -> &str {
        self.properties.icon_name
    }

    #[zbus(property)]
    fn icon_pixmap(&self) -> zbus::fdo::Result<Vec<DbusIconPixmap>> {
        self.properties
            .icon_pixmap
            .iter()
            .map(|pixmap| Ok(DbusIconPixmap::from(pixmap.clone())))
            .collect()
    }

    #[zbus(property)]
    #[zbus(name = "ToolTip")]
    fn tooltips(&self) -> Vec<DbusTooltip> {
        vec![DbusTooltip::new(
            self.properties.icon_name.to_owned(),
            self.properties.title.clone(),
            self.properties.tooltip.clone(),
        )]
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, serde::Serialize, zvariant::Type, zvariant::Value)]
struct DbusIconPixmap {
    width: i32,
    height: i32,
    argb: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl From<IconPixmap> for DbusIconPixmap {
    fn from(pixmap: IconPixmap) -> Self {
        Self {
            width: pixmap.width,
            height: pixmap.height,
            argb: pixmap.argb,
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, serde::Serialize, zvariant::Type)]
struct DbusTooltip(String, String, String, String);

impl From<DbusTooltip> for zvariant::Structure<'_> {
    fn from(tooltip: DbusTooltip) -> Self {
        Self::from((tooltip.0, tooltip.1, tooltip.2, tooltip.3))
    }
}

impl DbusTooltip {
    fn new(icon_name: String, title: String, description: String) -> Self {
        Self("meshlet".into(), icon_name, title, description)
    }
}

#[allow(dead_code)]
fn result_order_is_shared() -> DesktopPublish {
    desktop_result(true, true, true, true)
}
