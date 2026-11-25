//! Desktop session probing (injectable, so tests need not touch process environment
//! variables). The data source for headless / CI detection ("discipline four"):
//! [`EnvProbe::from_env`] reads environment variables and the Windows console
//! session, and the write layer no-ops outright when [`EnvProbe::has_desktop_session`] is false.

/// Desktop session probe (injectable, so tests need not touch process environment variables).
#[derive(Debug, Clone, Default)]
pub struct EnvProbe {
    /// X11 display (`$DISPLAY`).
    pub display: Option<String>,
    /// Wayland display (`$WAYLAND_DISPLAY`).
    pub wayland_display: Option<String>,
    /// `$XDG_SESSION_TYPE` (`x11` / `wayland` / `tty` / ...).
    pub session_type: Option<String>,
    /// Windows `%SESSIONNAME%` (`Console` / `RDP-Tcp#N`): **this process** is inside
    /// an interactive session (a user-session agent, the `install.ps1` HKCU Run model). Linux has no such
    /// variable, so it is always `None`.
    pub session_name: Option<String>,
    /// Windows: an active console session exists on the machine (`WTSGetActiveConsoleSessionId`).
    /// This lets an agent running as SYSTEM/service still write tray status images for the
    /// logged-in user session (the tray host is a process in the logged-in user session, and status
    /// is handed over via files - see [`crate::tray::TraySink`]).
    pub console_session: bool,
}

impl EnvProbe {
    pub fn from_env() -> Self {
        Self {
            display: nonempty(var("DISPLAY")),
            wayland_display: nonempty(var("WAYLAND_DISPLAY")),
            session_type: nonempty(var("XDG_SESSION_TYPE")),
            session_name: nonempty(var("SESSIONNAME")),
            console_session: active_console_session(),
        }
    }

    /// Whether a desktop session is available to hang the tray on. `tty` / empty values mean headless (CI, headless VPS) -> false.
    pub fn has_desktop_session(&self) -> bool {
        self.display.is_some()
            || self.wayland_display.is_some()
            || matches!(
                self.session_type.as_deref(),
                Some("x11") | Some("wayland") | Some("gnome") | Some("plasma")
            )
            || self.session_name.is_some()
            || self.console_session
    }
}

/// Windows: `WTSGetActiveConsoleSessionId() != 0xFFFFFFFF` (an active console session exists).
/// Other platforms have no such concept, so this is always `false`.
fn active_console_session() -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;
        unsafe { WTSGetActiveConsoleSessionId() != 0xFFFF_FFFF }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn nonempty(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_type_alone_counts_as_a_desktop_session() {
        assert!(EnvProbe {
            session_type: Some("wayland".into()),
            ..EnvProbe::default()
        }
        .has_desktop_session());
        assert!(!EnvProbe {
            session_type: Some("tty".into()),
            ..EnvProbe::default()
        }
        .has_desktop_session());
    }

    /// Windows user-session agent (`install.ps1` HKCU Run): `%SESSIONNAME%`
    /// is set (`Console` / `RDP-Tcp#N`) and must count as having a desktop session - before this, only
    /// X11/Wayland variables were probed, so Windows was always headless, the agent never wrote tray PNGs,
    /// and the tray host always fell back to a GDI green block (acceptance item 7, 2026-10-31).
    #[test]
    fn windows_session_name_counts_as_a_desktop_session() {
        assert!(EnvProbe {
            session_name: Some("Console".into()),
            ..EnvProbe::default()
        }
        .has_desktop_session());
        assert!(EnvProbe {
            session_name: Some("RDP-Tcp#5".into()),
            ..EnvProbe::default()
        }
        .has_desktop_session());
    }

    /// Windows SYSTEM/service agent (a real-machine AtStartup scheduled task): the process itself has
    /// no `%SESSIONNAME%`, but an active console session exists on the machine (the user is logged in) ->
    /// tray status is still written, for the tray host in the logged-in user session to read. No active
    /// session (CI, headless) -> false.
    #[test]
    fn windows_console_session_alone_counts_as_a_desktop_session() {
        assert!(EnvProbe {
            console_session: true,
            ..EnvProbe::default()
        }
        .has_desktop_session());
        assert!(!EnvProbe::default().has_desktop_session());
    }
}
