use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

/// Starts the local panel service (bound to a random port on `127.0.0.1` only) and records the URL.
/// Failure is only logged: the rest of the tray keeps working, and the menu item then reports
/// "not started" — it never pretends to have opened successfully.
/// On success returns the panel URL (the URL handoff file has been written); on failure `None`.
#[cfg(windows)]
pub(crate) fn start_local_panel(state_dir: &std::path::Path) -> Option<String> {
    match meshlet_tray_host::panel::start(state_dir.to_path_buf()) {
        Ok(port) => {
            let url = meshlet_tray_host::panel::url(port);
            tracing::info!(%url, "local panel listening (loopback only)");
            // URL handoff file: while the process is alive the log is locked by the redirection
            // handle and unreadable (Windows), so CI / ops read this write-then-close file for the port.
            if let Err(error) = meshlet_tray_host::panel::write_url_file(state_dir, &url) {
                tracing::warn!(%error, "local panel url file not written");
            }
            set_panel_url(Some(url.clone()));
            Some(url)
        }
        Err(error) => {
            tracing::warn!(%error, "local panel failed to start");
            None
        }
    }
}

static PANEL_URL: std::sync::OnceLock<String> = std::sync::OnceLock::new();

pub(crate) fn set_panel_url(url: Option<String>) -> Option<&'static String> {
    if let Some(url) = url {
        let _ = PANEL_URL.set(url);
    }
    PANEL_URL.get()
}

pub(crate) fn panel_url_global() -> Option<&'static String> {
    PANEL_URL.get()
}

/// "Local panel": opens in a browser the tray-host's self-hosted loopback read-only page —
/// the three blocks current node / direct nodes / local routes, with data read only from the
/// local state files (it does not depend on the server being reachable).
pub(crate) fn open_local_panel(hwnd: HWND, panel_url: Option<&str>) {
    match panel_url {
        Some(url) => {
            // Leave a log trace: real-machine acceptance uses it to prove the "menu item -> local panel URL" chain.
            tracing::info!(%url, "opening local panel from tray menu");
            shell_open(hwnd, url);
        }
        None => tracing::warn!("local panel not running, cannot open it"),
    }
}

/// "Console (web)": opens `server_url` in the default browser (the console hosted at the server root path).
pub(crate) fn open_console(hwnd: HWND, state_dir: Option<&std::path::Path>) {
    let Some(state_dir) = state_dir else {
        tracing::warn!("state dir unknown, cannot open console");
        return;
    };
    let Some(url) = panel_url(state_dir) else {
        tracing::warn!("no console URL (server_url missing from agent.toml)");
        return;
    };
    shell_open(hwnd, &url);
}

/// Opens `url` in the system default browser (`ShellExecuteW`, verb=open).
pub(crate) fn shell_open(hwnd: HWND, url: &str) {
    let op: Vec<u16> = "open\0".encode_utf16().collect();
    let wide: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        ShellExecuteW(
            hwnd,
            op.as_ptr(),
            wide.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        );
    }
}

/// Console URL: the `server_url` from the agent config file (`{state_dir}/..`). The console is
/// hosted at the server root path (the `ServeDir` fallback in `router_with_console`), so `server_url`
/// is the console entry. **The local panel does not use this chain** (see `meshlet_tray_host::panel`):
/// it is self-hosted by the tray-host and only reads the local state files. The legacy `config.toml`
/// file name from older deployments is also accepted.
pub(crate) fn panel_url(state_dir: &std::path::Path) -> Option<String> {
    meshlet_tray_host::panel::config_value(state_dir, "server_url")
}

/// Tray-host logging initialization.
///
/// - debug builds: the console subsystem is still present, so write straight to stderr — the
///   `-RedirectStandardError` gate in ci.yml (the `NIM_ADD`/`tooltip` assertions) depends on it.
/// - release builds: `windows_subsystem="windows"` has no console, so write a daily-rolling log
///   file (`%LOCALAPPDATA%/meshlet/logs/meshlet-tray-host.log`). If the directory does not exist
///   or is unwritable, degrade to `io::sink` — tray functionality comes first, never panic over logging.
pub(crate) fn init_tray_logging() -> Option<tracing_appender::non_blocking::WorkerGuard> {
    if cfg!(debug_assertions) {
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(std::io::stderr)
            .init();
        return None;
    }
    let log_dir = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .map(|base| base.join("meshlet").join("logs"))
        .filter(|dir| std::fs::create_dir_all(dir).is_ok());
    let (writer, guard) = match log_dir {
        Some(dir) => tracing_appender::non_blocking(tracing_appender::rolling::daily(
            dir,
            "meshlet-tray-host.log",
        )),
        // Log directory unavailable: drop logs silently, without panicking.
        None => tracing_appender::non_blocking(std::io::sink()),
    };
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(writer)
        .init();
    Some(guard)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a `<base>/state` structure (isomorphic to `install.ps1`'s
    /// `%LOCALAPPDATA%\meshlet\{agent.toml,state}`) and returns the state directory.
    fn temp_state_dir(tag: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!(
            "meshlet-tray-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = base.join("state");
        std::fs::create_dir_all(&state).unwrap();
        state
    }

    #[test]
    fn panel_url_reads_server_url_from_agent_toml() {
        let state = temp_state_dir("panel-agent");
        let base = state.parent().unwrap();
        std::fs::write(
            base.join("agent.toml"),
            "server_url = \"https://meshlet.example.com\"\nstate_dir = \"./state\"\n",
        )
        .unwrap();
        assert_eq!(
            panel_url(&state).as_deref(),
            Some("https://meshlet.example.com")
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn panel_url_falls_back_to_config_toml() {
        // Older deployments (real machines, 2026-10-31) write the config as config.toml; the panel entry must still work.
        let state = temp_state_dir("panel-config");
        let base = state.parent().unwrap();
        std::fs::write(
            base.join("config.toml"),
            "server_url = \"https://old.example.com\"\n",
        )
        .unwrap();
        assert_eq!(
            panel_url(&state).as_deref(),
            Some("https://old.example.com")
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn panel_url_missing_config_is_none() {
        let state = temp_state_dir("panel-none");
        let base = state.parent().unwrap();
        // No agent.toml / config.toml.
        assert!(panel_url(&state).is_none());
        // server_url empty -> None (do not return an empty string that would open a default page).
        std::fs::write(base.join("agent.toml"), "server_url = \"\"\n").unwrap();
        assert!(panel_url(&state).is_none());
        let _ = std::fs::remove_dir_all(base);
    }
}
