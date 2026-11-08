use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

/// 启动本地面板服务（只绑 `127.0.0.1` 随机端口）并记下 URL。失败只记日志：
/// 托盘其余功能不受影响，菜单项届时按「未启动」提示，绝不假装打开成功。
/// 成功返回面板 URL（已写 URL 交接文件）；失败返回 `None`。
#[cfg(windows)]
pub(crate) fn start_local_panel(state_dir: &std::path::Path) -> Option<String> {
    match meshlet_tray_host::panel::start(state_dir.to_path_buf()) {
        Ok(port) => {
            let url = meshlet_tray_host::panel::url(port);
            tracing::info!(%url, "local panel listening (loopback only)");
            // URL 交接文件：进程存活期间日志被重定向句柄锁住读不到（Windows），
            // CI / 运维改读这个写完即关的文件拿端口。
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

/// 「本地面板」：浏览器打开 tray-host 自托管的 loopback 只读页——当前节点 /
/// 直连节点 / 本地路由三块，数据只读本机状态文件（不依赖 server 可达）。
pub(crate) fn open_local_panel(hwnd: HWND, panel_url: Option<&str>) {
    match panel_url {
        Some(url) => {
            // 日志留痕：真机验收据此证明「菜单项 → 本地面板 URL」这条链路。
            tracing::info!(%url, "opening local panel from tray menu");
            shell_open(hwnd, url);
        }
        None => tracing::warn!("local panel not running, cannot open it"),
    }
}

/// 「控制台(网页)」：默认浏览器打开 `server_url`（server 根路径托管的控制台）。
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

/// 用系统默认浏览器打开 `url`（`ShellExecuteW` verb=open）。
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

/// 控制台 URL：agent 配置文件（`{state_dir}/..`）的 `server_url`。控制台由
/// server 根路径托管（`router_with_console` 的 `ServeDir` 兜底），故 `server_url`
/// 即控制台入口。**本地面板不走这条链路**（见 `meshlet_tray_host::panel`）：
/// 它由 tray-host 自托管，只读本机状态文件。兼容旧部署的 `config.toml` 文件名。
pub(crate) fn panel_url(state_dir: &std::path::Path) -> Option<String> {
    meshlet_tray_host::panel::config_value(state_dir, "server_url")
}

/// 托盘宿主日志初始化。
///
/// - debug 构建：控制台子系统仍在，直接写 stderr —— ci.yml 的
///   `-RedirectStandardError` 门禁（`NIM_ADD`/`tooltip` 断言）依赖它。
/// - release 构建：`windows_subsystem="windows"` 无控制台，写每日滚动的日志
///   文件（`%LOCALAPPDATA%/meshlet/logs/meshlet-tray-host.log`）。目录不存在
///   或不可写时降级为 `io::sink`——托盘功能优先，绝不因日志 panic。
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
        // 日志目录不可用：静默丢弃日志，不 panic。
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

    /// 建一个 `<base>/state` 结构（与 `install.ps1` 的
    /// `%LOCALAPPDATA%\meshlet\{agent.toml,state}` 同形），返回 state 目录。
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
        // 旧部署（2026-10-31 真机）把配置写成 config.toml；面板入口仍要工作。
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
        // 无 agent.toml / config.toml。
        assert!(panel_url(&state).is_none());
        // server_url 为空 → None（不返回空字符串打开默认页）。
        std::fs::write(base.join("agent.toml"), "server_url = \"\"\n").unwrap();
        assert!(panel_url(&state).is_none());
        let _ = std::fs::remove_dir_all(base);
    }
}
