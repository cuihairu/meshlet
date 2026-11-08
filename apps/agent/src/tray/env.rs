//! 桌面会话探测（注入式：测试不必动进程环境变量）。headless / CI 判定
//! （「纪律四」）的数据源：[`EnvProbe::from_env`] 读环境变量与 Windows 控制台
//! 会话，[`EnvProbe::has_desktop_session`] 为 false 时落盘层直接 no-op。

/// 桌面会话探测（注入式：测试不必动进程环境变量）。
#[derive(Debug, Clone, Default)]
pub struct EnvProbe {
    /// X11 显示（`$DISPLAY`）。
    pub display: Option<String>,
    /// Wayland 显示（`$WAYLAND_DISPLAY`）。
    pub wayland_display: Option<String>,
    /// `$XDG_SESSION_TYPE`（`x11` / `wayland` / `tty` / …）。
    pub session_type: Option<String>,
    /// Windows `%SESSIONNAME%`（`Console` / `RDP-Tcp#N`）：**本进程**处于
    /// 交互会话（用户会话 agent，`install.ps1` 的 HKCU Run 模型）。Linux 无此
    /// 变量，恒 `None`。
    pub session_name: Option<String>,
    /// Windows：机器上有活动控制台会话（`WTSGetActiveConsoleSessionId`）。
    /// 使以 SYSTEM/服务身份运行的 agent 也能为登录用户会话的托盘写状态图
    /// （托盘宿主是登录用户会话进程，状态经文件传递，见
    /// [`crate::tray::TraySink`]）。
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

    /// 是否有桌面会话可挂托盘。`tty` / 空值 = headless（CI、无头 VPS）→ false。
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

/// Windows：`WTSGetActiveConsoleSessionId() != 0xFFFFFFFF`（有活动控制台会话）。
/// 其它平台无此概念，恒 `false`。
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

    /// Windows 用户会话 agent（`install.ps1` HKCU Run）：`%SESSIONNAME%`
    /// 已设置（`Console` / `RDP-Tcp#N`），必须视为有桌面会话——此前只探测
    /// X11/Wayland 变量，Windows 上恒为 headless，agent 从不写托盘 PNG，
    /// 托盘宿主永远落到 GDI 绿块（2026-10-31 验收第 7 项）。
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

    /// Windows SYSTEM/服务 agent（真实机 AtStartup 计划任务）：进程自身无
    /// `%SESSIONNAME%`，但机器上有活动控制台会话（用户已登录）→ 仍写托盘
    /// 状态，供登录用户会话的托盘宿主读取。无活动会话（CI、无头）→ false。
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
