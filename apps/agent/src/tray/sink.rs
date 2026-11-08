//! 托盘产物落盘：[`TraySink`] 把状态图与 `status.json` 写到
//! `{state_dir}/tray/`，内容相同则不重写（幂等发布，「纪律二」）；
//! headless 下 no-op（不建目录、不写文件、不 panic，「纪律四」）。
//! [`TrayStatus`] 是发布的记录：状态 ＋ 文本等价物（tooltip / accessible_name，
//! 「纪律三」：不能只靠颜色）。

use std::path::{Path, PathBuf};

use super::env::EnvProbe;
use super::icon::IconSize;
use super::png::png_encode;
use super::state::TrayState;

/// 状态 ＋ 文本等价物。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayStatus {
    pub state: TrayState,
    /// tooltip（面板悬停显示；含设备名与整句说明）。
    pub tooltip: String,
    /// 无障碍短名。
    pub accessible_name: &'static str,
}

impl TrayStatus {
    /// 带设备名、**本机虚拟 IP** 与网络接口的 tooltip（tooltip 是文本等价物，
    /// 不能只靠颜色）。`virtual_ip` 来自计划隧道地址（`plan.tunnel.address`，
    /// 与 `info` 命令同一链路）——用户要求托盘 tooltip / 菜单首行
    /// = 设备名 + 虚拟 IPv4 + 状态。待审批（无计划）时为 `None`。
    pub fn new(
        state: TrayState,
        device_name: Option<&str>,
        virtual_ip: Option<std::net::Ipv4Addr>,
        interface: &str,
    ) -> Self {
        let mut who = device_name
            .map(|n| format!("「{n}」"))
            .unwrap_or_else(|| format!("接口 {interface}"));
        if let Some(ip) = virtual_ip {
            who.push(' ');
            who.push_str(&ip.to_string());
        }
        Self {
            tooltip: format!("Meshlet{who}：{}", state.tooltip()),
            state,
            accessible_name: state.accessible_name(),
        }
    }
}

/// 一次落盘的结果（区分「跳过」「写了」「内容未变」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayWrite {
    /// headless：不写任何文件。
    Skipped,
    /// 内容未变：不重写（幂等）。
    Unchanged,
    /// 状态变化，已写新图。
    Written,
}

/// 托盘产物落盘：`{state_dir}/tray/{icon-16.png,icon-24.png,status.json}`。
///
/// headless 下 no-op（不建目录、不写文件、不 panic）。
pub struct TraySink {
    dir: PathBuf,
}

impl TraySink {
    pub fn new(state_dir: impl AsRef<Path>) -> Self {
        Self {
            dir: state_dir.as_ref().join("tray"),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// 便利入口：用真实环境探测。
    pub fn publish(&self, status: &TrayStatus) -> Result<TrayWrite, String> {
        self.publish_with(status, &EnvProbe::from_env())
    }

    /// 注入环境探测（测试与 CI 用）。
    pub fn publish_with(&self, status: &TrayStatus, env: &EnvProbe) -> Result<TrayWrite, String> {
        if !env.has_desktop_session() {
            return Ok(TrayWrite::Skipped);
        }
        // 幂等比较只看语义字段（state + tooltip + version + env）：
        // `updated_at` 每次都会变，不参与比较，否则每轮 tick 都会重写。
        if status_unchanged(&self.dir, status, env) {
            return Ok(TrayWrite::Unchanged);
        }
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("create tray dir: {e}"))?;
        for size in [IconSize::Px16, IconSize::Px24] {
            let (_, _, rgba) = status.state.icon_rgba(size);
            let png = png_encode(size.px(), size.px(), &rgba);
            let name = format!("icon-{}.png", size.px());
            write_file(&self.dir.join(&name), &png).map_err(|e| format!("write {name}: {e}"))?;
        }
        let body = serde_json::json!({
            "state": status.state.accessible_name(),
            "tooltip": status.tooltip,
            "icon_16": "icon-16.png",
            "icon_24": "icon-24.png",
            "updated_at": chrono::Utc::now().to_rfc3339(),
            // 本地面板（tray-host `panel` 模块）的展示字段：版本 + 桌面会话探测。
            // 两者都是本进程已有的读数，不新增采集；`status_unchanged` 把它们
            // 一并比较——旧文件在升级后首次发布即补全，之后不会每轮重写。
            "version": env!("CARGO_PKG_VERSION"),
            "env": env_json(env),
        });
        write_file(&self.dir.join("status.json"), body.to_string().as_bytes())
            .map_err(|e| format!("write status.json: {e}"))?;
        Ok(TrayWrite::Written)
    }
}

fn read_file(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// EnvProbe → `status.json` 的 `env` 对象（发布与幂等比较共用同一构造，
/// 保证两边逐字段可比）。
fn env_json(env: &EnvProbe) -> serde_json::Value {
    serde_json::json!({
        "display": env.display.clone(),
        "wayland_display": env.wayland_display.clone(),
        "session_type": env.session_type.clone(),
        "session_name": env.session_name.clone(),
        "console_session": env.console_session,
    })
}

/// 上一份 `status.json` 的语义字段（state + tooltip + version + EnvProbe）是否
/// 与本次一致。
///
/// `version` / `env` 参与比较：升级前写出的旧文件在**升级后首次发布**即被补全
/// （否则 state/tooltip 未变就永远轮不到重写，本地面板会长期缺这两项）；补全后
/// 只要四者都不变就仍按幂等跳过，不会每轮 tick 重写。
fn status_unchanged(dir: &Path, status: &TrayStatus, env: &EnvProbe) -> bool {
    read_file(&dir.join("status.json"))
        .and_then(|prev| serde_json::from_str::<serde_json::Value>(&prev).ok())
        .map(|v| {
            v.get("state").and_then(|s| s.as_str()) == Some(status.state.accessible_name())
                && v.get("tooltip").and_then(|t| t.as_str()) == Some(status.tooltip.as_str())
                && v.get("version").and_then(|s| s.as_str()) == Some(env!("CARGO_PKG_VERSION"))
                && v.get("env") == Some(&env_json(env))
        })
        .unwrap_or(false)
}

fn write_file(path: &Path, body: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, body)
}

#[cfg(test)]
mod tests {
    use super::super::state::all_states;
    use super::*;

    // ── 纪律二/三：文本等价物，不靠颜色 ──────────────────────────────────

    #[test]
    fn every_state_has_a_nonempty_text_equivalent() {
        for state in all_states() {
            assert!(!state.accessible_name().is_empty());
            assert!(!state.tooltip().is_empty());
            let status = TrayStatus::new(
                state,
                Some("office-laptop"),
                Some("10.240.0.5".parse().unwrap()),
                "meshlet0",
            );
            assert!(status.tooltip.contains("office-laptop"));
            assert!(status.tooltip.contains("10.240.0.5"));
            assert_eq!(status.accessible_name, state.accessible_name());
        }
    }

    /// ① 用户要求：托盘 tooltip / 菜单首行 = 设备名 + 虚拟 IPv4 + 状态。
    /// 虚拟 IP 从计划隧道地址注入（`plan.tunnel.address`，与 `info` 同一链路）。
    #[test]
    fn tooltip_carries_device_name_and_virtual_ip() {
        let status = TrayStatus::new(
            TrayState::Online,
            Some("office-laptop"),
            Some("10.240.0.5".parse().unwrap()),
            "meshlet0",
        );
        assert!(status
            .tooltip
            .starts_with("Meshlet「office-laptop」 10.240.0.5："));
        assert!(status.tooltip.contains("在线"));
        // 无设备名：回退接口名；无 IP（待审批）：不出现空占位。
        let no_name = TrayStatus::new(TrayState::Offline, None, None, "mesh0");
        assert!(no_name.tooltip.starts_with("Meshlet接口 mesh0："));
        assert!(!no_name.tooltip.contains("： "));
        // 无设备名但有 IP。
        let ip_only = TrayStatus::new(
            TrayState::TunnelOnly,
            None,
            Some("10.240.0.5".parse().unwrap()),
            "mesh0",
        );
        assert!(ip_only
            .tooltip
            .starts_with("Meshlet接口 mesh0 10.240.0.5："));
    }

    // ── headless no-op（纪律四）─────────────────────────────────────────

    #[test]
    fn headless_publish_is_a_noop_without_touching_the_filesystem() {
        let dir = std::env::temp_dir().join("meshlet-tray-headless");
        let _ = std::fs::remove_dir_all(&dir);
        let sink = TraySink::new(&dir);
        let env = EnvProbe::default(); // 全空 = tty / CI
        assert!(!env.has_desktop_session());

        let write = sink
            .publish_with(
                &TrayStatus::new(TrayState::Online, None, None, "meshlet0"),
                &env,
            )
            .expect("headless publish must not error");
        assert_eq!(write, TrayWrite::Skipped);
        assert!(
            !dir.exists(),
            "headless publish must not create the tray dir"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn writes_icons_and_status_on_a_desktop_session_then_stays_idempotent() {
        let dir = std::env::temp_dir().join("meshlet-tray-desktop");
        let _ = std::fs::remove_dir_all(&dir);
        let sink = TraySink::new(&dir);
        let env = EnvProbe {
            display: Some(":0".into()),
            ..EnvProbe::default()
        };
        assert!(env.has_desktop_session());

        let first = TrayStatus::new(TrayState::Online, Some("laptop"), None, "meshlet0");
        assert_eq!(
            sink.publish_with(&first, &env).expect("desktop publish"),
            TrayWrite::Written
        );
        // 同内容再发 = 不重写（幂等）。
        assert_eq!(
            sink.publish_with(&first, &env).unwrap(),
            TrayWrite::Unchanged
        );

        // 状态变化 = 换图。
        let second = TrayStatus::new(TrayState::Offline, Some("laptop"), None, "meshlet0");
        assert_eq!(
            sink.publish_with(&second, &env).expect("state change"),
            TrayWrite::Written
        );
        let status = std::fs::read_to_string(sink.dir().join("status.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&status).unwrap();
        assert_eq!(value["state"], "Meshlet offline");
        let updated = value["updated_at"]
            .as_str()
            .expect("updated_at must be written");
        assert!(
            chrono::DateTime::parse_from_rfc3339(updated).is_ok(),
            "updated_at must be RFC3339, got {updated}"
        );
        for name in ["icon-16.png", "icon-24.png"] {
            let bytes = std::fs::read(sink.dir().join(name)).unwrap();
            assert!(
                bytes.starts_with(&[0x89, b'P', b'N', b'G']),
                "{name} must be a PNG"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 升级回归：旧 agent 写出的 `status.json`（无 `version`/`env`）在升级后
    /// **首次发布**必须被补全——否则 state/tooltip 未变就永远轮不到重写，本地
    /// 面板会长期缺这两项；补全后仍按幂等跳过，EnvProbe 变了才再写一次。
    #[test]
    fn status_upgrade_backfills_version_and_env_without_rewriting_every_tick() {
        let dir = std::env::temp_dir().join("meshlet-tray-status-upgrade");
        let _ = std::fs::remove_dir_all(&dir);
        let sink = TraySink::new(&dir);
        let env = EnvProbe {
            display: Some(":0".into()),
            ..EnvProbe::default()
        };
        let status = TrayStatus::new(TrayState::Online, Some("laptop"), None, "meshlet0");
        std::fs::create_dir_all(sink.dir()).unwrap();
        // 旧 agent 的文件：state/tooltip 已是最新，但没有 version/env。
        let legacy = serde_json::json!({
            "state": status.state.accessible_name(),
            "tooltip": status.tooltip,
            "icon_16": "icon-16.png",
            "icon_24": "icon-24.png",
            "updated_at": "2026-11-03T00:00:00Z",
        });
        std::fs::write(sink.dir().join("status.json"), legacy.to_string()).unwrap();

        assert_eq!(
            sink.publish_with(&status, &env).expect("upgrade publish"),
            TrayWrite::Written
        );
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(sink.dir().join("status.json")).unwrap())
                .unwrap();
        assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(value["env"]["display"], ":0");
        // 补全后同内容 → 仍幂等（不会每轮 tick 重写）。
        assert_eq!(
            sink.publish_with(&status, &env).unwrap(),
            TrayWrite::Unchanged
        );
        // EnvProbe 变化 → 再写一次（比较确实覆盖 env）。
        let moved = EnvProbe {
            display: Some(":1".into()),
            ..EnvProbe::default()
        };
        assert_eq!(
            sink.publish_with(&status, &moved).unwrap(),
            TrayWrite::Written
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
