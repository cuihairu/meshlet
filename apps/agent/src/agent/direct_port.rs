//! WIN-PORT-1 B2：直连监听端口的「生效端口」解析（probe-bind 探测回退）。
//!
//! Windows 上配置端口可能被 UDP 排除端口段（`netsh interface ipv4 show
//! excludedportrange protocol=udp`）或占用挡住——`WireGuardTunnel$` 服务绑
//! 不上即 `0xc0000022`（STATUS_ACCESS_DENIED；`wireguard.exe /dumplog` 实证
//! `Could not bind socket to 0.0.0.0:51820`，换高位端口即通过）。本模块在
//! apply 前 agent 侧 probe-bind 同端口探测（绑不上 = 服务也绑不上，同一
//! 排除段对任意进程拒绑），被挡则按确定性窗口选回退端口。
//!
//! 解析顺序（[`resolve`]，防自占误判与防 churn 是硬约束）：
//! 1. 快照端口 == 配置端口 → 直接用配置端口（现役已绑，零探测）；
//! 2. probe 配置端口可绑 → 配置端口（排除段解除后自愈回配置端口）；
//! 3. 账本端口 == 快照端口（现役在用）→ 沿用账本端口（换端口只会白断流，
//!    对端候选面也要重收敛——杜绝每轮换端口的 churn）；
//! 4. 回退窗口扫描（[`FALLBACK_PORT_BASE`] 起）→ 首个可绑端口；快照端口
//!    落在窗口内视为现役可绑证据（账本丢失也不换口）；
//! 5. 全部候选绑不上 → [`PortResolution::Blocked`]——调用方显式报错（附
//!    netsh 排查命令）、计划不钉端口、`direct_report` 不上报，绝不静默走
//!    中继还装作直连正常。
//!
//! 解析结果落 `{state_dir}/direct-port.json`（[load]/[save]）；conf
//! `ListenPort`、防火墙放行（`ensure_direct_udp_firewall_sync`）与
//! `direct_report` 三处取同一生效端口（硬不变量，调用点在
//! `super::reconcile`）。Linux 不探测不落账本（行为不变，恒取配置端口）。

/// 回退扫描窗口基址：52900。确定性（同机重扫收敛同口，对端候选面稳定）；
/// 高于 WireGuard 默认 51820 常用集群，窗口内含真机手工缓解实证可用的
/// 52931（cuihaitao 机 51820 被 `0xc0000022` 拒绑、52931 可绑）。
pub(super) const FALLBACK_PORT_BASE: u16 = 52900;
/// 回退扫描窗口大小：`52900..=53099` 共 200 个候选。
pub(super) const FALLBACK_PORT_COUNT: u16 = 200;

/// 直连监听端口的解析结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PortResolution {
    /// 生效监听端口：conf `ListenPort`、防火墙放行、`direct_report` 三处
    /// 必须同取此值。
    Port(u16),
    /// 配置端口与全部回退候选都绑不上：计划不钉端口、不上报候选端点，
    /// 显式报错（排查命令见模块文档），不装作直连正常。
    Blocked,
}

/// 解析生效监听端口（纯函数，probe 可注入跨平台单测）。
///
/// - `configured`：`[dataplane.direct_connect] listen_port` 配置值；
/// - `snapshot_port`：`inspect_sync()` 的 `tunnel_listen_port` 读数（现役
///   绑定证据；`Some(0)` = 绑定失败的隧道读数，按未绑定处理）；
/// - `persisted`：账本（[load]）里上一轮生效端口；
/// - `is_windows`：探测回退仅 Windows；其余平台恒取配置端口（行为不变）；
/// - `probe`：端口可绑性探测（生产为 [`probe_bind`]）。
pub(super) fn resolve(
    configured: u16,
    snapshot_port: Option<u16>,
    persisted: Option<u16>,
    is_windows: bool,
    probe: &dyn Fn(u16) -> bool,
) -> PortResolution {
    if !is_windows {
        return PortResolution::Port(configured);
    }
    // 绑定失败的服务在 dump 里报 0（读数在但没绑上）：不算现役证据。
    let snapshot_port = snapshot_port.filter(|p| *p != 0);
    // ① 现役已绑配置端口：probe 必自占误判——零探测直接用。
    if snapshot_port == Some(configured) {
        return PortResolution::Port(configured);
    }
    // ② 配置端口可绑（含排除段解除后的自愈回配置端口）。
    if probe(configured) {
        return PortResolution::Port(configured);
    }
    // ③ 现役绑在账本端口上：沿用，绝不换口（churn 只会白断流）。
    if let (Some(ledger_port), Some(in_use)) = (persisted, snapshot_port) {
        if ledger_port == in_use {
            return PortResolution::Port(ledger_port);
        }
    }
    // ④ 回退窗口扫描；快照端口落在窗口内 = 现役可绑证据（账本丢失也不换）。
    for offset in 0..FALLBACK_PORT_COUNT {
        let port = FALLBACK_PORT_BASE + offset;
        if Some(port) == snapshot_port || probe(port) {
            return PortResolution::Port(port);
        }
    }
    // ⑤ 全不可绑：显式 Blocked，调用方关闸报错。
    PortResolution::Blocked
}

/// 端口可绑性探测：与 `wireguard.exe` 同形状绑 `0.0.0.0:<port>`（UDP），
/// 绑得上即关（探测套接字即弃）。被排除段拒绑（WSAEACCES，即服务侧
/// `0xc0000022` 的用户态等价）与被占用（WSAEADDRINUSE）都算不可绑——
/// probe-bind 与服务侧绑定语义对齐，是 apply 前能拿到的最强证据
/// （探测到服务启动间仍存 TOCTOU 缝隙，由对账端口漂移判定兜底）。
pub(super) fn probe_bind(port: u16) -> bool {
    std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, port)).is_ok()
}

/// 生效端口账本路径：`{state_dir}/direct-port.json`。
pub(super) fn ledger_path(state_dir: &str) -> std::path::PathBuf {
    std::path::Path::new(state_dir).join("direct-port.json")
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct DirectPortLedger {
    /// 上一轮生效监听端口；`null` = 全部候选被挡（直连关闸中）。
    listen_port: Option<u16>,
}

/// 读账本：缺失/损坏按「无账本」处理（`None`，下一轮解析重新收敛，
/// 绝不拿坏数据当现役证据）。
pub(super) fn load(state_dir: &str) -> Option<u16> {
    let raw = std::fs::read_to_string(ledger_path(state_dir)).ok()?;
    serde_json::from_str::<DirectPortLedger>(&raw)
        .ok()
        .and_then(|ledger| ledger.listen_port)
}

/// 写账本（失败只由调用方记日志：账本是防 churn 优化，不阻塞数据面）。
pub(super) fn save(state_dir: &str, port: Option<u16>) -> Result<(), String> {
    let path = ledger_path(state_dir);
    let raw = serde_json::to_string(&DirectPortLedger { listen_port: port })
        .map_err(|e| format!("serialize direct-port ledger: {e}"))?;
    std::fs::write(&path, raw).map_err(|e| format!("write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 记录探测调用序的桩：返回预设的可绑集，外部断言探测了哪些口。
    struct ProbeRecorder {
        bindable: Vec<u16>,
        calls: std::cell::RefCell<Vec<u16>>,
    }

    impl ProbeRecorder {
        fn new(bindable: &[u16]) -> Self {
            Self {
                bindable: bindable.to_vec(),
                calls: std::cell::RefCell::new(Vec::new()),
            }
        }
        fn probe(&self, port: u16) -> bool {
            self.calls.borrow_mut().push(port);
            self.bindable.contains(&port)
        }
        fn called(&self) -> Vec<u16> {
            self.calls.borrow().clone()
        }
    }

    #[test]
    fn non_windows_keeps_configured_port_and_never_probes() {
        // Linux 行为不变：恒取配置端口；探测与账本一概不参与。
        let recorder = ProbeRecorder::new(&[]);
        let resolved = resolve(51820, None, Some(52931), false, &|p| recorder.probe(p));
        assert_eq!(resolved, PortResolution::Port(51820));
        assert!(recorder.called().is_empty());
    }

    /// ①现役已绑配置端口：零探测直接用（probe 对现役端口必自占误判）。
    #[test]
    fn snapshot_at_configured_port_short_circuits_without_probing() {
        let recorder = ProbeRecorder::new(&[]);
        let resolved = resolve(51820, Some(51820), None, true, &|p| recorder.probe(p));
        assert_eq!(resolved, PortResolution::Port(51820));
        assert!(recorder.called().is_empty());
    }

    /// 配置端口可绑：探测一次即收敛（含排除段解除后的自愈路径）。
    #[test]
    fn bindable_configured_port_wins() {
        let recorder = ProbeRecorder::new(&[51820]);
        let resolved = resolve(51820, None, Some(52931), true, &|p| recorder.probe(p));
        assert_eq!(resolved, PortResolution::Port(51820));
        assert_eq!(recorder.called(), vec![51820]);
    }

    /// ③配置端口被挡 + 现役绑在账本端口上：沿用账本端口，绝不换口
    /// （churn 只会白断流）。
    #[test]
    fn persisted_port_in_use_is_kept_without_churn() {
        let recorder = ProbeRecorder::new(&[]);
        let resolved = resolve(51820, Some(52931), Some(52931), true, &|p| {
            recorder.probe(p)
        });
        assert_eq!(resolved, PortResolution::Port(52931));
        // 只探过配置端口一次（防自占的现役判定在前），回退窗口不扫。
        assert_eq!(recorder.called(), vec![51820]);
    }

    /// ④配置端口与账本端口都不可用（隧道不在）：扫回退窗口取首个可绑口。
    #[test]
    fn tunnel_absent_falls_back_to_first_bindable_candidate() {
        // 52900/52901 被挡，52902 可绑。
        let recorder = ProbeRecorder::new(&[52902]);
        let resolved = resolve(51820, None, Some(52931), true, &|p| recorder.probe(p));
        assert_eq!(resolved, PortResolution::Port(FALLBACK_PORT_BASE + 2));
        assert_eq!(recorder.called(), vec![51820, 52900, 52901, 52902]);
    }

    /// 快照端口落在回退窗口内而账本丢失：视为现役可绑证据直接沿用
    /// （防「账本没了就换口」的 churn）。
    #[test]
    fn snapshot_inside_fallback_window_is_adopted_without_ledger() {
        let recorder = ProbeRecorder::new(&[]);
        let resolved = resolve(51820, Some(52931), None, true, &|p| recorder.probe(p));
        assert_eq!(resolved, PortResolution::Port(52931));
        // 现役端口本身不探测（现役即证据）：只探过配置端口 + 52900..=52930。
        let mut expected = vec![51820];
        expected.extend(FALLBACK_PORT_BASE..52931);
        assert_eq!(recorder.called(), expected);
    }

    /// 绑定失败的隧道在 dump 里报端口 0：不算现役证据（Some(0) 按未绑定
    /// 处理，绝不把 0 当生效端口采纳）。
    #[test]
    fn snapshot_port_zero_is_treated_as_unbound() {
        let recorder = ProbeRecorder::new(&[52900]);
        let resolved = resolve(51820, Some(0), None, true, &|p| recorder.probe(p));
        assert_eq!(resolved, PortResolution::Port(52900));
        assert_eq!(recorder.called(), vec![51820, 52900]);
    }

    /// ⑤配置端口与整个回退窗口全不可绑：显式 Blocked（调用方关闸报错，
    /// 绝不静默走中继还装作直连正常）。
    #[test]
    fn all_candidates_blocked_reports_blocked() {
        let recorder = ProbeRecorder::new(&[]);
        let resolved = resolve(51820, None, None, true, &|p| recorder.probe(p));
        assert_eq!(resolved, PortResolution::Blocked);
        // 探测了配置端口 + 全窗口（边界对齐：FALLBACK_PORT_COUNT 个候选）。
        assert_eq!(recorder.called().len(), 1 + FALLBACK_PORT_COUNT as usize);
        assert_eq!(recorder.called()[0], 51820);
    }

    /// 探测真值：被占端口假、释放后真（probe-bind 与真实绑定语义对齐）。
    /// 占位套接字必须同为通配绑定——Windows 允许「specific 127.0.0.1」与
    /// 「wildcard 0.0.0.0」同端口共存（Linux 拒；CI windows-latest 实证），
    /// 通配对通配才是三平台一致的冲突语义，也正是生产形态（wireguard.exe
    /// 与 probe 同绑 0.0.0.0）。
    #[test]
    fn probe_bind_reports_real_bindability() {
        let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        assert!(!probe_bind(port), "held port must read as not bindable");
        drop(socket);
        assert!(probe_bind(port), "released port must read as bindable");
    }

    /// 账本 round-trip：Some/None 都能落盘回读；损坏文件按无账本处理。
    #[test]
    fn ledger_round_trips_and_corruption_reads_as_absent() {
        let dir = std::env::temp_dir().join(format!(
            "meshlet-direct-port-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let state_dir = dir.to_str().unwrap().to_string();
        assert_eq!(load(&state_dir), None);
        save(&state_dir, Some(52931)).unwrap();
        assert_eq!(load(&state_dir), Some(52931));
        save(&state_dir, None).unwrap();
        assert_eq!(load(&state_dir), None);
        std::fs::write(ledger_path(&state_dir), "not json").unwrap();
        assert_eq!(load(&state_dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
