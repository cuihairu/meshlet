//! CLI↔agent 直连拨号契约（`peer dial <node>`，R-AGENT-WIN-1 补充 ③）。
//!
//! CLI（`apps/cli`）与 agent（`apps/agent`）是两个进程，且 CLI 运行在用户
//! 会话（无权限做 `wg set`），agent 以服务身份持有数据面后端。因此拨号走
//! **文件意图**而非 CLI 直改内核：
//! - CLI 把 [DirectDialRequest] 写到 `{state_dir}/direct-dial.json`；
//! - agent 在下一探测周期读到后，经
//!   [`NetworkBackend`](crate::NetworkBackend) 的 `set_direct_peer_sync`
//!   发起对目标节点的直连拨号（这就是「executor 接 meshlet-network 发起
//!   直连拨号」），把结果写回 `{state_dir}/direct-dial-result.json`；
//! - CLI 轮询结果文件，成功/失败结果据此显示。
//!
//! 走文件而非 HTTP/信号：agent 已是文件状态驱动（`status.json` /
//! `direct.json` / `applied.json`），同构零新增机制。`request_id` 对账防
//! 误读上一轮结果。
//!
//! agent 同时把「直连对端视图」（[DirectPeerView]）发布到
//! `{state_dir}/direct-peers.json`——CLI `peer dial` 用它解析 `<node>`，
//! 托盘「直连节点 / 连接节点…」子菜单也读它（数据源与 `peers` 命令同一
//! 链路：都来自 agent 直连探测周期对内核的读数）。

use std::path::{Path, PathBuf};

/// 直连拨号请求（CLI → agent）。
///
/// `node` 是用户输入的标识（名称 / IP / 公钥前缀，原样保留展示用）；
/// `public_key`/`virtual_ipv4` 是 CLI 解析 `direct-peers.json` 的结果——
/// agent 按 `public_key` 在**本周期**的候选集里对账，端点取服务端候选。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectDialRequest {
    /// 用户输入的节点标识（原样保留，展示用）。
    pub node: String,
    /// 目标 wg 公钥（agent 据此对账 + `wg set`）。
    pub public_key: String,
    /// 目标 overlay 地址（AllowedIPs `/32` 来源）。
    pub virtual_ipv4: std::net::Ipv4Addr,
    /// 请求 ID（CLI 生成，与结果对账；防误读上一轮结果）。
    pub request_id: String,
    /// 请求时刻（Unix 毫秒字符串，排查用）。
    pub requested_at: String,
}

/// 直连拨号结果（agent → CLI）。`ok=false` 必须带可读 `message`——绝不
/// 静默假装成功（与 [crate::ApplyResult] 同一纪律）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectDialResult {
    pub request_id: String,
    pub ok: bool,
    /// `p2p_direct` / `direct_pending`（成功）/ `hub_relay`（失败或中继）。
    pub mode: String,
    pub message: String,
    pub finished_at: String,
}

/// `direct-peers.json` 单条：一个服务端直连候选 + 当前链路状态。
///
/// 供 `peer dial` 解析 `<node>` 与托盘子菜单展示。`mode`：
/// - `p2p_direct`：直连已建立（最近握手在健康窗口内）；
/// - `direct_pending`：endpoint 已下发，等握手验证；
/// - `hub_relay`：候选但无可行直连路径（走中继），是可拨号目标。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectPeerView {
    /// 对端设备名（旧服务端缺省为空）。
    pub name: String,
    /// 对端 overlay 地址。
    pub virtual_ipv4: std::net::Ipv4Addr,
    /// 对端 wg 公钥。
    pub public_key: String,
    /// `p2p_direct` / `direct_pending` / `hub_relay`。
    pub mode: String,
    /// 最近一次直连路径实测 RTT（毫秒）；未测为 `None`。
    pub rtt_ms: Option<u64>,
    /// RTT 读数来源（`overlay` / `endpoint` / `unreachable`；未测 / 旧 agent
    /// 为 `None`）。托盘/面板据此标注 RTT 列的来源（见 `meshlet-domain`
    /// `DirectLinkStatus::rtt_source`）。
    #[serde(default)]
    pub rtt_source: Option<String>,
    /// 当前直连 endpoint（`ip:port`）；未建立 / 无候选为空。
    pub endpoint: String,
    /// 最近握手 Unix 秒；未握手为 `None`。
    pub last_handshake_at: Option<u64>,
}

/// SEL-002 直连 endpoint 切换事件（[`direct_switch_events_path`] 追加记录）。
///
/// 事件可查（任务书「切换事件可查」）：agent 每成功执行一次
/// `wg set endpoint` 漫游就追加一条到 `{state_dir}/direct-switch-events.json`
/// （JSON Lines），CLI / 运维可直接读该文件审计切换历史。
///
/// 事件类型由可选 `kind` 区分（缺省 = endpoint 漫游，旧事件/旧读者零感知）：
/// - 缺省：`from`/`to` 为 endpoint（`ip:port`）；
/// - [`SWITCH_KIND_MODE_FLIP`]：直连模式翻转，`from`/`to` 为
///   `p2p_direct` / `direct_pending` / `hub_relay`，`detail` 携带判据摘要。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SwitchEvent {
    /// 对端 wg 公钥。
    pub public_key: String,
    /// 切换前 endpoint（`ip:port`）或模式（`kind = mode_flip` 时）。
    pub from: String,
    /// 切换后 endpoint（`ip:port`）或模式（`kind = mode_flip` 时）。
    pub to: String,
    /// 切换理由（SEL-002 迟滞闸给出）。
    pub reason: String,
    /// 事件时刻（Unix 毫秒字符串）。
    pub at_ms: String,
    /// 事件类型（缺省 = endpoint 漫游；[`SWITCH_KIND_MODE_FLIP`] = 模式翻转）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// 判据摘要（模式翻转事件携带：握手年龄 / 劣化 / endpoint）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// RFC3339 UTC 时刻（新事件携带；旧事件只有 `at_ms`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts: Option<String>,
}

/// [`SwitchEvent::kind`]：直连模式翻转事件（`p2p_direct` ↔ `hub_relay` /
/// `direct_pending` 之间迁移，含降级回中继与再晋升）。
pub const SWITCH_KIND_MODE_FLIP: &str = "mode_flip";

/// 拨号请求路径：`{state_dir}/direct-dial.json`。
pub fn dial_request_path(state_dir: &Path) -> PathBuf {
    state_dir.join("direct-dial.json")
}

/// SEL-002 切换事件路径：`{state_dir}/direct-switch-events.json`。
pub fn direct_switch_events_path(state_dir: &Path) -> PathBuf {
    state_dir.join("direct-switch-events.json")
}

/// 拨号结果路径：`{state_dir}/direct-dial-result.json`。
pub fn dial_result_path(state_dir: &Path) -> PathBuf {
    state_dir.join("direct-dial-result.json")
}

/// 直连对端视图路径：`{state_dir}/direct-peers.json`。
pub fn direct_peers_path(state_dir: &Path) -> PathBuf {
    state_dir.join("direct-peers.json")
}

/// 当前 Unix 毫秒（字符串；请求/结果时间戳，无 chrono 依赖）。
pub fn now_millis() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().to_string())
        .unwrap_or_else(|_| "0".into())
}

pub fn load_request(state_dir: &Path) -> Option<DirectDialRequest> {
    read_json(&dial_request_path(state_dir))
}

pub fn write_request(state_dir: &Path, req: &DirectDialRequest) -> std::io::Result<()> {
    write_json(state_dir, &dial_request_path(state_dir), req)
}

/// 清除拨号请求（处理完即删；不存在视为成功——幂等）。
pub fn clear_request(state_dir: &Path) -> std::io::Result<()> {
    std::fs::remove_file(dial_request_path(state_dir)).or_else(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(e)
        }
    })
}

pub fn load_result(state_dir: &Path) -> Option<DirectDialResult> {
    read_json(&dial_result_path(state_dir))
}

pub fn write_result(state_dir: &Path, res: &DirectDialResult) -> std::io::Result<()> {
    write_json(state_dir, &dial_result_path(state_dir), res)
}

pub fn load_direct_peers(state_dir: &Path) -> Option<Vec<DirectPeerView>> {
    read_json(&direct_peers_path(state_dir))
}

pub fn write_direct_peers(state_dir: &Path, views: &[DirectPeerView]) -> std::io::Result<()> {
    write_json(state_dir, &direct_peers_path(state_dir), views)
}

/// 追加一条 SEL-002 切换事件（JSON Lines 追加；事件可查）。
pub fn append_switch_event(state_dir: &Path, event: &SwitchEvent) -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    let path = direct_switch_events_path(state_dir);
    let mut line = serde_json::to_vec(event).map_err(io_err)?;
    line.push(b'\n');
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(&line)
}

/// 读取全部 SEL-002 切换事件（缺失/损坏文件 → 空列表；可查）。
pub fn load_switch_events(state_dir: &Path) -> Vec<SwitchEvent> {
    let Ok(raw) = std::fs::read_to_string(direct_switch_events_path(state_dir)) else {
        return Vec::new();
    };
    raw.lines()
        .filter_map(|l| serde_json::from_str::<SwitchEvent>(l).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// 决策日志（无控制台上下文的事后回放）
// ---------------------------------------------------------------------------

/// agent 决策日志事件（[`decision_log_path`] JSONL 追加）：classify / 切换闸
/// 判定逐条入账，Windows 服务 / schtasks SYSTEM 等无控制台上下文也能事后
/// 回放降级/晋升的原因与判据输入（2026-11-14 巡检单：真机 demote 原因无
/// 文件级回放能力的诊断缺口）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DecisionEvent {
    /// 时刻（RFC3339 真 UTC；PS 5.1 `Get-Date -UFormat %s` 有 +28800s 伪影，
    /// 禁用该口径——这里由 chrono `Utc` 生成）。
    pub ts: String,
    /// 对端 wg 公钥。
    pub public_key: String,
    /// 对端名称（候选里读到的展示名）。
    pub peer_name: String,
    /// 动作：`promote` / `demote` / `hold_relay` / `probe` / `defer`。
    pub action: String,
    /// 判定前模式（`p2p_direct` / `direct_pending` / `hub_relay`）。
    pub from_mode: String,
    /// 判定后模式。
    pub to_mode: String,
    /// 判定原因（人读）。
    pub reason: String,
    /// 判据输入：最近直连握手年龄（秒；内核读数快照）。
    pub handshake_age_secs: Option<u64>,
    /// 判据输入：SEL-003 探测窗口劣化判定。
    pub degraded: bool,
    /// 涉事 endpoint（promote 目标 / demote 时的现役面；空 = 无）。
    pub endpoint: String,
    /// 判据输入：现役路径探测窗口摘要（如 `23,31,L,L loss=50% med=27ms`；
    /// 探测关 / 未采样为 `None`）。
    pub probe_window: Option<String>,
}

/// 决策日志路径：`{state_dir}/agent-decisions.jsonl`。
pub fn decision_log_path(state_dir: &Path) -> PathBuf {
    state_dir.join("agent-decisions.jsonl")
}

/// 决策日志单文件上限（超过即滚动为 `.jsonl.1`，覆盖上一份滚动件）。
/// 逐事件一行的量级 ≈ 300B × 每周期每对端一条，8MiB 足以覆盖数周。
pub const DECISION_LOG_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// 追加一条决策日志（JSON Lines；超限滚动）。
pub fn append_decision_event(state_dir: &Path, event: &DecisionEvent) -> std::io::Result<()> {
    append_decision_event_capped(state_dir, event, DECISION_LOG_MAX_BYTES)
}

/// 读取全部决策日志（缺失/损坏文件 → 空列表）。
pub fn load_decision_events(state_dir: &Path) -> Vec<DecisionEvent> {
    let Ok(raw) = std::fs::read_to_string(decision_log_path(state_dir)) else {
        return Vec::new();
    };
    raw.lines()
        .filter_map(|l| serde_json::from_str::<DecisionEvent>(l).ok())
        .collect()
}

fn append_decision_event_capped(
    state_dir: &Path,
    event: &DecisionEvent,
    max_bytes: u64,
) -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    let path = decision_log_path(state_dir);
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() > max_bytes {
            let rotated = path.with_extension("jsonl.1");
            let _ = std::fs::remove_file(&rotated);
            let _ = std::fs::rename(&path, &rotated);
        }
    }
    let mut line = serde_json::to_vec(event).map_err(io_err)?;
    line.push(b'\n');
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(&line)
}

/// 当前时刻 RFC3339 UTC（秒精度；决策日志时间戳口径）。
pub fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn write_json<T: serde::Serialize + ?Sized>(
    state_dir: &Path,
    path: &Path,
    value: &T,
) -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    let body = serde_json::to_vec(value).map_err(io_err)?;
    std::fs::write(path, body)
}

fn io_err(e: serde_json::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dial_request_round_trips_through_the_state_file() {
        let dir = std::env::temp_dir().join(format!("meshlet-dial-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let req = DirectDialRequest {
            node: "peer-b".into(),
            public_key: "abc==".into(),
            virtual_ipv4: "10.240.0.3".parse().unwrap(),
            request_id: "req-1".into(),
            requested_at: "1000".into(),
        };
        write_request(&dir, &req).unwrap();
        assert_eq!(load_request(&dir), Some(req));

        // 结果对账：request_id 区分不同拨号。
        let res = DirectDialResult {
            request_id: "req-1".into(),
            ok: true,
            mode: "p2p_direct".into(),
            message: "direct link established".into(),
            finished_at: "2000".into(),
        };
        write_result(&dir, &res).unwrap();
        assert_eq!(load_result(&dir), Some(res));

        // 清除请求：幂等（不存在也成功）。
        clear_request(&dir).unwrap();
        assert_eq!(load_request(&dir), None);
        clear_request(&dir).unwrap();

        // 缺失/损坏文件 → None（调用方按「无待处理拨号」处理）。
        assert_eq!(load_result(&dir.join("missing")), None);
        std::fs::write(dial_result_path(&dir), "not json").unwrap();
        assert_eq!(load_result(&dir), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn direct_peers_view_round_trips() {
        let dir = std::env::temp_dir().join(format!("meshlet-direct-peers-{}", std::process::id()));
        let views = vec![DirectPeerView {
            name: "peer-b".into(),
            virtual_ipv4: "10.240.0.3".parse().unwrap(),
            public_key: "abc==".into(),
            mode: "hub_relay".into(),
            rtt_ms: None,
            rtt_source: None,
            endpoint: String::new(),
            last_handshake_at: None,
        }];
        write_direct_peers(&dir, &views).unwrap();
        assert_eq!(load_direct_peers(&dir), Some(views));
        assert_eq!(load_direct_peers(&dir.join("missing")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn now_millis_is_a_numeric_string() {
        assert!(now_millis().parse::<u128>().is_ok());
    }

    #[test]
    fn switch_events_append_and_are_queryable() {
        let dir =
            std::env::temp_dir().join(format!("meshlet-switch-events-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let e1 = SwitchEvent {
            public_key: "key-a".into(),
            from: "192.168.1.50:51821".into(),
            to: "192.168.1.60:51821".into(),
            reason: "score 60 beats 100 by >=30%".into(),
            at_ms: "1000".into(),
            kind: None,
            detail: None,
            ts: None,
        };
        let e2 = SwitchEvent {
            public_key: "key-a".into(),
            from: "192.168.1.60:51821".into(),
            to: "192.168.1.50:51821".into(),
            reason: "score 40 beats 60 by >=30%".into(),
            at_ms: "2000".into(),
            kind: None,
            detail: None,
            ts: None,
        };
        append_switch_event(&dir, &e1).unwrap();
        append_switch_event(&dir, &e2).unwrap();
        // 事件可查：顺序保持追加序。
        assert_eq!(load_switch_events(&dir), vec![e1, e2]);
        // 缺失文件 → 空。
        assert!(load_switch_events(&dir.join("missing")).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn switch_event_parses_legacy_lines_without_new_fields() {
        // 旧事件行（无 kind/detail/ts）必须原样可读——向后兼容红线。
        let legacy = r#"{"public_key":"k","from":"1.2.3.4:51820","to":"5.6.7.8:51820","reason":"score","at_ms":"42"}"#;
        let parsed: SwitchEvent = serde_json::from_str(legacy).unwrap();
        assert_eq!(parsed.at_ms, "42");
        assert_eq!(parsed.kind, None);
        assert_eq!(parsed.detail, None);
        assert_eq!(parsed.ts, None);
    }

    #[test]
    fn mode_flip_event_round_trips_in_the_same_file() {
        let dir = std::env::temp_dir().join(format!("meshlet-mode-flip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let flip = SwitchEvent {
            public_key: "key-a".into(),
            from: "p2p_direct".into(),
            to: "hub_relay".into(),
            reason: "sel003 degraded: probe window".into(),
            at_ms: "3000".into(),
            kind: Some(SWITCH_KIND_MODE_FLIP.into()),
            detail: Some("hs_age=Some(56) degraded=true ep=10.147.19.49:51820".into()),
            ts: Some("2026-11-14T02:03:04+00:00".into()),
        };
        append_switch_event(&dir, &flip).unwrap();
        assert_eq!(load_switch_events(&dir), vec![flip]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn decision_event(action: &str, from: &str, to: &str) -> DecisionEvent {
        DecisionEvent {
            ts: "2026-11-14T02:03:04+00:00".into(),
            public_key: "key-a".into(),
            peer_name: "dev-b".into(),
            action: action.into(),
            from_mode: from.into(),
            to_mode: to.into(),
            reason: "sel003 degraded: probe window".into(),
            handshake_age_secs: Some(56),
            degraded: true,
            endpoint: "10.147.19.49:51820".into(),
            probe_window: Some("23,31,L,L,L loss=60% med=27ms".into()),
        }
    }

    #[test]
    fn decision_events_append_load_and_rotate() {
        let dir = std::env::temp_dir().join(format!("meshlet-decisions-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let e1 = decision_event("demote", "p2p_direct", "hub_relay");
        let e2 = decision_event("promote", "hub_relay", "direct_pending");
        append_decision_event(&dir, &e1).unwrap();
        append_decision_event(&dir, &e2).unwrap();
        assert_eq!(load_decision_events(&dir), vec![e1, e2]);
        assert!(load_decision_events(&dir.join("missing")).is_empty());

        // 滚动：超过上限后旧内容整体挪到 .jsonl.1，主文件重新起头。
        let e3 = decision_event("hold_relay", "hub_relay", "hub_relay");
        append_decision_event_capped(&dir, &e3, 1).unwrap();
        assert_eq!(load_decision_events(&dir), vec![e3]);
        let rotated = decision_log_path(&dir).with_extension("jsonl.1");
        let rotated_raw = std::fs::read_to_string(rotated).unwrap();
        assert!(rotated_raw.contains("\"demote\""));
        assert!(rotated_raw.contains("\"promote\""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rfc3339_now_is_true_utc_with_z_suffix() {
        let ts = rfc3339_now();
        // 真 UTC（Z 结尾、无 +28800 偏移伪影），可被标准解析器往返。
        assert!(ts.ends_with('Z'), "ts={ts}");
        assert!(chrono::DateTime::parse_from_rfc3339(&ts).is_ok());
    }
}
