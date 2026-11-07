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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SwitchEvent {
    /// 对端 wg 公钥。
    pub public_key: String,
    /// 切换前 endpoint（`ip:port`）。
    pub from: String,
    /// 切换后 endpoint（`ip:port`）。
    pub to: String,
    /// 切换理由（SEL-002 迟滞闸给出）。
    pub reason: String,
    /// 事件时刻（Unix 毫秒字符串）。
    pub at_ms: String,
}

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
        };
        let e2 = SwitchEvent {
            public_key: "key-a".into(),
            from: "192.168.1.60:51821".into(),
            to: "192.168.1.50:51821".into(),
            reason: "score 40 beats 60 by >=30%".into(),
            at_ms: "2000".into(),
        };
        append_switch_event(&dir, &e1).unwrap();
        append_switch_event(&dir, &e2).unwrap();
        // 事件可查：顺序保持追加序。
        assert_eq!(load_switch_events(&dir), vec![e1, e2]);
        // 缺失文件 → 空。
        assert!(load_switch_events(&dir.join("missing")).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
