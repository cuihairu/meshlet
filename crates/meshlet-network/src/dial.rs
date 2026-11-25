//! CLI↔agent direct-connect dialing contract (`peer dial <node>`, R-AGENT-WIN-1 supplement ③).
//!
//! The CLI (`apps/cli`) and the agent (`apps/agent`) are separate processes, and the CLI runs in the
//! user session (without permission to `wg set`), while the agent holds the dataplane backend as a
//! service identity. Dialing therefore goes through a **file-based intent** rather than the CLI
//! touching the kernel directly:
//! - the CLI writes the [DirectDialRequest] to `{state_dir}/direct-dial.json`;
//! - the agent, having read it on the next probe cycle, uses
//!   `set_direct_peer_sync` of [`NetworkBackend`](crate::NetworkBackend) to
//!   start a direct dial to the target node (this is what "the executor hooks meshlet-network up to
//!   initiate a direct dial" means), and writes the outcome back to `{state_dir}/direct-dial-result.json`;
//! - the CLI polls the result file and renders success/failure from it.
//!
//! Files rather than HTTP/signals: the agent is already file-state driven (`status.json` /
//! `direct.json` / `applied.json`), so this is isomorphic with zero new machinery. `request_id`
//! reconciliation prevents misreading the previous round's result.
//!
//! The agent also publishes the "direct peer view" ([DirectPeerView]) to
//! `{state_dir}/direct-peers.json` — CLI `peer dial` uses it to resolve `<node>`, and the tray's
//! "Direct node / Connect node..." submenu reads it too (same data path as the `peers` command:
//! both come from the agent's direct-probe cycle reading the kernel).

use std::path::{Path, PathBuf};

/// Direct dial request (CLI → agent).
///
/// `node` is the identifier the user typed (name / IP / public key prefix, kept verbatim for display);
/// `public_key`/`virtual_ipv4` are the result of the CLI parsing `direct-peers.json` —
/// the agent reconciles by `public_key` against the candidate set of **this cycle**, taking the
/// endpoint from the server-side candidate.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectDialRequest {
    /// The node identifier typed by the user (kept verbatim, for display).
    pub node: String,
    /// The target wg public key (the agent reconciles by it and issues `wg set`).
    pub public_key: String,
    /// The target overlay address (the source of the AllowedIPs `/32`).
    pub virtual_ipv4: std::net::Ipv4Addr,
    /// Request id (CLI-generated, reconciled against the result; prevents misreading a previous round's result).
    pub request_id: String,
    /// Request time (Unix millis as a string, for troubleshooting).
    pub requested_at: String,
}

/// Direct dial result (agent → CLI). `ok=false` must carry a human-readable `message` —
/// never silently pretend success (the same discipline as [crate::ApplyResult]).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectDialResult {
    pub request_id: String,
    pub ok: bool,
    /// `p2p_direct` / `direct_pending` (success) / `hub_relay` (failure or relay).
    pub mode: String,
    pub message: String,
    pub finished_at: String,
}

/// One `direct-peers.json` entry: one server-side direct candidate + the current link state.
///
/// Used by `peer dial` to resolve `<node>` and by the tray submenu. `mode`:
/// - `p2p_direct`: the direct link is up (the most recent handshake is within the healthy window);
/// - `direct_pending`: the endpoint has been dispatched and is awaiting handshake validation;
/// - `hub_relay`: a candidate with no feasible direct path (relay in use), still a dialable target.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectPeerView {
    /// The peer's device name (old servers leave it empty).
    pub name: String,
    /// The peer's device id (the tray's direct table exposes a loose short id; zerotier-style
    /// truncated display). Old files default to empty — new readers treat empty as normal, not
    /// an anomaly.
    #[serde(default)]
    pub device_id: String,
    /// The peer's overlay address.
    pub virtual_ipv4: std::net::Ipv4Addr,
    /// The peer's wg public key.
    pub public_key: String,
    /// `p2p_direct` / `direct_pending` / `hub_relay`.
    pub mode: String,
    /// The measured RTT of the most recent direct path (milliseconds); `None` when unmeasured.
    pub rtt_ms: Option<u64>,
    /// Where the RTT reading comes from (`overlay` / `endpoint` / `unreachable`; `None` for
    /// unmeasured / old agents). The tray/console use this to annotate the RTT column's source
    /// (see `meshlet-domain` `DirectLinkStatus::rtt_source`).
    #[serde(default)]
    pub rtt_source: Option<String>,
    /// The current direct endpoint (`ip:port`); empty when unestablished / no candidate.
    pub endpoint: String,
    /// The most recent handshake as Unix seconds; `None` when there has been no handshake.
    pub last_handshake_at: Option<u64>,
}

/// SEL-002 direct endpoint switch event (appended by [`direct_switch_events_path`]).
///
/// Events are queryable (the task sheet "switch events are queryable"): every successful
/// `wg set endpoint` roam appends one entry to `{state_dir}/direct-switch-events.json`
/// (JSON Lines); the CLI / ops can read that file directly to audit switch history.
///
/// The optional `kind` distinguishes event types (default = endpoint roam, old events/old readers
/// zero-change):
/// - default: `from`/`to` are endpoints (`ip:port`);
/// - [`SWITCH_KIND_MODE_FLIP`]: a direct mode flip, `from`/`to` are
///   `p2p_direct` / `direct_pending` / `hub_relay`, and `detail` carries the criterion summary.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SwitchEvent {
    /// The peer's wg public key.
    pub public_key: String,
    /// The endpoint before the switch (`ip:port`) or the mode (when `kind = mode_flip`).
    pub from: String,
    /// The endpoint after the switch (`ip:port`) or the mode (when `kind = mode_flip`).
    pub to: String,
    /// The reason for the switch (given by the SEL-002 hysteresis gate).
    pub reason: String,
    /// Event time (Unix millis as a string).
    pub at_ms: String,
    /// The event kind (default = endpoint roam; [`SWITCH_KIND_MODE_FLIP`] = mode flip).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Criterion summary (carried by mode-flip events: handshake age / degradation / endpoint).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// RFC3339 UTC instant (carried by new events; old events have only `at_ms`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts: Option<String>,
}

/// [`SwitchEvent::kind`]: a direct mode-flip event (migration among `p2p_direct` ↔ `hub_relay` /
/// `direct_pending`, including demotion back to relay and re-promotion).
pub const SWITCH_KIND_MODE_FLIP: &str = "mode_flip";

/// Dial request path: `{state_dir}/direct-dial.json`.
pub fn dial_request_path(state_dir: &Path) -> PathBuf {
    state_dir.join("direct-dial.json")
}

/// SEL-002 switch events path: `{state_dir}/direct-switch-events.json`.
pub fn direct_switch_events_path(state_dir: &Path) -> PathBuf {
    state_dir.join("direct-switch-events.json")
}

/// Dial result path: `{state_dir}/direct-dial-result.json`.
pub fn dial_result_path(state_dir: &Path) -> PathBuf {
    state_dir.join("direct-dial-result.json")
}

/// Direct peer view path: `{state_dir}/direct-peers.json`.
pub fn direct_peers_path(state_dir: &Path) -> PathBuf {
    state_dir.join("direct-peers.json")
}

/// The current Unix millis as a string (request/result timestamps, no chrono dependency).
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

/// Clear the dial request (deleted once processed; a missing file counts as success — idempotent).
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

/// Append one SEL-002 switch event (JSON Lines append; events are queryable).
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

/// Read all SEL-002 switch events (missing/corrupt file → empty list; queryable).
pub fn load_switch_events(state_dir: &Path) -> Vec<SwitchEvent> {
    let Ok(raw) = std::fs::read_to_string(direct_switch_events_path(state_dir)) else {
        return Vec::new();
    };
    raw.lines()
        .filter_map(|l| serde_json::from_str::<SwitchEvent>(l).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// Decision log (post-hoc replay for contexts without a console)
// ---------------------------------------------------------------------------

/// Agent decision-log event (JSONL append via [`decision_log_path`]): classify / switch-gate
/// verdicts are booked one by one, so console-less contexts such as the Windows service or
/// schtasks SYSTEM can still replay the reasons and criterion inputs behind demotions/promotions
/// afterwards (2026-11-14 inspection sheet: a diagnostics gap — no file-level replay of the real
/// demote reasons on real machines).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DecisionEvent {
    /// Instant (RFC3339 true UTC; PS 5.1 `Get-Date -UFormat %s` carries a +28800s artifact and is
    /// banned as a source — this field is generated by chrono `Utc`).
    pub ts: String,
    /// The peer's wg public key.
    pub public_key: String,
    /// The peer's name (the display name read from the candidate list).
    pub peer_name: String,
    /// The action: `promote` / `demote` / `hold_relay` / `probe` / `defer`.
    pub action: String,
    /// The mode before the verdict (`p2p_direct` / `direct_pending` / `hub_relay`).
    pub from_mode: String,
    /// The mode after the verdict.
    pub to_mode: String,
    /// The verdict reason (human-readable).
    pub reason: String,
    /// Criterion input: the age of the most recent direct handshake (seconds; a kernel-reading snapshot).
    pub handshake_age_secs: Option<u64>,
    /// Criterion input: the SEL-003 probe-window degradation verdict.
    pub degraded: bool,
    /// The endpoint involved (the promote target / the active face when demoting; empty = none).
    pub endpoint: String,
    /// Criterion input: a probe-window summary of the active path (e.g. `23,31,L,L loss=50% med=27ms`;
    /// `None` when probing is off / not sampled).
    pub probe_window: Option<String>,
}

/// Decision log path: `{state_dir}/agent-decisions.jsonl`.
pub fn decision_log_path(state_dir: &Path) -> PathBuf {
    state_dir.join("agent-decisions.jsonl")
}

/// Per-file size cap for the decision log (beyond it the file rolls to `.jsonl.1`, overwriting the
/// previous roll). One event per line is roughly 300B × one line per peer per cycle, so 8MiB covers weeks.
pub const DECISION_LOG_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Append one decision-log entry (JSON Lines; rolls when over the cap).
pub fn append_decision_event(state_dir: &Path, event: &DecisionEvent) -> std::io::Result<()> {
    append_decision_event_capped(state_dir, event, DECISION_LOG_MAX_BYTES)
}

/// Read all decision-log entries (missing/corrupt file → empty list).
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

/// The current instant as RFC3339 UTC (second precision; the decision-log timestamp convention).
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

        // Result reconciliation: request_id distinguishes different dials.
        let res = DirectDialResult {
            request_id: "req-1".into(),
            ok: true,
            mode: "p2p_direct".into(),
            message: "direct link established".into(),
            finished_at: "2000".into(),
        };
        write_result(&dir, &res).unwrap();
        assert_eq!(load_result(&dir), Some(res));

        // Clearing the request is idempotent (a missing file also succeeds).
        clear_request(&dir).unwrap();
        assert_eq!(load_request(&dir), None);
        clear_request(&dir).unwrap();

        // Missing/corrupt file -> None (the caller treats it as "no dial pending").
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
            device_id: "d-b".into(),
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
        // Events are queryable: ordering matches the append order.
        assert_eq!(load_switch_events(&dir), vec![e1, e2]);
        // Missing file -> empty.
        assert!(load_switch_events(&dir.join("missing")).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn switch_event_parses_legacy_lines_without_new_fields() {
        // Legacy event lines (no kind/detail/ts) must still parse as-is — a backward-compatibility red line.
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

        // Rotation: once the cap is exceeded the old content moves wholesale to .jsonl.1 and the main file starts fresh.
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
        // True UTC (ends in Z, no +28800 offset artifact), round-trippable by a standard parser.
        assert!(ts.ends_with('Z'), "ts={ts}");
        assert!(chrono::DateTime::parse_from_rfc3339(&ts).is_ok());
    }
}
