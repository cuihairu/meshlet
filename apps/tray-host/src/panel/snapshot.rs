use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::html;

/// Reads a JSON file; missing / corrupted -> `None` (the panel renders "no data" and does not panic).
pub(crate) fn read_json(path: &Path) -> Option<serde_json::Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Panel snapshot: the **single** source of data for render (server-side pre-rendered HTML) and
/// state_json (the partial-update data source) — one source feeds both paths, so any cell on the page can be diffed by JS under the same key.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PanelSnapshot {
    pub node: NodeSnapshot,
    pub peers: PeersSnapshot,
    pub routes: RoutesSnapshot,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NodeSnapshot {
    pub dot: &'static str,
    pub state_display: String,
    pub fields: Vec<(String, String)>,
    pub copy_index: Option<usize>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerRow {
    pub name: String,
    pub ip: String,
    pub mode: String,
    pub rtt: String,
    pub rtt_title: String,
    pub endpoint: String,
    pub handshake: String,
    pub public_key: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub ip_copyable: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PeersSnapshot {
    pub rows: Vec<PeerRow>,
    pub html: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RoutesSnapshot {
    pub caption: String,
    pub rows: Vec<RouteRow>,
    pub html: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(untagged)]
pub enum RouteRow {
    Cells([String; 4]),
    Placeholder(String),
}

pub fn snapshot(state_dir: &Path) -> PanelSnapshot {
    let status = read_json(&state_dir.join("tray").join("status.json"))
        .unwrap_or_else(|| serde_json::json!({}));
    let ledger = read_json(&state_dir.join("applied.json"));
    // "Ledger unavailable" (file missing / corrupt) and "ledger available but no routes" are two different things; keep the wording separate.
    let ledger_ok = ledger.is_some();
    let applied = ledger.unwrap_or_else(|| serde_json::json!({}));

    let raw_state = status.get("state").and_then(|v| v.as_str());
    let (state, dot) = html::state_and_dot(raw_state);
    // The status line carries both the Chinese wording and the agent's raw state string (kept aligned with the console/CLI wording).
    let state_line = match raw_state {
        Some(raw) => format!("{state}（{raw}）"),
        None => state.clone(),
    };
    // Missing / not a string = data unavailable; do not infer what the agent did.
    let tooltip = status
        .get("tooltip")
        .and_then(|v| v.as_str())
        .unwrap_or("状态说明不可用");
    let state_display = format!("{state_line} — {tooltip}");
    let (fields, copy_index) = html::node_fields(state_dir, &status, &applied);
    let peers = peers_snapshot(state_dir);
    let (routes, route_caption) = route_rows(&applied, ledger_ok);
    let routes_html = html::routes_html(&routes);

    PanelSnapshot {
        node: NodeSnapshot {
            dot,
            state_display,
            fields,
            copy_index,
        },
        peers,
        routes: RoutesSnapshot {
            caption: route_caption,
            rows: routes,
            html: routes_html,
        },
    }
}

/// Partial-update data source: the response body of `GET /state.json` (the same snapshot function as the page).
pub fn state_json(state_dir: &Path) -> String {
    serde_json::to_string(&snapshot(state_dir)).unwrap_or_else(|_| "{}".into())
}

fn peers_snapshot(state_dir: &Path) -> PeersSnapshot {
    let views = match read_json(&state_dir.join("direct-peers.json")) {
        Some(serde_json::Value::Array(items)) => items,
        // Missing / corrupt / wrong shape: it must **not** be reported as "no direct nodes", only as data unavailable
        //(the panel still renders, without blocking the other two blocks).
        _ => {
            let html = html::empty_row(7, "（直连节点数据不可用 — direct-peers.json 缺失或损坏）");
            return PeersSnapshot {
                rows: Vec::new(),
                html,
            };
        }
    };
    if views.is_empty() {
        // The file exists and is an array, just with no records — this is what "no node records" really means.
        let html = html::empty_row(7, "（没有节点记录）");
        return PeersSnapshot {
            rows: Vec::new(),
            html,
        };
    }
    let rows: Vec<PeerRow> = views
        .iter()
        .map(|v| {
            let name = v
                .get("name")
                .and_then(|x| x.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| "—".into());
            let ip = v
                .get("virtual_ipv4")
                .and_then(|x| x.as_str())
                .unwrap_or("—")
                .to_string();
            let mode = v.get("mode").and_then(|x| x.as_str()).unwrap_or("");
            let rtt_ms = v.get("rtt_ms").and_then(|x| x.as_u64());
            // RTT source: the agent's probe result (overlay / endpoint / unreachable);
            // a missing field (older agent / no direct path) is labeled "not measured".
            let rtt_title = html::rtt_source_label(v.get("rtt_source").and_then(|x| x.as_str()));
            let endpoint = v
                .get("endpoint")
                .and_then(|x| x.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("—")
                .to_string();
            let handshake = v
                .get("last_handshake_at")
                .and_then(|x| x.as_u64())
                .map(age_text)
                .unwrap_or_else(|| "—".into());
            // The public key is shown in full (the full `direct-peers.json` view): long strings wrap via CSS.
            let public_key = v
                .get("public_key")
                .and_then(|x| x.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("—")
                .to_string();
            PeerRow {
                name,
                ip_copyable: ip != "—",
                ip,
                mode: html::mode_label(mode).into(),
                rtt: match rtt_ms {
                    Some(ms) => format!("{ms} ms"),
                    None => "—".into(),
                },
                rtt_title: rtt_title.to_string(),
                endpoint,
                handshake,
                public_key,
            }
        })
        .collect();
    let html = rows
        .iter()
        .enumerate()
        .map(|(i, row)| html::peer_row_html(i, row))
        .collect();
    PeersSnapshot { rows, html }
}

/// Current Unix seconds (clock rollback / no epoch is treated as 0; the display layer does not panic).
pub(super) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Unix seconds -> "N seconds / minutes / hours ago" (beyond 3 days it shows "—" to avoid misreading).
pub(super) fn age_text(unix_secs: u64) -> String {
    let now = now_secs();
    if unix_secs > now {
        return "—".into();
    }
    let age = now - unix_secs;
    match age {
        0..=90 => format!("{age} 秒前"),
        91..=5_400 => format!("{} 分钟前", age / 60),
        5_401..=172_800 => format!("{} 小时前", age / 3_600),
        _ => "—".into(),
    }
}

/// ③ Local route rows + caption. Prefers `last_good_plan.routes` (the machine-local rewrite of the
/// server-issued plan); when absent it falls back to the ledger `routes` prefixes (still displayable with an old ledger / a missing plan section).
fn route_rows(applied: &serde_json::Value, ledger_ok: bool) -> (Vec<RouteRow>, String) {
    // Say "applied at <time>" only when there is a real timestamp (when `applied.json` is missing it is
    // just a placeholder, and must not be treated as an apply event).
    let applied_at = applied
        .get("applied_at")
        .and_then(|v| v.as_str())
        .filter(|t| !t.is_empty() && *t != "—");
    let time_clause = match applied_at {
        Some(t) => format!("应用于 {t}"),
        None => "无应用时间".to_string(),
    };
    // `AgentState.last_good_plan` is an `Option<DevicePlan>`; a serialized `null` is a legal
    // shape (an old ledger / a plan never applied) — it must be tested by "is an object", since `Some(Null)`
    // would hide the whole routes section of the ledger.
    let plan = applied.get("last_good_plan").filter(|p| p.is_object());

    if let Some(plan) = plan {
        let revision = plan
            .get("desired_revision")
            .and_then(|r| r.as_u64())
            .map(|r| format!("计划修订 rev{r}"))
            .unwrap_or_else(|| "服务端计划".into());
        let caption = format!("{revision} · 账本 applied.json · {time_clause}");
        match plan.get("routes").and_then(|r| r.as_array()) {
            // The plan **is applied** yet explicitly carries no route entries (a pure leaf node; the
            // real machine imac is exactly this shape): say truthfully "the plan issued no routes", never "the agent has not applied a plan yet".
            Some(routes) if routes.is_empty() => {
                return (
                    vec![RouteRow::Placeholder("（计划未下发任何路由项）".into())],
                    caption,
                );
            }
            Some(routes) => {
                let rows = routes
                    .iter()
                    .map(|r| {
                        let dest = r
                            .get("destination")
                            .and_then(|d| d.as_str())
                            .unwrap_or("—")
                            .to_string();
                        let iface = r
                            .get("interface")
                            .and_then(|i| i.as_str())
                            .unwrap_or("—")
                            .to_string();
                        // "Direct" is reserved for an explicit `null` (the Option serialization of RouteConfig);
                        // a missing field / wrong shape always gets `—`, never guessed into a direct route.
                        let next_hop = match r.get("gateway") {
                            Some(serde_json::Value::String(g)) => g.clone(),
                            Some(serde_json::Value::Null) => format!("直连（{iface}）"),
                            _ => "—".to_string(),
                        };
                        [
                            dest,
                            next_hop,
                            iface,
                            "服务端计划 · applied.json".to_string(),
                        ]
                    })
                    .map(RouteRow::Cells)
                    .collect();
                return (rows, caption);
            }
            // `routes` missing / wrong shape: do not guess "the plan issued no routes"; fall through to the ledger branch.
            None => {}
        }
    }

    if !ledger_ok {
        // The ledger is entirely unreadable (missing / corrupt) — stated separately from "ledger available but no routes".
        return (
            vec![RouteRow::Placeholder(
                "（本地账本不可用 — applied.json 缺失或损坏）".into(),
            )],
            "本地账本不可用".to_string(),
        );
    }
    let caption = format!("本地账本 applied.json · {time_clause}");
    let prefixes = match applied.get("routes") {
        Some(serde_json::Value::Array(items)) if !items.is_empty() => items.clone(),
        // Field missing / wrong shape (`null`, `{}`, `"invalid"`): must not be stated as "no route records".
        Some(serde_json::Value::Array(items)) if items.is_empty() => {
            // A genuinely empty array + a readable ledger: state the ledger fact, do not infer backwards whether a plan was ever applied.
            let _ = items;
            return (
                vec![RouteRow::Placeholder("（本地账本没有路由记录）".into())],
                caption,
            );
        }
        _ => {
            return (
                vec![RouteRow::Placeholder("（本地账本路由数据不可用）".into())],
                caption,
            )
        }
    };
    let rows = prefixes
        .iter()
        .map(|p| {
            let dest = p.as_str().unwrap_or("—").to_string();
            RouteRow::Cells([
                dest,
                "—".to_string(),
                "—".to_string(),
                "本地账本 · applied.json".to_string(),
            ])
        })
        .collect();
    (rows, caption)
}
