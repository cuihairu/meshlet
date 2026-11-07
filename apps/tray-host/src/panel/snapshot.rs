use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::html;

/// 读一个 JSON 文件；缺失 / 损坏 → `None`（面板按「无数据」渲染，不 panic）。
pub(crate) fn read_json(path: &Path) -> Option<serde_json::Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// 面板快照：render（服务端预渲染 HTML）与 state_json（局部更新数据源）
/// 的**唯一**数据源——两路同源，页面上任一单元格都能被 JS 用同一个键 diff。
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
    // 「账本不可用」（文件缺失/损坏）与「账本可用但没有路由」是两回事，文案分开。
    let ledger_ok = ledger.is_some();
    let applied = ledger.unwrap_or_else(|| serde_json::json!({}));

    let raw_state = status.get("state").and_then(|v| v.as_str());
    let (state, dot) = html::state_and_dot(raw_state);
    // 状态行同时给中文口径与 agent 的原始 state 串（与控制台/CLI 措辞对齐）。
    let state_line = match raw_state {
        Some(raw) => format!("{state}（{raw}）"),
        None => state.clone(),
    };
    // 缺失 / 非字符串 = 数据不可用，不推断 agent 干了什么。
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

/// 局部更新数据源：`GET /state.json` 的响应体（与页面同一快照函数）。
pub fn state_json(state_dir: &Path) -> String {
    serde_json::to_string(&snapshot(state_dir)).unwrap_or_else(|_| "{}".into())
}

fn peers_snapshot(state_dir: &Path) -> PeersSnapshot {
    let views = match read_json(&state_dir.join("direct-peers.json")) {
        Some(serde_json::Value::Array(items)) => items,
        // 缺失 / 损坏 / 形状不符：**不能**说成「没有直连节点」，只能说数据不可用
        //（面板照样出，不阻塞另两块）。
        _ => {
            let html = html::empty_row(7, "（直连节点数据不可用 — direct-peers.json 缺失或损坏）");
            return PeersSnapshot {
                rows: Vec::new(),
                html,
            };
        }
    };
    if views.is_empty() {
        // 文件在、也是数组，只是没记录 —— 这才是「没有节点记录」。
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
            // RTT 来源：agent 探测结果（overlay / endpoint / unreachable）；
            // 字段缺失（旧 agent / 无直连路径）按「未测」标注。
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
            // 公钥整串展示（`direct-peers.json` 全量口径）：长串靠 CSS 断行。
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

/// 当前 Unix 秒（时钟回拨 / 无 epoch 时按 0 处理，展示层不 panic）。
pub(super) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Unix 秒 → 「N 秒前 / N 分钟前 / N 小时前」（超过 3 天显示「—」防误读）。
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

/// ③ 本地路由数据行 + 说明。优先 `last_good_plan.routes`（服务端下发计划的
/// 本机改写版），缺省回落账本 `routes` 前缀（旧账本 / 计划段缺失时仍能展示）。
fn route_rows(applied: &serde_json::Value, ledger_ok: bool) -> (Vec<RouteRow>, String) {
    // 「应用于 <时间>」只在真有时间戳时才这么说（`applied.json` 缺失时只是
    // 占位符，不能拿它当一次应用事件）。
    let applied_at = applied
        .get("applied_at")
        .and_then(|v| v.as_str())
        .filter(|t| !t.is_empty() && *t != "—");
    let time_clause = match applied_at {
        Some(t) => format!("应用于 {t}"),
        None => "无应用时间".to_string(),
    };
    // `AgentState.last_good_plan` 是 `Option<DevicePlan>`，序列化为 `null` 是
    // 合法形状（旧账本 / 未应用过计划）——必须按「是对象」判，`Some(Null)`
    // 会把账本里的路由整段藏掉。
    let plan = applied.get("last_good_plan").filter(|p| p.is_object());

    if let Some(plan) = plan {
        let revision = plan
            .get("desired_revision")
            .and_then(|r| r.as_u64())
            .map(|r| format!("计划修订 rev{r}"))
            .unwrap_or_else(|| "服务端计划".into());
        let caption = format!("{revision} · 账本 applied.json · {time_clause}");
        match plan.get("routes").and_then(|r| r.as_array()) {
            // 计划**已应用**且显式没有路由项（纯叶子节点，真机 imac 即此形态）：
            // 如实说「计划没下发路由」，绝不能说成「agent 尚未应用计划」。
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
                        // 「直连」只留给显式 `null`（RouteConfig 的 Option 序列化）；
                        // 字段缺失 / 形状不对一律 `—`，不猜成直连路由。
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
            // `routes` 缺失 / 形状不对：不猜「计划没下发路由」，落到账本分支。
            None => {}
        }
    }

    if !ledger_ok {
        // 账本根本读不到（缺失 / 损坏）——与「账本可用但没有路由」分开陈述。
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
        // 字段缺失 / 形状不对（`null`、`{}`、`"invalid"`）：不能说「没有路由记录」。
        Some(serde_json::Value::Array(items)) if items.is_empty() => {
            // 真的是空数组 + 账本可读：陈述账本事实，不反推有没有应用过计划。
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
