use std::path::Path;

use super::runtime::config_value;
use super::snapshot::{snapshot, PeerRow, RouteRow};

/// Page partial-update polling interval (seconds). The page fetches `/state.json` on this interval and
/// patches only the changed cells — no more full-page reloads (no flicker; scroll/focus is preserved).
/// Page partial-update polling interval (seconds). The page fetches `/state.json` on this interval and
/// patches only the changed cells — no more full-page reloads (no flicker; scroll/focus is preserved).
pub const REFRESH_SECS: u32 = 5;
/// Failing to measure RTT from both overlay/endpoint does not mean the link is dead (WireGuard often
/// does not answer ICMP). Four truthful states (new agent): probe_ok / handshake_fresh / probe_failed / unprobed;
/// overlay / endpoint / unreachable are historical values persisted by older agents — their mapping is kept for compatibility.
pub(super) fn rtt_source_label(source: Option<&str>) -> &'static str {
    match source {
        Some("probe_ok") => "来源：直连路径实测（overlay/endpoint ping 成功）",
        Some("handshake_fresh") => "来源：握手新鲜（对端不答 ICMP，最近握手即链路活性证据）",
        Some("probe_failed") | Some("unreachable") => {
            "来源：不可测（overlay 与 endpoint 均无响应，以「最近握手」为活性证据）"
        }
        Some("overlay") => "来源：overlay 实测（对端 overlay VIP 直测）",
        Some("endpoint") => "来源：endpoint 实测（overlay 不通，回退 underlay endpoint）",
        _ => "来源：未测（对端无直连路径或探测尚未完成）",
    }
}

/// HTML for one direct-peer row (the same source as `PeersSnapshot::html`; `data-f` keys let JS diff it).
pub(super) fn peer_row_html(index: usize, row: &PeerRow) -> String {
    let button = if row.ip_copyable {
        copy_button_html(&row.ip)
    } else {
        String::new()
    };
    format!(
        "<tr><td><span data-f=\"peer.{i}.name\">{name}</span></td>\
         <td class=\"mono\"><span data-f=\"peer.{i}.ip\">{ip}</span>{button}</td>\
         <td><span data-f=\"peer.{i}.mode\">{mode}</span></td>\
         <td class=\"mono\" title=\"{rtt_title}\"><span data-f=\"peer.{i}.rtt\">{rtt}</span></td>\
         <td class=\"mono\"><span data-f=\"peer.{i}.endpoint\">{endpoint}</span></td>\
         <td class=\"mono\"><span data-f=\"peer.{i}.handshake\">{handshake}</span></td>\
         <td class=\"mono key\"><span data-f=\"peer.{i}.key\">{key}</span></td></tr>",
        i = index,
        name = esc(&row.name),
        ip = esc(&row.ip),
        button = button,
        mode = esc(&row.mode),
        rtt_title = esc(&row.rtt_title),
        rtt = esc(&row.rtt),
        endpoint = esc(&row.endpoint),
        handshake = esc(&row.handshake),
        key = esc(&row.public_key),
    )
}

/// HTML for one local-route row (`rows[i]` = [destination prefix, next hop, interface, source]).
fn route_row_html(index: usize, cells: &[String; 4]) -> String {
    format!(
        "<tr><td class=\"mono\"><span data-f=\"routes.{i}.dest\">{dest}</span></td>\
         <td class=\"mono\"><span data-f=\"routes.{i}.next\">{next}</span></td>\
         <td class=\"mono\"><span data-f=\"routes.{i}.iface\">{iface}</span></td>\
         <td><span data-f=\"routes.{i}.src\">{src}</span></td></tr>",
        i = index,
        dest = esc(&cells[0]),
        next = esc(&cells[1]),
        iface = esc(&cells[2]),
        src = esc(&cells[3]),
    )
}

/// HTML for the whole route table (placeholder rows and data rows are both produced here).
pub(super) fn routes_html(rows: &[RouteRow]) -> String {
    rows.iter()
        .enumerate()
        .map(|(i, row)| match row {
            RouteRow::Cells(cells) => route_row_html(i, cells),
            RouteRow::Placeholder(message) => empty_row(4, message),
        })
        .collect()
}

/// Renders the full page HTML (read and rendered fresh on every request, no cache; the initial
/// pre-render plus the inline snapshot give JS the partial-update baseline, and the three blocks stay visible without JS).
pub fn render(state_dir: &Path) -> String {
    let snap = snapshot(state_dir);

    let console_link = config_value(state_dir, "server_url").map(|server_url| {
        format!(
            "<p class=\"console\"><a href=\"{url}\">控制台（网页）↗</a></p>",
            url = esc(&server_url)
        )
    });
    let console_link = console_link.unwrap_or_default();

    // Current-node field table (pre-rendered server-side, the same data as state.json).
    let node_rows: String = snap
        .node
        .fields
        .iter()
        .enumerate()
        .map(|(i, (label, value))| {
            // The copy button is attached only to rows carrying a real value (currently the virtual IP only); it is the only
            // non-escaped fragment, and its data-copy attribute value is escaped inside copy_button_html.
            let button = snap
                .node
                .copy_index
                .filter(|ci| *ci == i)
                .map(|_| copy_button_html(value))
                .unwrap_or_default();
            format!(
                "<tr><th>{label}</th><td class=\"mono\"><span data-f=\"node.{i}\">{value}</span>{button}</td></tr>",
                label = esc(label),
                value = esc(value),
                button = button,
            )
        })
        .collect();

    // Inline initial snapshot: the JS diff baseline (the `<` is escaped so `</script>` cannot close the tag early;
    // HTML does not parse entities inside script content, and JSON.parse takes `<`).
    let seed = serde_json::to_string(&snap)
        .unwrap_or_else(|_| "{}".into())
        .replace('<', "\\u003c");

    format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Meshlet 本地面板</title>
<style>
:root {{ color-scheme: dark; }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; padding: 24px; background: #14171a; color: #e6e8ea;
  font: 14px/1.6 system-ui, "Segoe UI", "Microsoft YaHei", sans-serif; }}
header {{ display: flex; flex-wrap: wrap; gap: 8px 16px; align-items: baseline;
  justify-content: space-between; margin-bottom: 20px; }}
h1 {{ font-size: 20px; margin: 0; }}
.sub {{ margin: 0; color: #98a2ab; font-size: 12px; }}
.console a {{ color: #e0a458; text-decoration: none; font-size: 13px; }}
section {{ background: #1c2126; border: 1px solid #2a3138; border-radius: 10px;
  padding: 16px 18px; margin-bottom: 16px; }}
h2 {{ font-size: 15px; margin: 0 0 10px; color: #f0f2f4; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th, td {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid #262c33;
  vertical-align: top; }}
th {{ color: #98a2ab; font-weight: 600; white-space: nowrap; }}
tr:last-child td {{ border-bottom: none; }}
code, .mono {{ font-family: ui-monospace, Consolas, monospace; }}
.key {{ word-break: break-all; font-size: 12px; color: #b9c2ca; }}
.copy {{ margin-left: 8px; padding: 1px 8px; font-size: 12px; cursor: pointer;
  background: #262c33; color: #b9c2ca; border: 1px solid #3a424b; border-radius: 6px; }}
.copy:hover {{ background: #31383f; color: #e6e8ea; }}
.copy.copied {{ background: #1d3a2a; color: #6fd08c; border-color: #2f5e42; }}
.dot {{ display: inline-block; width: 10px; height: 10px; border-radius: 50%;
  margin-right: 6px; vertical-align: middle; }}
.caption {{ color: #98a2ab; font-size: 12px; margin: 0 0 8px; }}
.empty {{ color: #98a2ab; font-style: italic; }}
footer {{ color: #6f7a83; font-size: 12px; margin-top: 8px; }}
</style>
</head>
<body>
<header>
  <h1>Meshlet 本地面板</h1>
  <p class="sub">本机自托管 · 数据来自本机状态文件 · 不依赖服务端可达 · 每 {refresh} 秒局部更新（不整页刷新）</p>
  {console_link}
</header>
<main>
<section id="node">
  <h2>当前节点</h2>
  <p class="caption"><span class="dot" id="node-dot" data-dot="{dot}" style="background:{dot}"></span><span data-f="node-state">{state_display}</span></p>
  <table><tbody id="node-body">{node_rows}</tbody></table>
</section>
<section id="direct">
  <h2>直连节点</h2>
  <table>
    <tr><th>名称</th><th>Overlay IP</th><th>链路模式</th><th>RTT</th><th>Endpoint</th><th>最近握手</th><th>公钥</th></tr>
    <tbody id="peers-body">{peers_html}</tbody>
  </table>
</section>
<section id="routes">
  <h2>本地路由</h2>
  <p class="caption"><span data-f="routes-caption">{route_caption}</span></p>
  <table>
    <tr><th>目标网段</th><th>下一跳</th><th>接口</th><th>来源</th></tr>
    <tbody id="routes-body">{routes_html}</tbody>
  </table>
</section>
</main>
<footer>数据源：tray/status.json · direct-peers.json · applied.json · agent.toml（{state_dir}）</footer>
<script type="application/json" id="panel-state">{seed}</script>
<script>
// Partial updates: every {refresh}s fetch /state.json and JSON-diff against the
// inline snapshot — only changed values patch the matching cell (preserving
// scroll / focus / copy-button state); the tbody is replaced wholesale only when
// the row count changes (node add/remove / placeholder switch). Never location.reload.
(function () {{
  var INTERVAL = {refresh} * 1000;
  var last = null;
  function setText(key, text) {{
    var el = document.querySelector('[data-f="' + key + '"]');
    if (el && el.textContent !== text) {{ el.textContent = text; }}
  }}
  function applyNode(n) {{
    var dot = document.getElementById('node-dot');
    if (dot && dot.getAttribute('data-dot') !== n.dot) {{
      dot.setAttribute('data-dot', n.dot);
      dot.style.background = n.dot;
    }}
    setText('node-state', n.state_display);
    for (var i = 0; i < n.fields.length; i++) {{ setText('node.' + i, n.fields[i][1]); }}
  }}
  function applyPeers(p) {{
    var body = document.getElementById('peers-body');
    if (!body) {{ return; }}
    if (body.children.length !== p.rows.length) {{ body.innerHTML = p.html; return; }}
    for (var i = 0; i < p.rows.length; i++) {{
      var r = p.rows[i];
      setText('peer.' + i + '.name', r.name);
      setText('peer.' + i + '.ip', r.ip);
      setText('peer.' + i + '.mode', r.mode);
      setText('peer.' + i + '.rtt', r.rtt);
      setText('peer.' + i + '.endpoint', r.endpoint);
      setText('peer.' + i + '.handshake', r.handshake);
      setText('peer.' + i + '.key', r.key);
      var span = document.querySelector('[data-f="peer.' + i + '.rtt"]');
      if (span && span.parentNode && span.parentNode.getAttribute('title') !== r.rtt_title) {{
        span.parentNode.setAttribute('title', r.rtt_title);
      }}
    }}
  }}
  function applyRoutes(rs) {{
    setText('routes-caption', rs.caption);
    var body = document.getElementById('routes-body');
    if (!body) {{ return; }}
    if (body.children.length !== rs.rows.length) {{ body.innerHTML = rs.html; return; }}
    for (var i = 0; i < rs.rows.length; i++) {{
      if (typeof rs.rows[i] === 'string') {{ continue; }} // placeholder row, no diff
      setText('routes.' + i + '.dest', rs.rows[i][0]);
      setText('routes.' + i + '.next', rs.rows[i][1]);
      setText('routes.' + i + '.iface', rs.rows[i][2]);
      setText('routes.' + i + '.src', rs.rows[i][3]);
    }}
  }}
  function poll() {{
    fetch('/state.json', {{ cache: 'no-store' }}).then(function (res) {{
      if (!res.ok) {{ throw new Error('HTTP ' + res.status); }}
      return res.json();
    }}).then(function (state) {{
      if (last && JSON.stringify(state) !== JSON.stringify(last)) {{
        applyNode(state.node);
        applyPeers(state.peers);
        applyRoutes(state.routes);
      }}
      last = state;
    }}).catch(function () {{
      // A failed fetch retries next cycle (the panel's data path is read-only on
      // this machine, so a failure is not fatal).
    }});
  }}
  var seed = document.getElementById('panel-state');
  if (seed) {{ try {{ last = JSON.parse(seed.textContent); }} catch (e) {{ last = null; }} }}
  setInterval(poll, INTERVAL);

  // Copy button: pure client-side behavior, no new network requests (the panel
  // stays a read-only GET/HEAD page). Event delegation — the buttons keep
  // working after JS rebuilds the rows; when navigator.clipboard is unavailable
  // it falls back to execCommand, and if that fails too it gives a "copy failed"
  // feedback.
  function flash(button, ok) {{
    button.classList.add('copied');
    button.textContent = ok ? '已复制' : '复制失败';
    setTimeout(function () {{
      button.classList.remove('copied');
      button.textContent = '复制';
    }}, 1500);
  }}
  function fallbackCopy(text) {{
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try {{ ok = document.execCommand('copy'); }} catch (e) {{}}
    document.body.removeChild(ta);
    return ok;
  }}
  document.addEventListener('click', function (event) {{
    var target = event.target;
    var button = target && target.closest ? target.closest('button.copy') : null;
    if (!button) {{ return; }}
    var text = button.getAttribute('data-copy');
    if (navigator.clipboard && navigator.clipboard.writeText) {{
      navigator.clipboard.writeText(text).then(
        function () {{ flash(button, true); }},
        function () {{ flash(button, fallbackCopy(text)); }}
      );
    }} else {{
      flash(button, fallbackCopy(text));
    }}
  }});
}})();
</script>
</body>
</html>
"#,
        refresh = REFRESH_SECS,
        dot = snap.node.dot,
        state_display = esc(&snap.node.state_display),
        node_rows = node_rows,
        peers_html = snap.peers.html,
        route_caption = esc(&snap.routes.caption),
        routes_html = snap.routes.html,
        console_link = console_link,
        seed = seed,
        state_dir = esc(&state_dir.display().to_string()),
    )
}

/// Minimal page for 404 / 405 (also uncached).
pub(super) fn error_page(message: &str) -> String {
    format!(
        "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">\
         <title>Meshlet 本地面板</title></head><body><p>{message}</p>\
         <p><a href=\"/\">返回本地面板</a></p></body></html>",
        message = esc(message)
    )
}

/// Status string -> (display name, status light color). Color is a second channel; the text is always present (never color alone).
pub(crate) fn state_and_dot(state: Option<&str>) -> (String, &'static str) {
    match state {
        Some("Meshlet online") => ("在线".into(), "#c97b2e"),
        Some("Meshlet tunnel only") => ("仅隧道".into(), "#e4a03c"),
        Some("Meshlet tunnel drift") => ("隧道异常".into(), "#c0392b"),
        Some("Meshlet offline") => ("已断开".into(), "#78828a"),
        Some(other) => (other.into(), "#78828a"),
        None => ("未知".into(), "#78828a"),
    }
}

/// Status -> hub / control-channel wording (the existing semantics of the four tray states, see `agent::tray::TrayState`).
///
/// `TunnelDrift` is judged in `TrayState::derive` **before** `control_ok` (tunnel drift takes
/// precedence), so for that state one cannot tell whether the control channel is up — mark it truthfully
/// as "unknown"; never present a kernel drift as a hub disconnect.
pub(crate) fn hub_status(state: Option<&str>) -> &'static str {
    match state {
        Some("Meshlet online") => "已连接（控制通道正常）",
        Some("Meshlet tunnel only") => "仅隧道（控制通道失效，agent 上报过期）",
        Some("Meshlet tunnel drift") => "未知（隧道异常优先判定，控制通道状态未单独上报）",
        Some("Meshlet offline") => "已断开（无新鲜的控制通道或隧道证据）",
        Some(_) => "未知（agent 上报了未识别状态）",
        None => "未知（状态不可用）",
    }
}

/// HTML for the copy button (the `data-copy` value must be `esc`-ed first — it comes from local
/// state files and must never inject markup beyond an attribute).
pub(crate) fn copy_button_html(value: &str) -> String {
    format!(
        "<button type=\"button\" class=\"copy\" data-copy=\"{value}\">复制</button>",
        value = esc(value)
    )
}

/// ① Current-node fields (label, value), plus the index of the row carrying the copy button.
pub(super) fn node_fields(
    state_dir: &Path,
    status: &serde_json::Value,
    applied: &serde_json::Value,
) -> (Vec<(String, String)>, Option<usize>) {
    let mut rows: Vec<(String, String)> = Vec::new();
    // The copy value for the virtual IP: the copy button is emitted only when there is a real value (a "—" placeholder has nothing to copy).
    let mut copy_index: Option<usize> = None;

    // Device name: agent.toml first, then the tooltip's "…" span, and unknown as the last resort.
    let device_name = config_value(state_dir, "device_name").unwrap_or_else(|| {
        tooltip_name(
            status
                .get("tooltip")
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
        )
        .unwrap_or_else(|| "unknown".into())
    });
    rows.push(("设备名".into(), device_name));

    let tunnel_address = applied
        .get("tunnel_address")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let tunnel_cell = match &tunnel_address {
        Some(ip) => {
            copy_index = Some(rows.len());
            ip.clone()
        }
        None => "—".into(),
    };
    rows.push(("虚拟 IP".into(), tunnel_cell));

    let pubkey = applied
        .get("local_public_key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(short_key)
        .unwrap_or_else(|| "—（agent 未记录公钥指纹）".into());
    rows.push(("节点公钥指纹".into(), pubkey));

    let state = status.get("state").and_then(|v| v.as_str());
    rows.push(("hub / 控制通道".into(), hub_status(state).into()));

    let agent_version = status
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("未知（agent 未上报，可能早于本地面板版本）");
    rows.push((
        "版本".into(),
        format!(
            "agent {agent_version} · 面板 meshlet-tray-host {panel}",
            panel = env!("CARGO_PKG_VERSION")
        ),
    ));

    rows.push((
        "状态更新时间".into(),
        status
            .get("updated_at")
            .and_then(|v| v.as_str())
            .unwrap_or("—")
            .into(),
    ));
    rows.push((
        "计划应用时间".into(),
        applied
            .get("applied_at")
            .and_then(|v| v.as_str())
            .unwrap_or("—")
            .into(),
    ));
    rows.push((
        "控制台".into(),
        config_value(state_dir, "server_url").unwrap_or_else(|| "—".into()),
    ));

    // Key EnvProbe items: the `env` from status.json (reported by the agent) first, falling back to this
    // process's environment — the tray host and the agent share the logged-in user session, so the readings come from the same source.
    for (label, value) in env_rows(status.get("env")) {
        rows.push((label, value));
    }

    (rows, copy_index)
}

/// The device name inside the tooltip "Meshlet「name」 ip：…".
fn tooltip_name(tooltip: &str) -> Option<String> {
    let start = tooltip.find('「')? + '「'.len_utf8();
    let rest = &tooltip[start..];
    let end = rest.find('」')?;
    let name = &rest[..end];
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Abbreviates a public key fingerprint: the first 20 characters + `…` (the full string is useless to humans and should not fill the table).
pub(crate) fn short_key(key: &str) -> String {
    if key.chars().count() <= 20 {
        key.to_string()
    } else {
        let head: String = key.chars().take(20).collect();
        format!("{head}…")
    }
}

/// Key EnvProbe items (`env` is the object reported by the agent; falling back to this process's environment when absent).
fn env_rows(env: Option<&serde_json::Value>) -> Vec<(String, String)> {
    let text = |value: Option<&serde_json::Value>| -> String {
        value
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| "—".into())
    };
    if let Some(obj) = env.and_then(|v| v.as_object()) {
        let get = |k: &str| obj.get(k);
        let console = match get("console_session").and_then(|v| v.as_bool()) {
            Some(true) => "是",
            Some(false) => "否",
            None => "—",
        };
        return vec![
            ("XDG_SESSION_TYPE".into(), text(get("session_type"))),
            ("DISPLAY (X11)".into(), text(get("display"))),
            ("WAYLAND_DISPLAY".into(), text(get("wayland_display"))),
            ("SESSIONNAME (Windows)".into(), text(get("session_name"))),
            ("活动控制台会话".into(), console.into()),
        ];
    }
    vec![
        (
            "XDG_SESSION_TYPE".into(),
            std::env::var("XDG_SESSION_TYPE").unwrap_or_else(|_| "—".into()),
        ),
        (
            "DISPLAY (X11)".into(),
            std::env::var("DISPLAY").unwrap_or_else(|_| "—".into()),
        ),
        (
            "WAYLAND_DISPLAY".into(),
            std::env::var("WAYLAND_DISPLAY").unwrap_or_else(|_| "—".into()),
        ),
        (
            "SESSIONNAME (Windows)".into(),
            std::env::var("SESSIONNAME").unwrap_or_else(|_| "—".into()),
        ),
    ]
}

/// A direct mode -> a short Chinese label (unknown modes are shown as-is; no data swallowed).
pub fn mode_label(mode: &str) -> &str {
    match mode {
        "p2p_direct" => "直连",
        "direct_pending" => "拨号中",
        "hub_relay" => "中继",
        other => other,
    }
}

/// The empty-table placeholder row.
pub(super) fn empty_row(cols: usize, message: &str) -> String {
    format!(
        "<tr><td colspan=\"{cols}\" class=\"empty\">{message}</td></tr>",
        cols = cols,
        message = esc(message)
    )
}

/// HTML escaping (device names / tooltips all come from the server or config and must be escaped before going into the page).
pub(super) fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests;
