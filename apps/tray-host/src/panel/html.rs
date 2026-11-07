use std::path::Path;

use super::runtime::config_value;
use super::snapshot::{snapshot, PeerRow, RouteRow};

/// 页面局部更新轮询间隔（秒）。页面每间隔 `fetch /state.json`，值有变才
/// patch 对应单元格——不再整页重载（无闪屏、滚动/焦点不丢）。
/// 页面局部更新轮询间隔（秒）。页面每间隔 `fetch /state.json`，值有变才
/// patch 对应单元格——不再整页重载（无闪屏、滚动/焦点不丢）。
pub const REFRESH_SECS: u32 = 5;
/// overlay/endpoint 都测不出 RTT 不代表链路死了（WireGuard 常不答 ICMP）。
/// 如实四态（新 agent）：probe_ok / handshake_fresh / probe_failed / unprobed；
/// overlay / endpoint / unreachable 是旧 agent 落盘的历史值，保留映射兼容。
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

/// 直连节点单行 HTML（与 `PeersSnapshot::html` 同源；`data-f` 键供 JS diff）。
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

/// 本地路由单行 HTML（`rows[i]` = [目标网段, 下一跳, 接口, 来源]）。
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

/// 路由表整段 HTML（占位行与数据行都由此生成）。
pub(super) fn routes_html(rows: &[RouteRow]) -> String {
    rows.iter()
        .enumerate()
        .map(|(i, row)| match row {
            RouteRow::Cells(cells) => route_row_html(i, cells),
            RouteRow::Placeholder(message) => empty_row(4, message),
        })
        .collect()
}

/// 渲染整页 HTML（每次请求现读现渲染，无缓存；初始预渲染 + 内联快照供
/// JS 做局部更新基线，无 JS 时三块照常可见）。
pub fn render(state_dir: &Path) -> String {
    let snap = snapshot(state_dir);

    let console_link = config_value(state_dir, "server_url").map(|server_url| {
        format!(
            "<p class=\"console\"><a href=\"{url}\">控制台（网页）↗</a></p>",
            url = esc(&server_url)
        )
    });
    let console_link = console_link.unwrap_or_default();

    // 当前节点字段表（服务端预渲染，与 state.json 同一数据）。
    let node_rows: String = snap
        .node
        .fields
        .iter()
        .enumerate()
        .map(|(i, (label, value))| {
            // 复制按钮只挂在携带真值的行（当前仅虚拟 IP）；按钮是仅有的
            // 非转义片段，其 data-copy 属性值在 copy_button_html 内转义。
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

    // 内联初始快照：JS 的 diff 基线（`<` 转义防 `</script>` 提前闭合；
    // HTML 不解析 script 内容里的实体，JSON.parse 吃 `\u003c`）。
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
// 局部更新：每 {refresh}s fetch /state.json，与内联快照做 JSON diff——
// 值有变才 patch 对应单元格（保留滚动 / 焦点 / 复制钮状态）；行数变化
// （节点增删 / 占位切换）才整体替换 tbody。绝不 location.reload。
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
      if (typeof rs.rows[i] === 'string') {{ continue; }} // 占位行，不 diff
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
      // 拉取失败下个周期重试（面板数据链路只读本机，失败不致命）。
    }});
  }}
  var seed = document.getElementById('panel-state');
  if (seed) {{ try {{ last = JSON.parse(seed.textContent); }} catch (e) {{ last = null; }} }}
  setInterval(poll, INTERVAL);

  // 复制按钮：纯客户端行为，不新增任何网络请求（面板仍是 GET/HEAD 只读页）。
  // 事件委托——行被 JS 重建后按钮依旧可用；navigator.clipboard 不可用降级
  // execCommand，再不行给出「复制失败」反馈。
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

/// 404 / 405 的极简页（同样不缓存）。
pub(super) fn error_page(message: &str) -> String {
    format!(
        "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">\
         <title>Meshlet 本地面板</title></head><body><p>{message}</p>\
         <p><a href=\"/\">返回本地面板</a></p></body></html>",
        message = esc(message)
    )
}

/// 状态串 →（展示名, 状态灯色）。色是第二通道，文本始终在（不靠颜色）。
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

/// 状态 → hub / 控制通道口径（托盘四态的既有语义，见 `agent::tray::TrayState`）。
///
/// `TunnelDrift` 在 `TrayState::derive` 里**先于** `control_ok` 判定（隧道异常
/// 优先），故该态推不出控制通道是否连着——如实标「未知」，不把内核漂移说成
/// hub 断开。
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

/// 复制按钮 HTML（`data-copy` 值必须先 `esc`——值来自本机状态文件，
/// 不得把文件内容注入成属性外的标记）。
pub(crate) fn copy_button_html(value: &str) -> String {
    format!(
        "<button type=\"button\" class=\"copy\" data-copy=\"{value}\">复制</button>",
        value = esc(value)
    )
}

/// ① 当前节点字段（label, value），及携带复制按钮的行下标。
pub(super) fn node_fields(
    state_dir: &Path,
    status: &serde_json::Value,
    applied: &serde_json::Value,
) -> (Vec<(String, String)>, Option<usize>) {
    let mut rows: Vec<(String, String)> = Vec::new();
    // 虚拟 IP 的复制值：有真值才出复制按钮（占位符「—」没有可复制的东西）。
    let mut copy_index: Option<usize> = None;

    // 设备名：agent.toml 优先，缺省从 tooltip「…」里取，再兜底 unknown。
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

    // EnvProbe 关键项：status.json 的 `env`（agent 上报）优先，缺省回落本进程
    // 环境——托盘宿主与 agent 同处登录用户会话，读数同源。
    for (label, value) in env_rows(status.get("env")) {
        rows.push((label, value));
    }

    (rows, copy_index)
}

/// tooltip「Meshlet「name」 ip：…」里的设备名。
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

/// 公钥指纹缩写：前 20 字符 + `…`（整串对人无用，且不该占满表格）。
pub(crate) fn short_key(key: &str) -> String {
    if key.chars().count() <= 20 {
        key.to_string()
    } else {
        let head: String = key.chars().take(20).collect();
        format!("{head}…")
    }
}

/// EnvProbe 关键项（`env` 为 agent 上报的对象；缺省回落本进程环境）。
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

/// 直连模式 → 中文短名（未知模式原样展示，不吞数据）。
pub fn mode_label(mode: &str) -> &str {
    match mode {
        "p2p_direct" => "直连",
        "direct_pending" => "拨号中",
        "hub_relay" => "中继",
        other => other,
    }
}

/// 空表占位行。
pub(super) fn empty_row(cols: usize, message: &str) -> String {
    format!(
        "<tr><td colspan=\"{cols}\" class=\"empty\">{message}</td></tr>",
        cols = cols,
        message = esc(message)
    )
}

/// HTML 转义（设备名 / tooltip 均来自服务端或配置，必须转义后再进页面）。
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
