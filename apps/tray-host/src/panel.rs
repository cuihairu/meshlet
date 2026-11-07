//! 本地面板：托盘「本地面板」打开的本机自托管只读页（loopback 随机端口）。
//!
//! 定案（2026-11-06 用户，见 todo.md `LOCAL-PANEL-1`）：托盘「打开面板」必须
//! 打开**本地面板**，不是 server 托管的控制台；控制台另列菜单项。
//!
//! - **三块信息**：① 当前节点（设备名 / 虚拟 IP / 公钥指纹 / 状态灯 / hub 控制
//!   通道 / 版本 / EnvProbe 关键项）② 直连节点（`direct-peers.json` 全量）③
//!   本地路由（`applied.json` 的计划路由，缺省回落账本前缀）。
//! - **只读本机文件**：每次请求重读 → 文件变更即刷新；页面初始服务端预渲染
//!   （无 JS 也见三块），有 JS 时每 5s `fetch /state.json` 做**局部更新**——
//!   值 diff 只 patch 变化单元格，保留滚动位置 / 焦点 / 复制钮状态，不再
//!   `<meta refresh>` 整页重载（整页刷新会闪屏丢滚动，用户可见抖动）。
//!   数据链路完全不经过 server，**server 挂了本地面板照样开**。
//! - **只绑 loopback**：`127.0.0.1:0`（内核分配端口，避开冲突），只应答
//!   `GET/HEAD /`（页面）与 `GET/HEAD /state.json`（局部更新数据源）；纯展示
//!   无写操作，页面不含私钥 / token 等敏感数据。
//! - **复制按钮是纯客户端行为**：overlay IP 旁的「复制」点击后写剪贴板
//!   （`navigator.clipboard`，`file://` 等无该 API 的环境降级
//!   `execCommand`，再失败给「复制失败」反馈），不新增任何网络请求，
//!   只读纪律（GET/HEAD）不变；`data-copy` 属性值经 `esc` 转义。
//! - **零新增依赖**：`std::net` 起一个后台线程，tray-host 保持
//!   windows-sys + serde 的零数据面依赖纪律；页面无构建链（单二进制内联
//!   JS，fetch + 单元格 patch，不上 React）。
//!
//! 数据源（全部现成，无新采集）：
//!
//! | 块 | 文件 | 关键字段 |
//! |---|---|---|
//! | 当前节点 | `{state}/tray/status.json` | `state` / `tooltip` / `updated_at` / `version` / `env` |
//! | 当前节点 | `{state}/applied.json` | `tunnel_address` / `local_public_key` / `applied_at` |
//! | 当前节点 | `{state}/../agent.toml` | `device_name` / `server_url`（控制台入口） |
//! | 直连节点 | `{state}/direct-peers.json` | 名称 / overlay IP / 模式 / RTT（含来源）/ endpoint / 最近握手 |
//! | 本地路由 | `{state}/applied.json` | `last_good_plan.routes`（目标网段 / 下一跳 / 接口） |

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 页面局部更新轮询间隔（秒）。页面每间隔 `fetch /state.json`，值有变才
/// patch 对应单元格——不再整页重载（无闪屏、滚动/焦点不丢）。
pub const REFRESH_SECS: u32 = 5;
/// 单请求读取上限（请求行），超长请求直接断开，不占服务线程。
const REQUEST_LIMIT: u64 = 8 * 1024;
/// 读写超时：慢速客户端不会拖住 accept 循环。
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// 起本地面板服务：绑定 `127.0.0.1:0`，返回实际端口（URL 见 [`url`]）。
///
/// 端口在返回前就已监听，调用方拿到端口即可打开浏览器，不存在竞态。
pub fn start(state_dir: PathBuf) -> std::io::Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    std::thread::Builder::new()
        .name("meshlet-local-panel".into())
        .spawn(move || serve(listener, state_dir))?;
    Ok(port)
}

/// 面板 URL（仅 loopback）。
pub fn url(port: u16) -> String {
    format!("http://127.0.0.1:{port}/")
}

/// 面板 URL 交接文件（`{state_dir}/local-panel.json`）。
///
/// 为什么要有它：Windows 上被重定向的日志文件在进程存活期间读不到（本仓
/// `tray-windows` 作业踩过），而面板必须在托盘进程**还活着**时被 curl/浏览器
/// 访问——URL 另写一个写完即关的小文件，CI 与运维据此拿端口。退出时由调用方
/// best-effort 删除。
pub const URL_FILE: &str = "local-panel.json";

/// 写面板 URL 交接文件（`{url, pid}`）。
///
/// **原子发布**：先写 `.tmp` 再 rename 覆盖——`fs::write` 会先截断再写，读方
/// （CI 门禁 / 运维）可能撞见空文件或半个 JSON。
pub fn write_url_file(state_dir: &Path, url: &str) -> std::io::Result<()> {
    let body = serde_json::json!({ "url": url, "pid": std::process::id() }).to_string();
    let tmp = state_dir.join(format!("{URL_FILE}.tmp"));
    std::fs::write(&tmp, body)?;
    // Windows 上 `rename` 对应 `MoveFileEx(..., MOVEFILE_REPLACE_EXISTING)`，
    // 覆盖已存在的目标文件。
    std::fs::rename(&tmp, state_dir.join(URL_FILE))
}

/// 读面板 URL 交接文件；缺失 / 损坏 → `None`。
pub fn read_url_file(state_dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(state_dir.join(URL_FILE)).ok()?;
    serde_json::from_str::<serde_json::Value>(&text)
        .ok()?
        .get("url")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// 退出时清掉交接文件（best-effort：残留只会让下一次读到旧 URL，不致命）。
pub fn remove_url_file(state_dir: &Path) {
    let _ = std::fs::remove_file(state_dir.join(URL_FILE));
}

/// accept 循环：单线程顺序服务（本机单用户页面，请求毫秒级完成）。
fn serve(listener: TcpListener, state_dir: PathBuf) {
    for conn in listener.incoming() {
        let Ok(stream) = conn else {
            continue; // 瞬时 accept 错误：继续服务，不退出线程。
        };
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        if let Err(error) = handle(&state_dir, stream) {
            tracing::debug!(%error, "local panel request failed");
        }
    }
}

/// 处理一次请求：只放行 `GET|HEAD /`（页面）与 `GET|HEAD /state.json`
/// （局部更新数据源），其余 404/405。
fn handle(state_dir: &Path, stream: TcpStream) -> std::io::Result<()> {
    let reader = BufReader::new(&stream);
    let mut line = String::new();
    reader.take(REQUEST_LIMIT).read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let head_only = match method {
        "GET" => false,
        "HEAD" => true,
        _ => {
            return respond(
                stream,
                "405 Method Not Allowed",
                CONTENT_HTML,
                &error_page("仅支持 GET"),
                false,
            )
        }
    };
    let path = target.split('?').next().unwrap_or_default();
    match path {
        "/" | "/index.html" => respond(
            stream,
            "200 OK",
            CONTENT_HTML,
            &render(state_dir),
            head_only,
        ),
        "/state.json" => respond(
            stream,
            "200 OK",
            CONTENT_JSON,
            &state_json(state_dir),
            head_only,
        ),
        _ => respond(
            stream,
            "404 Not Found",
            CONTENT_HTML,
            &error_page("页面不存在（本地面板只有 / 与 /state.json）"),
            head_only,
        ),
    }
}

const CONTENT_HTML: &str = "text/html; charset=utf-8";
const CONTENT_JSON: &str = "application/json; charset=utf-8";

/// 写响应（`Connection: close`：一请求一连接，浏览器无需 keep-alive）。
fn respond(
    mut stream: TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
    head_only: bool,
) -> std::io::Result<()> {
    let bytes = body.as_bytes();
    let header = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Connection: close\r\n\r\n",
        bytes.len()
    );
    stream.write_all(header.as_bytes())?;
    if !head_only {
        stream.write_all(bytes)?;
    }
    stream.flush()
}

/// 读 `{state_dir}/../<file>` 的单个**顶层**键（`agent.toml` / 旧部署 `config.toml`）。
///
/// 只认第一个 `[section]` 之前的顶层 `key = value`：段内键（`[dataplane]` 的
/// `interface` 等数据面配置）一律跳过，面板绝不把段内配置误当节点信息展示。
pub fn config_value(state_dir: &Path, key: &str) -> Option<String> {
    let parent = state_dir.parent()?;
    for name in ["agent.toml", "config.toml"] {
        let Ok(text) = std::fs::read_to_string(parent.join(name)) else {
            continue;
        };
        let mut in_section = false;
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                in_section = true;
                continue;
            }
            if in_section || line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                if k.trim() == key {
                    let value = v.trim().trim_matches('"');
                    if !value.is_empty() {
                        return Some(value.to_string());
                    }
                }
            }
        }
    }
    None
}

/// 读一个 JSON 文件；缺失 / 损坏 → `None`（面板按「无数据」渲染，不 panic）。
fn read_json(path: &Path) -> Option<serde_json::Value> {
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

/// ① 当前节点：状态灯 + 状态行 + (label, value) 字段表。
#[derive(Debug, Clone, serde::Serialize)]
pub struct NodeSnapshot {
    /// 状态灯色（`data-dot` 键，JS 变色前先比对）。
    pub dot: &'static str,
    /// 状态行展示文本（状态 + tooltip，服务端拼好，JS 只做文本 diff）。
    pub state_display: String,
    /// 字段行（label, value）；value 落在 `data-f="node.{i}"`。
    pub fields: Vec<(String, String)>,
    /// 携带复制按钮的字段下标（虚拟 IP）；`None` = 无可复制值。
    pub copy_index: Option<usize>,
}

/// ② 直连节点单行。
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerRow {
    pub name: String,
    pub ip: String,
    pub mode: String,
    /// RTT 展示文本（`12 ms` / `—`）。
    pub rtt: String,
    /// RTT 来源 tooltip（overlay / endpoint / 不可测），落在 RTT 单元格 title。
    pub rtt_title: String,
    pub endpoint: String,
    pub handshake: String,
    pub public_key: String,
    /// overlay IP 是否带复制按钮（占位符 `—` 不带）。
    pub ip_copyable: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PeersSnapshot {
    pub rows: Vec<PeerRow>,
    /// 整段 tbody HTML。常态走单元格 diff；行数变化（节点增删 / 数据不可用
    /// 占位切换）时 JS 整体替换——html 与页面由同一 Rust 代码生成，不分叉。
    pub html: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RoutesSnapshot {
    pub caption: String,
    /// 数据行 `[目标网段, 下一跳, 接口, 来源]` 或占位行（字符串，跨列提示）。
    /// JS 对数据行走单元格 diff，占位行只随整体替换出现。
    pub rows: Vec<RouteRow>,
    pub html: String,
}

/// 本地路由一行：数据行（4 列）或占位行（跨列提示）。
#[derive(Debug, Clone, serde::Serialize)]
#[serde(untagged)]
pub enum RouteRow {
    Cells([String; 4]),
    Placeholder(String),
}

/// RTT 来源 → 人话 tooltip。「最近握手」列始终保留为链路活性主证据——
/// overlay/endpoint 都测不出 RTT 不代表链路死了（WireGuard 常不答 ICMP）。
/// 如实四态（新 agent）：probe_ok / handshake_fresh / probe_failed / unprobed；
/// overlay / endpoint / unreachable 是旧 agent 落盘的历史值，保留映射兼容。
fn rtt_source_label(source: Option<&str>) -> &'static str {
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

/// 读三块数据 → 面板快照（render 与 state_json 都走这里）。
pub fn snapshot(state_dir: &Path) -> PanelSnapshot {
    let status = read_json(&state_dir.join("tray").join("status.json"))
        .unwrap_or_else(|| serde_json::json!({}));
    let ledger = read_json(&state_dir.join("applied.json"));
    // 「账本不可用」（文件缺失/损坏）与「账本可用但没有路由」是两回事，文案分开。
    let ledger_ok = ledger.is_some();
    let applied = ledger.unwrap_or_else(|| serde_json::json!({}));

    let raw_state = status.get("state").and_then(|v| v.as_str());
    let (state, dot) = state_and_dot(raw_state);
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
    let (fields, copy_index) = node_fields(state_dir, &status, &applied);
    let peers = peers_snapshot(state_dir);
    let (routes, route_caption) = route_rows(&applied, ledger_ok);
    let routes_html = routes_html(&routes);

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

/// 直连节点单行 HTML（与 `PeersSnapshot::html` 同源；`data-f` 键供 JS diff）。
fn peer_row_html(index: usize, row: &PeerRow) -> String {
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
fn routes_html(rows: &[RouteRow]) -> String {
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
fn error_page(message: &str) -> String {
    format!(
        "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">\
         <title>Meshlet 本地面板</title></head><body><p>{message}</p>\
         <p><a href=\"/\">返回本地面板</a></p></body></html>",
        message = esc(message)
    )
}

/// 状态串 →（展示名, 状态灯色）。色是第二通道，文本始终在（不靠颜色）。
fn state_and_dot(state: Option<&str>) -> (String, &'static str) {
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
fn hub_status(state: Option<&str>) -> &'static str {
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
fn copy_button_html(value: &str) -> String {
    format!(
        "<button type=\"button\" class=\"copy\" data-copy=\"{value}\">复制</button>",
        value = esc(value)
    )
}

/// ① 当前节点字段（label, value），及携带复制按钮的行下标。
fn node_fields(
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
fn short_key(key: &str) -> String {
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

/// ② 直连节点快照（`direct-peers.json` 全量，含中继候选）。RTT 值带来源
/// tooltip（overlay / endpoint / 不可测），「最近握手」保留为活性主证据。
fn peers_snapshot(state_dir: &Path) -> PeersSnapshot {
    let views = match read_json(&state_dir.join("direct-peers.json")) {
        Some(serde_json::Value::Array(items)) => items,
        // 缺失 / 损坏 / 形状不符：**不能**说成「没有直连节点」，只能说数据不可用
        //（面板照样出，不阻塞另两块）。
        _ => {
            let html = empty_row(7, "（直连节点数据不可用 — direct-peers.json 缺失或损坏）");
            return PeersSnapshot {
                rows: Vec::new(),
                html,
            };
        }
    };
    if views.is_empty() {
        // 文件在、也是数组，只是没记录 —— 这才是「没有节点记录」。
        let html = empty_row(7, "（没有节点记录）");
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
            let rtt_title = rtt_source_label(v.get("rtt_source").and_then(|x| x.as_str()));
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
                mode: mode_label(mode).into(),
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
        .map(|(i, row)| peer_row_html(i, row))
        .collect();
    PeersSnapshot { rows, html }
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

/// 当前 Unix 秒（时钟回拨 / 无 epoch 时按 0 处理，展示层不 panic）。
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Unix 秒 → 「N 秒前 / N 分钟前 / N 小时前」（超过 3 天显示「—」防误读）。
fn age_text(unix_secs: u64) -> String {
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
/// 行 = [目标网段, 下一跳, 接口, 来源]；占位情况（无计划路由 / 账本不可用
/// 等）返回单条占位行，HTML 侧统一处理。
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

/// 空表占位行。
fn empty_row(cols: usize, message: &str) -> String {
    format!(
        "<tr><td colspan=\"{cols}\" class=\"empty\">{message}</td></tr>",
        cols = cols,
        message = esc(message)
    )
}

/// HTML 转义（设备名 / tooltip 均来自服务端或配置，必须转义后再进页面）。
fn esc(text: &str) -> String {
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
mod tests {
    use super::*;

    /// `<base>/state` 结构（与 `install.ps1` 的 `%LOCALAPPDATA%\meshlet\{…,state}` 同形）。
    fn temp_state_dir(tag: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "meshlet-panel-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = base.join("state");
        std::fs::create_dir_all(state.join("tray")).unwrap();
        state
    }

    /// 三块数据齐全的 mock 数据源（不依赖 agent / server）。
    fn write_mock_data(state: &Path) {
        std::fs::write(
            state.parent().unwrap().join("agent.toml"),
            "server_url = \"https://meshlet.example.com\"\n\
             device_name = \"office-nas\"\n\
             state_dir = \"./state\"\n\
             [dataplane]\n\
             interface = \"wg-meshlet\"\n",
        )
        .unwrap();
        std::fs::write(
            state.join("tray").join("status.json"),
            r#"{"state":"Meshlet online","tooltip":"Meshlet「office-nas」 10.240.0.5：在线：控制通道正常，数据面与服务端期望一致（流量经 VPS 中继）","updated_at":"2026-11-06T12:00:00Z","version":"0.4.0","env":{"display":null,"wayland_display":null,"session_type":"tty","session_name":"Console","console_session":true}}"#,
        )
        .unwrap();
        std::fs::write(
            state.join("direct-peers.json"),
            r#"[{"name":"peer-b","virtual_ipv4":"10.240.0.3","public_key":"abc==","mode":"p2p_direct","rtt_ms":12,"rtt_source":"overlay","endpoint":"203.0.113.7:51820","last_handshake_at":1793980000},
               {"name":"","virtual_ipv4":"10.240.0.4","public_key":"def==","mode":"hub_relay","rtt_ms":null,"rtt_source":"unreachable","endpoint":"","last_handshake_at":null}]"#,
        )
        .unwrap();
        std::fs::write(
            state.join("applied.json"),
            r#"{"desired_config_hash":"abc","tunnel_address":"10.240.0.5","routes":["10.240.0.0/16"],"nat_rules":[],"nat_owners":[],"applied_at":"2026-11-06T11:59:00Z","local_public_key":"cWf8S0mVn1pQr7sT9uX2yZ4aB6dC8eF0gH1iJ3kL5=","last_good_plan":{"desired_revision":7,"tunnel":{"address":"10.240.0.5"},"routes":[{"destination":"10.240.0.0/16","interface":"wg-meshlet","gateway":null},{"destination":"192.168.8.0/24","interface":"wg-meshlet","gateway":"10.240.0.3"}],"nat_rules":[],"desired_config_hash":"abc"}}"#,
        )
        .unwrap();
    }

    #[test]
    fn render_shows_all_three_sections_with_mock_data() {
        let state = temp_state_dir("render");
        write_mock_data(&state);
        let html = render(&state);

        // 三块齐全（截图/断言口径：node / direct / routes）。
        for id in ["id=\"node\"", "id=\"direct\"", "id=\"routes\""] {
            assert!(html.contains(id), "missing section {id}");
        }
        for title in ["当前节点", "直连节点", "本地路由"] {
            assert!(html.contains(title), "missing section title {title}");
        }
        // ① 当前节点：名称 / 状态 / 版本 / EnvProbe。
        assert!(html.contains("office-nas"));
        assert!(html.contains("Meshlet online"));
        assert!(html.contains("已连接（控制通道正常）"));
        assert!(html.contains("10.240.0.5"));
        assert!(html.contains("agent 0.4.0"));
        assert!(html.contains("XDG_SESSION_TYPE"));
        assert!(html.contains("Console"));
        // ② 直连节点：全量两条（直连 + 中继候选），含 endpoint / 模式 / RTT。
        assert!(html.contains("peer-b"));
        assert!(html.contains("203.0.113.7:51820"));
        // 公钥整串（direct-peers.json 全量口径，缺省字段显示 —）。
        assert!(html.contains("abc=="));
        assert!(html.contains("def=="));
        assert!(html.contains("直连"));
        assert!(html.contains("中继"));
        assert!(html.contains("12 ms"));
        // ③ 本地路由：目标网段 / 下一跳 / 接口 / 来源。
        assert!(html.contains("192.168.8.0/24"));
        assert!(html.contains("10.240.0.3"));
        assert!(html.contains("wg-meshlet"));
        assert!(html.contains("服务端计划 · applied.json"));
        // 控制台入口（另列，不是本地面板的替代）。
        assert!(html.contains("https://meshlet.example.com"));
        // Overlay IP 复制按钮：当前节点的虚拟 IP + 直连节点两条 IP 都有按钮，
        // 且 data-copy 携带正确值（点击写剪贴板的数据源）。
        assert_eq!(
            html.matches("class=\"copy\"").count(),
            3,
            "three copy buttons"
        );
        assert!(
            html.contains("data-copy=\"10.240.0.5\""),
            "node virtual ip copy value"
        );
        assert!(
            html.contains("data-copy=\"10.240.0.3\""),
            "peer ip copy value"
        );
        assert!(
            html.contains("data-copy=\"10.240.0.4\""),
            "relay peer ip copy value"
        );
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    /// 复制按钮的安全纪律：`data-copy` 值来自本机状态文件，必须转义——
    /// 恶意值不得逃出属性变成标记（面板其余动态文本的既有转义口径）。
    #[test]
    fn copy_button_escapes_hostile_ip_values() {
        let state = temp_state_dir("copy-escape");
        std::fs::write(
            state.join("applied.json"),
            r#"{"tunnel_address":"\"><script>alert(1)</script>"}"#,
        )
        .unwrap();
        let html = render(&state);
        // 属性值整体被转义：引号变 &quot;、尖括号变实体。
        assert!(html.contains("data-copy=\"&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;\""));
        // 原始的引号/尖括号组合不得出现在任何 data-copy 属性边界外。
        assert!(!html.contains("\"><script>alert(1)"));
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    /// 没有虚拟 IP（账本缺失）时不出复制按钮——没有可复制的东西。
    #[test]
    fn no_copy_button_without_a_real_overlay_ip() {
        let state = temp_state_dir("copy-absent");
        let html = render(&state);
        assert!(!html.contains("data-copy="), "no copy button without data");
        // 直连节点也缺失时一条按钮都没有。
        assert!(!html.contains("class=\"copy\""));
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    /// 直连节点 IP 缺失（形状不符 → 「—」占位）时该行不出复制按钮。
    #[test]
    fn placeholder_peer_ip_gets_no_copy_button() {
        let state = temp_state_dir("copy-placeholder");
        std::fs::write(state.join("direct-peers.json"), r#"[{"name":"peer-x"}]"#).unwrap();
        let html = render(&state);
        assert!(html.contains(">—<"), "placeholder ip renders");
        assert!(
            !html.contains("data-copy=\"—\""),
            "placeholder must not be copyable"
        );
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn render_degrades_gracefully_without_any_data_files() {
        let state = temp_state_dir("empty");
        let html = render(&state);
        for id in ["id=\"node\"", "id=\"direct\"", "id=\"routes\""] {
            assert!(html.contains(id), "sections must render even with no data");
        }
        // 数据不可用 ≠ 数据为空：三处都按「不可用」陈述，不推断 agent 行为。
        assert!(html.contains("直连节点数据不可用"));
        assert!(html.contains("本地账本不可用"));
        assert!(html.contains("未知（状态不可用）"));
        assert!(html.contains("状态说明不可用"));
        assert!(!html.contains("没有路由记录"));
        assert!(!html.contains("agent 尚未"));
        // 没有公钥指纹 ≠ 没有应用计划：措辞不得误导。
        assert!(html.contains("—（agent 未记录公钥指纹）"));
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn render_falls_back_to_ledger_route_prefixes() {
        let state = temp_state_dir("ledger-routes");
        std::fs::write(
            state.join("applied.json"),
            r#"{"applied_at":"2026-11-06T11:59:00Z","routes":["10.240.0.0/16","198.51.100.0/24"]}"#,
        )
        .unwrap();
        let html = render(&state);
        assert!(html.contains("10.240.0.0/16"));
        assert!(html.contains("198.51.100.0/24"));
        assert!(html.contains("本地账本 · applied.json"));
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    /// 真机 imac 形态：计划**已应用**但 `routes` 为空（纯叶子节点）。面板必须
    /// 说「计划没下发路由」，不能把已应用的计划说成「尚未应用」。
    #[test]
    fn applied_plan_without_routes_says_so_instead_of_claiming_no_plan() {
        let state = temp_state_dir("empty-plan-routes");
        std::fs::write(
            state.join("applied.json"),
            r#"{"applied_at":"2026-11-05T08:24:17Z","routes":[],"last_good_plan":{"desired_revision":31,"routes":[]}}"#,
        )
        .unwrap();
        let html = render(&state);
        assert!(html.contains("计划未下发任何路由项"));
        assert!(html.contains("计划修订 rev31"));
        assert!(!html.contains("agent 尚未应用任何计划"));
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    /// `last_good_plan: null` 是 `AgentState::Option` 序列化的合法形状：必须走
    /// 账本分支，不能当成「计划已应用但没路由」，更不能把账本里的路由藏掉。
    #[test]
    fn null_last_good_plan_falls_back_to_ledger_routes() {
        let state = temp_state_dir("null-plan");
        std::fs::write(
            state.join("applied.json"),
            r#"{"applied_at":"2026-11-05T08:24:17Z","routes":["10.240.0.0/16"],"last_good_plan":null}"#,
        )
        .unwrap();
        let html = render(&state);
        assert!(html.contains("10.240.0.0/16"), "ledger route must show");
        assert!(html.contains("本地账本 · applied.json"));
        assert!(!html.contains("计划未下发任何路由项"));
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    /// 计划段是对象但没有 `routes`（形状不完整）：不能说「计划没下发路由」——
    /// 那会把账本里的路由藏掉；回落账本分支。
    #[test]
    fn plan_without_routes_array_falls_back_to_ledger() {
        let state = temp_state_dir("plan-no-routes");
        std::fs::write(
            state.join("applied.json"),
            r#"{"applied_at":"2026-11-05T08:24:17Z","routes":["10.240.0.0/16"],"last_good_plan":{"desired_revision":31}}"#,
        )
        .unwrap();
        let html = render(&state);
        assert!(html.contains("10.240.0.0/16"), "ledger route must show");
        assert!(!html.contains("计划未下发任何路由项"));
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    /// 空数组（文件在、就是没记录）与数据不可用必须分开说。
    #[test]
    fn empty_peer_array_says_no_records_while_missing_file_says_unavailable() {
        let state = temp_state_dir("peer-empty");
        std::fs::write(state.join("direct-peers.json"), "[]").unwrap();
        assert!(render(&state).contains("没有节点记录"));
        std::fs::remove_file(state.join("direct-peers.json")).unwrap();
        assert!(render(&state).contains("直连节点数据不可用"));
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    /// 账本可读但 `routes` 字段形状不对：不能说「没有路由记录」。
    #[test]
    fn malformed_ledger_routes_are_reported_as_unavailable() {
        let state = temp_state_dir("ledger-routes-invalid");
        std::fs::write(
            state.join("applied.json"),
            r#"{"applied_at":"2026-11-05T08:24:17Z","routes":"oops"}"#,
        )
        .unwrap();
        let html = render(&state);
        assert!(html.contains("本地账本路由数据不可用"));
        assert!(!html.contains("没有路由记录"));
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    /// 「直连」只留给显式 `null` gateway；字段缺失显示 `—`，不猜成直连路由。
    #[test]
    fn next_hop_reserves_direct_label_for_explicit_null_gateway() {
        let state = temp_state_dir("gateway-shapes");
        std::fs::write(
            state.join("applied.json"),
            r#"{"applied_at":"2026-11-05T08:24:17Z","routes":[],"last_good_plan":{"desired_revision":3,"routes":[{"destination":"10.0.0.0/8","interface":"wg0","gateway":null},{"destination":"10.1.0.0/16","interface":"wg0"},{"destination":"10.2.0.0/16","interface":"wg0","gateway":"10.9.9.9"}]}}"#,
        )
        .unwrap();
        let html = render(&state);
        assert!(html.contains("直连（wg0）"), "explicit null = direct route");
        // 缺失 gateway 的那条：目标网段后必须是 `—`，不能也被标成直连。
        let missing = html
            .split("10.1.0.0/16")
            .nth(1)
            .expect("route with missing gateway renders");
        assert!(
            missing.contains("<span data-f=\"routes.1.next\">—</span>"),
            "missing gateway must show —"
        );
        assert!(html.contains("10.9.9.9"));
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    /// 账本缺失时不得出现「应用于 —」这类没有证据的应用事件。
    #[test]
    fn missing_ledger_never_claims_an_application_time() {
        let state = temp_state_dir("no-ledger");
        let html = render(&state);
        assert!(!html.contains("应用于 —"));
        assert!(html.contains("本地账本不可用"));
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    /// 旧账本：计划段为 null 且账本无路由 —— 只陈述账本事实，不反推有没有应用计划。
    #[test]
    fn empty_legacy_ledger_states_the_ledger_fact_only() {
        let state = temp_state_dir("empty-ledger");
        std::fs::write(
            state.join("applied.json"),
            r#"{"applied_at":"2026-11-05T08:24:17Z","routes":[],"last_good_plan":null}"#,
        )
        .unwrap();
        let html = render(&state);
        assert!(html.contains("本地账本没有路由记录"));
        assert!(!html.contains("尚未应用任何计划"));
        assert!(!html.contains("计划未下发任何路由项"));
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn render_escapes_hostile_text() {
        let state = temp_state_dir("escape");
        std::fs::write(
            state.join("tray").join("status.json"),
            r#"{"state":"Meshlet online","tooltip":"<script>alert(1)</script>"}"#,
        )
        .unwrap();
        let html = render(&state);
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn config_value_reads_top_level_keys_only() {
        let state = temp_state_dir("config");
        std::fs::write(
            state.parent().unwrap().join("agent.toml"),
            "server_url = \"https://hub.example\"\n\
             device_name = \"nas\"\n\
             [dataplane]\n\
             interface = \"wg-meshlet\"\n",
        )
        .unwrap();
        assert_eq!(
            config_value(&state, "server_url").as_deref(),
            Some("https://hub.example")
        );
        assert_eq!(config_value(&state, "device_name").as_deref(), Some("nas"));
        // section 内的键不算顶层 → None（不把 interface 当配置读出来）。
        assert_eq!(config_value(&state, "interface"), None);
        assert_eq!(config_value(&state, "nope"), None);
        // 旧部署 config.toml 兜底。
        std::fs::remove_file(state.parent().unwrap().join("agent.toml")).unwrap();
        std::fs::write(
            state.parent().unwrap().join("config.toml"),
            "server_url = \"http://old.example:8080\"\n",
        )
        .unwrap();
        assert_eq!(
            config_value(&state, "server_url").as_deref(),
            Some("http://old.example:8080")
        );
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn state_and_hub_status_map_the_four_tray_states() {
        assert_eq!(
            state_and_dot(Some("Meshlet online")),
            ("在线".into(), "#c97b2e")
        );
        assert_eq!(
            hub_status(Some("Meshlet tunnel only")),
            "仅隧道（控制通道失效，agent 上报过期）"
        );
        // 漂移态推不出控制通道（derive 先判 drift）→ 如实标未知，不谎称断开。
        assert_eq!(
            hub_status(Some("Meshlet tunnel drift")),
            "未知（隧道异常优先判定，控制通道状态未单独上报）"
        );
        assert_eq!(
            hub_status(Some("Meshlet offline")),
            "已断开（无新鲜的控制通道或隧道证据）"
        );
        assert_eq!(hub_status(None), "未知（状态不可用）");
    }

    #[test]
    fn mode_label_maps_known_modes_and_keeps_unknowns() {
        assert_eq!(mode_label("p2p_direct"), "直连");
        assert_eq!(mode_label("direct_pending"), "拨号中");
        assert_eq!(mode_label("hub_relay"), "中继");
        assert_eq!(mode_label("something_new"), "something_new");
    }

    /// 端到端：真起一个 loopback 服务，用裸 TCP 客户端验证 200 + 三块内容 +
    /// 只读语义（POST 405、未知路径 404、HEAD 无 body）。
    #[test]
    fn server_answers_200_with_three_sections_and_rejects_writes() {
        let state = temp_state_dir("serve");
        write_mock_data(&state);
        let port = start(state.clone()).expect("bind loopback");
        let base = url(port);

        let get = |target: &str, method: &str| -> String {
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
            let mut stream = stream;
            write!(
                stream,
                "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            let mut out = String::new();
            std::io::Read::read_to_string(&mut stream, &mut out).unwrap();
            out
        };

        assert!(base.starts_with("http://127.0.0.1:"), "url = {base}");
        let body = get("/", "GET");
        assert!(
            body.starts_with("HTTP/1.1 200 OK"),
            "status line: {}",
            &body[..40]
        );
        assert!(body.contains("Cache-Control: no-store"));
        for id in ["id=\"node\"", "id=\"direct\"", "id=\"routes\""] {
            assert!(body.contains(id), "response missing {id}");
        }
        assert!(body.contains("office-nas"));
        assert!(body.contains("192.168.8.0/24"));

        // HEAD：头齐全、无 body。
        let head = get("/", "HEAD");
        assert!(head.starts_with("HTTP/1.1 200 OK"));
        assert!(head.ends_with("\r\n\r\n"), "HEAD must not carry a body");

        // 只读面板：非 GET/HEAD 一律拒绝。
        let post = get("/", "POST");
        assert!(post.starts_with("HTTP/1.1 405"));
        // 只有根路径与 state.json 是端点。
        let missing = get("/etc/passwd", "GET");
        assert!(missing.starts_with("HTTP/1.1 404"));

        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    /// 局部更新数据源：`GET /state.json` 200 + 三块 JSON（与页面同一数据源）；
    /// 写方法 405、未知路径 404、HEAD 无 body（只读纪律不变）。
    #[test]
    fn state_json_route_serves_three_sections_and_stays_read_only() {
        let state = temp_state_dir("state-json");
        write_mock_data(&state);
        let port = start(state.clone()).expect("bind loopback");

        let get = |target: &str, method: &str| -> String {
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
            let mut stream = stream;
            write!(
                stream,
                "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            let mut out = String::new();
            std::io::Read::read_to_string(&mut stream, &mut out).unwrap();
            out
        };

        let response = get("/state.json", "GET");
        let (headers, body) = response
            .split_once("\r\n\r\n")
            .expect("response splits into headers and body");
        assert!(
            headers.starts_with("HTTP/1.1 200 OK"),
            "status line: {}",
            &headers[..40]
        );
        assert!(
            headers.contains("Content-Type: application/json"),
            "state.json must be served as JSON: {headers}"
        );
        assert!(headers.contains("Cache-Control: no-store"));

        // 三块齐全：node / peers / routes（与 render 同一快照函数）。
        let json: serde_json::Value = serde_json::from_str(body).expect("valid JSON body");
        let node = json.get("node").expect("node block");
        assert_eq!(node.get("dot").and_then(|v| v.as_str()), Some("#c97b2e"));
        assert!(
            node.get("state_display")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .contains("Meshlet online"),
            "state_display carries the raw agent state"
        );
        let fields = node.get("fields").and_then(|v| v.as_array()).unwrap();
        assert!(
            fields.iter().any(|f| f.as_array().unwrap()[0] == "设备名"),
            "node fields carry (label, value) pairs"
        );
        let peers = json
            .get("peers")
            .and_then(|p| p.get("rows"))
            .and_then(|v| v.as_array())
            .expect("peers rows");
        assert_eq!(peers.len(), 2, "both mock peers present");
        assert_eq!(peers[0].get("rtt").and_then(|v| v.as_str()), Some("12 ms"));
        assert_eq!(
            peers[0].get("rtt_title").and_then(|v| v.as_str()),
            Some("来源：overlay 实测（对端 overlay VIP 直测）"),
            "rtt source tooltip rides the row"
        );
        assert_eq!(
            peers[1].get("rtt_title").and_then(|v| v.as_str()),
            Some("来源：不可测（overlay 与 endpoint 均无响应，以「最近握手」为活性证据）"),
        );
        let routes = json
            .get("routes")
            .and_then(|r| r.get("rows"))
            .and_then(|v| v.as_array())
            .expect("routes rows");
        assert_eq!(routes.len(), 2, "both plan routes present");

        // 只读纪律：/state.json 同样只放行 GET/HEAD。
        let post = get("/state.json", "POST");
        assert!(post.starts_with("HTTP/1.1 405"));
        let head = get("/state.json", "HEAD");
        assert!(head.starts_with("HTTP/1.1 200 OK"));
        assert!(head.ends_with("\r\n\r\n"), "HEAD must not carry a body");
        let missing = get("/state.json.bak", "GET");
        assert!(missing.starts_with("HTTP/1.1 404"));

        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    /// 门禁：页面不再整页刷新（无 meta refresh、无 reload 调用），改用
    /// fetch /state.json + 单元格 diff（滚动/焦点/复制钮状态不丢）。
    #[test]
    fn page_polls_state_json_and_never_full_page_reloads() {
        let state = temp_state_dir("no-refresh");
        write_mock_data(&state);
        let html = render(&state);

        assert!(
            !html.contains("http-equiv=\"refresh\""),
            "meta refresh must be gone (it caused the visible flicker)"
        );
        assert!(
            !html.contains("location.reload("),
            "full page reload is forbidden in the panel script"
        );
        assert!(
            html.contains("fetch('/state.json'"),
            "page must poll /state.json for partial updates"
        );
        assert!(html.contains("setInterval(poll"), "poll loop present");
        // 初始快照内联（无 JS 也见三块——服务端预渲染仍在）。
        assert!(html.contains("id=\"panel-state\""));
        assert!(html.contains("id=\"peers-body\""));
        // 单元格 diff 键：节点字段、直连节点行、路由行都有 data-f。
        assert!(html.contains("data-f=\"node."), "node field diff keys");
        assert!(html.contains("data-f=\"peer.0.rtt\""), "peer rtt diff key");
        assert!(html.contains("data-f=\"routes-caption\""));
        // 页面自身说明不再宣称「自动刷新」整页语义。
        assert!(html.contains("局部更新（不整页刷新）"));

        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    /// RTT 来源标注：如实四态（新 agent）+ 旧 agent 落盘的历史值（无来源字段）
    /// 各得对应的 tooltip；「最近握手」列保留（活性主证据）。
    #[test]
    fn rtt_column_labels_its_source() {
        let state = temp_state_dir("rtt-source");
        std::fs::write(
            state.join("direct-peers.json"),
            r#"[{"name":"a","virtual_ipv4":"10.240.0.3","mode":"p2p_direct","rtt_ms":12,"rtt_source":"probe_ok","endpoint":"203.0.113.7:51820"},
               {"name":"b","virtual_ipv4":"10.240.0.4","mode":"p2p_direct","rtt_ms":null,"rtt_source":"handshake_fresh"},
               {"name":"c","virtual_ipv4":"10.240.0.5","mode":"p2p_direct","rtt_ms":null,"rtt_source":"probe_failed"},
               {"name":"d","virtual_ipv4":"10.240.0.6","mode":"p2p_direct","rtt_ms":9},
               {"name":"e","virtual_ipv4":"10.240.0.7","mode":"p2p_direct","rtt_ms":null,"rtt_source":"unreachable"},
               {"name":"f","virtual_ipv4":"10.240.0.8","mode":"p2p_direct","rtt_ms":5,"rtt_source":"overlay"}]"#,
        )
        .unwrap();
        let html = render(&state);
        assert!(html.contains("来源：直连路径实测（overlay/endpoint ping 成功）"));
        assert!(html.contains("来源：握手新鲜（对端不答 ICMP，最近握手即链路活性证据）"));
        assert!(
            html.contains("来源：不可测（overlay 与 endpoint 均无响应，以「最近握手」为活性证据）")
        );
        assert!(html.contains("来源：未测（对端无直连路径或探测尚未完成）"));
        // 旧 agent 历史值仍可读（滚动升级兼容）。
        assert!(html.contains("来源：overlay 实测（对端 overlay VIP 直测）"));
        // 数值照常显示；不可测显示占位符。
        assert!(html.contains("12 ms"));
        assert!(html.contains(">—</span>"));
        // 最近握手表头仍在（活性主证据）。
        assert!(html.contains("最近握手"));
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    /// 交接文件：写→读→删（CI 门禁与运维都靠它拿端口；写入是原子的）。
    #[test]
    fn url_file_round_trips_and_is_removed() {
        let state = temp_state_dir("url-file");
        assert!(read_url_file(&state).is_none());
        write_url_file(&state, "http://127.0.0.1:58132/").expect("write url file");
        assert_eq!(
            read_url_file(&state).as_deref(),
            Some("http://127.0.0.1:58132/")
        );
        // 覆盖写（第二次写必须替换旧文件，不是失败/追加）。
        write_url_file(&state, "http://127.0.0.1:44444/").expect("overwrite url file");
        assert_eq!(
            read_url_file(&state).as_deref(),
            Some("http://127.0.0.1:44444/")
        );
        // 原子发布：不留 .tmp 残骸。
        assert!(!state.join(format!("{URL_FILE}.tmp")).exists());
        remove_url_file(&state);
        assert!(read_url_file(&state).is_none());
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn short_key_and_age_helpers_are_human_readable() {
        assert_eq!(short_key("abc"), "abc");
        let long = "012345678901234567890123";
        assert_eq!(short_key(long), "01234567890123456789…");
        // 未来时间戳不显示负数。
        assert_eq!(age_text(now_secs() + 10_000), "—");
        // 刚刚 / 分钟 / 小时三档。
        assert_eq!(age_text(now_secs() - 5), "5 秒前");
        assert_eq!(age_text(now_secs() - 300), "5 分钟前");
        assert_eq!(age_text(now_secs() - 7_200), "2 小时前");
    }
}
