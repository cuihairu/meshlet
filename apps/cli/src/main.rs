//! meshlet-cli：类 ZeroTier 的命令行工具。
//!
//! 常用命令：
//!   meshlet info             设备信息（名称、IP、状态）
//!   meshlet status           agent 运行状态
//!   meshlet peers            直连节点列表（IP/模式/延时/端点/流量）
//!   meshlet peer dial <node> 强制对目标节点发起直连拨号（名称/IP）
//!   meshlet agent diag       网络诊断快照（路由表/接口清单/wg 读数）
//!   meshlet agent diag --peers   在快照后追加直连 peers 表
//!   meshlet task ls          任务队列（--network <id>）
//!   meshlet task assign      下发任务（--network/--node/--cmd）
//!   meshlet task confirm <id>    确认完成（用户侧动作）
//!   meshlet task retry <id>      驳回重跑（新代任务）
//!   meshlet networks         子网/路由列表
//!   meshlet config           显示配置
//!   meshlet version          版本号

use meshlet_network::dial::{self, DirectDialRequest, DirectPeerView};
use meshlet_network::SystemBackend;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("");

    // `meshlet agent diag [--peers]`：二层子命令。
    if cmd == "agent" {
        let sub = args.get(1).map(|s| s.as_str()).unwrap_or("");
        match sub {
            "diag" => {
                let show_peers = args.iter().any(|a| a == "--peers");
                cmd_agent_diag(show_peers);
            }
            other => {
                eprintln!("error: unknown agent subcommand '{other}'");
                std::process::exit(1);
            }
        }
        return;
    }

    // `meshlet peer dial [<node>]`：二层子命令。
    if cmd == "peer" {
        let sub = args.get(1).map(|s| s.as_str()).unwrap_or("");
        match sub {
            "dial" => cmd_peer_dial(args.get(2).map(|s| s.as_str())),
            other => {
                eprintln!("error: unknown peer subcommand '{other}'");
                eprintln!();
                print_usage();
                std::process::exit(1);
            }
        }
        return;
    }

    // `meshlet task <sub>`（MT-003）：控制台任务队列的 CLI 面。
    if cmd == "task" {
        let sub = args.get(1).map(|s| s.as_str()).unwrap_or("");
        let rest: Vec<String> = args.iter().skip(2).cloned().collect();
        match sub {
            "assign" => cmd_task_assign(&rest),
            "ls" | "list" => cmd_task_ls(&rest),
            "confirm" => cmd_task_confirm(&rest),
            "retry" => cmd_task_retry(&rest),
            // `meshlet task` / `--help`：任务域用法（比全局帮助更聚焦）。
            "help" | "--help" | "-h" | "" => print_task_usage(),
            other => {
                eprintln!("error: unknown task subcommand '{other}'");
                eprintln!();
                print_task_usage();
                std::process::exit(1);
            }
        }
        return;
    }

    match cmd {
        "info" => cmd_info(),
        "status" => cmd_status(),
        "peers" => cmd_peers(),
        "networks" => cmd_networks(),
        "config" => cmd_config(),
        "version" | "--version" | "-V" => {
            println!("meshlet-cli {}", env!("CARGO_PKG_VERSION"));
        }
        "help" | "--help" | "-H" | "" => print_usage(),
        other => {
            eprintln!("error: unknown command '{other}'");
            eprintln!();
            print_usage();
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    // R-TRAY-1：帮助文本由命令目录生成（单一事实源），与托盘「命令」区
    // 同源——新增命令自动出现在两处，`--help` 与目录不可能漂移。
    print!(
        "{}",
        meshlet_commands::usage_text(env!("CARGO_PKG_VERSION"))
    );
}

/// `meshlet task` 域内用法（子命令 + 必选参数速查）。
fn print_task_usage() {
    print!(
        "meshlet task <subcommand> [options]\n\
         \n\
         subcommands:\n\
         \x20 assign   --network <id> --node <device-id> --cmd <command>\n\
         \x20          [--workdir <dir>] [--timeout <secs>] [--id <id>]\n\
         \x20 ls       --network <id>\n\
         \x20 confirm  --network <id> <task-id>\n\
         \x20 retry    --network <id> <task-id>\n\
         \n\
         server/token: --server <url> / --token <mlt_...> >\n\
         MESHLET_SERVER / MESHLET_TOKEN > agent.toml. `meshlet --help` for all commands.\n"
    );
}

fn state_dir() -> PathBuf {
    // 与安装脚本/agent/tray 约定一致：状态写 `%LOCALAPPDATA%\meshlet\state`
    // （install.ps1 的 state_dir；tray `meshlet_state_dir` 同源）。旧的
    // ProgramData/config.toml 读不到真实 agent 状态，故废弃。
    state_dir_from_local(&local_appdata().to_string_lossy())
}

fn config_path() -> PathBuf {
    // 与安装脚本/agent/tray 约定一致：agent 配置 `%LOCALAPPDATA%\meshlet\agent.toml`
    // （install.ps1 写该路径；tray `config_path_from_local` 同源）。
    config_path_from_local(&local_appdata().to_string_lossy())
}

/// `%LOCALAPPDATA%`（回退 `%USERPROFILE%\AppData\Local`，再回退 Public）。
fn local_appdata() -> PathBuf {
    std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|_| {
            std::env::var("USERPROFILE").map(|h| PathBuf::from(h).join("AppData").join("Local"))
        })
        .unwrap_or_else(|_| PathBuf::from("C:/Users/Public/AppData/Local"))
}

/// 纯路径构造（可测）：`<local>/meshlet/state`——与 tray
/// `state_dir_from_local` 同一约定。
fn state_dir_from_local(local: &str) -> PathBuf {
    PathBuf::from(local).join("meshlet").join("state")
}

/// 纯路径构造（可测）：`<local>/meshlet/agent.toml`——与 tray
/// `config_path_from_local` 同一约定。
fn config_path_from_local(local: &str) -> PathBuf {
    PathBuf::from(local).join("meshlet").join("agent.toml")
}

fn cmd_info() {
    let cfg = read_config();
    let device_name = cfg
        .get("device_name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let server_url = cfg
        .get("server_url")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // 从 WireGuard 获取本机 IP
    let wg_ip = wg_local_ip().unwrap_or_else(|| "not connected".to_string());

    // 从 status.json 获取状态
    let status = read_status();
    let state = status
        .get("state")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    println!("device:    {device_name}");
    println!("server:    {server_url}");
    println!("ip:        {wg_ip}");
    println!("status:    {state}");
}

fn cmd_status() {
    let status = read_status();
    let state = status
        .get("state")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let tooltip = status.get("tooltip").and_then(|v| v.as_str()).unwrap_or("");

    // agent 进程是否存活
    let agent_alive = cfg!(windows) && process_exists("meshlet-agent");
    let tray_alive = cfg!(windows) && process_exists("meshlet-tray");

    println!(
        "agent:     {}",
        if agent_alive { "running" } else { "stopped" }
    );
    println!(
        "tray:      {}",
        if tray_alive { "running" } else { "stopped" }
    );
    println!("state:     {state}");
    if !tooltip.is_empty() {
        println!("detail:    {tooltip}");
    }

    // WireGuard 隧道（实际隧道名按 install.ps1/README 为 wg-meshlet，后端
    // 默认 meshlet；旧硬编码 "WireGuard" 查不到真实隧道服务）。
    if cfg!(windows) {
        let tunnel = tunnel_service_running();
        println!("tunnel:    {}", if tunnel { "up" } else { "down" });
    }
}

/// `meshlet peers`（R-DIAG-2）：本机直连对端表——overlay IP / 连接模式 /
/// 直连端点 / 实测 RTT / 最近握手 / 累计流量。
///
/// 数据源为本机 wg 读数（`diagnostics_sync` 的 wg 段）+ 对 overlay 地址实测
/// RTT：wg 里存在即直连候选（agent 已下发 `wg set`），握手新鲜判 P2P 直连、
/// 否则直连 pending。中继对端不出现在 wg（走 hub 整段路由），不在此列。
fn cmd_peers() {
    let backend = diag_backend();
    let ifname = detect_wg_interface().unwrap_or_else(|| "wg0".into());
    print_peers_table(&backend, &ifname);
}

/// 拨号结果等待上限（秒）：agent 探测周期 30s，留足一个周期 + 处理余量。
const DIAL_RESULT_TIMEOUT_SECS: u64 = 45;
/// 结果轮询间隔（毫秒）。
const DIAL_POLL_MILLIS: u64 = 500;

/// `meshlet peer dial [<node>]`（R-AGENT-WIN-1 补充 ③）。
///
/// 无 `<node>`：列出可拨号候选（名称/IP/模式/延时/端点）——托盘「连接节点…」
/// 子菜单的数据源。有 `<node>`：解析目标（名称/IP/公钥前缀）→ 写拨号意图 →
/// 轮询 agent 结果 → 显示成功/失败。
///
/// 数据源 = agent 发布的 `{state_dir}/direct-peers.json`（与 `peers` 命令同一
/// 链路：都来自 agent 直连探测周期对内核的读数）。拨号本身经 agent 执行
/// （CLI 用户会话无权限 `wg set`；agent 持数据面后端），本命令只发意图、
/// 等结果——这就是「executor 接 meshlet-network 发起直连拨号」的进程边界。
fn cmd_peer_dial(node: Option<&str>) {
    let state = state_dir();
    let views = dial::load_direct_peers(&state);
    match node {
        None => print_dial_targets(&views),
        Some(node) => dial_node(&state, views, node),
    }
}

/// 无参模式：打印可拨号候选表。
fn print_dial_targets(views: &Option<Vec<DirectPeerView>>) {
    let views = match views {
        Some(v) => v,
        None => {
            println!("(no direct candidates — agent not reporting yet)");
            return;
        }
    };
    if views.is_empty() {
        println!("(no direct candidates)");
        return;
    }
    print!("{}", format_dial_targets(views));
}

/// 候选表渲染（纯函数，可测）：名称/overlay/模式/延时/端点。
fn format_dial_targets(views: &[DirectPeerView]) -> String {
    let mut out = format!(
        "{:<24} {:<16} {:<14} {:>8}  {}\n",
        "NAME", "OVERLAY_IP", "MODE", "RTT_MS", "ENDPOINT"
    );
    for v in views {
        let rtt = v
            .rtt_ms
            .map(|r| r.to_string())
            .unwrap_or_else(|| "—".into());
        let endpoint = if v.endpoint.is_empty() {
            "—".into()
        } else {
            v.endpoint.clone()
        };
        out.push_str(&format!(
            "{:<24} {:<16} {:<14} {:>8}  {}\n",
            v.name, v.virtual_ipv4, v.mode, rtt, endpoint
        ));
    }
    out
}

/// 解析 `<node>`：名称精确 / overlay IP / 公钥前缀（大小写不敏感）。
/// 纯函数（可测），无匹配返回 `None`。
fn resolve_dial_target<'a>(views: &'a [DirectPeerView], node: &str) -> Option<&'a DirectPeerView> {
    let node = node.trim();
    let lower = node.to_ascii_lowercase();
    views.iter().find(|v| {
        v.name == node
            || v.virtual_ipv4.to_string() == node
            || v.public_key.to_ascii_lowercase().starts_with(&lower)
    })
}

/// 有参模式：解析目标 → 写意图 → 轮询结果 → 打印成功/失败。
fn dial_node(state: &std::path::Path, views: Option<Vec<DirectPeerView>>, node: &str) {
    let views = match views {
        Some(v) => v,
        None => {
            eprintln!("peer dial: no direct candidates (agent not reporting yet)");
            std::process::exit(1);
        }
    };
    let target = match resolve_dial_target(&views, node) {
        Some(t) => t,
        None => {
            eprintln!("peer dial: unknown node '{node}'");
            std::process::exit(1);
        }
    };
    let request = DirectDialRequest {
        node: node.trim().to_string(),
        public_key: target.public_key.clone(),
        virtual_ipv4: target.virtual_ipv4,
        request_id: dial_request_id(),
        requested_at: dial::now_millis(),
    };
    if let Err(e) = dial::write_request(state, &request) {
        eprintln!("peer dial: cannot write request: {e}");
        std::process::exit(1);
    }
    println!(
        "dialing {} ({}) — waiting for agent...",
        target.name, target.virtual_ipv4
    );
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(DIAL_RESULT_TIMEOUT_SECS);
    while std::time::Instant::now() < deadline {
        if let Some(result) = dial::load_result(state) {
            if result.request_id == request.request_id {
                if result.ok {
                    println!("ok: {} ({})", result.message, result.mode);
                } else {
                    eprintln!("failed: {}", result.message);
                    std::process::exit(1);
                }
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(DIAL_POLL_MILLIS));
    }
    eprintln!("peer dial: timeout waiting for agent (is the agent running?)");
    std::process::exit(1);
}

/// 拨号请求 ID：Unix 毫秒 + 本进程号（跨进程唯一性足够）。
fn dial_request_id() -> String {
    format!("{}-{}", dial::now_millis(), std::process::id())
}

// ── meshlet task（MT-003：控制台任务队列的 CLI 面）───────────────────
//
// 任务 API 是管理面（Bearer `mlt_` API Token + `x-requested-with` CSRF 头）。
// 服务器地址与 Token 解析顺序：`--server`/`--token` 标志 > 环境变量
// （MESHLET_SERVER / MESHLET_TOKEN）> agent.toml（server_url / api_token）。

/// 任务子命令错误退出。
fn task_fail(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

/// 解析 `--flag value` 与位置参数（纯函数，可测）。
fn parse_flags(args: &[String]) -> (std::collections::HashMap<String, String>, Vec<String>) {
    let mut flags = std::collections::HashMap::new();
    let mut pos = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(key) = a.strip_prefix("--") {
            // `--flag value`：下一 token 不以 `--` 开头即视为值；否则裸开关。
            if let Some(v) = args.get(i + 1) {
                if !v.starts_with("--") {
                    flags.insert(key.to_string(), v.clone());
                    i += 2;
                    continue;
                }
            }
            flags.insert(key.to_string(), String::new());
            i += 1;
        } else {
            pos.push(a.clone());
            i += 1;
        }
    }
    (flags, pos)
}

/// 服务器地址：`--server` > `MESHLET_SERVER` > 配置 `server_url`。
fn task_server(flags: &std::collections::HashMap<String, String>) -> String {
    if let Some(s) = flags.get("server").filter(|s| !s.is_empty()) {
        return s.clone();
    }
    if let Ok(s) = std::env::var("MESHLET_SERVER") {
        if !s.is_empty() {
            return s;
        }
    }
    read_config()
        .get("server_url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// API Token：`--token` > `MESHLET_TOKEN` > 配置 `api_token`。
fn task_token(flags: &std::collections::HashMap<String, String>) -> String {
    if let Some(t) = flags.get("token").filter(|t| !t.is_empty()) {
        return t.clone();
    }
    if let Ok(t) = std::env::var("MESHLET_TOKEN") {
        if !t.is_empty() {
            return t;
        }
    }
    read_config()
        .get("api_token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// 任务 API 调用（Bearer + CSRF 头）。`body=None` 为 GET。返回 JSON。
fn task_request(
    method: &str,
    server: &str,
    token: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    if server.is_empty() {
        return Err(
            "no server: pass --server <url>, set MESHLET_SERVER, or set server_url in agent.toml"
                .into(),
        );
    }
    if token.is_empty() {
        return Err(
            "no API token: pass --token <mlt_...>, set MESHLET_TOKEN, or set api_token in agent.toml"
                .into(),
        );
    }
    let url = format!("{}/api/v1{}", server.trim_end_matches('/'), path);
    let agent = ureq::AgentBuilder::new().build();
    let req = agent
        .request(method, &url)
        .set("Authorization", &format!("Bearer {token}"))
        .set("x-requested-with", "XMLHttpRequest")
        .set("content-type", "application/json");
    let payload = body.map(|b| b.to_string()).unwrap_or_default();
    match req.send_string(&payload) {
        Ok(r) => {
            let text = r.into_string().unwrap_or_default();
            serde_json::from_str(&text).map_err(|e| format!("bad response: {e}"))
        }
        Err(ureq::Error::Status(code, r)) => {
            let text = r.into_string().unwrap_or_default();
            Err(format!("HTTP {code}: {text}"))
        }
        Err(e) => Err(e.to_string()),
    }
}

/// `meshlet task assign --network <id> --node <device-id> --cmd <cmd>`
/// [--workdir <dir>] [--timeout <secs>] [--id <id>]。
fn cmd_task_assign(args: &[String]) {
    let (flags, _pos) = parse_flags(args);
    let server = task_server(&flags);
    let token = task_token(&flags);
    let network = flags.get("network").cloned().unwrap_or_default();
    let node = flags.get("node").cloned().unwrap_or_default();
    let cmd = flags.get("cmd").cloned().unwrap_or_default();
    if network.is_empty() || node.is_empty() || cmd.is_empty() {
        task_fail("task assign requires --network <id>, --node <device-id>, --cmd <command>");
    }
    let mut body = serde_json::json!({ "target_device_id": node, "cmd": cmd });
    if let Some(w) = flags.get("workdir").filter(|w| !w.is_empty()) {
        body["workdir"] = serde_json::json!(w);
    }
    // `--timeout` 必须是秒数；非法值不静默丢（否则用默认超时跑，行为悄悄变）。
    if let Some(raw) = flags.get("timeout") {
        match raw.parse::<u64>() {
            Ok(t) => {
                body["timeout_secs"] = serde_json::json!(t);
            }
            Err(_) => task_fail(&format!(
                "task assign: --timeout expects seconds, got '{raw}'"
            )),
        }
    }
    if let Some(id) = flags.get("id").filter(|id| !id.is_empty()) {
        body["id"] = serde_json::json!(id);
    }
    match task_request(
        "POST",
        &server,
        &token,
        &format!("/networks/{network}/tasks"),
        Some(body),
    ) {
        Ok(v) => {
            println!("assigned: {}", v["id"].as_str().unwrap_or("?"));
            print!("{}", format_task_view(&v));
        }
        Err(e) => task_fail(&e),
    }
}

/// `meshlet task ls --network <id>`。
fn cmd_task_ls(args: &[String]) {
    let (flags, _pos) = parse_flags(args);
    let server = task_server(&flags);
    let token = task_token(&flags);
    let network = flags.get("network").cloned().unwrap_or_default();
    if network.is_empty() {
        task_fail("task ls requires --network <id>");
    }
    match task_request(
        "GET",
        &server,
        &token,
        &format!("/networks/{network}/tasks"),
        None,
    ) {
        Ok(arr) => print!("{}", format_task_list(&arr)),
        Err(e) => task_fail(&e),
    }
}

/// `meshlet task confirm <task-id> --network <id>`（用户侧确认完成）。
fn cmd_task_confirm(args: &[String]) {
    let (flags, pos) = parse_flags(args);
    let server = task_server(&flags);
    let token = task_token(&flags);
    let network = flags.get("network").cloned().unwrap_or_default();
    let id = pos.first().cloned().unwrap_or_default();
    if network.is_empty() || id.is_empty() {
        task_fail("task confirm <task-id> requires --network <id>");
    }
    match task_request(
        "POST",
        &server,
        &token,
        &format!("/networks/{network}/tasks/{id}/confirm"),
        Some(serde_json::json!({})),
    ) {
        Ok(v) => {
            println!("confirmed: {}", v["id"].as_str().unwrap_or("?"));
            print!("{}", format_task_view(&v));
        }
        Err(e) => task_fail(&e),
    }
}

/// `meshlet task retry <task-id> --network <id>`（驳回重跑，新代任务）。
fn cmd_task_retry(args: &[String]) {
    let (flags, pos) = parse_flags(args);
    let server = task_server(&flags);
    let token = task_token(&flags);
    let network = flags.get("network").cloned().unwrap_or_default();
    let id = pos.first().cloned().unwrap_or_default();
    if network.is_empty() || id.is_empty() {
        task_fail("task retry <task-id> requires --network <id>");
    }
    match task_request(
        "POST",
        &server,
        &token,
        &format!("/networks/{network}/tasks/{id}/retry"),
        Some(serde_json::json!({})),
    ) {
        Ok(v) => {
            println!(
                "retried: {} (rerun dispatched)",
                v["id"].as_str().unwrap_or("?")
            );
            print!("{}", format_task_view(&v));
        }
        Err(e) => task_fail(&e),
    }
}

/// 任务列表渲染（纯函数，可测）。
fn format_task_list(arr: &serde_json::Value) -> String {
    let rows = match arr.as_array() {
        Some(r) if !r.is_empty() => r,
        _ => return "(no tasks)\n".to_string(),
    };
    let mut out = format!(
        "{:<16} {:<10} {:<16} {:<12} {:<10} {:<10}  {}\n",
        "ID", "STATE", "TARGET", "CMD", "CONFIRMED", "REJECTED", "PARENT"
    );
    for t in rows {
        out.push_str(&format!(
            "{:<16} {:<10} {:<16} {:<12} {:<10} {:<10}  {}\n",
            t["id"].as_str().unwrap_or("?"),
            t["state"].as_str().unwrap_or("?"),
            t["target_device_id"].as_str().unwrap_or("?"),
            cmd_short(t["cmd"].as_str().unwrap_or("?")),
            t["confirmed_at"].as_str().map(|_| "yes").unwrap_or("—"),
            t["rejected_at"].as_str().map(|_| "yes").unwrap_or("—"),
            t["parent_task_id"].as_str().unwrap_or("—"),
        ));
    }
    out
}

/// 命令摘要（列宽 `{:&<12}` 内截断：11 字符 + 省略号 = 12 列，纯函数）。
fn cmd_short(cmd: &str) -> String {
    let count = cmd.chars().count();
    if count > 12 {
        let c: String = cmd.chars().take(11).collect();
        format!("{c}…")
    } else {
        cmd.to_string()
    }
}

/// 单任务视图（纯函数，可测）。
fn format_task_view(v: &serde_json::Value) -> String {
    format!(
        "  id={} state={} target={} confirmed={} rejected={} parent={}\n  cmd={} exit_code={}\n",
        v["id"].as_str().unwrap_or("?"),
        v["state"].as_str().unwrap_or("?"),
        v["target_device_id"].as_str().unwrap_or("?"),
        v["confirmed_at"].as_str().map(|_| "yes").unwrap_or("—"),
        v["rejected_at"].as_str().map(|_| "yes").unwrap_or("—"),
        v["parent_task_id"].as_str().unwrap_or("—"),
        v["cmd"].as_str().unwrap_or("?"),
        v["exit_code"]
            .as_i64()
            .map(|c| c.to_string())
            .unwrap_or("—".into()),
    )
}

/// 构造诊断后端：默认 `wg0`，若本机存在实际 wg 接口则用其名（配置常改
/// `wg-mlt` 等，默认名不符实；按链路类型自动检测，读不到回落默认）。
fn diag_backend() -> SystemBackend {
    let backend = SystemBackend::new();
    match detect_wg_interface() {
        Some(ifname) => backend.with_interface(ifname),
        None => backend,
    }
}

/// 检测本机 wireguard 类型接口名（Linux `ip -o link show type wireguard`）。
fn detect_wg_interface() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let out = std::process::Command::new("ip")
            .args(["-o", "link", "show", "type", "wireguard"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 2 {
                let name = fields[1].trim_end_matches(':');
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = ();
    }
    None
}

/// `meshlet agent diag [--peers]`（R-DIAG / R-DIAG-2）：本机网络诊断快照。
/// 采集失败如实报错（诊断面绝不臆测默认值）；`--peers` 在快照后追加直连表。
fn cmd_agent_diag(show_peers: bool) {
    let backend = diag_backend();
    let ifname = detect_wg_interface().unwrap_or_else(|| "wg0".into());
    let net = match backend.diagnostics_sync() {
        Ok(net) => net,
        Err(e) => {
            eprintln!("diag failed: {e}");
            std::process::exit(1);
        }
    };

    println!(
        "== routes ({}) ==",
        net.collected_at.as_deref().unwrap_or("?")
    );
    if net.route_table.is_empty() {
        println!("(not collected)");
    } else {
        for line in &net.route_table {
            println!("{line}");
        }
    }

    println!("\n== interfaces ==");
    if net.interfaces.is_empty() {
        println!("(not collected)");
    } else {
        println!("{:<16} {:<6} {:>5}  IPV4", "NAME", "STATE", "MTU");
        for i in &net.interfaces {
            let ipv4 = match (&i.ipv4, i.prefix) {
                (ip, Some(p)) if !ip.is_empty() => format!("{ip}/{p}"),
                _ => "—".to_string(),
            };
            println!(
                "{:<16} {:<6} {:>5}  {}",
                i.name,
                i.state,
                i.mtu.map(|m| m.to_string()).unwrap_or_else(|| "?".into()),
                ipv4
            );
        }
    }

    println!("\n== wg peers ({ifname}) ==");
    print_wg_peers(&net.wg, &ifname);

    if show_peers {
        println!("\n== direct peers ==");
        print_peers_table(&backend, &ifname);
    }
}

/// 打印 wg 段：读数为空时如实区分「无直连对端」与「读数需提权」。
fn print_wg_peers(wg: &[meshlet_network::WgPeerDiagnostic], ifname: &str) {
    if wg.is_empty() {
        if wg_readable(ifname) {
            println!("(no direct peers)");
        } else {
            println!("(wg reading unavailable — requires root/administrator)");
        }
        return;
    }
    for p in wg {
        println!(
            "endpoint={} allowed_ips={} last_handshake={} rx={} tx={}",
            if p.endpoint.is_empty() {
                "—"
            } else {
                &p.endpoint
            },
            if p.allowed_ips.is_empty() {
                "—"
            } else {
                &p.allowed_ips
            },
            if p.last_handshake > 0 {
                p.last_handshake.to_string()
            } else {
                "never".into()
            },
            format_bytes(p.rx_bytes),
            format_bytes(p.tx_bytes),
        );
    }
}

/// wg 配置读数是否可访问（`wg show <if> dump` 需 root/CAP_NET_ADMIN）。
fn wg_readable(ifname: &str) -> bool {
    std::process::Command::new("wg")
        .args(["show", ifname, "dump"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// 打印直连对端表（`meshlet peers` 与 `agent diag --peers` 共用）。
fn print_peers_table(backend: &SystemBackend, ifname: &str) {
    let net = match backend.diagnostics_sync() {
        Ok(net) => net,
        Err(e) => {
            eprintln!("peers: diagnostics unavailable: {e}");
            return;
        }
    };
    if net.wg.is_empty() {
        if wg_readable(ifname) {
            println!("(no direct peers; hub relay covers all)");
        } else {
            println!("(wg reading unavailable — requires root/administrator)");
        }
        return;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!(
        "{:<18} {:<14} {:<12} {:<20} {:>6} {:>9} {:>8} {:>8}",
        "PUBLIC_KEY", "OVERLAY_IP", "MODE", "ENDPOINT", "RTT_MS", "HANDSHAKE", "RX", "TX"
    );
    for p in &net.wg {
        let (mode, overlay, is_direct) = peer_mode(&p.allowed_ips, p.last_handshake, now);
        let addr = overlay.parse::<std::net::Ipv4Addr>().ok();
        let rtt = match (is_direct, addr) {
            (true, Some(ip)) => backend
                .ping_rtt_ms(ip)
                .map(|v| v.to_string())
                .unwrap_or_else(|| "—".into()),
            _ => "—".into(),
        };
        let handshake = if p.last_handshake > 0 {
            format!("{}s ago", now.saturating_sub(p.last_handshake))
        } else {
            "never".into()
        };
        println!(
            "{:<18} {:<14} {:<12} {:<20} {:>6} {:>9} {:>8} {:>8}",
            &p.public_key[..p.public_key.len().min(18)],
            overlay,
            mode,
            if p.endpoint.is_empty() {
                "—"
            } else {
                &p.endpoint
            },
            rtt,
            handshake,
            format_bytes(p.rx_bytes),
            format_bytes(p.tx_bytes),
        );
    }
}

/// 直连对端表一行判定（纯函数，可测）：allowed_ips 首个 CIDR 为 /32 =
/// 直连对端（agent 下发 `wg set` 时只写对端 /32），整段（如 /16）= hub
/// 中继对端。直连对端再按握手新鲜度分 p2p_direct / direct_pending。
/// 返回 (mode, overlay_ip, is_direct)；中继对端 overlay 为 "—"。
fn peer_mode(allowed_ips: &str, last_handshake: u64, now: u64) -> (String, String, bool) {
    let cidr = allowed_ips
        .split(',')
        .next()
        .unwrap_or("")
        .trim()
        .split_once('/');
    let prefix = cidr.and_then(|(_, p)| p.parse::<u8>().ok());
    let addr = cidr.map(|(a, _)| a.trim().to_string());
    let is_direct = prefix == Some(32);
    let mode = if !is_direct {
        "hub_relay".to_string()
    } else if last_handshake > 0 && now.saturating_sub(last_handshake) < 180 {
        "p2p_direct".to_string()
    } else {
        "direct_pending".to_string()
    };
    let overlay = if is_direct {
        addr.unwrap_or_default()
    } else {
        "—".to_string()
    };
    (mode, overlay, is_direct)
}

fn cmd_networks() {
    // 从 WireGuard 配置和路由表获取
    if cfg!(windows) {
        let routes = wg_routes();
        if routes.is_empty() {
            println!("no routes");
            return;
        }
        println!("{:<24} INTERFACE", "DESTINATION");
        for r in routes {
            println!("{:<24} {}", r.0, r.1);
        }
    } else {
        println!("networks: not supported on this platform yet");
    }
}

fn cmd_config() {
    let path = config_path();
    println!("# {}", path.display());
    match std::fs::read_to_string(&path) {
        Ok(text) => print!("{text}"),
        Err(_) => println!("(config not found)"),
    }
}

// ── helpers ──────────────────────────────────────────────────────────

fn read_config() -> serde_json::Value {
    let path = config_path();
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let mut map = serde_json::Map::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim().to_string();
            let v = v.trim().trim_matches('"').to_string();
            map.insert(k, serde_json::Value::String(v));
        }
    }
    serde_json::Value::Object(map)
}

fn read_status() -> serde_json::Value {
    let path = state_dir().join("tray").join("status.json");
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::json!({}))
}

fn wg_local_ip() -> Option<String> {
    #[cfg(windows)]
    {
        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command",
                "(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -match '^(wg-meshlet|meshlet)$' } | Select-Object -First 1).IPAddress"])
            .output()
            .ok()?;
        let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if ip.is_empty() {
            None
        } else {
            Some(ip)
        }
    }
    #[cfg(not(windows))]
    {
        None
    }
}

fn wg_routes() -> Vec<(String, String)> {
    #[cfg(windows)]
    {
        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command",
                "(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -match '^(wg-meshlet|meshlet)$' } | ForEach-Object { \"$($_.DestinationPrefix)|$($_.InterfaceAlias)\" })"])
            .output()
            .ok();
        if let Some(o) = output {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|l| {
                    l.split_once('|')
                        .map(|(a, b)| (a.to_string(), b.to_string()))
                })
                .collect()
        } else {
            vec![]
        }
    }
    #[cfg(not(windows))]
    {
        vec![]
    }
}

#[cfg(windows)]
fn process_exists(name: &str) -> bool {
    std::process::Command::new("tasklist")
        .args(["/FI", &format!("IMAGENAME eq {name}.exe"), "/NH"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(name))
        .unwrap_or(false)
}

#[cfg(windows)]
fn service_running(name: &str) -> bool {
    std::process::Command::new("sc")
        .args(["query", name])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("RUNNING"))
        .unwrap_or(false)
}

/// WireGuard Windows 隧道服务名候选（`WireGuardTunnel$<iface>`）：实际隧道名
/// 按 install.ps1/README 为 wg-meshlet，后端默认 meshlet。纯函数（可测）。
/// 非 Windows 构建下仅测试引用，允许 dead_code 以免 `clippy -D warnings` 挂。
#[cfg_attr(not(windows), allow(dead_code))]
fn tunnel_service_names() -> Vec<String> {
    ["wg-meshlet", "meshlet"]
        .iter()
        .map(|iface| format!("WireGuardTunnel${iface}"))
        .collect()
}

#[cfg(windows)]
fn tunnel_service_running() -> bool {
    tunnel_service_names()
        .iter()
        .any(|svc| service_running(svc))
}

#[cfg(not(windows))]
fn tunnel_service_running() -> bool {
    false
}

#[cfg(not(windows))]
fn process_exists(_: &str) -> bool {
    false
}

fn format_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n}B")
    } else if n < 1024 * 1024 {
        format!("{:.1}K", n as f64 / 1024.0)
    } else if n < 1024 * 1024 * 1024 {
        format!("{:.1}M", n as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2}G", n as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::peer_mode;

    /// 微型 mock 服务器记录：每个请求的 (method, path, authorization, csrf)。
    type MockLog = Vec<(String, String, String, String)>;

    #[test]
    fn usage_works() {
        // 确保 version 命令不 panic
        let _ = super::format_bytes(0);
    }

    /// R-TRAY-1：命令目录与 `meshlet --help` 实际输出一致（对账测试）。
    /// 帮助文本由目录生成，故二者同源；本测防「有人手改 help 造成漂移」。
    #[test]
    fn catalog_matches_help_and_dispatch() {
        let help = meshlet_commands::usage_text(env!("CARGO_PKG_VERSION"));
        // ① 目录每条命令都出现在 --help 输出里（名称+用途）。
        for c in meshlet_commands::COMMANDS {
            assert!(
                help.contains(c.name),
                "catalog '{}' missing from help",
                c.name
            );
            assert!(help.contains(c.summary), "summary of '{}' missing", c.name);
        }
        // ② 目录顶层命令集合与 main() 实际分发的命令集合一致（不遗漏、
        //    不虚增——新增命令必须进目录，目录命令必须能分发）。
        let catalog_top: std::collections::BTreeSet<&str> = meshlet_commands::COMMANDS
            .iter()
            .map(|c| c.name.split(' ').next().unwrap())
            .collect();
        let dispatched = std::collections::BTreeSet::from([
            "info", "status", "peers", "peer", "agent", "task", "networks", "config", "version",
            "help",
        ]);
        assert_eq!(catalog_top, dispatched, "catalog and dispatch disagree");
        // ③ agent/peer 子命令同样覆盖（diag/dial 在目录，分发只认它们）。
        let sub_catalog: Vec<&str> = meshlet_commands::COMMANDS
            .iter()
            .filter(|c| c.name.starts_with("agent ") || c.name.starts_with("peer "))
            .map(|c| c.name)
            .collect();
        assert!(sub_catalog.contains(&"agent diag"));
        assert!(sub_catalog.contains(&"peer dial"));
    }

    /// 审核发现 3a：state_dir/config_path 走 `%LOCALAPPDATA%\meshlet\`
    /// （install.ps1/agent/tray 同一约定），旧 ProgramData/config.toml 废弃。
    /// 用 PathBuf 同构期望，跨平台（Linux `/` 分隔）不失真。
    #[test]
    fn state_dir_uses_localappdata_meshlet() {
        let local = r"C:\Users\bob\AppData\Local";
        let state = super::state_dir_from_local(local);
        assert_eq!(
            state,
            std::path::Path::new(local).join("meshlet").join("state")
        );
        let cfg = super::config_path_from_local(local);
        assert_eq!(
            cfg,
            std::path::Path::new(local)
                .join("meshlet")
                .join("agent.toml")
        );
    }

    /// 审核发现 3b：隧道服务名按实际隧道 wg-meshlet/后端默认 meshlet，
    /// 不再有 `WireGuardTunnel$WireGuard` 硬编码。
    #[test]
    fn tunnel_service_names_match_install_conventions() {
        let names = super::tunnel_service_names();
        assert!(names.contains(&"WireGuardTunnel$wg-meshlet".to_string()));
        assert!(names.contains(&"WireGuardTunnel$meshlet".to_string()));
        assert!(!names.iter().any(|n| n.contains("$WireGuard")));
    }

    /// R-DIAG-2：allowed_ips 判直连（/32）与 hub（整段），握手判 P2P/pending。
    #[test]
    fn peer_mode_distinguishes_direct_from_hub() {
        let now = 1_000_000u64;
        // hub 中继：整段 /16，无论握手多新都是 relay，overlay 不显示。
        let (mode, overlay, is_direct) = peer_mode("10.240.0.0/16", now - 5, now);
        assert_eq!(mode, "hub_relay");
        assert_eq!(overlay, "—");
        assert!(!is_direct);

        // 直连对端 /32 + 新鲜握手 → p2p_direct，overlay 取地址。
        let (mode, overlay, is_direct) = peer_mode("10.240.0.3/32", now - 5, now);
        assert_eq!(mode, "p2p_direct");
        assert_eq!(overlay, "10.240.0.3");
        assert!(is_direct);

        // 直连对端 /32 + 陈旧/从未握手 → pending。
        let (mode, _, _) = peer_mode("10.240.0.3/32", now - 5000, now);
        assert_eq!(mode, "direct_pending");
        let (mode, _, _) = peer_mode("10.240.0.3/32", 0, now);
        assert_eq!(mode, "direct_pending");

        // 多 allowed-ips 取首个；空/无前缀按非直连处理（不误报）。
        let (mode, _, is_direct) = peer_mode("10.240.0.3/32,192.168.1.0/24", now - 5, now);
        assert_eq!(mode, "p2p_direct");
        assert!(is_direct);
        let (mode, _, is_direct) = peer_mode("", 0, now);
        assert_eq!(mode, "hub_relay");
        assert!(!is_direct);
    }

    /// `peer dial <node>`：解析目标（名称/IP/公钥前缀），未知目标不误配。
    #[test]
    fn resolve_dial_target_matches_name_ip_and_key_prefix() {
        use super::DirectPeerView;
        let views = vec![DirectPeerView {
            name: "peer-b".into(),
            virtual_ipv4: "10.240.0.3".parse().unwrap(),
            public_key: "AbCdEfGh1234==".into(),
            mode: "hub_relay".into(),
            rtt_ms: None,
            rtt_source: None,
            endpoint: String::new(),
            last_handshake_at: None,
        }];
        // 名称精确。
        assert_eq!(
            super::resolve_dial_target(&views, "peer-b").unwrap().name,
            "peer-b"
        );
        // overlay IP。
        assert_eq!(
            super::resolve_dial_target(&views, "10.240.0.3")
                .unwrap()
                .name,
            "peer-b"
        );
        // 公钥前缀（大小写不敏感）。
        assert_eq!(
            super::resolve_dial_target(&views, "abcdefgh").unwrap().name,
            "peer-b"
        );
        // 未知目标 → None（不误配别的节点）。
        assert!(super::resolve_dial_target(&views, "peer-c").is_none());
        assert!(super::resolve_dial_target(&views, "10.240.0.9").is_none());
    }

    /// 无参 `peer dial`：候选表含表头与每节点一行。
    #[test]
    fn format_dial_targets_lists_every_candidate() {
        use super::DirectPeerView;
        let views = vec![DirectPeerView {
            name: "peer-b".into(),
            virtual_ipv4: "10.240.0.3".parse().unwrap(),
            public_key: "k==".into(),
            mode: "hub_relay".into(),
            rtt_ms: None,
            rtt_source: None,
            endpoint: String::new(),
            last_handshake_at: None,
        }];
        let text = super::format_dial_targets(&views);
        assert!(text.contains("NAME"));
        assert!(text.contains("peer-b"));
        assert!(text.contains("10.240.0.3"));
        assert!(text.contains("hub_relay"));
    }

    // ── MT-003：`meshlet task` 解析与渲染 ───────────────────────────

    #[test]
    fn parse_flags_extracts_values_and_positionals() {
        let args: Vec<String> = [
            "task-1",
            "--network",
            "net-1",
            "--cmd",
            "echo hi",
            "--timeout",
            "30",
            "--verbose",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let (flags, pos) = super::parse_flags(&args);
        assert_eq!(pos, vec!["task-1".to_string()]);
        assert_eq!(flags.get("network").map(|s| s.as_str()), Some("net-1"));
        assert_eq!(flags.get("cmd").map(|s| s.as_str()), Some("echo hi"));
        assert_eq!(flags.get("timeout").map(|s| s.as_str()), Some("30"));
        assert_eq!(flags.get("verbose").map(|s| s.as_str()), Some(""));
        // flag 后随的非 `--` token 是它的值；末尾裸开关值为空。
        let (flags2, pos2) = super::parse_flags(&[
            "--x".to_string(),
            "task-2".to_string(),
            "--bare".to_string(),
        ]);
        assert_eq!(flags2.get("x").map(|s| s.as_str()), Some("task-2"));
        assert_eq!(flags2.get("bare").map(|s| s.as_str()), Some(""));
        assert!(pos2.is_empty());
        // 位置参数在前、flag 在后（实际用法 `task confirm <id> --network <id>`）。
        let (flags3, pos3) = super::parse_flags(&[
            "task-9".to_string(),
            "--network".to_string(),
            "net-2".to_string(),
        ]);
        assert_eq!(pos3, vec!["task-9".to_string()]);
        assert_eq!(flags3.get("network").map(|s| s.as_str()), Some("net-2"));
    }

    #[test]
    fn task_list_renders_columns_with_confirmation_marks() {
        let arr = serde_json::json!([
            {
                "id": "task-1", "state": "done", "target_device_id": "dev-1",
                "cmd": "echo hi", "confirmed_at": "t", "rejected_at": null,
                "parent_task_id": null,
            },
            {
                "id": "task-1-r1", "state": "assigned", "target_device_id": "dev-1",
                "cmd": "echo a very long command that truncates", "confirmed_at": null,
                "rejected_at": null, "parent_task_id": "task-1",
            },
        ]);
        let text = super::format_task_list(&arr);
        assert!(text.contains("ID"));
        assert!(text.contains("task-1"));
        assert!(text.contains("task-1-r1"));
        assert!(text.contains("yes")); // confirmed 标记
        assert!(text.contains("…")); // cmd 截断
        assert!(text.contains("PARENT")); // 父链列
        assert!(text.contains("task-1")); // r1 行的父链指向原任务
                                          // 空列表 → 明确空态。
        assert_eq!(
            super::format_task_list(&serde_json::json!([])),
            "(no tasks)\n"
        );
    }

    /// MT-003 验收「CLI 交互测试」：真实 socket + 真实 ureq 客户端 + 真实
    /// JSON 解析/渲染。起微型 HTTP 服务器按路径应答，验证 CLI 任务客户端
    /// 发出正确方法/路径/Bearer/CSRF 头并正确解析响应。
    #[test]
    fn task_cli_interacts_with_live_server() {
        let mut routes = std::collections::HashMap::new();
        routes.insert(
            "/api/v1/networks/net-1/tasks".to_string(),
            (
                200,
                serde_json::json!([
                    {
                        "id": "task-1", "network_id": "net-1", "target_device_id": "dev-1",
                        "cmd": "echo hi", "workdir": null, "timeout_secs": null,
                        "state": "done", "retry_limit": 0, "result_ref": "task-1",
                        "exit_code": 0, "log_tail": "hi", "confirmed_at": null,
                        "rejected_at": null, "parent_task_id": null,
                        "created_at": "t", "updated_at": "t",
                    }
                ]),
            ),
        );
        routes.insert(
            "/api/v1/networks/net-1/tasks/task-1/confirm".to_string(),
            (
                200,
                serde_json::json!({
                    "id": "task-1", "network_id": "net-1", "target_device_id": "dev-1",
                    "cmd": "echo hi", "workdir": null, "timeout_secs": null,
                    "state": "done", "retry_limit": 0, "result_ref": "task-1",
                    "exit_code": 0, "log_tail": "hi", "confirmed_at": "t",
                    "rejected_at": null, "parent_task_id": null,
                    "created_at": "t", "updated_at": "t",
                }),
            ),
        );
        routes.insert(
            "/api/v1/networks/net-1/tasks/task-1/retry".to_string(),
            (
                201,
                serde_json::json!({
                    "id": "task-1-r1", "network_id": "net-1", "target_device_id": "dev-1",
                    "cmd": "echo hi", "workdir": null, "timeout_secs": null,
                    "state": "assigned", "retry_limit": 0, "result_ref": null,
                    "exit_code": null, "log_tail": null, "confirmed_at": null,
                    "rejected_at": null, "parent_task_id": "task-1",
                    "created_at": "t", "updated_at": "t",
                }),
            ),
        );
        let (base, handle) = spawn_mock(routes, 3);

        // ls：GET 拉队列。
        let list =
            super::task_request("GET", &base, "mlt_secret", "/networks/net-1/tasks", None).unwrap();
        let rendered = super::format_task_list(&list);
        assert!(rendered.contains("task-1"));

        // confirm：POST + 空 JSON 体。
        let confirmed = super::task_request(
            "POST",
            &base,
            "mlt_secret",
            "/networks/net-1/tasks/task-1/confirm",
            Some(serde_json::json!({})),
        )
        .unwrap();
        assert_eq!(confirmed["confirmed_at"], "t");

        // retry：POST 返回新代（parent 链）。
        let rerun = super::task_request(
            "POST",
            &base,
            "mlt_secret",
            "/networks/net-1/tasks/task-1/retry",
            Some(serde_json::json!({})),
        )
        .unwrap();
        assert_eq!(rerun["id"], "task-1-r1");
        assert_eq!(rerun["parent_task_id"], "task-1");

        // 服务器记录：方法/路径/Bearer/CSRF 头全部符合管理面约定（服务端
        // 对写操作硬性要求 x-requested-with，丢头会 403——回归必须被看见）。
        let log = handle.join().unwrap();
        assert_eq!(log.len(), 3);
        assert_eq!(
            log[0],
            (
                "GET".into(),
                "/api/v1/networks/net-1/tasks".into(),
                "Bearer mlt_secret".into(),
                "XMLHttpRequest".into()
            )
        );
        assert_eq!(log[0].3, "XMLHttpRequest");
        assert_eq!(log[1].0, "POST");
        assert!(log[1].1.contains("/confirm"));
        assert_eq!(log[1].2, "Bearer mlt_secret");
        assert_eq!(log[1].3, "XMLHttpRequest");
        assert_eq!(log[2].0, "POST");
        assert!(log[2].1.contains("/retry"));
        assert_eq!(log[2].3, "XMLHttpRequest");
    }

    /// 微型 HTTP 服务器（测试）：按路径应答脚本，记录 (method, path, auth)。
    /// 处理 `requests` 个连接后退出。返回 (base_url, join_handle)。
    fn spawn_mock(
        routes: std::collections::HashMap<String, (u16, serde_json::Value)>,
        requests: usize,
    ) -> (String, std::thread::JoinHandle<MockLog>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let mut log = Vec::new();
            for stream in listener.incoming().take(requests) {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                // 读请求头（\r\n\r\n 结束）。
                let header_end;
                loop {
                    let n = stream.read(&mut tmp).unwrap();
                    if n == 0 {
                        return log;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end = pos + 4;
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let mut lines = head.lines();
                let request_line = lines.next().unwrap_or("").to_string();
                let mut auth = String::new();
                let mut csrf = String::new();
                for l in lines {
                    if l.to_ascii_lowercase().starts_with("authorization:") {
                        auth = l
                            .split_once(':')
                            .map(|(_, v)| v)
                            .unwrap_or("")
                            .trim()
                            .to_string();
                    }
                    if l.to_ascii_lowercase().starts_with("x-requested-with:") {
                        csrf = l
                            .split_once(':')
                            .map(|(_, v)| v)
                            .unwrap_or("")
                            .trim()
                            .to_string();
                    }
                }
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                let clen = head
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                    .and_then(|l| l.split_once(':').map(|(_, v)| v))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                while buf.len() < header_end + clen {
                    let n = stream.read(&mut tmp).unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                log.push((method, path.clone(), auth.clone(), csrf.clone()));
                let (status, body) = routes
                    .get(&path)
                    .cloned()
                    .unwrap_or((404, serde_json::json!({ "error": "not found" })));
                let body_str = serde_json::to_string(&body).unwrap();
                let reason = match status {
                    200 => "OK",
                    201 => "Created",
                    404 => "Not Found",
                    _ => "X",
                };
                let resp = format!(
                    "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body_str}",
                    body_str.len()
                );
                stream.write_all(resp.as_bytes()).unwrap();
            }
            log
        });
        (base, handle)
    }
}
