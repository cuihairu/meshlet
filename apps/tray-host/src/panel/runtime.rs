//! 本地面板：托盘「本地面板」打开的本机自托管只读页（loopback 随机端口）。
//!
//! 定案（2026-11-06 用户，见 todo.md `LOCAL-PANEL-1`）：托盘「打开面板」必须
//! 打开**本地面板**，不是 server 托管的控制台；控制台另列菜单项。
//!
//! - **三块信息**：① 当前节点（设备名 / 虚拟 IP / 公钥指纹 / 状态灯 / hub 控制
//!   通道 / 版本 / EnvProbe 关键项）② 直连节点（`direct-peers.json` 全量）③
//!   本地路由（`applied.json` 的计划路由，缺省回落账本前缀）。
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{html, snapshot};

/// 单请求读取上限（请求行），超长请求直接断开，不占服务线程。
const REQUEST_LIMIT: u64 = 8 * 1024;
/// 读写超时：慢速客户端不会拖住 accept 循环。
const IO_TIMEOUT: Duration = Duration::from_secs(5);

const CONTENT_HTML: &str = "text/html; charset=utf-8";
const CONTENT_JSON: &str = "application/json; charset=utf-8";

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

/// 读面板 URL 交接文件（`{state_dir}/local-panel.json`）。
pub fn read_url_file(state_dir: &Path) -> Option<String> {
    let value = super::snapshot::read_json(&state_dir.join(URL_FILE))?;
    value
        .as_object()?
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
                &html::error_page("仅支持 GET"),
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
            &html::render(state_dir),
            head_only,
        ),
        "/state.json" => respond(
            stream,
            "200 OK",
            CONTENT_JSON,
            &snapshot::state_json(state_dir),
            head_only,
        ),
        _ => respond(
            stream,
            "404 Not Found",
            CONTENT_HTML,
            &html::error_page("页面不存在（本地面板只有 / 与 /state.json）"),
            head_only,
        ),
    }
}

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
