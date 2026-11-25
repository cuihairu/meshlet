//! Local panel: the self-hosted read-only page on this machine (loopback on a random port)
//! opened by the tray's "local panel" item.
//!
//! Decided (user, 2026-11-06, see `LOCAL-PANEL-1` in todo.md): the tray's "open panel" must open
//! the **local panel**, not the server-hosted console; the console gets its own menu item.
//!
//! - **Three blocks of information**: ① current node (device name / virtual IP / public key
//!   fingerprint / status light / hub control channel / version / key EnvProbe items) ② direct
//!   nodes (the full `direct-peers.json`) ③ local routes (the planned routes from `applied.json`,
//!   falling back to the ledger prefixes when absent).
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{html, snapshot};

/// Per-request read cap (the request line); overlong requests are dropped outright so they do not tie up a serving thread.
const REQUEST_LIMIT: u64 = 8 * 1024;
/// Read/write timeout: a slow client cannot hold up the accept loop.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

const CONTENT_HTML: &str = "text/html; charset=utf-8";
const CONTENT_JSON: &str = "application/json; charset=utf-8";

/// Starts the local panel service: binds `127.0.0.1:0` and returns the actual port (see [`url`] for the URL).
///
/// The port is already listening before this returns, so the caller can open a browser as soon as it has the port — no race.
pub fn start(state_dir: PathBuf) -> std::io::Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    std::thread::Builder::new()
        .name("meshlet-local-panel".into())
        .spawn(move || serve(listener, state_dir))?;
    Ok(port)
}

/// Panel URL (loopback only).
pub fn url(port: u16) -> String {
    format!("http://127.0.0.1:{port}/")
}

/// Panel URL handoff file (`{state_dir}/local-panel.json`).
///
/// Why it exists: on Windows a redirected log file cannot be read while the process is alive (the
/// `tray-windows` job in this repo hit that), yet the panel must be reachable by curl/browser while
/// the tray process is **still alive** — so the URL goes into a small write-then-close file that CI and
/// ops use to obtain the port. The caller removes it on exit, best-effort.
pub const URL_FILE: &str = "local-panel.json";

/// Writes the panel URL handoff file (`{url, pid}`).
///
/// **Atomic publish**: write `.tmp` first, then rename over the target — `fs::write` truncates
/// before writing, so a reader (CI gate / ops) could otherwise catch an empty file or half a JSON.
pub fn write_url_file(state_dir: &Path, url: &str) -> std::io::Result<()> {
    let body = serde_json::json!({ "url": url, "pid": std::process::id() }).to_string();
    let tmp = state_dir.join(format!("{URL_FILE}.tmp"));
    std::fs::write(&tmp, body)?;
    // On Windows `rename` maps to `MoveFileEx(..., MOVEFILE_REPLACE_EXISTING)`, which overwrites an existing target file.
    std::fs::rename(&tmp, state_dir.join(URL_FILE))
}

/// Reads the panel URL handoff file (`{state_dir}/local-panel.json`).
pub fn read_url_file(state_dir: &Path) -> Option<String> {
    let value = super::snapshot::read_json(&state_dir.join(URL_FILE))?;
    value
        .as_object()?
        .get("url")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Removes the handoff file on exit (best-effort: a leftover only means the next read sees a stale URL, not fatal).
pub fn remove_url_file(state_dir: &Path) {
    let _ = std::fs::remove_file(state_dir.join(URL_FILE));
}

/// Accept loop: single-threaded sequential serving (a local single-user page; requests finish in milliseconds).
fn serve(listener: TcpListener, state_dir: PathBuf) {
    for conn in listener.incoming() {
        let Ok(stream) = conn else {
            continue; // Transient accept error: keep serving, do not exit the thread.
        };
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        if let Err(error) = handle(&state_dir, stream) {
            tracing::debug!(%error, "local panel request failed");
        }
    }
}

/// Handles one request: only `GET|HEAD /` (the page) and `GET|HEAD /state.json`
/// (the partial-update data source) are allowed; everything else gets 404/405.
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

/// Writes the response (`Connection: close`: one request per connection, so the browser needs no keep-alive).
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

/// Reads a single **top-level** key from `{state_dir}/../<file>` (`agent.toml`, or `config.toml` for older deployments).
///
/// Only a top-level `key = value` before the first `[section]` counts: keys inside sections
/// (data-plane settings such as `interface` under `[dataplane]`) are always skipped, so the panel
/// never mistakes in-section configuration for node information.
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
