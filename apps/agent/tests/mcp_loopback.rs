//! `apps/agent/src/mcp.rs` 的端到端验证：真起服务、真走 HTTP、真做 MCP
//! JSON-RPC 往返。不依赖 `Agent::run()` 的数据面路径（那条路需要内核权限
//! 与真实 server），只验证「本地开启后 AI 客户端能查询本机事实」这一交付点。
//!
//! 覆盖：
//! 1. `initialize` → 拿到 `Mcp-Session-Id`，服务宣告 tools 能力；
//! 2. `tools/list` → 六个只读工具俱全（status/info/peers/routes/networks/diag）；
//! 3. `tools/call` status/peers → 返回的是 state_dir 里真实文件内容；
//! 4. 交接文件 `mcp.json` 有 url/port/pid，drop 服务后被清掉；
//! 5. 只读边界：`info` 不吐 `device_token`/`bootstrap_token`。

use std::io::Write;
use std::net::TcpStream;
use std::path::PathBuf;

use meshlet_agent::mcp;

/// 造一个临时 state_dir，写入被测数据文件（与 agent/tray 生产同款路径）。
fn fixture_state_dir(name: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "meshlet-mcp-test-{name}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(base.join("tray")).unwrap();
    std::fs::write(
        base.join("tray").join("status.json"),
        r#"{"state":"connected","device_name":"dev-a","virtual_ip":"10.240.0.2",
            "version":"0.1.0","tooltip":"Meshlet「dev-a」 10.240.0.2：已连接"}"#,
    )
    .unwrap();
    std::fs::write(
        base.join("direct-peers.json"),
        r#"[{"name":"peer-b","overlay_ip":"10.240.0.3","mode":"direct","rtt_ms":12,
             "endpoint":"203.0.113.9:51820","last_handshake":"2026-11-08T10:00:00Z",
             "public_key":"PUBKEY_B"}]"#,
    )
    .unwrap();
    std::fs::write(
        base.join("applied.json"),
        r#"{"last_good_plan":{"routes":[{"destination":"10.240.0.0/24","next_hop":null,
             "interface":"meshlet0","source":"mesh"}]}}"#,
    )
    .unwrap();
    // 父目录放 agent.toml（`read_config_top` 读的是 state_dir 的父级）。
    std::fs::write(
        base.parent().unwrap().join("agent.toml"),
        "device_name = \"dev-a\"\nserver_url = \"https://ctrl.example\"\ndevice_token = \"SECRET_TOKEN\"\nbootstrap_token = \"SECRET_BOOTSTRAP\"\n\n[dataplane]\nenabled = false\n",
    )
    .unwrap();
    base
}

/// 一次 JSON-RPC over HTTP 往返。返回 (status, headers, body)。
/// 极简 HTTP/1.1 客户端：避免为测试引入额外 HTTP 依赖，且能完整看到
/// `Mcp-Session-Id` 头（ureq 也能取，但这里要不带 cookie 干扰地直连 loopback）。
/// 按 Content-Length 读取响应体，绝不 `read_to_end`（keep-alive 下会挂死）。
fn rpc(port: u16, session: Option<&str>, body: &str) -> (u16, Vec<(String, String)>, String) {
    use std::io::Read;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let mut req = format!(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
         Content-Type: application/json\r\n\
         Accept: application/json, text/event-stream\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n",
        body.len()
    );
    if let Some(sid) = session {
        req.push_str(&format!("Mcp-Session-Id: {sid}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    stream.write_all(req.as_bytes()).unwrap();

    // 先读头部（直到空行），解析 Content-Length，再精确读 body。
    let mut header_buf = Vec::new();
    let mut byte = [0u8; 1];
    while !header_buf.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).unwrap();
        header_buf.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&header_buf).to_string();
    // SSE 响应通常用 chunked 传输（无 Content-Length）。两种都支持：
    // 有 Content-Length 按长度读；有 Transfer-Encoding: chunked 按块读。
    let is_chunked = head
        .lines()
        .any(|l| l.to_ascii_lowercase().starts_with("transfer-encoding:") && l.contains("chunked"));
    let content_length: Option<usize> = head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        if k.eq_ignore_ascii_case("content-length") {
            v.trim().parse().ok()
        } else {
            None
        }
    });

    let payload = if is_chunked {
        // 逐块读：`<hex len>\r\n<bytes>\r\n` … `0\r\n\r\n`
        let mut out = Vec::new();
        loop {
            let mut size_line = Vec::new();
            loop {
                stream.read_exact(&mut byte).unwrap();
                if byte[0] == b'\n' {
                    break;
                }
                if byte[0] != b'\r' {
                    size_line.push(byte[0]);
                }
            }
            let size =
                usize::from_str_radix(String::from_utf8_lossy(&size_line).trim(), 16).unwrap_or(0);
            if size == 0 {
                break;
            }
            let mut chunk = vec![0u8; size];
            stream.read_exact(&mut chunk).unwrap();
            out.extend_from_slice(&chunk);
            // 吃掉块尾的 \r\n
            let mut crlf = [0u8; 2];
            let _ = stream.read_exact(&mut crlf);
        }
        String::from_utf8_lossy(&out).to_string()
    } else {
        let len = content_length.unwrap_or(0);
        let mut payload = vec![0u8; len];
        if len > 0 {
            stream.read_exact(&mut payload).unwrap();
        }
        String::from_utf8_lossy(&payload).to_string()
    };

    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    (status, headers, payload)
}

/// MCP 的响应可能是纯 JSON，也可能是 SSE（`event: message\ndata: {...}`）。
/// 取最后一条 data 行解析成 JSON。
fn body_json(payload: &str) -> serde_json::Value {
    let candidate = payload
        .lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .map(str::trim)
        .rfind(|s| s.starts_with('{'))
        .unwrap_or_else(|| payload.trim())
        .to_string();
    serde_json::from_str(&candidate)
        .unwrap_or_else(|e| panic!("body not JSON: {e}\nraw: {payload}"))
}

fn tool_text(result: &serde_json::Value) -> String {
    // CallToolResult.content[0].text
    result["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no text content: {result}"))
        .to_string()
}

#[test]
fn mcp_serves_read_only_facts_over_loopback_and_cleans_up() {
    let state = fixture_state_dir("e2e");
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let _guard = runtime.enter();
    let server = mcp::start(&state, 0).expect("start mcp");
    let port = server.port();
    assert_ne!(port, 0, "must bind a real port");

    // 交接文件：url/port/pid 齐全，且 url 是 loopback。
    let endpoint = mcp::read_url_file(&state).expect("mcp.json written");
    assert_eq!(endpoint.port, port);
    assert_eq!(endpoint.pid, std::process::id());
    assert!(
        endpoint.url.starts_with("http://127.0.0.1:"),
        "loopback only"
    );

    // 1) initialize
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}"#;
    let (status, headers, payload) = rpc(port, None, init);
    assert_eq!(status, 200, "initialize status; body={payload}");
    let session = headers
        .iter()
        .find(|(k, _)| k == "mcp-session-id")
        .map(|(_, v)| v.clone())
        .expect("server must issue a session id");
    let init_json = body_json(&payload);
    assert!(init_json["result"]["capabilities"]["tools"].is_object());
    assert!(init_json["result"]["serverInfo"]["name"].as_str().is_some());

    // notifications/initialized（无 id，202）
    let note = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    let (note_status, _, _) = rpc(port, Some(&session), note);
    assert!(
        note_status == 200 || note_status == 202,
        "got {note_status}"
    );

    // 2) tools/list → 六个只读工具
    let list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
    let (status, _, payload) = rpc(port, Some(&session), list);
    assert_eq!(status, 200);
    let list_json = body_json(&payload);
    let mut names: Vec<String> = list_json["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec!["diag", "info", "networks", "peers", "routes", "status"],
        "exactly the read-only tool set"
    );

    // 3) tools/call status → 真读到 status.json 的 tooltip 里的设备事实
    let call_status = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"status","arguments":{}}}"#;
    let (status, _, payload) = rpc(port, Some(&session), call_status);
    assert_eq!(status, 200);
    let text = tool_text(&body_json(&payload));
    assert!(
        text.contains("dev-a"),
        "status should carry device name: {text}"
    );
    assert!(
        text.contains("connected"),
        "status should carry state: {text}"
    );

    // 3b) tools/call peers → 真读到 direct-peers.json
    let call_peers = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"peers","arguments":{}}}"#;
    let (_, _, payload) = rpc(port, Some(&session), call_peers);
    let peers_text = tool_text(&body_json(&payload));
    assert!(
        peers_text.contains("peer-b"),
        "peers should carry peer name: {peers_text}"
    );
    assert!(
        peers_text.contains("10.240.0.3"),
        "peers should carry overlay ip"
    );

    // 5) 只读边界：info 不得泄漏 token
    let call_info =
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"info","arguments":{}}}"#;
    let (_, _, payload) = rpc(port, Some(&session), call_info);
    let info_text = tool_text(&body_json(&payload));
    assert!(info_text.contains("dev-a"));
    assert!(
        !info_text.contains("SECRET_TOKEN") && !info_text.contains("SECRET_BOOTSTRAP"),
        "secrets must never surface: {info_text}"
    );

    // 4) drop → 交接文件被清
    drop(server);
    assert!(
        mcp::read_url_file(&state).is_none(),
        "mcp.json must be removed on stop"
    );
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}
