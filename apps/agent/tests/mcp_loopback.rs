//! End-to-end verification of `apps/agent/src/mcp.rs`: really start the server, really speak HTTP,
//! really do an MCP JSON-RPC round trip. It does not depend on `Agent::run()`'s data-plane path (that one
//! needs kernel privileges and a real server); it only checks the delivery point "once enabled locally, an AI client can query this machine's facts".
//!
//! Covers:
//! 1. `initialize` -> obtain `Mcp-Session-Id`, the server announces tool capability;
//! 2. `tools/list` -> all seven read-only tools present (status/info/peers/routes/networks/diag/doctor);
//! 3. `tools/call` status/peers -> the replies are the real file contents in state_dir;
//! 4. the handoff file `mcp.json` has url/port/pid, and is removed when the service drops;
//! 5. read-only boundary: `info` never leaks `device_token`/`bootstrap_token`.

use std::io::Write;
use std::net::TcpStream;
use std::path::PathBuf;

use meshlet_agent::mcp;

/// Build a temporary state_dir and write the fixture data files (the same paths agent/tray use in production).
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
    // Put agent.toml in the parent directory (`read_config_top` reads the parent of state_dir).
    std::fs::write(
        base.parent().unwrap().join("agent.toml"),
        "device_name = \"dev-a\"\nserver_url = \"https://ctrl.example\"\ndevice_token = \"SECRET_TOKEN\"\nbootstrap_token = \"SECRET_BOOTSTRAP\"\n\n[dataplane]\nenabled = false\n",
    )
    .unwrap();
    base
}

/// One JSON-RPC round trip over HTTP. Returns (status, headers, body).
/// A minimal HTTP/1.1 client: avoids pulling an extra HTTP dependency into tests and lets us see the
/// full `Mcp-Session-Id` header (ureq could do it too, but here we want a direct loopback without cookie interference).
/// Reads the response body by Content-Length, never `read_to_end` (which hangs under keep-alive).
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

    // Read the headers first (until the blank line), parse Content-Length, then read the body exactly.
    let mut header_buf = Vec::new();
    let mut byte = [0u8; 1];
    while !header_buf.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).unwrap();
        header_buf.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&header_buf).to_string();
    // SSE responses are usually chunked (no Content-Length). Support both:
    // read by length when Content-Length is present; read by chunks when Transfer-Encoding: chunked.
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
        // Read chunk by chunk: `<hex len>\r\n<bytes>\r\n` ... `0\r\n\r\n`
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
            // Consume the trailing \r\n of the chunk
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

/// An MCP response may be plain JSON or SSE (`event: message\ndata: {...}`).
/// Take the last data line and parse it as JSON.
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

    // Handoff file: url/port/pid all present, and the url is loopback.
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

    // notifications/initialized (no id, 202)
    let note = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    let (note_status, _, _) = rpc(port, Some(&session), note);
    assert!(
        note_status == 200 || note_status == 202,
        "got {note_status}"
    );

    // 2) tools/list -> all seven read-only tools
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
        vec!["diag", "doctor", "info", "networks", "peers", "routes", "status"],
        "exactly the read-only tool set"
    );

    // 3) tools/call status -> really reads the device facts from status.json's tooltip
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

    // 3b) tools/call peers -> really reads direct-peers.json
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

    // 5) read-only boundary: info must not leak the token
    let call_info =
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"info","arguments":{}}}"#;
    let (_, _, payload) = rpc(port, Some(&session), call_info);
    let info_text = tool_text(&body_json(&payload));
    assert!(info_text.contains("dev-a"));
    assert!(
        !info_text.contains("SECRET_TOKEN") && !info_text.contains("SECRET_BOOTSTRAP"),
        "secrets must never surface: {info_text}"
    );

    // 4) drop -> the handoff file is cleaned up
    drop(server);
    assert!(
        mcp::read_url_file(&state).is_none(),
        "mcp.json must be removed on stop"
    );
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}
