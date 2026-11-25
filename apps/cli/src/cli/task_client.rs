use crate::cli::local_state::read_config;
use std::collections::HashMap;

/// Task-domain usage for `meshlet task` (subcommands + required-argument quick reference).
pub(crate) fn print_task_usage() {
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

/// Error exit for the task subcommands.
fn task_fail(message: &str) -> ! {
    eprintln!("error: {message}");
    std::process::exit(1);
}

/// Parse `--flag value` pairs and positional arguments (pure function, testable).
pub(crate) fn parse_flags(args: &[String]) -> (HashMap<String, String>, Vec<String>) {
    let mut flags = HashMap::new();
    let mut positional = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(key) = arg.strip_prefix("--") {
            // `--flag value`: the next token counts as the value unless it starts with `--`; otherwise a bare switch.
            if let Some(value) = args.get(index + 1) {
                if !value.starts_with("--") {
                    flags.insert(key.to_string(), value.clone());
                    index += 2;
                    continue;
                }
            }
            flags.insert(key.to_string(), String::new());
            index += 1;
        } else {
            positional.push(arg.clone());
            index += 1;
        }
    }
    (flags, positional)
}

/// Server address: `--server` > `MESHLET_SERVER` > config `server_url`.
fn task_server(flags: &HashMap<String, String>) -> String {
    if let Some(server) = flags.get("server").filter(|server| !server.is_empty()) {
        return server.clone();
    }
    if let Ok(server) = std::env::var("MESHLET_SERVER") {
        if !server.is_empty() {
            return server;
        }
    }
    read_config()
        .get("server_url")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string()
}

/// API token: `--token` > `MESHLET_TOKEN` > config `api_token`.
fn task_token(flags: &HashMap<String, String>) -> String {
    if let Some(token) = flags.get("token").filter(|token| !token.is_empty()) {
        return token.clone();
    }
    if let Ok(token) = std::env::var("MESHLET_TOKEN") {
        if !token.is_empty() {
            return token;
        }
    }
    read_config()
        .get("api_token")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string()
}

/// Task API call (Bearer + CSRF headers). `body=None` means GET. Returns JSON.
pub(crate) fn task_request(
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
    let request = agent
        .request(method, &url)
        .set("Authorization", &format!("Bearer {token}"))
        .set("x-requested-with", "XMLHttpRequest")
        .set("content-type", "application/json");
    let payload = body.map(|body| body.to_string()).unwrap_or_default();
    match request.send_string(&payload) {
        Ok(response) => {
            let text = response.into_string().unwrap_or_default();
            serde_json::from_str(&text).map_err(|error| format!("bad response: {error}"))
        }
        Err(ureq::Error::Status(code, response)) => {
            let text = response.into_string().unwrap_or_default();
            Err(format!("HTTP {code}: {text}"))
        }
        Err(error) => Err(error.to_string()),
    }
}

/// `meshlet task assign --network <id> --node <device-id> --cmd <cmd>`
/// [--workdir <dir>] [--timeout <secs>] [--id <id>]
pub(crate) fn cmd_task_assign(args: &[String]) {
    let (flags, _positional) = parse_flags(args);
    let server = task_server(&flags);
    let token = task_token(&flags);
    let network = flags.get("network").cloned().unwrap_or_default();
    let node = flags.get("node").cloned().unwrap_or_default();
    let command = flags.get("cmd").cloned().unwrap_or_default();
    if network.is_empty() || node.is_empty() || command.is_empty() {
        task_fail("task assign requires --network <id>, --node <device-id>, --cmd <command>");
    }
    let mut body = serde_json::json!({ "target_device_id": node, "cmd": command });
    if let Some(workdir) = flags.get("workdir").filter(|workdir| !workdir.is_empty()) {
        body["workdir"] = serde_json::json!(workdir);
    }
    // `--timeout` must be a number of seconds; an invalid value is not silently dropped (otherwise it would run with the default timeout and the behaviour would change quietly).
    if let Some(raw) = flags.get("timeout") {
        match raw.parse::<u64>() {
            Ok(timeout) => {
                body["timeout_secs"] = serde_json::json!(timeout);
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
        Ok(task) => {
            println!("assigned: {}", task["id"].as_str().unwrap_or("?"));
            print!("{}", format_task_view(&task));
        }
        Err(error) => task_fail(&error),
    }
}

/// `meshlet task ls --network <id>`.
pub(crate) fn cmd_task_ls(args: &[String]) {
    let (flags, _positional) = parse_flags(args);
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
        Ok(tasks) => print!("{}", format_task_list(&tasks)),
        Err(error) => task_fail(&error),
    }
}

/// `meshlet task confirm <task-id> --network <id>` (user-side completion confirmation).
pub(crate) fn cmd_task_confirm(args: &[String]) {
    let (flags, positional) = parse_flags(args);
    let server = task_server(&flags);
    let token = task_token(&flags);
    let network = flags.get("network").cloned().unwrap_or_default();
    let id = positional.first().cloned().unwrap_or_default();
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
        Ok(task) => {
            println!("confirmed: {}", task["id"].as_str().unwrap_or("?"));
            print!("{}", format_task_view(&task));
        }
        Err(error) => task_fail(&error),
    }
}

/// `meshlet task retry <task-id> --network <id>` (reject and re-run, spawning a new-generation task).
pub(crate) fn cmd_task_retry(args: &[String]) {
    let (flags, positional) = parse_flags(args);
    let server = task_server(&flags);
    let token = task_token(&flags);
    let network = flags.get("network").cloned().unwrap_or_default();
    let id = positional.first().cloned().unwrap_or_default();
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
        Ok(task) => {
            println!(
                "retried: {} (rerun dispatched)",
                task["id"].as_str().unwrap_or("?")
            );
            print!("{}", format_task_view(&task));
        }
        Err(error) => task_fail(&error),
    }
}

/// Command summary (truncated inside the column width `{:&<12}`: 11 chars + ellipsis = 12 columns; pure function).
fn cmd_short(command: &str) -> String {
    let count = command.chars().count();
    if count > 12 {
        let truncated: String = command.chars().take(11).collect();
        format!("{truncated}…")
    } else {
        command.to_string()
    }
}

/// Single task view (pure function, testable).
pub(crate) fn format_task_view(task: &serde_json::Value) -> String {
    format!(
        "  id={} state={} target={} confirmed={} rejected={} parent={}\n  cmd={} exit_code={}\n",
        task["id"].as_str().unwrap_or("?"),
        task["state"].as_str().unwrap_or("?"),
        task["target_device_id"].as_str().unwrap_or("?"),
        task["confirmed_at"].as_str().map(|_| "yes").unwrap_or("—"),
        task["rejected_at"].as_str().map(|_| "yes").unwrap_or("—"),
        task["parent_task_id"].as_str().unwrap_or("—"),
        task["cmd"].as_str().unwrap_or("?"),
        task["exit_code"]
            .as_i64()
            .map(|code| code.to_string())
            .unwrap_or("—".into()),
    )
}

/// Task list rendering (pure function, testable).
pub(crate) fn format_task_list(tasks: &serde_json::Value) -> String {
    let rows = match tasks.as_array() {
        Some(rows) if !rows.is_empty() => rows,
        _ => return "(no tasks)\n".to_string(),
    };
    let mut output = format!(
        "{:<16} {:<10} {:<16} {:<12} {:<10} {:<10}  {}\n",
        "ID", "STATE", "TARGET", "CMD", "CONFIRMED", "REJECTED", "PARENT"
    );
    for task in rows {
        output.push_str(&format!(
            "{:<16} {:<10} {:<16} {:<12} {:<10} {:<10}  {}\n",
            task["id"].as_str().unwrap_or("?"),
            task["state"].as_str().unwrap_or("?"),
            task["target_device_id"].as_str().unwrap_or("?"),
            cmd_short(task["cmd"].as_str().unwrap_or("?")),
            task["confirmed_at"].as_str().map(|_| "yes").unwrap_or("—"),
            task["rejected_at"].as_str().map(|_| "yes").unwrap_or("—"),
            task["parent_task_id"].as_str().unwrap_or("—"),
        ));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{format_task_list, parse_flags, task_request};
    use std::collections::HashMap;

    /// Miniature mock server log: (method, path, authorization, csrf) per request.
    type MockLog = Vec<(String, String, String, String)>;

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
        .map(|argument| argument.to_string())
        .collect();
        let (flags, positional) = parse_flags(&args);
        assert_eq!(positional, vec!["task-1".to_string()]);
        assert_eq!(flags.get("network").map(String::as_str), Some("net-1"));
        assert_eq!(flags.get("cmd").map(String::as_str), Some("echo hi"));
        assert_eq!(flags.get("timeout").map(String::as_str), Some("30"));
        assert_eq!(flags.get("verbose").map(String::as_str), Some(""));

        // A non-`--` token following a flag is its value; a trailing bare switch has an empty value.
        let (flags, positional) = parse_flags(&[
            "--x".to_string(),
            "task-2".to_string(),
            "--bare".to_string(),
        ]);
        assert_eq!(flags.get("x").map(String::as_str), Some("task-2"));
        assert_eq!(flags.get("bare").map(String::as_str), Some(""));
        assert!(positional.is_empty());

        // Positional arguments first, flags after (real usage: `task confirm <id> --network <id>`).
        let (flags, positional) = parse_flags(&[
            "task-9".to_string(),
            "--network".to_string(),
            "net-2".to_string(),
        ]);
        assert_eq!(positional, vec!["task-9".to_string()]);
        assert_eq!(flags.get("network").map(String::as_str), Some("net-2"));
    }

    #[test]
    fn task_list_renders_columns_with_confirmation_marks() {
        let tasks = serde_json::json!([
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
        let text = format_task_list(&tasks);
        assert!(text.contains("ID"));
        assert!(text.contains("task-1"));
        assert!(text.contains("task-1-r1"));
        assert!(text.contains("yes")); // confirmed marker
        assert!(text.contains("…")); // cmd truncation
        assert!(text.contains("PARENT")); // parent-chain column
        assert!(text.contains("task-1")); // r1's parent chain points at the original task

        // Empty list -> an explicit empty state.
        assert_eq!(format_task_list(&serde_json::json!([])), "(no tasks)\n");
    }

    /// MT-003 acceptance "CLI interaction test": a real socket + a real ureq client + real
    /// JSON parsing/rendering. A miniature HTTP server answers per path, verifying that the CLI
    /// task client sends the right method/path/Bearer/CSRF headers and parses responses correctly.
    #[test]
    fn task_cli_interacts_with_live_server() {
        let mut routes = HashMap::new();
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
        let (base_url, handle) = spawn_mock(routes, 3);

        // ls: GET to pull the queue.
        let tasks = task_request(
            "GET",
            &base_url,
            "mlt_secret",
            "/networks/net-1/tasks",
            None,
        )
        .unwrap();
        assert!(format_task_list(&tasks).contains("task-1"));

        // confirm: POST + empty JSON body.
        let confirmed = task_request(
            "POST",
            &base_url,
            "mlt_secret",
            "/networks/net-1/tasks/task-1/confirm",
            Some(serde_json::json!({})),
        )
        .unwrap();
        assert_eq!(confirmed["confirmed_at"], "t");

        // retry: POST returns a new generation (parent chain).
        let rerun = task_request(
            "POST",
            &base_url,
            "mlt_secret",
            "/networks/net-1/tasks/task-1/retry",
            Some(serde_json::json!({})),
        )
        .unwrap();
        assert_eq!(rerun["id"], "task-1-r1");
        assert_eq!(rerun["parent_task_id"], "task-1");

        // Matches the management-plane convention (the server hard-requires x-requested-with on write
        // operations; dropping the header is a 403 — the regression must be visible).
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

    /// Miniature HTTP server (test): answers per a path-based script, logging (method, path, auth).
    fn spawn_mock(
        routes: HashMap<String, (u16, serde_json::Value)>,
        requests: usize,
    ) -> (String, std::thread::JoinHandle<MockLog>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let mut log = Vec::new();
            for stream in listener.incoming().take(requests) {
                let mut stream = match stream {
                    Ok(stream) => stream,
                    Err(_) => break,
                };
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 4096];

                // Read the request headers (terminated by \r\n\r\n).
                let header_end;
                loop {
                    let read = stream.read(&mut chunk).unwrap();
                    if read == 0 {
                        return log;
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                    if let Some(position) =
                        buffer.windows(4).position(|window| window == b"\r\n\r\n")
                    {
                        header_end = position + 4;
                        break;
                    }
                }

                let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
                let mut lines = head.lines();
                let request_line = lines.next().unwrap_or("").to_string();
                let mut authorization = String::new();
                let mut csrf = String::new();
                for line in lines {
                    if line.to_ascii_lowercase().starts_with("authorization:") {
                        authorization = line
                            .split_once(':')
                            .map(|(_, value)| value)
                            .unwrap_or("")
                            .trim()
                            .to_string();
                    }
                    if line.to_ascii_lowercase().starts_with("x-requested-with:") {
                        csrf = line
                            .split_once(':')
                            .map(|(_, value)| value)
                            .unwrap_or("")
                            .trim()
                            .to_string();
                    }
                }

                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                let content_length = head
                    .lines()
                    .find(|line| line.to_ascii_lowercase().starts_with("content-length:"))
                    .and_then(|line| line.split_once(':').map(|(_, value)| value))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                while buffer.len() < header_end + content_length {
                    let read = stream.read(&mut chunk).unwrap();
                    if read == 0 {
                        break;
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                }

                log.push((method, path.clone(), authorization, csrf));
                let (status, body) = routes
                    .get(&path)
                    .cloned()
                    .unwrap_or((404, serde_json::json!({ "error": "not found" })));
                let body_string = serde_json::to_string(&body).unwrap();
                let reason = match status {
                    200 => "OK",
                    201 => "Created",
                    404 => "Not Found",
                    _ => "X",
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body_string}",
                    body_string.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
            log
        });
        (base_url, handle)
    }
}
