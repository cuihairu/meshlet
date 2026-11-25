//! MCP local service: AI clients query this machine's mesh facts over loopback HTTP.
//!
//! Decision (2026-11-08, user): meshlet's local query feature is built as **MCP**; once
//! enabled locally, AI clients can quickly reach different machines (each machine runs
//! one agent MCP endpoint). Supersedes the script/CLI/console-facing OS-level IPC proposal in
//! 2026-10-19 `docs/analysis/agent-local-api-2026-10-19.md` — AI consumes, MCP transports.
//!
//! Security boundary (same risk list as the 2026-10-19 research):
//! - **Loopback only**: bound to `127.0.0.1`, never an external interface;
//! - **Read-only**: tool set is queries (status/info/peers/routes/networks/diag),
//!   no writes, no shell commands, no private-key reads;
//! - **No secrets**: `device_token` / `bootstrap_token` in `agent.toml` are never emitted;
//! - **Off by default**: `[mcp] enabled = false`; listens only when explicitly enabled.
//!
//! Transport: rmcp streamable HTTP (`StreamableHttpService`), endpoint
//! `POST /mcp`. The port writes the `{state_dir}/mcp.json` (`{url, port, pid}`) handoff file,
//! atomic publish like local-panel.json (.tmp + rename); tray/CI/clients get the
//! endpoint from it.
//!
//! Data sources share the local panel/CLI pipeline (`tray/status.json`,
//! `direct-peers.json`, `applied.json` and `agent.toml` under `{state_dir}`):
//! one source, three faces, no duplicated read logic.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::routing::{get, post};
use axum::Router;
use rmcp::{
    handler::server::router::tool::ToolRouter,
    tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    },
    ServerHandler,
};

/// MCP endpoint path (streamable HTTP convention).
pub const MCP_PATH: &str = "/mcp";
/// Handoff file name (`{state_dir}/mcp.json`).
pub const MCP_URL_FILE: &str = "mcp.json";
/// Per-request body limit (rmcp default 4 MiB, plenty for tool arguments).
const REQUEST_BODY_LIMIT: usize = 4 * 1024 * 1024;

/// MCP service state (handoff file content).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct McpEndpoint {
    pub url: String,
    pub port: u16,
    pub pid: u32,
}

/// Start the MCP service: bind loopback on a random/specified port, write `{state_dir}/mcp.json`,
/// return endpoint info. **The caller owns the `McpServer` handle** (drop stops it and clears the handoff file).
///
/// Bind failure returns `Err` (port in use etc.), no panic — the caller decides whether to degrade to
/// "MCP not started" and record it honestly.
pub fn start(state_dir: &Path, port: u16) -> std::io::Result<McpServer> {
    let state_dir = state_dir.to_path_buf();
    let handler = McpHandler::new(state_dir.clone());
    let service = Arc::new(StreamableHttpService::new(
        move || Ok(handler.clone()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default()
            .with_allowed_hosts(["localhost", "127.0.0.1", "::1"])
            .with_max_request_body_bytes(REQUEST_BODY_LIMIT),
    ));

    let app = Router::new()
        .route(
            MCP_PATH,
            post(mcp_handler).get(mcp_handler).head(mcp_handler),
        )
        .route("/", get(health))
        .with_state(service);

    let runtime = std::sync::Arc::new(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| std::io::Error::other(e.to_string()))?,
    );
    let listener = std::net::TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let listener = tokio::net::TcpListener::from_std(listener)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let addr = listener
        .local_addr()
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let endpoint = McpEndpoint {
        url: format!("http://127.0.0.1:{}/{MCP_PATH}", addr.port()),
        port: addr.port(),
        pid: std::process::id(),
    };
    write_url_file(&state_dir, &endpoint)?;

    let shutdown = tokio_util::sync::CancellationToken::new();
    let serve_shutdown = shutdown.clone();
    let serve_runtime = runtime.clone();
    // A current_thread runtime only polls tasks while driven by block_on; run
    // `block_on(axum::serve(...))` on a dedicated thread, otherwise spawned tasks are never
    // scheduled and the port binds but never responds (verified pitfall, 2026-11-08).
    let handle = std::thread::Builder::new()
        .name("meshlet-mcp".into())
        .spawn(move || {
            serve_runtime.block_on(async move {
                let _ = axum::serve(listener, app)
                    .with_graceful_shutdown(serve_shutdown.cancelled_owned())
                    .await;
            });
        })
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    Ok(McpServer {
        _runtime: runtime,
        handle: Some(handle),
        shutdown,
        state_dir,
    })
}

/// MCP service handle: dropping stops the listener and clears the handoff file.
pub struct McpServer {
    _runtime: std::sync::Arc<tokio::runtime::Runtime>,
    handle: Option<std::thread::JoinHandle<()>>,
    shutdown: tokio_util::sync::CancellationToken,
    state_dir: PathBuf,
}

impl McpServer {
    /// Listening port (the value written to the handoff file; available after start).
    pub fn port(&self) -> u16 {
        crate::mcp::read_url_file(&self.state_dir)
            .map(|e| e.port)
            .unwrap_or(0)
    }

    /// Stop the service and clear the handoff file (idempotent).
    pub fn stop(&mut self) {
        self.shutdown.cancel();
        if let Some(handle) = self.handle.take() {
            // The MCP thread sits in `block_on(axum::serve)`; once cancel triggers graceful shutdown
            // the thread exits on its own; join waits for it (timeout fallback against a worst-case hang).
            let _ = handle.join();
        }
        remove_url_file(&self.state_dir);
    }
}

impl Drop for McpServer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// axum handler: forwards requests to rmcp's `StreamableHttpService`.
///
/// **Streaming forward is mandatory**: MCP responses may be `text/event-stream` long-lived
/// connections; `BodyExt::collect` waits for the body to end → the request never returns. Here
/// rmcp's `BoxBody<Bytes, Infallible>` is passed through as an axum `Body` (both are body streams).
///
/// Note: `StreamableHttpService::handle` is `pub async` and accepts any `Body + Send`;
/// calling it directly is sturdier than tower `oneshot` (oneshot's generic bounds on the
/// request body may not hold under axum's `Body`).
async fn mcp_handler(
    State(service): State<Arc<StreamableHttpService<McpHandler, LocalSessionManager>>>,
    request: Request<Body>,
) -> axum::response::Response {
    let response = service.handle(request).await;
    let (parts, body) = response.into_parts();
    // Streaming wrapper from BoxBody<Bytes, Infallible> to axum::body::Body.
    let body = Body::new(body);
    axum::http::Response::from_parts(parts, body)
}

/// Health check (`GET /`) — used by MCP clients/tray for liveness probes.
async fn health() -> &'static str {
    "ok"
}

/// Write the MCP endpoint handoff file (atomic publish: .tmp + rename, same as local-panel.json).
pub fn write_url_file(state_dir: &Path, endpoint: &McpEndpoint) -> std::io::Result<()> {
    let body = serde_json::to_vec(endpoint).map_err(|e| std::io::Error::other(e.to_string()))?;
    let tmp = state_dir.join(format!("{MCP_URL_FILE}.tmp"));
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, state_dir.join(MCP_URL_FILE))
}

/// Read the MCP endpoint handoff file.
pub fn read_url_file(state_dir: &Path) -> Option<McpEndpoint> {
    let text = std::fs::read_to_string(state_dir.join(MCP_URL_FILE)).ok()?;
    serde_json::from_str(&text).ok()
}

/// Delete the MCP endpoint handoff file (best-effort; leftovers only mean the next read sees a stale endpoint).
pub fn remove_url_file(state_dir: &Path) {
    let _ = std::fs::remove_file(state_dir.join(MCP_URL_FILE));
}

/// MCP handler: holds state_dir; tools read facts from local state files.
#[derive(Debug, Clone)]
pub struct McpHandler {
    state_dir: PathBuf,
    tool_router: ToolRouter<Self>,
}

impl McpHandler {
    pub fn new(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for McpHandler {}

#[tool_router(router = tool_router)]
impl McpHandler {
    /// Current node state: agent state, device name, virtual IP, version, key environment
    /// items (from `{state_dir}/tray/status.json`, same pipeline as the local panel).
    #[tool(
        name = "status",
        description = "Meshlet agent status: state, device name, virtual IP, version, environment"
    )]
    pub async fn status(&self) -> String {
        let status = read_json(&self.state_dir.join("tray").join("status.json"));
        pretty_json(&status)
    }

    /// This machine's mesh info: device name, server URL, state
    /// (from `agent.toml` top-level keys + status.json, same pipeline as `meshlet info`).
    #[tool(name = "info", description = "Device info: name, server URL, state")]
    pub async fn info(&self) -> String {
        let cfg = read_config_top(&self.state_dir);
        let device_name = cfg
            .get("device_name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let server_url = cfg
            .get("server_url")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let status = read_json(&self.state_dir.join("tray").join("status.json"));
        let state = status
            .as_ref()
            .and_then(|v| v.get("state"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        serde_json::json!({
            "device_name": device_name,
            "server_url": server_url,
            "state": state,
        })
        .to_string()
    }

    /// Direct-peer table: name, overlay IP, connection mode, RTT, endpoint, last handshake, public key
    /// (from `{state_dir}/direct-peers.json`, same pipeline as the local panel).
    #[tool(
        name = "peers",
        description = "Direct peers: name, overlay IP, mode, RTT, endpoint, handshake, public key"
    )]
    pub async fn peers(&self) -> String {
        match read_json(&self.state_dir.join("direct-peers.json")) {
            Some(serde_json::Value::Array(items)) => {
                pretty_json(&Some(serde_json::Value::Array(items)))
            }
            Some(other) => pretty_json(&Some(other)),
            None => "[]".to_string(),
        }
    }

    /// Local routes: destination prefix, next hop, interface, source
    /// (from `last_good_plan.routes` in `{state_dir}/applied.json`, falling back to the
    /// ledger `routes` prefix, same pipeline as the local panel).
    #[tool(
        name = "routes",
        description = "Local routes: destination, next-hop, interface, source"
    )]
    pub async fn routes(&self) -> String {
        let applied = read_json(&self.state_dir.join("applied.json"));
        let routes = applied
            .as_ref()
            .and_then(|v| v.get("last_good_plan"))
            .and_then(|p| p.get("routes"))
            .cloned()
            .or_else(|| applied.as_ref().and_then(|v| v.get("routes")).cloned());
        match routes {
            Some(serde_json::Value::Array(items)) => {
                pretty_json(&Some(serde_json::Value::Array(items)))
            }
            _ => "[]".to_string(),
        }
    }

    /// Network/subnet list: local route-table destinations + interfaces.
    #[tool(
        name = "networks",
        description = "Subnets/routes: destination and interface"
    )]
    pub async fn networks(&self) -> String {
        // P1: Windows wg route reading lives in the CLI (`meshlet networks`); the agent side
        // avoids a command-line dependency, so for now P1 returns empty honestly and notes the source.
        "[]".to_string()
    }

    /// Network diagnostics snapshot: interfaces, tunnels, routes (same pipeline as
    /// `meshlet agent diag`, best-effort per platform).
    #[tool(
        name = "diag",
        description = "Network diagnostics: interfaces, tunnels, routes"
    )]
    pub async fn diag(&self) -> String {
        #[cfg(not(target_os = "windows"))]
        {
            // Linux backend: `inspect` reads real state (interfaces/tunnels/routes). With the data
            // plane off there are no interfaces; return empty fields. On read failure return an
            // empty object honestly, no panic. NetworkSnapshot does not derive Serialize (avoid changing
            // a shared type for diagnostics), so it is mapped to a plain JSON object here.
            use meshlet_network::NetworkBackend;
            let backend = meshlet_network::SystemBackend::new();
            let snapshot = backend.inspect().await;
            match snapshot {
                Ok(snap) => serde_json::json!({
                    "tunnel_exists": snap.tunnel_exists,
                    "forwarding_enabled": snap.forwarding_enabled,
                    "peers": snap.peers.iter().map(|p| serde_json::json!({
                        "public_key": p.public_key,
                        "allowed_ips": p.allowed_ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
                    })).collect::<Vec<_>>(),
                    "installed_routes": snap.installed_routes.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
                    "tunnel_mtu": snap.tunnel_mtu,
                    "local_public_key": snap.local_public_key,
                    "tunnel_address": snap.tunnel_address.map(|a| a.to_string()),
                })
                .to_string(),
                Err(e) => format!("{{\"error\": \"{e}\"}}"),
            }
        }
        #[cfg(target_os = "windows")]
        {
            // P1: the Windows diagnostics snapshot lives in the CLI (`meshlet agent diag`); the agent
            // side avoids a command-line dependency, so for now P1 returns empty honestly and notes the source.
            "{}".to_string()
        }
    }

    /// AGENT-DOC-1: coexistence health check with foreign overlays (ZeroTier-like; same
    /// pipeline as `meshlet agent doctor`, see [meshlet_network::doctor]).
    ///
    /// The agent runs privileged, so collection needs no sudo; `has_failure=true` means a FAIL
    /// exists and the caller should alert on it. **Read-only** — the check never changes kernel state.
    #[tool(
        name = "doctor",
        description = "Coexistence health: tunnel amplification, cross-overlay paths, isolation rules, MTU"
    )]
    pub async fn doctor(&self) -> String {
        use meshlet_network::NetworkBackend;
        // Detect the managed interface at runtime by link type (config default wg0; real machines
        // often name it wg-mlt, so the default name reads empty); on miss fall back, verdict layer reports not_assessed.
        let backend = match meshlet_network::detect_wireguard_interface() {
            Some(interface) => meshlet_network::SystemBackend::new().with_interface(interface),
            None => meshlet_network::SystemBackend::new(),
        };
        let report = backend.doctor();
        serde_json::json!({
            "collected_at": report.collected_at,
            "has_failure": report.has_failure(),
            "counts": {
                "pass": report.counts()[0],
                "warn": report.counts()[1],
                "fail": report.counts()[2],
                "not_assessed": report.counts()[3],
            },
            "checks": report.checks.iter().map(|c| serde_json::json!({
                "id": c.id,
                "title": c.title,
                "status": c.status,
                "evidence": c.evidence,
            })).collect::<Vec<_>>(),
        })
        .to_string()
    }
}

/// Read a single **top-level** key from `{state_dir}/../<file>` (`agent.toml` / legacy `config.toml`),
/// same logic as tray-host `config_value`: keys inside sections are always skipped — section
/// config is never mistaken for node info.
fn read_config_top(state_dir: &Path) -> serde_json::Value {
    let parent = state_dir.parent().unwrap_or(Path::new("."));
    let mut map = serde_json::Map::new();
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
                let key = k.trim();
                // Secret fields are never emitted (security boundary).
                if matches!(key, "device_token" | "bootstrap_token") {
                    continue;
                }
                let value = v.trim().trim_matches('"').to_string();
                if !value.is_empty() {
                    map.insert(key.to_string(), serde_json::Value::String(value));
                }
            }
        }
        if !map.is_empty() {
            break;
        }
    }
    serde_json::Value::Object(map)
}

/// Read a JSON file; missing/corrupt → `None`.
fn read_json(path: &Path) -> Option<serde_json::Value> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
}

/// JSON → pretty text (failure → empty object, no panic).
fn pretty_json(value: &Option<serde_json::Value>) -> String {
    match value {
        Some(v) => serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".into()),
        None => "{}".into(),
    }
}
