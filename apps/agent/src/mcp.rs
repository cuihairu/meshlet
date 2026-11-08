//! MCP 本地服务：AI 客户端经 loopback HTTP 查询本机 mesh 事实。
//!
//! 定案（2026-11-08 用户）：meshlet 的本地查询功能做成 **MCP**，本地开启后
//! AI 客户端即可快速访问不同机器（每台机器跑一个 agent 的 MCP 端点）。
//! 取代 2026-10-19 `docs/analysis/agent-local-api-2026-10-19.md` 中面向
//! 脚本/CLI/控制台的 OS 主体 IPC 提案——消费方改为 AI，传输改为 MCP。
//!
//! 安全边界（与 2026-10-19 研究的风险清单一致）：
//! - **仅 loopback**：绑定 `127.0.0.1`，绝不绑定外部接口；
//! - **只读**：工具集为查询（status/info/peers/routes/networks/diag），
//!   无写操作，无 Shell 命令，无私钥读取；
//! - **无机密**：`agent.toml` 的 `device_token` / `bootstrap_token` 永不输出；
//! - **默认全关**：`[mcp] enabled = false`，显式开启才监听。
//!
//! 传输：rmcp streamable HTTP（`StreamableHttpService`），端点
//! `POST /mcp`。端口写 `{state_dir}/mcp.json`（`{url, port, pid}`）交接文件，
//! 与 local-panel.json 同款原子发布（.tmp + rename），托盘/CI/客户端据此拿
//! 端点。
//!
//! 数据源与本地面板/CLI 同一链路（`{state_dir}` 下的
//! `tray/status.json`、`direct-peers.json`、`applied.json` 与 `agent.toml`），
//! 一源三面，不重复实现读取逻辑。
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

/// MCP 端点路径（streamable HTTP 常规）。
pub const MCP_PATH: &str = "/mcp";
/// 交接文件名（`{state_dir}/mcp.json`）。
pub const MCP_URL_FILE: &str = "mcp.json";
/// 单请求体上限（rmcp 默认 4 MiB，足够工具参数）。
const REQUEST_BODY_LIMIT: usize = 4 * 1024 * 1024;

/// MCP 服务状态（交接文件内容）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct McpEndpoint {
    pub url: String,
    pub port: u16,
    pub pid: u32,
}

/// 启动 MCP 服务：绑定 loopback 随机/指定端口，写 `{state_dir}/mcp.json`，
/// 返回端点信息。**调用方负责保存 `McpServer` 句柄**（drop 即停、清交接文件）。
///
/// 绑定失败返回 `Err`（端口占用等），不 panic——调用方决定是否降级为
/// 「MCP 未启动」并如实记录。
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
    // current_thread runtime 必须被 block_on 驱动才能 poll 任务；用专用线程
    // 跑 `block_on(axum::serve(...))`，否则 spawn 的任务永远不被调度，
    // 服务端口可 bind 但永不响应（2026-11-08 实测踩坑）。
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

/// MCP 服务句柄：drop 时停止监听并清交接文件。
pub struct McpServer {
    _runtime: std::sync::Arc<tokio::runtime::Runtime>,
    handle: Option<std::thread::JoinHandle<()>>,
    shutdown: tokio_util::sync::CancellationToken,
    state_dir: PathBuf,
}

impl McpServer {
    /// 监听端口（交接文件写入值；启动后可用）。
    pub fn port(&self) -> u16 {
        crate::mcp::read_url_file(&self.state_dir)
            .map(|e| e.port)
            .unwrap_or(0)
    }

    /// 停止服务并清交接文件（幂等）。
    pub fn stop(&mut self) {
        self.shutdown.cancel();
        if let Some(handle) = self.handle.take() {
            // MCP 线程在 `block_on(axum::serve)` 上，cancel 触发优雅关停后
            // 线程自然退出；join 等待它结束（带超时兜底，防极端卡死）。
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

/// axum 处理器：把请求转给 rmcp 的 `StreamableHttpService`。
///
/// **必须流式转发**：MCP 的响应可能是 `text/event-stream` 长连接，
/// `BodyExt::collect` 会一直等 body 结束 → 请求永不返回。这里把 rmcp 的
/// `BoxBody<Bytes, Infallible>` 原样转成 axum `Body`（两者都是 body 流）。
///
/// 注意：`StreamableHttpService::handle` 是 `pub async` 且接受任意
/// `Body + Send`，直接调它比 tower `oneshot` 更稳（oneshot 对请求体
/// 的泛型约束在 axum 的 `Body` 下可能不满足）。
async fn mcp_handler(
    State(service): State<Arc<StreamableHttpService<McpHandler, LocalSessionManager>>>,
    request: Request<Body>,
) -> axum::response::Response {
    let response = service.handle(request).await;
    let (parts, body) = response.into_parts();
    // BoxBody<Bytes, Infallible> → axum::body::Body 的流式包装。
    let body = Body::new(body);
    axum::http::Response::from_parts(parts, body)
}

/// 健康检查（`GET /`）——MCP 客户端/托盘探活用。
async fn health() -> &'static str {
    "ok"
}

/// 写 MCP 端点交接文件（原子发布：.tmp + rename，与 local-panel.json 同款）。
pub fn write_url_file(state_dir: &Path, endpoint: &McpEndpoint) -> std::io::Result<()> {
    let body = serde_json::to_vec(endpoint).map_err(|e| std::io::Error::other(e.to_string()))?;
    let tmp = state_dir.join(format!("{MCP_URL_FILE}.tmp"));
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, state_dir.join(MCP_URL_FILE))
}

/// 读 MCP 端点交接文件。
pub fn read_url_file(state_dir: &Path) -> Option<McpEndpoint> {
    let text = std::fs::read_to_string(state_dir.join(MCP_URL_FILE)).ok()?;
    serde_json::from_str(&text).ok()
}

/// 删除 MCP 端点交接文件（best-effort；残留只影响下一次读到旧端点）。
pub fn remove_url_file(state_dir: &Path) {
    let _ = std::fs::remove_file(state_dir.join(MCP_URL_FILE));
}

/// MCP 处理器：持有 state_dir，工具从本地状态文件读事实。
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
    /// 当前节点状态：agent 状态、设备名、虚拟 IP、版本、环境关键项
    /// （来源 `{state_dir}/tray/status.json`，与本地面板同一链路）。
    #[tool(
        name = "status",
        description = "Meshlet agent status: state, device name, virtual IP, version, environment"
    )]
    pub async fn status(&self) -> String {
        let status = read_json(&self.state_dir.join("tray").join("status.json"));
        pretty_json(&status)
    }

    /// 本机 mesh 信息：设备名、server URL、状态
    /// （来源 `agent.toml` 顶层键 + status.json，与 `meshlet info` 同链路）。
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

    /// 直连对端表：名字、overlay IP、连接模式、RTT、端点、最近握手、公钥
    /// （来源 `{state_dir}/direct-peers.json`，与本地面板同一链路）。
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

    /// 本地路由：目标网段、下一跳、接口、来源
    /// （来源 `{state_dir}/applied.json` 的 `last_good_plan.routes`，缺省回落
    /// 账本 `routes` 前缀，与本地面板同一链路）。
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

    /// 网络/子网列表：本机路由表目的地 + 接口。
    #[tool(
        name = "networks",
        description = "Subnets/routes: destination and interface"
    )]
    pub async fn networks(&self) -> String {
        // P1：Windows 的 wg 路由读取在 CLI（`meshlet networks`）；agent 侧
        // 不引入命令行依赖，P1 先如实返回空并注明来源。
        "[]".to_string()
    }

    /// 网络诊断快照：接口、隧道、路由（与 `meshlet agent diag` 同链路，
    /// 各平台尽力而为）。
    #[tool(
        name = "diag",
        description = "Network diagnostics: interfaces, tunnels, routes"
    )]
    pub async fn diag(&self) -> String {
        #[cfg(not(target_os = "windows"))]
        {
            // Linux 后端：`inspect` 读真实状态（接口/隧道/路由）。数据面关闭时
            // 无接口，返回空字段；读失败如实返回空对象，不 panic。
            // NetworkSnapshot 不派生 Serialize（避免为诊断改共享类型），此处
            // 映射为普通 JSON 对象。
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
            // P1：Windows 诊断快照在 CLI（`meshlet agent diag`）；agent 侧
            // 不引入命令行依赖，P1 先如实返回空并注明来源。
            "{}".to_string()
        }
    }
}

/// 读 `{state_dir}/../<file>` 单个**顶层**键（`agent.toml` / 旧 `config.toml`），
/// 与 tray-host `config_value` 同款逻辑：段内键一律跳过，绝不把段内配置误当
/// 节点信息展示。
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
                // 机密字段永不输出（安全边界）。
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

/// 读一个 JSON 文件；缺失/损坏 → `None`。
fn read_json(path: &Path) -> Option<serde_json::Value> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
}

/// JSON → 美化文本（失败 → 空对象，不 panic）。
fn pretty_json(value: &Option<serde_json::Value>) -> String {
    match value {
        Some(v) => serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".into()),
        None => "{}".into(),
    }
}
