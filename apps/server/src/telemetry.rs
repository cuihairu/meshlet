//! 结构化日志（[存档 §17.1](../../docs/review/chatgpt-2026-10-13.md)）。
//!
//! 规定八字段，**每条操作日志都必须齐**（不适用者留空串——字段仍在，JSON
//! 里是独立键，不是把值拼进消息文本）：
//!
//! | 字段 | 说明 |
//! | --- | --- |
//! | `time` | 事件时刻（ISO-8601 UTC，与库内时间戳同源） |
//! | `component` | 组件：`http` / `auth` / `network` / `device` / `route` / `revision` / `agent` |
//! | `operation` | 操作名（如 `create_network`、`apply_revision`；访问日志用路由模板） |
//! | `network_id` | 适用时；不适用为空串 |
//! | `device_id` | 适用时；不适用为空串 |
//! | `config_revision` | 适用时（修订号字符串）；不适用为空串 |
//! | `error_category` | 错误类别：`none`/`not_found`/`validation`/`conflict`/`unauthorized`/`forbidden`/`rate_limited`/`internal` |
//! | `result` | 操作结果：`ok` / `error` |
//!
//! 两个层次：
//! - **访问日志**（[`request_log`] 中间件）：每个已路由请求一条，`component=http`，
//!   `operation` = 路由模板，`result`/`error_category` 由响应状态派生；
//! - **领域事件**（[`op_log!`]）：handler 在完成业务动作后记录，携带真实的
//!   `network_id` / `device_id` / `config_revision`。
//!
//! 生产输出为 JSON（`main.rs` 的 `fmt().json().flatten_event(true)`），字段是
//! 顶层键，可直接被日志系统按字段索引。

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;

use axum::extract::{MatchedPath, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;

use crate::auth::{AuthApiError, SharedAppState};
use crate::service::ServiceError;

/// 字段名常量（文档与测试共用，避免拼写漂移）。
pub mod field {
    pub const TIME: &str = "time";
    pub const COMPONENT: &str = "component";
    pub const OPERATION: &str = "operation";
    pub const NETWORK_ID: &str = "network_id";
    pub const DEVICE_ID: &str = "device_id";
    pub const CONFIG_REVISION: &str = "config_revision";
    pub const ERROR_CATEGORY: &str = "error_category";
    pub const RESULT: &str = "result";
}

/// 不适用字段的占位（空串：字段存在但无值）。
pub const NOT_APPLICABLE: &str = "";

pub const RESULT_OK: &str = "ok";
pub const RESULT_ERROR: &str = "error";

/// 错误类别（§17.1「错误类别」）：稳定字符串，不随错误文本变化。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    None,
    NotFound,
    Validation,
    Conflict,
    Unauthorized,
    Forbidden,
    RateLimited,
    Internal,
}

impl ErrorCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCategory::None => "none",
            ErrorCategory::NotFound => "not_found",
            ErrorCategory::Validation => "validation",
            ErrorCategory::Conflict => "conflict",
            ErrorCategory::Unauthorized => "unauthorized",
            ErrorCategory::Forbidden => "forbidden",
            ErrorCategory::RateLimited => "rate_limited",
            ErrorCategory::Internal => "internal",
        }
    }
}

impl From<&ServiceError> for ErrorCategory {
    fn from(e: &ServiceError) -> Self {
        match e {
            ServiceError::NetworkNotFound(_)
            | ServiceError::InviteNotFound(_)
            | ServiceError::DeviceNotFound(_)
            | ServiceError::RouteNotFound(_)
            | ServiceError::AliasNotFound(_)
            | ServiceError::RevisionNotFound(_)
            | ServiceError::DiagnosticsNotRun(_)
            | ServiceError::InvalidInviteToken => ErrorCategory::NotFound,
            ServiceError::InvalidCidr(_) | ServiceError::InvalidInput(_) => {
                ErrorCategory::Validation
            }
            ServiceError::Conflict(_) | ServiceError::RouteConflict(_) => ErrorCategory::Conflict,
            ServiceError::Internal(_) => ErrorCategory::Internal,
        }
    }
}

impl From<&AuthApiError> for ErrorCategory {
    fn from(e: &AuthApiError) -> Self {
        match e {
            AuthApiError::Unauthorized => ErrorCategory::Unauthorized,
            AuthApiError::ForbiddenCsrf | AuthApiError::ForbiddenScopes => ErrorCategory::Forbidden,
            AuthApiError::NotFound(_) => ErrorCategory::NotFound,
            AuthApiError::InvalidInput(_) => ErrorCategory::Validation,
            AuthApiError::AlreadyBootstrapped => ErrorCategory::Conflict,
            AuthApiError::RateLimited => ErrorCategory::RateLimited,
            AuthApiError::Internal(_) => ErrorCategory::Internal,
        }
    }
}

impl From<&crate::agent::AgentApiError> for ErrorCategory {
    fn from(e: &crate::agent::AgentApiError) -> Self {
        match e {
            crate::agent::AgentApiError::Unauthorized => ErrorCategory::Unauthorized,
            crate::agent::AgentApiError::InvalidInput(_) => ErrorCategory::Validation,
            crate::agent::AgentApiError::NotFound(_) => ErrorCategory::NotFound,
            // 服务端数据面未开启（503）：请求本身合法，按服务端配置缺失归类。
            crate::agent::AgentApiError::DataplaneNotConfigured(_) => ErrorCategory::Internal,
            crate::agent::AgentApiError::Internal(_) => ErrorCategory::Internal,
        }
    }
}

/// 由响应状态派生错误类别（访问日志用；2xx/3xx = `none`）。
fn category_of_status(status: StatusCode) -> &'static str {
    match status.as_u16() {
        200..=399 => ErrorCategory::None.as_str(),
        401 => ErrorCategory::Unauthorized.as_str(),
        403 => ErrorCategory::Forbidden.as_str(),
        404 => ErrorCategory::NotFound.as_str(),
        409 => ErrorCategory::Conflict.as_str(),
        422 => ErrorCategory::Validation.as_str(),
        429 => ErrorCategory::RateLimited.as_str(),
        _ => ErrorCategory::Internal.as_str(),
    }
}

/// 结构化操作日志：八字段一次给全（§17.1）。不适用字段传
/// [`NOT_APPLICABLE`]（空串），字段仍在。
#[macro_export]
macro_rules! op_log {
    ($level:ident, $component:expr, $operation:expr, $network_id:expr, $device_id:expr, $config_revision:expr, $error_category:expr, $result:expr) => {
        ::tracing::$level!(
            time = %$crate::service::now(),
            component = %$component,
            operation = %$operation,
            network_id = %$network_id,
            device_id = %$device_id,
            config_revision = %$config_revision,
            error_category = %$error_category,
            result = %$result,
            "meshlet operation"
        )
    };
}

/// 访问日志中间件：每个已路由请求一条结构化事件 + 指标计数。
///
/// `network_id` / `device_id` / `config_revision` 在此层不适用（留空串）；
/// 领域事件由各 handler 用 [`op_log!`] 补齐真实值。
pub async fn request_log(
    State(state): State<SharedAppState>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().to_string();
    // 路由模板（基数为路由数，不含路径参数）——抓取前取，req 随后被消费。
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "unmatched".to_string());

    let response = next.run(req).await;
    let status = response.status();
    // 缓冲响应体统计字节数（控制面响应都是小体量 JSON / 指标文本；oneshot
    // 测试与 hyper 场景下行为一致——Content-Length 头在测试里不存在）。
    let (parts, body) = response.into_parts();
    let collected = axum::body::to_bytes(body, usize::MAX).await;
    let byte_len = collected.as_ref().map(|b| b.len() as u64).unwrap_or(0);

    state.metrics.record_http(&method, &route, status);
    state.metrics.add_response_bytes(byte_len);

    let result = if status.is_client_error() || status.is_server_error() {
        RESULT_ERROR
    } else {
        RESULT_OK
    };
    op_log!(
        info,
        "http",
        &route,
        NOT_APPLICABLE,
        NOT_APPLICABLE,
        NOT_APPLICABLE,
        category_of_status(status),
        result
    );
    let body = collected.unwrap_or_default();
    Response::from_parts(parts, axum::body::Body::from(body))
}

// ---------------------------------------------------------------------------
// 测试辅助：把结构化日志捕获进内存（集成测试断言八字段）
// ---------------------------------------------------------------------------

/// 内存日志捕获（测试用）：安装一次全局 JSON 订阅者，之后可用
/// [`lines`] 读取已发出的 JSON 行。
pub mod log_capture {
    use super::*;

    static BUFFER: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();

    /// 共享写入器（每行一条 JSON）。
    #[derive(Clone)]
    pub struct SharedWriter(pub Arc<Mutex<Vec<u8>>>);

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedWriter {
        type Writer = SharedWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    impl std::io::Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// 安装捕获（幂等；返回共享缓冲）。已安装时直接复用。
    ///
    /// 只收 `meshlet_server` 的目标事件（sqlx 等依赖的 DEBUG 语句噪声不参与
    /// 验收断言；`RUST_LOG` 覆盖默认）。
    pub fn install() -> Arc<Mutex<Vec<u8>>> {
        let buf = BUFFER.get_or_init(|| {
            let buf = Arc::new(Mutex::new(Vec::new()));
            let filter = tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "meshlet_server=info".into());
            let _ = tracing_subscriber::fmt()
                .json()
                .flatten_event(true)
                .with_env_filter(filter)
                .with_writer(SharedWriter(buf.clone()))
                .try_init();
            buf
        });
        buf.clone()
    }

    /// 已捕获的日志行（解析为 JSON；忽略非 JSON 行）。
    pub fn lines() -> Vec<serde_json::Value> {
        let buf = install();
        let raw = String::from_utf8(buf.lock().unwrap().clone()).unwrap_or_default();
        raw.lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    /// 清空缓冲（测试隔离）。
    pub fn clear() {
        let buf = install();
        buf.lock().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_category_maps_to_a_stable_string() {
        assert_eq!(
            ErrorCategory::from(&ServiceError::NetworkNotFound("n".into())).as_str(),
            "not_found"
        );
        assert_eq!(
            ErrorCategory::from(&ServiceError::InvalidCidr("x".into())).as_str(),
            "validation"
        );
        assert_eq!(
            ErrorCategory::from(&ServiceError::Conflict("x".into())).as_str(),
            "conflict"
        );
        assert_eq!(
            ErrorCategory::from(&ServiceError::RouteConflict("x".into())).as_str(),
            "conflict"
        );
        assert_eq!(
            ErrorCategory::from(&ServiceError::Internal("x".into())).as_str(),
            "internal"
        );
        assert_eq!(
            ErrorCategory::from(&AuthApiError::Unauthorized).as_str(),
            "unauthorized"
        );
        assert_eq!(
            ErrorCategory::from(&AuthApiError::ForbiddenCsrf).as_str(),
            "forbidden"
        );
        assert_eq!(
            ErrorCategory::from(&AuthApiError::RateLimited).as_str(),
            "rate_limited"
        );
        assert_eq!(
            ErrorCategory::from(&AuthApiError::AlreadyBootstrapped).as_str(),
            "conflict"
        );
        assert_eq!(category_of_status(StatusCode::OK), "none");
        assert_eq!(category_of_status(StatusCode::NOT_FOUND), "not_found");
        assert_eq!(
            category_of_status(StatusCode::TOO_MANY_REQUESTS),
            "rate_limited"
        );
        assert_eq!(category_of_status(StatusCode::BAD_GATEWAY), "internal");
    }

    #[test]
    fn op_log_emits_all_eight_fields() {
        // §17.1 验收：八字段齐全，且是独立字段而非拼串。
        // 注：并行测试不清共享缓冲，按操作名 + 内容唯一定位自己的事件；
        // 但订阅者必须先装好（无订阅者的事件会被丢弃）。
        log_capture::install();

        op_log!(
            info,
            "revision",
            "apply_revision",
            "net-1",
            NOT_APPLICABLE,
            "7",
            ErrorCategory::None.as_str(),
            RESULT_OK
        );

        let lines = log_capture::lines();
        let event = lines
            .iter()
            .rev()
            .find(|l| l["operation"] == "apply_revision")
            .expect("structured event captured");
        for key in [
            field::TIME,
            field::COMPONENT,
            field::OPERATION,
            field::NETWORK_ID,
            field::DEVICE_ID,
            field::CONFIG_REVISION,
            field::ERROR_CATEGORY,
            field::RESULT,
        ] {
            assert!(event.get(key).is_some(), "missing field {key}: {event}");
        }
        assert_eq!(event["component"], "revision");
        assert_eq!(event["network_id"], "net-1");
        assert_eq!(event["device_id"], "");
        assert_eq!(event["config_revision"], "7");
        assert_eq!(event["result"], "ok");
        assert_eq!(event["error_category"], "none");
        assert!(event["time"].as_str().unwrap().ends_with('Z'));
    }

    #[test]
    fn op_log_carries_error_category_and_result() {
        log_capture::install();

        op_log!(
            warn,
            "route",
            "create_route",
            "net-2",
            NOT_APPLICABLE,
            NOT_APPLICABLE,
            ErrorCategory::Conflict.as_str(),
            RESULT_ERROR
        );

        let event = log_capture::lines()
            .into_iter()
            .rev()
            .find(|l| l["operation"] == "create_route")
            .expect("structured event captured");
        assert_eq!(event["result"], "error");
        assert_eq!(event["error_category"], "conflict");
        assert_eq!(event["config_revision"], "");
    }
}
