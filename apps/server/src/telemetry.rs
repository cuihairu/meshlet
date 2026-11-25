//! Structured logging ([archive §17.1](../../docs/review/chatgpt-2026-10-13.md)).
//!
//! Eight fields are mandated, and **every operation log entry must carry all
//! of them** (non-applicable ones stay as empty strings -- the field is still
//! present, as an independent key in the JSON, not a value spliced into the
//! message text):
//!
//! | Field | Description |
//! | --- | --- |
//! | `time` | event time (ISO-8601 UTC, same source as in-store timestamps) |
//! | `component` | component: `http` / `auth` / `network` / `device` / `route` / `revision` / `agent` |
//! | `operation` | operation name (e.g. `create_network`, `apply_revision`; access logs use the route template) |
//! | `network_id` | when applicable; empty string when not |
//! | `device_id` | when applicable; empty string when not |
//! | `config_revision` | when applicable (revision number string); empty string when not |
//! | `error_category` | error category: `none`/`not_found`/`validation`/`conflict`/`unauthorized`/`forbidden`/`rate_limited`/`internal` |
//! | `result` | operation result: `ok` / `error` |
//!
//! Two layers:
//! - **access log** ([`request_log`] middleware): one entry per routed
//!   request, `component=http`, `operation` = the route template, with
//!   `result`/`error_category` derived from the response status;
//! - **domain events** ([`op_log!`]): recorded by handlers after completing a
//!   business action, carrying the real `network_id` / `device_id` /
//!   `config_revision`.
//!
//! Production output is JSON (`fmt().json().flatten_event(true)` in
//! `main.rs`); the fields are top-level keys, directly indexable per field by
//! a log system.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;

use axum::extract::{MatchedPath, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;

use crate::auth::{AuthApiError, SharedAppState};
use crate::service::ServiceError;

/// Field name constants (shared by docs and tests, to avoid spelling drift).
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

/// Placeholder for a non-applicable field (empty string: the field exists but
/// has no value).
pub const NOT_APPLICABLE: &str = "";

pub const RESULT_OK: &str = "ok";
pub const RESULT_ERROR: &str = "error";

/// Error category (§17.1 "error category"): a stable string that does not
/// vary with the error text.
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
            | ServiceError::PublishNotFound(_)
            | ServiceError::SegmentNotFound(_)
            | ServiceError::SegmentGrantNotFound(_)
            | ServiceError::RevisionNotFound(_)
            | ServiceError::TaskNotFound(_)
            | ServiceError::DiagnosticsNotRun(_)
            | ServiceError::BootstrapTokenNotFound(_)
            | ServiceError::InvalidInviteToken => ErrorCategory::NotFound,
            ServiceError::InvalidBootstrapToken => ErrorCategory::Unauthorized,
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
            // The server data plane is not enabled (503): the request itself is
            // valid, classified as a missing server configuration.
            crate::agent::AgentApiError::DataplaneNotConfigured(_) => ErrorCategory::Internal,
            crate::agent::AgentApiError::Internal(_) => ErrorCategory::Internal,
        }
    }
}

/// Derive the error category from the response status (access log use;
/// 2xx/3xx = `none`).
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

/// Structured operation log: all eight fields given at once (§17.1). Pass
/// [`NOT_APPLICABLE`] (empty string) for a non-applicable field; the field is
/// still present.
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

/// Access log middleware: one structured event + a metrics count per routed
/// request.
///
/// `network_id` / `device_id` / `config_revision` are not applicable at this
/// layer (left as empty strings); handlers fill in the real values in their
/// domain events via [`op_log!`].
pub async fn request_log(
    State(state): State<SharedAppState>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().to_string();
    // Route template (its cardinality is the number of routes, path parameters
    // excluded) -- grabbed before, since req is consumed right after.
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "unmatched".to_string());

    let response = next.run(req).await;
    let status = response.status();
    // Buffer the response body to count its bytes (control-plane responses are
    // all small JSON / metrics text; behaves the same in oneshot tests and in
    // the hyper setup -- there is no Content-Length header in tests).
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
// Test helper: capture structured logs in memory (integration tests assert
// on the eight fields)
// ---------------------------------------------------------------------------

/// In-memory log capture (for tests): installs a global JSON subscriber once,
/// after which [`lines`] reads the JSON lines that were emitted.
pub mod log_capture {
    use super::*;

    static BUFFER: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();

    /// Shared writer (one JSON per line).
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

    /// Install the capture (idempotent; returns the shared buffer). If already
    /// installed, reuses it directly.
    ///
    /// Only target events from `meshlet_server` are captured (DEBUG noise from
    /// dependencies such as sqlx takes no part in acceptance assertions;
    /// `RUST_LOG` overrides the default).
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

    /// Captured log lines (parsed as JSON; non-JSON lines are ignored).
    pub fn lines() -> Vec<serde_json::Value> {
        let buf = install();
        let raw = String::from_utf8(buf.lock().unwrap().clone()).unwrap_or_default();
        raw.lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    /// Clear the buffer (test isolation).
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
        // §17.1 acceptance: all eight fields present, and as independent fields
        // rather than spliced strings.
        // Note: parallel tests do not clear the shared buffer; each locates its
        // own event by operation name + content, but the subscriber must be
        // installed first (events with no subscriber are dropped).
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
