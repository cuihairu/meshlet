//! meshlet-api-types：管理 API 的共享 DTO 与错误契约。
//!
//! 契约来源：[api-contract](../../docs/architecture/api-contract.md)、
//! [openapi.yaml](../../docs/public/api/openapi.yaml)。错误结构与 OpenAPI `Error` schema 保持一致。

use serde::{Deserialize, Serialize};

/// 统一错误码（§13.7，openapi.yaml `Error.error.code`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    ValidationFailed,
    ApplyFailed,
    Internal,
}

/// 统一错误响应：`{"error": {"code": "...", "message": "...", "details": {}}}`。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: ErrorBody,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl ErrorResponse {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            error: ErrorBody {
                code,
                message: message.into(),
                details: None,
            },
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.error.details = Some(details);
        self
    }
}

/// 分页信封（§13.7：列表接口分页）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub total: u64,
}

/// 配置修改类响应必须携带 revision 与应用状态（§13.7、ADR-009）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionRef {
    pub revision_id: String,
    pub apply_status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_response_matches_openapi_shape() {
        let e = ErrorResponse::new(ErrorCode::Conflict, "alias prefix overlaps overlay cidr");
        let json = serde_json::to_value(&e).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "error": {
                    "code": "conflict",
                    "message": "alias prefix overlaps overlay cidr"
                }
            })
        );
        let parsed: ErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, e);
    }

    #[test]
    fn error_codes_snake_case_serialization() {
        assert_eq!(
            serde_json::to_value(ErrorCode::ValidationFailed).unwrap(),
            serde_json::json!("validation_failed")
        );
        assert_eq!(
            serde_json::to_value(ErrorCode::ApplyFailed).unwrap(),
            serde_json::json!("apply_failed")
        );
    }

    #[test]
    fn error_response_with_details_roundtrip() {
        let e = ErrorResponse::new(ErrorCode::ApplyFailed, "nft rejected")
            .with_details(serde_json::json!({ "revision": 7 }));
        let json = serde_json::to_value(&e).unwrap();
        assert_eq!(json["error"]["details"]["revision"], 7);
        let parsed: ErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, e);
    }

    #[test]
    fn page_envelope_roundtrip() {
        let p = Page { items: vec![1, 2, 3], total: 42 };
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["total"], 42);
        assert_eq!(json["items"].as_array().unwrap().len(), 3);
        let parsed: Page<u32> = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, p);
    }
}
