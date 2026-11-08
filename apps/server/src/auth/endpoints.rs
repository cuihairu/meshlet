use super::extract::{
    clear_cookie_header, record_audit, session_cookie_header, session_token_from_headers,
};
use super::{
    AppState, AuthApiError, AuthenticatedUser, CsrfHeader, SharedAppState, WriteUser, DUMMY_HASH,
};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use meshlet_domain::auth::{validate_email, validate_password, Session, User};
use meshlet_domain::totp;
use meshlet_domain::{generate_token, Timestamp, UserId};
use serde::{Deserialize, Serialize};
use std::time::Instant;

use crate::service;

// ---------------------------------------------------------------------------
// 端点
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialsRequest {
    pub email: String,
    pub password: String,
    /// TOTP 验证码（第二步）。该用户已启用 2FA 时提供；未启用则忽略。
    #[serde(default)]
    pub code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub user_id: String,
    pub email: String,
    /// 本次登录尚缺 TOTP 第二步（响应未种会话 Cookie；客户端应提示输入验证码）。
    pub two_factor_required: bool,
    /// 该用户已启用 TOTP（客户端据此决定是否显示绑定引导）。
    pub two_factor_enabled: bool,
}

/// TOTP 绑定/激活/关停请求体。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpCodeRequest {
    pub code: String,
}

/// `GET /api/v1/auth/2fa/status` 响应。
#[derive(Debug, Serialize)]
pub struct TotpStatusResponse {
    /// 已激活（登录需第二步）。
    pub enabled: bool,
    /// 已生成密钥、待验证码激活（绑定引导进行中）。
    pub pending: bool,
}

/// `POST /api/v1/auth/2fa/enroll` 响应。
#[derive(Debug, Serialize)]
pub struct TotpEnrollResponse {
    /// 认证器扫码导入的 otpauth:// URI。仅此 URI 承载 base32 密钥——这是认证器
    /// 导入的标准材料；响应不含密钥原文的其他表示形式。
    pub otpauth_uri: String,
}

/// 建会话 + 种 Cookie。
async fn open_session(state: &AppState, user_id: &UserId) -> Result<HeaderMap, AuthApiError> {
    let (raw_token, session) = Session::generate(user_id.clone(), service::now());
    state
        .auth
        .insert_session(&session)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?;
    Ok(session_cookie_header(&raw_token, state.cookie_secure))
}

/// `POST /api/v1/auth/bootstrap`：仅空库可用，创建首个管理员并直接登录。
pub async fn bootstrap_handler(
    State(state): State<SharedAppState>,
    Json(req): Json<CredentialsRequest>,
) -> Result<Response, AuthApiError> {
    let _bootstrap = state.persist.lock().await;
    let count = state
        .auth
        .user_count()
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?;
    if count > 0 {
        return Err(AuthApiError::AlreadyBootstrapped);
    }
    validate_email(&req.email).map_err(|e| AuthApiError::InvalidInput(e.to_string()))?;
    validate_password(&req.password).map_err(|e| AuthApiError::InvalidInput(e.to_string()))?;

    let password = req.password;
    let user = {
        let email = req.email;
        let _permit = state.auth_blocking.acquire().await;
        tokio::task::spawn_blocking(move || {
            User::new(UserId(generate_token()), email, &password, service::now())
        })
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?
        .map_err(|e| AuthApiError::InvalidInput(e.to_string()))?
    };
    let (user_id, email) = (user.id.clone(), user.email.clone());
    if !state
        .auth
        .insert_first_user(&user)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?
    {
        return Err(AuthApiError::AlreadyBootstrapped);
    }

    let headers = open_session(&state, &user_id).await?;
    record_audit(
        &state,
        Some(&user_id.0),
        "user.bootstrap",
        Some(&user_id.0),
        None,
    )
    .await?;
    crate::op_log!(
        info,
        "auth",
        "bootstrap",
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((
        StatusCode::CREATED,
        headers,
        Json(SessionResponse {
            user_id: user_id.0,
            email,
            two_factor_required: false,
            two_factor_enabled: false,
        }),
    )
        .into_response())
}

/// `POST /api/v1/auth/login`：校验密码，成功发会话 Cookie。
/// 不区分「用户不存在」与「密码错误」（统一 401 + 恒时校验）。
pub async fn login_handler(
    State(state): State<SharedAppState>,
    Json(req): Json<CredentialsRequest>,
) -> Result<Response, AuthApiError> {
    let key = format!("login:{}", req.email.to_lowercase());
    if !state.login_limiter.check(&key, Instant::now()) {
        return Err(AuthApiError::RateLimited);
    }

    let record = state
        .auth
        .find_user_by_email(&req.email)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?;
    let Some(record) = record else {
        // 恒时：对固定哈希跑一次校验再拒绝。
        let password = req.password;
        let _permit = state.auth_blocking.acquire().await;
        let _ = tokio::task::spawn_blocking(move || {
            meshlet_domain::auth::verify_password(&password, DUMMY_HASH)
        })
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()));
        // 失败也要留痕（§16.5：登录失败必记录）；email 非秘密字段，有助
        // 暴破诊断。不记录密码本身。
        record_audit(
            &state,
            None,
            "user.login_failed",
            None,
            Some(serde_json::json!({ "email": req.email, "reason": "unknown_user" })),
        )
        .await?;
        crate::op_log!(
            warn,
            "auth",
            "login",
            crate::telemetry::NOT_APPLICABLE,
            crate::telemetry::NOT_APPLICABLE,
            crate::telemetry::NOT_APPLICABLE,
            crate::telemetry::ErrorCategory::Unauthorized.as_str(),
            crate::telemetry::RESULT_ERROR
        );
        return Err(AuthApiError::Unauthorized);
    };
    let user_id = record.id.clone();
    let email = record.email;
    let password = req.password;
    let _permit = state.auth_blocking.acquire().await;
    let valid = tokio::task::spawn_blocking(move || {
        meshlet_domain::auth::verify_password(&password, &record.password_hash)
    })
    .await
    .map_err(|e| AuthApiError::Internal(e.to_string()))?;
    if !valid {
        record_audit(
            &state,
            None,
            "user.login_failed",
            None,
            Some(serde_json::json!({ "email": email, "reason": "bad_password" })),
        )
        .await?;
        crate::op_log!(
            warn,
            "auth",
            "login",
            crate::telemetry::NOT_APPLICABLE,
            crate::telemetry::NOT_APPLICABLE,
            crate::telemetry::NOT_APPLICABLE,
            crate::telemetry::ErrorCategory::Unauthorized.as_str(),
            crate::telemetry::RESULT_ERROR
        );
        return Err(AuthApiError::Unauthorized);
    }

    // 第二步（TOTP）：已启用 2FA 时，缺码→提示补码（不种会话）；错码→401。
    if record.totp_enabled {
        let secret = record.totp_secret.clone().unwrap_or_default();
        let provided = req.code.clone();
        let now = service::now_unix() as u64;
        let ok = provided
            .as_deref()
            .map(|c| totp::verify_code(&secret, c, now))
            .unwrap_or(false);
        if provided.is_none() {
            // 客户端据此提示输入验证码；本响应不带 Set-Cookie。
            return Ok((
                StatusCode::OK,
                Json(SessionResponse {
                    user_id: user_id.0,
                    email,
                    two_factor_required: true,
                    two_factor_enabled: true,
                }),
            )
                .into_response());
        }
        if !ok {
            record_audit(
                &state,
                None,
                "user.login_failed",
                None,
                Some(serde_json::json!({ "email": email, "reason": "bad_totp_code" })),
            )
            .await?;
            crate::op_log!(
                warn,
                "auth",
                "login",
                crate::telemetry::NOT_APPLICABLE,
                crate::telemetry::NOT_APPLICABLE,
                crate::telemetry::NOT_APPLICABLE,
                crate::telemetry::ErrorCategory::Unauthorized.as_str(),
                crate::telemetry::RESULT_ERROR
            );
            return Err(AuthApiError::Unauthorized);
        }
    }
    state.login_limiter.reset(&key);

    let headers = open_session(&state, &user_id).await?;
    record_audit(
        &state,
        Some(&user_id.0),
        "user.login",
        Some(&user_id.0),
        None,
    )
    .await?;
    crate::op_log!(
        info,
        "auth",
        "login",
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((
        StatusCode::OK,
        headers,
        Json(SessionResponse {
            user_id: user_id.0,
            email,
            two_factor_required: false,
            two_factor_enabled: record.totp_enabled,
        }),
    )
        .into_response())
}

/// `GET /api/v1/auth/2fa/status`：当前用户的 TOTP 绑定状态。
pub async fn two_factor_status_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(user_id): AuthenticatedUser,
) -> Result<Json<TotpStatusResponse>, AuthApiError> {
    let record = state
        .auth
        .find_user_by_id(&user_id)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?
        .ok_or(AuthApiError::Unauthorized)?;
    Ok(Json(TotpStatusResponse {
        enabled: record.totp_enabled,
        pending: record.totp_secret.is_some() && !record.totp_enabled,
    }))
}

/// `POST /api/v1/auth/2fa/enroll`：生成新 TOTP 密钥（服务端持有，待激活），
/// 返回扫码导入 URI。已激活则先关停旧绑定再重建（重新绑定）。
pub async fn two_factor_enroll_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
) -> Result<Json<TotpEnrollResponse>, AuthApiError> {
    let record = state
        .auth
        .find_user_by_id(&user_id)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?
        .ok_or(AuthApiError::Unauthorized)?;
    let secret = totp::generate_secret();
    state
        .auth
        .set_totp_secret(&user_id, Some(&secret))
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?;
    state
        .auth
        .set_totp_enabled(&user_id, false)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?;
    let uri = totp::otpauth_uri(totp::OTPAUTH_ISSUER, &record.email, &secret);
    record_audit(
        &state,
        Some(&user_id.0),
        "user.totp_enroll",
        Some(&user_id.0),
        None,
    )
    .await?;
    Ok(Json(TotpEnrollResponse { otpauth_uri: uri }))
}

/// `POST /api/v1/auth/2fa/activate`：以验证码确认并激活 TOTP（绑定引导收尾）。
pub async fn two_factor_activate_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Json(req): Json<TotpCodeRequest>,
) -> Result<Json<TotpStatusResponse>, AuthApiError> {
    let record = state
        .auth
        .find_user_by_id(&user_id)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?
        .ok_or(AuthApiError::Unauthorized)?;
    let secret = record
        .totp_secret
        .as_deref()
        .ok_or_else(|| AuthApiError::InvalidInput("no pending totp secret; enroll first".into()))?;
    let now = service::now_unix() as u64;
    if !totp::verify_code(secret, &req.code, now) {
        return Err(AuthApiError::InvalidInput("totp code mismatch".into()));
    }
    state
        .auth
        .set_totp_enabled(&user_id, true)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?;
    record_audit(
        &state,
        Some(&user_id.0),
        "user.totp_activate",
        Some(&user_id.0),
        None,
    )
    .await?;
    Ok(Json(TotpStatusResponse {
        enabled: true,
        pending: false,
    }))
}

/// `POST /api/v1/auth/2fa/disable`：以验证码确认后关停并清除 TOTP 绑定。
pub async fn two_factor_disable_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Json(req): Json<TotpCodeRequest>,
) -> Result<Json<TotpStatusResponse>, AuthApiError> {
    let record = state
        .auth
        .find_user_by_id(&user_id)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?
        .ok_or(AuthApiError::Unauthorized)?;
    let secret = record
        .totp_secret
        .as_deref()
        .ok_or_else(|| AuthApiError::InvalidInput("no totp binding to disable".into()))?;
    let now = service::now_unix() as u64;
    if !totp::verify_code(secret, &req.code, now) {
        return Err(AuthApiError::InvalidInput("totp code mismatch".into()));
    }
    state
        .auth
        .set_totp_secret(&user_id, None)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?;
    state
        .auth
        .set_totp_enabled(&user_id, false)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?;
    record_audit(
        &state,
        Some(&user_id.0),
        "user.totp_disable",
        Some(&user_id.0),
        None,
    )
    .await?;
    Ok(Json(TotpStatusResponse {
        enabled: false,
        pending: false,
    }))
}

/// `POST /api/v1/auth/logout`：撤销会话并清 Cookie。
pub async fn logout_handler(
    State(state): State<SharedAppState>,
    req: axum::extract::Request,
) -> Response {
    if let Some(token) = session_token_from_headers(req.headers()) {
        let now: Timestamp = service::now();
        // 先取属主再撤销（撤销后查不到了），登出留痕归属到人。
        let actor = state
            .auth
            .validate_session(&token, &now)
            .await
            .ok()
            .flatten();
        if let Err(e) = state.auth.revoke_session(&token, &now).await {
            return AuthApiError::Internal(e.to_string()).into_response();
        }
        if let Err(e) = record_audit(
            &state,
            actor.as_ref().map(|u| u.0.as_str()),
            "user.logout",
            actor.as_ref().map(|u| u.0.as_str()),
            None,
        )
        .await
        {
            return e.into_response();
        }
        crate::op_log!(
            info,
            "auth",
            "logout",
            crate::telemetry::NOT_APPLICABLE,
            crate::telemetry::NOT_APPLICABLE,
            crate::telemetry::NOT_APPLICABLE,
            crate::telemetry::ErrorCategory::None.as_str(),
            crate::telemetry::RESULT_OK
        );
    }
    (
        StatusCode::NO_CONTENT,
        clear_cookie_header(state.cookie_secure),
    )
        .into_response()
}

/// `GET /api/v1/auth/me`：返回当前会话用户。
pub async fn me_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(user_id): AuthenticatedUser,
) -> Result<Json<SessionResponse>, AuthApiError> {
    // 会话有效 ≠ 用户仍存在；再核一次。
    let record = state
        .auth
        .find_user_by_id(&user_id)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?
        .ok_or(AuthApiError::Unauthorized)?;
    Ok(Json(SessionResponse {
        user_id: record.id.0,
        email: record.email,
        two_factor_required: false,
        two_factor_enabled: record.totp_enabled,
    }))
}
