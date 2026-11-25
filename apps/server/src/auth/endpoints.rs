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
// Endpoints
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialsRequest {
    pub email: String,
    pub password: String,
    /// TOTP verification code (second factor). Provide it when this user has 2FA enabled; ignored otherwise.
    #[serde(default)]
    pub code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub user_id: String,
    pub email: String,
    /// This login still lacks the TOTP second factor (no session cookie set in this response; the client should prompt for the code).
    pub two_factor_required: bool,
    /// TOTP is enabled for this user (the client uses this to decide whether to show the enrollment flow).
    pub two_factor_enabled: bool,
}

/// Request body for TOTP enrollment/activation/disabling.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpCodeRequest {
    pub code: String,
}

/// Response for `GET /api/v1/auth/2fa/status`.
#[derive(Debug, Serialize)]
pub struct TotpStatusResponse {
    /// Activated (login requires the second factor).
    pub enabled: bool,
    /// Secret generated, awaiting activation by code (enrollment flow in progress).
    pub pending: bool,
}

/// Response for `POST /api/v1/auth/2fa/enroll`.
#[derive(Debug, Serialize)]
pub struct TotpEnrollResponse {
    /// The otpauth:// URI the authenticator scans to import. This URI is the only
    /// carrier of the base32 secret — it is the standard material for authenticator
    /// import; the response holds no other representation of the raw secret.
    pub otpauth_uri: String,
}

/// Create a session and set the cookie.
async fn open_session(state: &AppState, user_id: &UserId) -> Result<HeaderMap, AuthApiError> {
    let (raw_token, session) = Session::generate(user_id.clone(), service::now());
    state
        .auth
        .insert_session(&session)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?;
    Ok(session_cookie_header(&raw_token, state.cookie_secure))
}

/// `POST /api/v1/auth/bootstrap`: only usable on an empty database; creates the first admin and logs in immediately.
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

/// `POST /api/v1/auth/login`: verifies the password and issues a session cookie on success.
/// Does not distinguish "unknown user" from "wrong password" (uniform 401 + constant-time check).
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
        // Constant time: run one verification pass against a fixed hash before rejecting.
        let password = req.password;
        let _permit = state.auth_blocking.acquire().await;
        let _ = tokio::task::spawn_blocking(move || {
            meshlet_domain::auth::verify_password(&password, DUMMY_HASH)
        })
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()));
        // Failures must leave a trace too (§16.5: login failures are always recorded);
        // email is not a secret field and helps brute-force diagnosis. The password
        // itself is never recorded.
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

    // Second factor (TOTP): when 2FA is enabled, a missing code -> prompt for the code
    // (no session cookie set); a wrong code -> 401.
    if record.totp_enabled {
        let secret = record.totp_secret.clone().unwrap_or_default();
        let provided = req.code.clone();
        let now = service::now_unix() as u64;
        let ok = provided
            .as_deref()
            .map(|c| totp::verify_code(&secret, c, now))
            .unwrap_or(false);
        if provided.is_none() {
            // The client uses this to prompt for the verification code; this response carries no Set-Cookie.
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

/// `GET /api/v1/auth/2fa/status`: the current user's TOTP enrollment state.
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

/// `POST /api/v1/auth/2fa/enroll`: generates a new TOTP secret (held by the server,
/// awaiting activation) and returns the URI to scan for import. If already activated,
/// the old binding is disabled first and then rebuilt (re-enrollment).
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

/// `POST /api/v1/auth/2fa/activate`: confirms with the code and activates TOTP (concludes the enrollment flow).
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

/// `POST /api/v1/auth/2fa/disable`: after confirming with the code, disables and clears the TOTP binding.
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

/// `POST /api/v1/auth/logout`: revokes the session and clears the cookie.
pub async fn logout_handler(
    State(state): State<SharedAppState>,
    req: axum::extract::Request,
) -> Response {
    if let Some(token) = session_token_from_headers(req.headers()) {
        let now: Timestamp = service::now();
        // Fetch the owner first, then revoke (it cannot be looked up after revocation); the logout trace is attributed to the person.
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

/// `GET /api/v1/auth/me`: returns the current session user.
pub async fn me_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(user_id): AuthenticatedUser,
) -> Result<Json<SessionResponse>, AuthApiError> {
    // A valid session != the user still exists; check once more.
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
