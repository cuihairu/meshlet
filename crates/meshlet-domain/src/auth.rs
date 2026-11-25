//! Console authentication ([archive §11.4](../../docs/review/chatgpt-2026-10-13.md)).
//!
//! Invariants:
//! - passwords are stored only as Argon2id hashes, **plaintext never enters any struct/log/error message**;
//! - session tokens and invite tokens follow the [crate::tokens] discipline (store digests only);
//! - login rate limiting is an in-process fixed window (single-VPS deployment, ADR-002), counted per key (e.g. IP+email);
//! - **no default admin password**: the first admin can only be created via the "empty-DB bootstrap" (§11.4).

use std::collections::HashMap;
use std::time::Duration;

use crate::entities::{Timestamp, UserId};
use crate::tokens::{generate_token, token_hash};

/// Session cookie name.
pub const SESSION_COOKIE_NAME: &str = "meshlet_session";

/// Session TTL (increment in seconds over the ISO-8601 string timestamp).
pub const SESSION_TTL_SECS: u64 = 12 * 60 * 60;

/// Argon2id parameters: 32 MiB / 2 passes / 4 lanes
/// (above the OWASP minimum of 19 MiB / 2 passes / 4 lanes; console logins are infrequent, so affordable).
const ARGON2_M_KIB: u32 = 32 * 1024;
const ARGON2_T: u32 = 2;
const ARGON2_P: u32 = 4;

fn argon2() -> argon2::Argon2<'static> {
    use argon2::Algorithm::Argon2id;
    use argon2::{Params, Version};
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, None).expect("valid Argon2 params");
    argon2::Argon2::new(Argon2id, Version::V0x13, params)
}

/// Argon2id hash (PHC string format, includes a random salt).
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    use argon2::PasswordHasher;
    let salt =
        argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    argon2()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| AuthError::HashFailure)
}

/// Verify a password. A malformed hash counts as verification failure (no distinction between "bad hash" and "wrong password").
pub fn verify_password(password: &str, phc_hash: &str) -> bool {
    use argon2::PasswordVerifier;
    let Ok(parsed) = argon2::password_hash::PasswordHash::new(phc_hash) else {
        return false;
    };
    argon2()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error("email format is not valid")]
    InvalidEmail,
    #[error("password must be at least {0} characters")]
    PasswordTooShort(usize),
    #[error("password hash failure")]
    HashFailure,
}

/// Minimum password length (console admins).
pub const MIN_PASSWORD_LEN: usize = 12;

/// Validate the minimal shape of an email: `local@domain.tld` (not full RFC validation; enough for the console).
pub fn validate_email(email: &str) -> Result<(), AuthError> {
    let (local, rest) = email.split_once('@').ok_or(AuthError::InvalidEmail)?;
    if local.is_empty() || !rest.contains('.') || rest.starts_with('.') || rest.ends_with('.') {
        return Err(AuthError::InvalidEmail);
    }
    if email.matches('@').count() != 1 {
        return Err(AuthError::InvalidEmail);
    }
    Ok(())
}

/// Validate the password policy: minimum 12 characters.
pub fn validate_password(password: &str) -> Result<(), AuthError> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(AuthError::PasswordTooShort(MIN_PASSWORD_LEN));
    }
    Ok(())
}

/// Console user. **password_hash is an Argon2id PHC string; plaintext passwords are never stored** (§11.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: UserId,
    pub email: String,
    pub password_hash: String,
    pub created_at: Timestamp,
}

impl User {
    /// Create a user: validate the email/password policy, then hash immediately.
    /// The plaintext password passed in only exists within this call stack.
    pub fn new(
        id: UserId,
        email: impl Into<String>,
        password: &str,
        created_at: Timestamp,
    ) -> Result<Self, AuthError> {
        let email = email.into();
        validate_email(&email)?;
        validate_password(password)?;
        Ok(Self {
            id,
            email,
            password_hash: hash_password(password)?,
            created_at,
        })
    }

    /// Verify a login password.
    pub fn verify(&self, password: &str) -> bool {
        verify_password(password, &self.password_hash)
    }
}

/// Session record (server side). **Stores only the token digest**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub token_hash: String,
    pub user_id: UserId,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub revoked_at: Option<Timestamp>,
}

impl Session {
    /// Generate a new session: returns (`raw_token`, `Session`). The raw token appears here and only here.
    pub fn generate(user_id: UserId, now: Timestamp) -> (String, Self) {
        let raw = generate_token();
        let expires_at = expiry_after(&now, SESSION_TTL_SECS).expect("valid timestamp");
        let session = Self {
            token_hash: token_hash(&raw),
            user_id,
            created_at: now,
            expires_at,
            revoked_at: None,
        };
        (raw, session)
    }

    pub fn is_valid(&self, now: &Timestamp) -> bool {
        self.revoked_at.is_none() && self.expires_at.as_str() > now.as_str()
    }
}

/// Add seconds to an ISO-8601 (`Z`, second-precision) timestamp. Returns `None` on parse failure (caller decides the fallback).
fn expiry_after(ts: &Timestamp, secs: u64) -> Option<Timestamp> {
    let dt = chrono::DateTime::parse_from_rfc3339(ts.as_str()).ok()?;
    Some(
        dt.checked_add_signed(chrono::Duration::seconds(secs as i64))?
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    )
}

/// Login rate limiting: an in-process fixed-window counter (ADR-002 single VPS; no distributed store needed).
///
/// `check` takes an injected clock (`Instant`) for deterministic unit tests.
#[derive(Debug)]
pub struct RateLimiter {
    max_per_window: u32,
    window: Duration,
    buckets: std::sync::Mutex<HashMap<String, (std::time::Instant, u32)>>,
}

impl RateLimiter {
    pub fn new(max_per_window: u32, window: Duration) -> Self {
        Self {
            max_per_window,
            window,
            buckets: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Record one attempt and decide whether to allow it. `true` = allowed.
    pub fn check(&self, key: &str, now: std::time::Instant) -> bool {
        let mut buckets = self.buckets.lock().expect("rate limiter lock");
        let entry = buckets.entry(key.to_string()).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        if entry.1 >= self.max_per_window {
            return false;
        }
        entry.1 += 1;
        true
    }

    /// Clear the count after a successful login (only failure counts stay in the window).
    pub fn reset(&self, key: &str) {
        self.buckets.lock().expect("rate limiter lock").remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> Timestamp {
        "2026-10-14T00:00:00Z".into()
    }

    #[test]
    fn password_hash_roundtrip_and_wrong_password_fails() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("wrong password entirely", &hash));
    }

    #[test]
    fn hash_is_salted_each_call_differs() {
        let a = hash_password("same password").unwrap();
        let b = hash_password("same password").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn malformed_hash_fails_closed() {
        assert!(!verify_password("whatever", "not-a-phc-hash"));
        assert!(!verify_password("whatever", ""));
    }

    #[test]
    fn user_new_validates_and_hashes() {
        let user = User::new(
            UserId("u-1".into()),
            "admin@example.com",
            "a-long-enough-password",
            ts(),
        )
        .unwrap();
        assert_eq!(user.email, "admin@example.com");
        assert!(user.password_hash.starts_with("$argon2id$"));
        assert!(!format!("{user:?}").contains("a-long-enough-password"));
        assert!(user.verify("a-long-enough-password"));
        assert!(!user.verify("other"));
    }

    #[test]
    fn user_new_rejects_bad_email_and_short_password() {
        assert_eq!(
            User::new(UserId("u".into()), "no-at-sign", &"x".repeat(16), ts()).unwrap_err(),
            AuthError::InvalidEmail
        );
        assert_eq!(
            User::new(UserId("u".into()), "a@b", &"x".repeat(16), ts()).unwrap_err(),
            AuthError::InvalidEmail
        );
        assert_eq!(
            User::new(UserId("u".into()), "a@b.c", "short", ts()).unwrap_err(),
            AuthError::PasswordTooShort(MIN_PASSWORD_LEN)
        );
    }

    #[test]
    fn session_stores_only_digest_and_expires() {
        let (raw, session) = Session::generate(UserId("u-1".into()), ts());
        assert_eq!(session.token_hash, token_hash(&raw));
        assert!(!format!("{session:?}").contains(&raw));
        assert_eq!(session.expires_at, "2026-10-14T12:00:00Z");
        assert!(session.is_valid(&"2026-10-14T11:59:59Z".into()));
        assert!(!session.is_valid(&"2026-10-14T12:00:01Z".into()));
    }

    #[test]
    fn revoked_session_is_invalid_regardless_of_expiry() {
        let (_, mut session) = Session::generate(UserId("u-1".into()), ts());
        session.revoked_at = Some("2026-10-14T01:00:00Z".into());
        assert!(!session.is_valid(&"2026-10-14T02:00:00Z".into()));
    }

    #[test]
    fn rate_limiter_blocks_after_max_within_window() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        let t0 = std::time::Instant::now();

        assert!(limiter.check("ip-1", t0));
        assert!(limiter.check("ip-1", t0 + Duration::from_secs(10)));
        assert!(limiter.check("ip-1", t0 + Duration::from_secs(20)));
        // The 4th attempt is rejected within the window.
        assert!(!limiter.check("ip-1", t0 + Duration::from_secs(30)));
        // Other keys are unaffected.
        assert!(limiter.check("ip-2", t0 + Duration::from_secs(30)));
        // Reset once the window has elapsed.
        assert!(limiter.check("ip-1", t0 + Duration::from_secs(61)));
    }

    #[test]
    fn rate_limiter_reset_clears_failures() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        let t0 = std::time::Instant::now();
        assert!(limiter.check("k", t0));
        assert!(limiter.check("k", t0));
        assert!(!limiter.check("k", t0));
        limiter.reset("k");
        assert!(limiter.check("k", t0));
    }
}
