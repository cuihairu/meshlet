//! Invite token security ([archive §11.3](../../docs/review/chatgpt-2026-10-13.md),
//! [ADR-010](../../docs/decisions/adr-010-console-auth-enrollment.md)).
//!
//! Invariants:
//! - tokens come from a secure random source (32 bytes → 64 hex characters);
//! - **the server stores only the SHA-256 digest**: the raw token exists only transiently, in the create response and the redeem request;
//!   no persisted structure (`Invite`) or error message ever contains the raw token;
//! - expiry, revocation, and a use cap are supported; redemption validates digest → revocation → expiry → use count,
//!   and increments `used_count` only after all pass;
//! - concurrent races are closed by the caller invoking `redeem` under a mutex (§11.3 "avoid double consumption and concurrent races");
//!   this layer guarantees the atomic semantics of a single `redeem`.
//!
//! Timestamps are ISO-8601 UTC (`Z`) strings; in this format, lexicographic order equals chronological order.

use crate::entities::{InviteId, NetworkId, Timestamp};

pub use crate::tokens::{generate_token, token_hash, TOKEN_BYTES};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InviteError {
    #[error("invite token is not valid")]
    InvalidToken,
    #[error("invite expired at {0}")]
    Expired(Timestamp),
    #[error("invite revoked at {0}")]
    Revoked(Timestamp),
    #[error("invite use limit ({0}) reached")]
    Exhausted(u32),
    #[error("invite already revoked at {0}")]
    AlreadyRevoked(Timestamp),
}

/// Invite record. **Stores only the token digest**; the raw token never enters this struct (§11.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub id: InviteId,
    pub network_id: NetworkId,
    pub token_hash: String,
    pub expires_at: Option<Timestamp>,
    pub max_uses: u32,
    pub used_count: u32,
    pub created_at: Timestamp,
    pub revoked_at: Option<Timestamp>,
}

impl Invite {
    /// Creates an invite: the digest is computed immediately and the raw token never enters this struct.
    pub fn new(
        id: InviteId,
        network_id: NetworkId,
        raw_token: &str,
        expires_at: Option<Timestamp>,
        max_uses: u32,
        created_at: Timestamp,
    ) -> Self {
        Self {
            id,
            network_id,
            token_hash: token_hash(raw_token),
            expires_at,
            max_uses,
            used_count: 0,
            created_at,
            revoked_at: None,
        }
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    pub fn is_expired(&self, at: &Timestamp) -> bool {
        self.expires_at.as_ref().is_some_and(|exp| at > exp)
    }

    pub fn has_capacity(&self) -> bool {
        self.used_count < self.max_uses
    }

    /// Revokes; revoking twice errors instead of silently succeeding.
    pub fn revoke(&mut self, at: Timestamp) -> Result<(), InviteError> {
        if let Some(prev) = self.revoked_at.clone() {
            return Err(InviteError::AlreadyRevoked(prev));
        }
        self.revoked_at = Some(at);
        Ok(())
    }

    /// Redeems: validates digest → revocation → expiry → use count, then increments `used_count` only if all pass.
    /// **The caller must invoke this under a mutex** to close concurrent races (§11.3).
    pub fn redeem(&mut self, raw_token: &str, at: Timestamp) -> Result<(), InviteError> {
        if token_hash(raw_token) != self.token_hash {
            return Err(InviteError::InvalidToken);
        }
        if let Some(at) = self.revoked_at.clone() {
            return Err(InviteError::Revoked(at));
        }
        if self.is_expired(&at) {
            return Err(InviteError::Expired(self.expires_at.clone().unwrap_or(at)));
        }
        if !self.has_capacity() {
            return Err(InviteError::Exhausted(self.max_uses));
        }
        self.used_count += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::thread;

    // Test-only string shaped like a real token (64 characters).
    const RAW: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn invite(max_uses: u32) -> Invite {
        Invite::new(
            InviteId("inv-1".into()),
            NetworkId("net-1".into()),
            RAW,
            None,
            max_uses,
            "2026-10-14T08:00:00Z".into(),
        )
    }

    #[test]
    fn create_stores_hash_not_raw_token() {
        let inv = invite(1);
        assert_eq!(inv.token_hash, token_hash(RAW));
        assert_ne!(inv.token_hash, RAW);
        // The raw token never appears in any persisted form: the Debug output holds only the digest.
        let dbg = format!("{inv:?}");
        assert!(!dbg.contains(RAW));
        assert!(dbg.contains("token_hash"));
    }

    #[test]
    fn generated_token_is_64_hex_chars_and_unique() {
        let t1 = generate_token();
        let t2 = generate_token();
        assert_eq!(t1.len(), 64);
        assert!(t1.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(t1, t2);
    }

    #[test]
    fn token_hash_matches_sha256_test_vector() {
        // Standard test vector for SHA-256("").
        assert_eq!(
            token_hash(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn redeem_happy_path_increments_uses() {
        let mut inv = invite(2);
        inv.redeem(RAW, "2026-10-14T08:00:00Z".into()).unwrap();
        assert_eq!(inv.used_count, 1);
        inv.redeem(RAW, "2026-10-14T08:00:01Z".into()).unwrap();
        assert_eq!(inv.used_count, 2);
    }

    #[test]
    fn redeem_invalid_token_rejected_without_leaking_state() {
        // A wrong token must not leak revocation/expiry state, nor consume a use.
        let mut inv = invite(1);
        inv.revoke("2026-10-14T08:00:00Z".into()).unwrap();
        assert!(matches!(
            inv.redeem("wrong-token", "2026-10-14T08:00:01Z".into()),
            Err(InviteError::InvalidToken)
        ));
        assert_eq!(inv.used_count, 0);
    }

    #[test]
    fn redeem_rejected_when_revoked() {
        let mut inv = invite(1);
        inv.revoke("2026-10-14T08:00:00Z".into()).unwrap();
        assert!(matches!(
            inv.redeem(RAW, "2026-10-14T08:00:01Z".into()),
            Err(InviteError::Revoked(_))
        ));
        assert_eq!(inv.used_count, 0);
    }

    #[test]
    fn redeem_rejected_when_expired() {
        let mut inv = Invite::new(
            InviteId("inv-1".into()),
            NetworkId("net-1".into()),
            RAW,
            Some("2026-10-14T08:00:00Z".into()),
            1,
            "2026-10-14T07:00:00Z".into(),
        );
        assert!(matches!(
            inv.redeem(RAW, "2026-10-14T08:00:01Z".into()),
            Err(InviteError::Expired(_))
        ));
        // Boundary: exactly at the expiry instant is not yet expired.
        inv.expires_at = Some("2026-10-14T08:00:01Z".into());
        inv.redeem(RAW, "2026-10-14T08:00:01Z".into()).unwrap();
    }

    #[test]
    fn single_use_invite_exhausts_after_one_redeem() {
        let mut inv = invite(1);
        inv.redeem(RAW, "2026-10-14T08:00:00Z".into()).unwrap();
        assert!(matches!(
            inv.redeem(RAW, "2026-10-14T08:00:01Z".into()),
            Err(InviteError::Exhausted(1))
        ));
    }

    #[test]
    fn revoke_is_idempotent_by_error() {
        let mut inv = invite(1);
        inv.revoke("2026-10-14T08:00:00Z".into()).unwrap();
        assert!(matches!(
            inv.revoke("2026-10-14T08:00:01Z".into()),
            Err(InviteError::AlreadyRevoked(_))
        ));
    }

    #[test]
    fn concurrent_redeem_has_single_winner() {
        // §11.3: once the concurrent race is closed, the same token can be redeemed successfully only once.
        let inv = Arc::new(Mutex::new(invite(1)));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let inv = Arc::clone(&inv);
            handles.push(thread::spawn(move || {
                inv.lock()
                    .unwrap()
                    .redeem(RAW, "2026-10-14T08:00:00Z".into())
            }));
        }
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(inv.lock().unwrap().used_count, 1);
    }
}
