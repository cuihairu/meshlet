//! 邀请 Token 安全（[存档 §11.3](../../docs/review/chatgpt-2026-10-13.md)、
//! [ADR-010](../../docs/decisions/adr-010-console-auth-enrollment.md)）。
//!
//! 不变量：
//! - Token 由安全随机数生成（32 字节 → 64 个 hex 字符）；
//! - **服务端只存 SHA-256 摘要**：原始 Token 仅存在于创建响应与兑换请求的瞬时值，
//!   任何持久化结构（`Invite`）与错误消息都不含原始 Token；
//! - 支持过期、撤销、次数上限；兑换按 摘要 → 撤销 → 过期 → 次数 顺序校验，
//!   全部通过后递增 `used_count`；
//! - 并发竞态由调用方在互斥锁内调用 `redeem` 闭合（§11.3「避免重复消费和并发竞态」），
//!   本层保证单次 `redeem` 的原子语义。
//!
//! 时间戳为 ISO-8601 UTC（`Z`）字符串，同格式下字典序即时间序。

use crate::entities::{InviteId, NetworkId, Timestamp};
use sha2::{Digest, Sha256};

/// Token 熵长度（字节）：32 字节 = 256 bit，hex 编码后 64 字符。
pub const TOKEN_BYTES: usize = 32;

/// 生成安全随机邀请 Token（64 个 hex 字符）。
pub fn generate_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    to_hex(&bytes)
}

/// Token 的安全摘要（SHA-256 hex）。服务端只保存此值。
pub fn token_hash(raw_token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw_token.as_bytes());
    to_hex(&hasher.finalize())
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

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

/// 邀请记录。**只存 Token 摘要**，原始 Token 不进入本结构（§11.3）。
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
    /// 创建邀请：立即计算摘要，原始 Token 不进入本结构。
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

    /// 撤销；重复撤销报错而不是静默成功。
    pub fn revoke(&mut self, at: Timestamp) -> Result<(), InviteError> {
        if let Some(prev) = self.revoked_at.clone() {
            return Err(InviteError::AlreadyRevoked(prev));
        }
        self.revoked_at = Some(at);
        Ok(())
    }

    /// 兑换：校验摘要 → 撤销 → 过期 → 次数，全部通过后递增 `used_count`。
    /// **调用方须在互斥锁内调用**以闭合并发竞态（§11.3）。
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

    // 仅为格式接近真实 Token 的测试串（64 字符）。
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
        // 原始 Token 不出现在任何持久化形态：Debug 结构里只有摘要。
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
        // SHA-256("") 的标准测试向量。
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
        // 错误 Token 不泄露撤销/过期状态，也不消耗次数。
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
        // 边界：等于过期时刻尚未过期。
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
        // §11.3：并发竞态闭合后，同一 Token 只能成功兑换一次。
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
