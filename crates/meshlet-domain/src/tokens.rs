//! Shared Token utilities ([archive §11.3](../../docs/review/chatgpt-2026-10-13.md)).
//!
//! Invite Tokens and console session Tokens share one discipline:
//! - cryptographically random (32 bytes → 64 hex chars, 256 bit entropy);
//! - the server stores only the SHA-256 digest; the raw Token appears transiently only in creation/usage responses.

use sha2::{Digest, Sha256};

/// Token entropy length (bytes): 32 bytes = 256 bit, i.e. 64 hex chars after encoding.
pub const TOKEN_BYTES: usize = 32;

/// Generate a cryptographically random Token (64 hex chars).
pub fn generate_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    to_hex(&bytes)
}

/// Secure digest of a Token (SHA-256 hex). The server stores only this value.
pub fn token_hash(raw_token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw_token.as_bytes());
    to_hex(&hasher.finalize())
}

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256 empty-string test vector (FIPS 180-2).
    #[test]
    fn token_hash_matches_sha256_test_vector() {
        assert_eq!(
            token_hash(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            token_hash("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn generated_tokens_are_unique_and_wellformed() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), TOKEN_BYTES * 2);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    }
}
