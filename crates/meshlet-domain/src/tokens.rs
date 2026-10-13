//! 共享 Token 工具（[存档 §11.3](../../docs/review/chatgpt-2026-10-13.md)）。
//!
//! 邀请 Token 与控制台会话 Token 共用同一纪律：
//! - 安全随机（32 字节 → 64 个 hex 字符，256 bit 熵）；
//! - 服务端只存 SHA-256 摘要，原始 Token 只在创建/使用响应中瞬时出现。

use sha2::{Digest, Sha256};

/// Token 熵长度（字节）：32 字节 = 256 bit，hex 编码后 64 字符。
pub const TOKEN_BYTES: usize = 32;

/// 生成安全随机 Token（64 个 hex 字符）。
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

    /// SHA-256 空串测试向量（FIPS 180-2）。
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
