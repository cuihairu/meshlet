//! WireGuard 密钥对（Curve25519）：agent 自举注册用。
//!
//! 设备注册需要上报**公钥**（服务端存公钥 + 指纹，绝不存私钥侧材料，
//! ADR-010）。agent 本机持私钥（`[dataplane] private_key_file`，0600）：
//! 首次注册时生成密钥对并落盘；文件已存在时从私钥推导公钥（私钥不动）。
//!
//! 与 `wg genkey` / `wg pubkey` 同构：32 字节 Curve25519，标准 base64
//! （44 字符含 `=` 填充）。x25519-dalek 的 `StaticSecret::from([u8; 32])`
//! 自带 RFC 7748 clamping，与 `wg genkey` 语义一致。

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

/// 生成本机密钥对：返回 `(私钥 base64, 公钥 base64)`。
///
/// 私钥**只在内存中返回一次**，由调用方立即写入 0600 文件；本模块不落盘。
pub fn generate_keypair() -> Result<(String, String), String> {
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    Ok((
        BASE64.encode(secret.to_bytes()),
        BASE64.encode(public.as_bytes()),
    ))
}

/// 从本机私钥推导公钥（私钥文件已存在的注册路径）。
pub fn public_from_private(private_b64: &str) -> Result<String, String> {
    let raw = BASE64
        .decode(private_b64.trim())
        .map_err(|e| format!("decode the local private key: {e}"))?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| "the local private key must decode to 32 bytes".to_string())?;
    let secret = x25519_dalek::StaticSecret::from(bytes);
    let public = x25519_dalek::PublicKey::from(&secret);
    Ok(BASE64.encode(public.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_roundtrip_via_public_from_private() {
        let (private, public) = generate_keypair().expect("keypair generates");
        let derived = public_from_private(&private).expect("public derives");
        assert_eq!(public, derived);
        // 与 `wg` 同构的编码：32 字节 → 44 字符标准 base64。
        assert_eq!(private.len(), 44);
        assert_eq!(public.len(), 44);
    }

    #[test]
    fn keypairs_are_unique() {
        let (a, _) = generate_keypair().expect("a");
        let (b, _) = generate_keypair().expect("b");
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_bad_private_key_material() {
        assert!(public_from_private("not-base64!!").is_err());
        // 4 字节合法 base64 但长度不对。
        assert!(public_from_private(&BASE64.encode([0u8; 4])).is_err());
    }
}
