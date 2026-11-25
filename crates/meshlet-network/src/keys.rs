//! WireGuard keypair (Curve25519): used for agent bootstrap registration.
//!
//! Device registration must report the **public key** (the server stores the
//! public key + fingerprint and never any private-side material, ADR-010). The
//! agent keeps the private key locally (`[dataplane] private_key_file`, 0600):
//! on first registration a keypair is generated and written to disk; if the file
//! already exists, the public key is derived from the private one (the private
//! key is left untouched).
//!
//! Isomorphic to `wg genkey` / `wg pubkey`: 32-byte Curve25519 in standard
//! base64 (44 characters with `=` padding). x25519-dalek's
//! `StaticSecret::from([u8; 32])` applies RFC 7748 clamping itself, matching
//! the semantics of `wg genkey`.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

/// Generate the local keypair: returns `(private key base64, public key base64)`.
///
/// The private key is **only returned once, in memory**; the caller writes it
/// immediately to a 0600 file. This module never touches disk.
pub fn generate_keypair() -> Result<(String, String), String> {
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    Ok((
        BASE64.encode(secret.to_bytes()),
        BASE64.encode(public.as_bytes()),
    ))
}

/// Derive the public key from the local private key (the registration path where the private key file already exists).
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
        // Encoding isomorphic to `wg`: 32 bytes -> 44 characters of standard base64.
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
        // 4 bytes of valid base64 but the wrong length.
        assert!(public_from_private(&BASE64.encode([0u8; 4])).is_err());
    }
}
