//! TOTP second-factor core (RFC 4226 HOTP / RFC 6238 TOTP, SHA-1, 6 digits, 30-second steps).
//!
//! Invariants (non-negotiable):
//! - the secret is stored in the server's user table only as a **base32 string**; no response carries
//!   anything else that could reconstruct it, and the `otpauth://` URI contains only the base32 secret itself (no plaintext passwords);
//! - the verification window is ±1 step (`TOTP_WINDOW`); anything beyond it is rejected;
//! - invalid base32 secrets / non-numeric codes / empty codes always fail (no panic, no reason distinction).
//!
//! Tests use the RFC 4226 Appendix D vectors (ASCII key `12345678901234567890`) and
//! the RFC 6238 SHA-1 vectors (8-digit variant), with no external libraries.

use hmac::{Hmac, Mac};
use sha1::Sha1;

/// TOTP time step (seconds).
pub const TOTP_STEP_SECS: u64 = 30;
/// Number of code digits (mainstream authenticators default to 6).
pub const TOTP_DIGITS: u32 = 6;
/// Verification window: one step before or after is allowed (±1 step).
pub const TOTP_WINDOW: u64 = 1;
/// Entropy of generated secrets (20 bytes = 160 bits, 32 chars after base32 encoding).
pub const SECRET_BYTES: usize = 20;
/// Authenticator display name (the otpauth issuer field).
pub const OTPAUTH_ISSUER: &str = "meshlet";

/// Generate a fresh base32 secret for a new enrollment (RFC 4648, unpadded, uppercase). The
/// randomness comes from the in-process CSPRNG (rand `OsRng`).
pub fn generate_secret() -> String {
    use rand_core::RngCore;
    let mut bytes = [0u8; SECRET_BYTES];
    rand_core::OsRng.fill_bytes(&mut bytes);
    data_encoding::BASE32_NOPAD.encode(&bytes)
}

/// RFC 4226 HOTP: HMAC-SHA1 + dynamic truncation, returning a `digits`-digit code (zero-padded).
pub fn hotp_sha1(key: &[u8], counter: u64, digits: u32) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let bin = ((digest[offset] & 0x7f) as u32) << 24
        | (digest[offset + 1] as u32) << 16
        | (digest[offset + 2] as u32) << 8
        | digest[offset + 3] as u32;
    let modulus = 10u32.pow(digits);
    format!("{:0width$}", bin % modulus, width = digits as usize)
}

/// Expected code at a moment (unix seconds). Returns `None` for an invalid secret.
pub fn code_at(secret_b32: &str, unix_secs: u64) -> Option<String> {
    let key = base32_decode(secret_b32)?;
    let counter = unix_secs / TOTP_STEP_SECS;
    Some(hotp_sha1(&key, counter, TOTP_DIGITS))
}

/// Verify a TOTP code (±1 step window). Invalid secret / non-numeric code / wrong length all return `false`.
pub fn verify_code(secret_b32: &str, code: &str, unix_secs: u64) -> bool {
    let Some(code) = normalized_code(code) else {
        return false;
    };
    let Some(key) = base32_decode(secret_b32) else {
        return false;
    };
    let counter = unix_secs / TOTP_STEP_SECS;
    let mut lo = counter.saturating_sub(TOTP_WINDOW);
    let hi = counter + TOTP_WINDOW;
    while lo <= hi {
        if hotp_sha1(&key, lo, TOTP_DIGITS) == code {
            return true;
        }
        lo += 1;
    }
    false
}

/// Canonical code: digits only, exactly `TOTP_DIGITS` long.
fn normalized_code(code: &str) -> Option<String> {
    let code = code.trim();
    if code.len() != TOTP_DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(code.to_string())
}

/// RFC 4648 base32 decode (padded or unpadded; uppercase or lowercase). Returns `None` on invalid input.
fn base32_decode(s: &str) -> Option<Vec<u8>> {
    use data_encoding::{BASE32, BASE32_NOPAD};
    let s = s.trim().to_ascii_uppercase();
    BASE32_NOPAD
        .decode(s.as_bytes())
        .or_else(|_| BASE32.decode(s.as_bytes()))
        .ok()
}

/// `otpauth://totp/{issuer}:{account}?secret=…&issuer=…&algorithm=SHA1&digits=6&period=30`
///
/// The label is URI-component encoded (`@` kept so emails stay readable), and the secret is the raw base32.
/// This URI is the only material for authenticator QR import; the server writes nothing beyond the secret into responses.
pub fn otpauth_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
    let label = format!("{}:{}", encode_label(issuer), encode_label(account));
    format!(
        "otpauth://totp/{label}?secret={secret_b32}&issuer={}&algorithm=SHA1&digits={}&period={}",
        encode_label(issuer),
        TOTP_DIGITS,
        TOTP_STEP_SECS,
    )
}

/// URI component encoding: alphanumeric plus `-._~@` are kept, everything else is percent-encoded.
fn encode_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'@' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4226 Appendix D (HMAC-SHA1, ASCII key, 6 digits): counts 0..=9.
    const RFC4226_VECTORS: [(u64, &str); 10] = [
        (0, "755224"),
        (1, "287082"),
        (2, "359152"),
        (3, "969429"),
        (4, "338314"),
        (5, "254676"),
        (6, "287922"),
        (7, "162583"),
        (8, "399871"),
        (9, "520489"),
    ];

    #[test]
    fn hotp_matches_rfc4226_vectors() {
        let key = b"12345678901234567890";
        for (count, expected) in RFC4226_VECTORS {
            assert_eq!(hotp_sha1(key, count, 6), expected, "counter {count}");
        }
    }

    #[test]
    fn hotp_pads_leading_zero_and_agrees_with_rfc6238_8digit() {
        // The 8-digit value for counter 1 with the same key is exactly the RFC 6238 SHA-1 vector at T=59, 94287082
        // (T=59 → counter=1), and the 6-digit truncation matches its low 6 digits, corroborating each other.
        let key = b"12345678901234567890";
        assert_eq!(hotp_sha1(key, 1, 8), "94287082");
        assert_eq!(hotp_sha1(key, 1, 6), "287082");
        assert_eq!(hotp_sha1(key, 0, 6).len(), 6);
    }

    #[test]
    fn verify_code_accepts_rfc4226_counter_and_window() {
        // TOTP counter = unix/30. Taking unix=30*5=150 → counter 5 → 254676.
        assert!(verify_code(
            &data_encoding::BASE32_NOPAD.encode(b"12345678901234567890"),
            "254676",
            150
        ));
        // ±1 step (counters 4 and 6) also falls inside the window.
        assert!(verify_code(
            &data_encoding::BASE32_NOPAD.encode(b"12345678901234567890"),
            "338314",
            150
        ));
        assert!(verify_code(
            &data_encoding::BASE32_NOPAD.encode(b"12345678901234567890"),
            "287922",
            150
        ));
    }

    #[test]
    fn verify_code_rejects_beyond_window_and_bad_input() {
        let sec = &data_encoding::BASE32_NOPAD.encode(b"12345678901234567890");
        // Step is 30: a 2-step counter gap → rejected.
        assert!(!verify_code(sec, "338314", 150 + 2 * 30));
        // Wrong code / non-numeric / wrong length / empty.
        assert!(!verify_code(sec, "000000", 150));
        assert!(!verify_code(sec, "abcabc", 150));
        assert!(!verify_code(sec, "12345", 150));
        assert!(!verify_code(sec, "", 150));
        // Invalid base32 secret.
        assert!(!verify_code("not base32 !!", "254676", 150));
    }

    #[test]
    fn generate_secret_is_32_char_base32_and_unique() {
        let a = generate_secret();
        let b = generate_secret();
        assert_eq!(a.len(), 32);
        // base32 uppercase letters + digits 2-7; no lowercase (`is_ascii_uppercase` is false for digits).
        assert!(a
            .bytes()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
        assert_ne!(a, b);
        // Decodable as base32 (i.e. the secret is self-consistent).
        assert_eq!(base32_decode(&a).map(|v| v.len()), Some(SECRET_BYTES));
    }

    #[test]
    fn otpauth_uri_has_standard_format_and_no_plaintext() {
        let uri = otpauth_uri(OTPAUTH_ISSUER, "admin@meshlet.local", "JBSWY3DPEHPK3PXP");
        assert!(uri.starts_with("otpauth://totp/meshlet:admin@meshlet.local?"));
        assert!(uri.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(uri.contains("issuer=meshlet"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
        // Plaintext passwords never enter the URI.
        assert!(!uri.contains("password="));
        assert!(!uri.contains("P@ssw0rd"));
    }

    #[test]
    fn code_at_matches_verify() {
        let sec = generate_secret();
        let now = 1_800_000_000u64;
        let code = code_at(&sec, now).unwrap();
        assert!(verify_code(&sec, &code, now));
    }

    #[test]
    fn label_encoding_keeps_at_and_encodes_reserved() {
        assert_eq!(encode_label("meshlet"), "meshlet");
        assert_eq!(encode_label("a@b.c"), "a@b.c");
        assert_eq!(encode_label("a b"), "a%20b");
        assert_eq!(encode_label("a?b"), "a%3Fb");
    }
}
