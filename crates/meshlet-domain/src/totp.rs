//! TOTP 二次认证核心（RFC 4226 HOTP / RFC 6238 TOTP，SHA-1，6 位，30 秒步长）。
//!
//! 不变量（守规矩）：
//! - 密钥只以 **base32 字符串**存在服务端用户表；任何响应不携带密钥外的
//!   可还原材料，`otpauth://` URI 只含 base32 密钥本身（不含明文密码）；
//! - 校验窗口 ±1 步（`TOTP_WINDOW`），超窗一律拒绝；
//! - 非法 base32 密钥 / 非数字码 / 空码一律失败（不 panic、不区分原因）。
//!
//! 测试用 RFC 4226 附录 D 向量（ASCII 密钥 `12345678901234567890`）与
//! RFC 6238 SHA-1 向量（8 位版），不依赖任何外部库。

use hmac::{Hmac, Mac};
use sha1::Sha1;

/// TOTP 时间步长（秒）。
pub const TOTP_STEP_SECS: u64 = 30;
/// 码位数（主流认证器默认 6）。
pub const TOTP_DIGITS: u32 = 6;
/// 校验窗口：允许前后各 1 步（±1 步）。
pub const TOTP_WINDOW: u64 = 1;
/// 生成密钥的熵（20 字节 = 160 位，base32 编码后 32 字符）。
pub const SECRET_BYTES: usize = 20;
/// 认证器显示名（otpauth 的 issuer 字段）。
pub const OTPAUTH_ISSUER: &str = "meshlet";

/// 生成本次绑定的新 base32 密钥（RFC 4648 无填充大写字母）。随机源为
/// 进程内 CSPRNG（rand `OsRng`）。
pub fn generate_secret() -> String {
    use rand_core::RngCore;
    let mut bytes = [0u8; SECRET_BYTES];
    rand_core::OsRng.fill_bytes(&mut bytes);
    data_encoding::BASE32_NOPAD.encode(&bytes)
}

/// RFC 4226 HOTP：HMAC-SHA1 + 动态截断，返回 `digits` 位码（前导零补齐）。
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

/// 某时刻（unix 秒）的期望码。密钥非法返回 `None`。
pub fn code_at(secret_b32: &str, unix_secs: u64) -> Option<String> {
    let key = base32_decode(secret_b32)?;
    let counter = unix_secs / TOTP_STEP_SECS;
    Some(hotp_sha1(&key, counter, TOTP_DIGITS))
}

/// 校验 TOTP 码（±1 步窗口）。密钥非法 / 码非数字 / 长度不符一律 `false`。
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

/// 规范码：仅数字、恰好 `TOTP_DIGITS` 位。
fn normalized_code(code: &str) -> Option<String> {
    let code = code.trim();
    if code.len() != TOTP_DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(code.to_string())
}

/// RFC 4648 base32 解码（无填充 / 带填充均可；大写或小写）。非法返回 `None`。
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
/// 标签做 URI 组件编码（保留 `@` 便于邮箱可读），secret 为 base32 原文。
/// 该 URI 是认证器扫码导入的唯一材料；服务端不向响应写入密钥以外的材料。
pub fn otpauth_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
    let label = format!("{}:{}", encode_label(issuer), encode_label(account));
    format!(
        "otpauth://totp/{label}?secret={secret_b32}&issuer={}&algorithm=SHA1&digits={}&period={}",
        encode_label(issuer),
        TOTP_DIGITS,
        TOTP_STEP_SECS,
    )
}

/// URI 组件编码：保留字母数字与 `-._~@`，其余百分号编码。
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

    /// RFC 4226 附录 D（HMAC-SHA1，ASCII 密钥，6 位）：count 0..=9。
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
        // 同一密钥 counter 1 的 8 位值恰为 RFC 6238 SHA-1 向量 T=59 的 94287082
        // （T=59 → counter=1），且 6 位截断与其低 6 位一致，互相印证。
        let key = b"12345678901234567890";
        assert_eq!(hotp_sha1(key, 1, 8), "94287082");
        assert_eq!(hotp_sha1(key, 1, 6), "287082");
        assert_eq!(hotp_sha1(key, 0, 6).len(), 6);
    }

    #[test]
    fn verify_code_accepts_rfc4226_counter_and_window() {
        // TOTP counter = unix/30。取 unix=30*5=150 → counter 5 → 254676。
        assert!(verify_code(
            &data_encoding::BASE32_NOPAD.encode(b"12345678901234567890"),
            "254676",
            150
        ));
        // ±1 步（counter 4 与 6）也在窗口内。
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
        // 步长 30：counter 差 2 步 → 拒绝。
        assert!(!verify_code(sec, "338314", 150 + 2 * 30));
        // 错码 / 非数字 / 长度不符 / 空。
        assert!(!verify_code(sec, "000000", 150));
        assert!(!verify_code(sec, "abcabc", 150));
        assert!(!verify_code(sec, "12345", 150));
        assert!(!verify_code(sec, "", 150));
        // 非法 base32 密钥。
        assert!(!verify_code("not base32 !!", "254676", 150));
    }

    #[test]
    fn generate_secret_is_32_char_base32_and_unique() {
        let a = generate_secret();
        let b = generate_secret();
        assert_eq!(a.len(), 32);
        // base32 大写字母 + 数字 2-7；不含小写（`is_ascii_uppercase` 对数字为 false）。
        assert!(a
            .bytes()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
        assert_ne!(a, b);
        // 可被 base32 解码（即密钥自洽）。
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
        // 明文密码绝不进 URI。
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
