//! Tray quit password protection (user order 2026-11-20: quitting must not be callable by just anyone).
//!
//! Storage: `{state}/tray/exit-guard.json` = `{"version":1,"salt_hex":..,
//! "hash_hex":..}`, `hash = sha256(salt ‖ password)` (salted sha256; the plaintext password never hits
//! disk). Set/change/clear in the settings window's "General" section; the tray menu's "Quit" first opens
//! the exit-guard mini window to verify when a password is set, and only a match exits.
//!
//! Why not agent.toml: the agent parses configs strictly and refuses to start on unknown fields
//! (the 2026-11-19 target_homes precedent); quit protection is pure tray-side semantics, unrelated to the agent.
//! A missing/corrupt file always counts as unset and lets quit through — the guard may fail safe, but must never
//! lock the resident tray process.

use rand::RngCore;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Record file name (stored in `{state}/tray/`, same dir as the tray language mirror).
const GUARD_FILE: &str = "exit-guard.json";
/// Record format version; bump when fields change — older records are treated as corrupt (allow).
const GUARD_VERSION: u32 = 1;
/// Minimum password length when setting/changing (clearing skips the length check, only the current password is verified).
const MIN_PASSWORD_LEN: usize = 4;
/// Salt length in bytes.
const SALT_LEN: usize = 16;

/// Pure path construction (testable): `<state>/tray/exit-guard.json`.
fn guard_path_from(state_dir: &str) -> PathBuf {
    Path::new(state_dir).join("tray").join(GUARD_FILE)
}

fn guard_path() -> PathBuf {
    guard_path_from(&crate::config_io::meshlet_state_dir())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct GuardFile {
    version: u32,
    salt_hex: String,
    hash_hex: String,
}

/// sha256(salt ‖ password utf8).
fn hash_password(salt: &[u8], password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(password.as_bytes());
    hasher.finalize().into()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// Constant-time byte-array comparison (leaks no matching-prefix length via timing).
fn bytes_equal_const(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Load and validate the record: version mismatch / wrong salt or hash length = None (treated as unset, allow).
fn load_from(path: &Path) -> Option<GuardFile> {
    let text = std::fs::read_to_string(path).ok()?;
    let guard: GuardFile = serde_json::from_str(&text).ok()?;
    if guard.version != GUARD_VERSION {
        return None;
    }
    if from_hex(&guard.salt_hex)?.len() != SALT_LEN {
        return None;
    }
    if from_hex(&guard.hash_hex)?.len() != 32 {
        return None;
    }
    Some(guard)
}

fn save_at(path: &Path, password: &str) -> Result<(), String> {
    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    let hash = hash_password(&salt, password);
    let guard = GuardFile {
        version: GUARD_VERSION,
        salt_hex: to_hex(&salt),
        hash_hex: to_hex(&hash),
    };
    let body = serde_json::to_string(&guard).map_err(|e| e.to_string())?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, body).map_err(|e| e.to_string())
}

/// Verify the current password: with an existing guard, `current` must be provided and match; without one
/// (first-time setup) it passes directly.
fn verify_current(guard: Option<&GuardFile>, current: Option<&str>) -> Result<(), String> {
    let Some(guard) = guard else {
        return Ok(());
    };
    let Some(current) = current else {
        return Err("current password required".into());
    };
    let salt = from_hex(&guard.salt_hex).ok_or("corrupt guard file")?;
    let expected = from_hex(&guard.hash_hex).ok_or("corrupt guard file")?;
    if bytes_equal_const(&hash_password(&salt, current), &expected) {
        Ok(())
    } else {
        Err("wrong current password".into())
    }
}

/// Whether a quit password is set (missing/corrupt file = not set).
pub(crate) fn guard_is_set() -> bool {
    load_from(&guard_path()).is_some()
}

/// Set/change the quit password; if one is already set, the current password must be verified first.
pub(crate) fn set_guard(current: Option<&str>, new_password: &str) -> Result<(), String> {
    set_guard_at(&guard_path(), current, new_password)
}

fn set_guard_at(path: &Path, current: Option<&str>, new_password: &str) -> Result<(), String> {
    if new_password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        ));
    }
    verify_current(load_from(path).as_ref(), current)?;
    save_at(path, new_password)
}

/// Clear the quit password; if one is set, the current password must be verified first (or anyone could strip the lock in one click).
pub(crate) fn clear_guard(current: Option<&str>) -> Result<(), String> {
    clear_guard_at(&guard_path(), current)
}

fn clear_guard_at(path: &Path, current: Option<&str>) -> Result<(), String> {
    verify_current(load_from(path).as_ref(), current)?;
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        // Clearing when no password was ever set succeeds idempotently.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Quit verification: not set (or corrupt record) = allow; otherwise compare by hash.
pub(crate) fn verify_quit(password: &str) -> bool {
    verify_quit_at(&guard_path(), password)
}

fn verify_quit_at(path: &Path, password: &str) -> bool {
    let Some(guard) = load_from(path) else {
        return true;
    };
    let Some(salt) = from_hex(&guard.salt_hex) else {
        return true;
    };
    let Some(expected) = from_hex(&guard.hash_hex) else {
        return true;
    };
    bytes_equal_const(&hash_password(&salt, password), &expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_state(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "meshlet-exit-guard-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn guard_path_matches_state_tray_convention() {
        let got = guard_path_from(r"C:\Users\bob\AppData\Local\meshlet\state");
        let text = got.to_string_lossy().replace('\\', "/");
        assert!(text.ends_with("/tray/exit-guard.json"));
    }

    #[test]
    fn hex_roundtrip_and_rejects_bad_input() {
        let bytes = [0u8, 1, 0x0f, 0xa5, 0xff];
        let hexed = to_hex(&bytes);
        assert_eq!(from_hex(&hexed).unwrap(), bytes);
        assert!(from_hex("abc").is_none()); // odd length
        assert!(from_hex("zz").is_none()); // not hex
        assert_eq!(from_hex("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn hash_is_salted_and_deterministic_per_salt() {
        let a = hash_password(&[1u8; SALT_LEN], "same-password");
        let b = hash_password(&[2u8; SALT_LEN], "same-password");
        assert_ne!(a, b, "same password under different salts must differ");
        assert_eq!(
            hash_password(&[1u8; SALT_LEN], "same-password"),
            a,
            "same salt+password must be reproducible"
        );
    }

    #[test]
    fn const_compare_covers_equal_diff_and_length_mismatch() {
        assert!(bytes_equal_const(&[1, 2, 3], &[1, 2, 3]));
        assert!(!bytes_equal_const(&[1, 2, 3], &[1, 2, 4]));
        assert!(!bytes_equal_const(&[1, 2], &[1, 2, 3]));
        assert!(bytes_equal_const(&[], &[]));
    }

    #[test]
    fn set_verify_clear_lifecycle_requires_current_password() {
        let state = temp_state("life");
        let path = guard_path_from(state.to_str().unwrap());
        // Not set: verification passes, clearing succeeds idempotently.
        assert!(verify_quit_at(&path, "whatever"));
        assert!(clear_guard_at(&path, None).is_ok());

        // First-time setup needs no current password; short passwords are rejected.
        assert!(set_guard_at(&path, None, "abc").is_err());
        set_guard_at(&path, None, "secret1").unwrap();
        assert!(load_from(&path).is_some());

        assert!(!verify_quit_at(&path, "wrong"));
        assert!(verify_quit_at(&path, "secret1"));

        // Once set: changing/clearing both require the correct current password.
        assert!(set_guard_at(&path, None, "secret2").is_err());
        assert!(set_guard_at(&path, Some("bad"), "secret2").is_err());
        set_guard_at(&path, Some("secret1"), "secret2").unwrap();
        assert!(!verify_quit_at(&path, "secret1"));
        assert!(verify_quit_at(&path, "secret2"));

        assert!(clear_guard_at(&path, Some("secret2")).is_ok());
        assert!(load_from(&path).is_none());
        assert!(verify_quit_at(&path, "anything"));
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn corrupt_guard_file_never_locks_quit() {
        let state = temp_state("corrupt");
        let path = guard_path_from(state.to_str().unwrap());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{not json").unwrap();
        assert!(load_from(&path).is_none());
        assert!(
            verify_quit_at(&path, "anything"),
            "corrupt record must allow quit"
        );
        // Structurally valid but wrong field lengths: also allowed through.
        std::fs::write(&path, r#"{"version":1,"salt_hex":"aabb","hash_hex":"cc"}"#).unwrap();
        assert!(verify_quit_at(&path, "anything"));
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn old_version_guard_file_is_ignored() {
        let state = temp_state("version");
        let path = guard_path_from(state.to_str().unwrap());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, r#"{"version":0,"salt_hex":"00","hash_hex":"00"}"#).unwrap();
        assert!(verify_quit_at(&path, "anything"));
        let _ = std::fs::remove_dir_all(&state);
    }
}
