//! 托盘退出密码保护（用户令 2026-11-20：退出不该人人可点）。
//!
//! 存储：`{state}/tray/exit-guard.json` = `{"version":1,"salt_hex":..,
//! "hash_hex":..}`，`hash = sha256(salt ‖ password)`（sha256+随机盐，明文
//! 密码永不落盘）。设置窗「常规」区设置/修改/清除；托盘菜单「退出」在
//! 已设密码时先弹 exit-guard 小窗验证，匹配才退出。
//!
//! 为什么不写 agent.toml：agent 对配置做严格解析，未知字段直接拒启
//! （2026-11-19 target_homes 先例）；且退出保护是纯 tray 侧语义，与
//! agent 无关。文件缺失/损坏一律按未设置放行——保护宁可失效，也不能
//! 把常驻托盘进程锁死。

use rand::RngCore;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// 记录文件名（放 `{state}/tray/`，与托盘语言镜像同目录）。
const GUARD_FILE: &str = "exit-guard.json";
/// 记录格式版本；改字段时递增，旧版记录按损坏处理（放行）。
const GUARD_VERSION: u32 = 1;
/// 设置/修改时的最短密码长度（清除不校验长度，只校验当前密码）。
const MIN_PASSWORD_LEN: usize = 4;
/// 盐长度（字节）。
const SALT_LEN: usize = 16;

/// 纯路径构造（可测）：`<state>/tray/exit-guard.json`。
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

/// sha256(salt ‖ password utf8)。
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

/// 常数时间字节数组比较（不靠时序泄漏匹配前缀长度）。
fn bytes_equal_const(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// 读取并校验记录：版本不符 / 盐或哈希长度不对 = None（按未设置放行）。
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

/// 校验当前密码：已有 guard 时 `current` 必须提供且匹配；没有 guard
/// （首次设置）直接放行。
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

/// 是否已设退出密码（文件缺失/损坏 = 未设置）。
pub(crate) fn guard_is_set() -> bool {
    load_from(&guard_path()).is_some()
}

/// 设置/修改退出密码；已设密码时必须先验当前密码。
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

/// 清除退出密码；已设密码时必须先验当前密码（否则人人可一键拆锁）。
pub(crate) fn clear_guard(current: Option<&str>) -> Result<(), String> {
    clear_guard_at(&guard_path(), current)
}

fn clear_guard_at(path: &Path, current: Option<&str>) -> Result<(), String> {
    verify_current(load_from(path).as_ref(), current)?;
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        // 没设过密码的清除按幂等成功。
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// 退出验证：未设置（或记录损坏）= 放行；已设置则按哈希比对。
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
        assert!(from_hex("abc").is_none()); // 奇数长度
        assert!(from_hex("zz").is_none()); // 非 hex
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
        // 未设置：验证放行，清除幂等成功。
        assert!(verify_quit_at(&path, "whatever"));
        assert!(clear_guard_at(&path, None).is_ok());

        // 首次设置无需当前密码；短密码拒收。
        assert!(set_guard_at(&path, None, "abc").is_err());
        set_guard_at(&path, None, "secret1").unwrap();
        assert!(load_from(&path).is_some());

        assert!(!verify_quit_at(&path, "wrong"));
        assert!(verify_quit_at(&path, "secret1"));

        // 已设后：改/清都必须带对当前密码。
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
        // 结构合法但字段长度不对：同样放行。
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

    // ── 05 收口批：权限失败 / 重开 / 明文不落盘不回显 ─────────────────────

    /// 权限失败：记录文件只读（set 的覆盖写被拒）+ 目录只读（clear 的
    /// unlink 被拒）时改密/清除都失败且原记录逐字节不动（保护不被静默
    /// 拆掉）；未设置状态下清除仍幂等成功；权限恢复后重试成功。
    /// 注：save_at 是对已有文件的就地覆盖写，目录只读拦不住它——文件位
    /// 才是 set 的权限闸；clear 的 unlink 走目录位。两条腿分开钉。
    #[cfg(unix)]
    #[test]
    fn readonly_dir_surfaces_errors_and_keeps_previous_guard() {
        use std::os::unix::fs::PermissionsExt;
        let state = temp_state("perm");
        let path = guard_path_from(state.to_str().unwrap());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        set_guard_at(&path, None, "secret1").unwrap();
        let before = std::fs::read(&path).unwrap();
        let tray_dir = path.parent().unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        std::fs::set_permissions(tray_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        // root 无视权限位（CI 容器场景）：探测到仍可写就还原跳过，不作断言。
        // 探测用 append 打开（非破坏性，不截断记录）。
        let probe = std::fs::OpenOptions::new().append(true).open(&path).is_ok();
        if probe {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            std::fs::set_permissions(tray_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            let _ = std::fs::remove_dir_all(&state);
            return;
        }
        // 改密（文件覆盖写）/清除（unlink）失败浮出，记录原样（不能因为
        // 写不进就把锁拆了或换掉）。
        assert!(set_guard_at(&path, Some("secret1"), "secret3").is_err());
        assert!(clear_guard_at(&path, Some("secret1")).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        // 未设置状态：清除幂等成功（缺文件的 NotFound 优先于目录权限错）。
        let empty_state = temp_state("perm-empty");
        let empty_path = guard_path_from(empty_state.to_str().unwrap());
        std::fs::create_dir_all(empty_path.parent().unwrap()).unwrap();
        std::fs::set_permissions(
            empty_path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        assert!(clear_guard_at(&empty_path, None).is_ok());
        std::fs::set_permissions(
            empty_path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();

        // 权限恢复后重试成功，且状态与预期一致（重试路径）。
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(tray_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        set_guard_at(&path, Some("secret1"), "secret3").unwrap();
        assert!(verify_quit_at(&path, "secret3"));
        assert!(!verify_quit_at(&path, "secret1"));
        let _ = std::fs::remove_dir_all(&state);
        let _ = std::fs::remove_dir_all(&empty_state);
    }

    /// 重开：设置后跨「进程重启」（重新从磁盘加载）仍生效；改密后旧密码
    /// 立即失效——状态只认磁盘记录，无内存缓存可漂移。
    #[test]
    fn guard_persists_across_reopen() {
        let state = temp_state("reopen");
        let path = guard_path_from(state.to_str().unwrap());
        set_guard_at(&path, None, "first-pw").unwrap();
        // 模拟重开：不借助任何既有内存状态，直接从文件重新加载。
        assert!(load_from(&path).is_some());
        assert!(verify_quit_at(&path, "first-pw"));
        set_guard_at(&path, Some("first-pw"), "second-pw").unwrap();
        assert!(load_from(&path).is_some());
        assert!(!verify_quit_at(&path, "first-pw"));
        assert!(verify_quit_at(&path, "second-pw"));
        let _ = std::fs::remove_dir_all(&state);
    }

    /// 明文密码不落盘、不进错误串（截图/诊断不回显密码的存储侧前提）：
    /// 磁盘只有 salt+hash 十六进制；各类失败文案不含尝试过的密码。
    #[test]
    fn plaintext_password_never_reaches_disk_or_errors() {
        let state = temp_state("plain");
        let path = guard_path_from(state.to_str().unwrap());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        set_guard_at(&path, None, "sEkret-pw").unwrap();
        let raw = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned();
        assert!(
            !raw.contains("sEkret"),
            "password bytes must not be on disk: {raw}"
        );
        assert!(!raw.contains("pw"), "no password fragment on disk: {raw}");

        // 失败文案：长度不足 / 当前密码缺失 / 当前密码错误，都不回显尝试值。
        let short = set_guard_at(&path, Some("sEkret-pw"), "ab").unwrap_err();
        assert!(!short.contains("ab") && !short.contains("sEkret"));
        let missing = set_guard_at(&path, None, "brand-new-pw").unwrap_err();
        assert!(!missing.contains("brand-new-pw"));
        let wrong = set_guard_at(&path, Some("wrong-guess"), "brand-new-pw").unwrap_err();
        assert!(!wrong.contains("wrong-guess") && !wrong.contains("brand-new-pw"));
        let wrong_clear = clear_guard_at(&path, Some("bad-attempt")).unwrap_err();
        assert!(!wrong_clear.contains("bad-attempt"));

        // 一串失败之后记录未被动过：原密码仍可验证（失败路径不写盘）。
        assert!(verify_quit_at(&path, "sEkret-pw"));
        let _ = std::fs::remove_dir_all(&state);
    }
}
