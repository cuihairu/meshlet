//! Library-level semantics of the single-instance lock (two-way mutual exclusion / no conflict across state_dirs / re-acquire after release).
//!
//! These tests **must live in their own integration-test binary**, they cannot move back
//! into `src/instance_lock.rs`'s `#[cfg(test)] mod tests`. Root cause of the 2026-11-13
//! flake (strace forensics + a C mechanism repro, doubly confirmed): flock attaches to the
//! open file description (OFD), `fork()` copies the whole fd table (lock-holding fd included),
//! and `O_CLOEXEC` only closes on exec **success**. Other unit tests in the lib binary fork
//! real processes concurrently (hostname / sh / ip / wg / ping — one strace round counted 1773
//! execve); the child's PATH walk before exec (a run of ENOENTs, none closing the fd) lets the
//! lock outlive the test thread's `drop(first)`=close — the microsecond "re-acquire after
//! release" window gets occasionally crossed by a millisecond fork window (~5% observed).
//! This binary has only these tests and zero concurrent forks, so the race is structurally absent.
//!
//! Related: the mechanism-level sentinel (a fork's fd copy keeps the lock alive past close
//! until exec) lives in `tests/instance_lock_fork_window.rs` (its own binary, see its header
//! comment); true two-process mutual exclusion (a real meshlet-agent process rejected, start
//! allowed after release) lives in `tests/instance_lock.rs`.

use std::path::{Path, PathBuf};

use meshlet_agent::instance_lock::{lock_path, try_acquire};

/// A per-test directory, so parallel tests do not trample each other's locks.
fn scratch_state_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "meshlet-agent-instance-lock-{tag}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Two-way mutual exclusion. flock / LockFileEx locks attach to the **open file description
/// or handle**, not to the process, so two independent `open`s are two "processes": the second
/// must be rejected by the OS — mutual exclusion does not rely on code being polite. Re-acquiring after release must succeed (closing the handle hands it back).
#[test]
fn second_open_of_the_same_state_dir_is_rejected() {
    let state_dir = scratch_state_dir("mutex");
    let first = try_acquire(&state_dir).expect("first acquire succeeds");
    let Err(err) = try_acquire(&state_dir) else {
        panic!("second acquire while the first holder is alive must be rejected");
    };
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::WouldBlock,
        "rejection must be the lock being held, not another io failure: {err}"
    );
    drop(first);
    let _released = try_acquire(&state_dir).expect("acquire succeeds again after release");
}

/// Distinct `state_dir`s are distinct device identities: both acquires must succeed (mutual exclusion only binds the same device).
#[test]
fn distinct_state_dirs_do_not_conflict() {
    let root = scratch_state_dir("distinct");
    let a = root.join("device-a");
    let b = root.join("device-b");
    let _first = try_acquire(&a).expect("device-a acquires");
    let _second = try_acquire(&b).expect("device-b acquires while device-a holds its own");
}

#[test]
fn lock_path_lives_inside_the_state_dir() {
    assert_eq!(
        lock_path(Path::new("/var/lib/meshlet")),
        PathBuf::from("/var/lib/meshlet/agent.lock")
    );
}
