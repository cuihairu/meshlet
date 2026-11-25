//! Mechanism-level sentinel: a fork's fd copy keeps flock alive past the holder's close, until exec.
//!
//! This is the root-cause mechanism behind the 2026-11-13 instance_lock unit-test flake
//! (strace forensics + a C repro, doubly confirmed), turned into an executable regression:
//! `fork()` copies the whole fd table (including the `O_CLOEXEC` lock-holding fd); the copy
//! only closes when exec **succeeds** — during that window the kernel still sees the lock as held
//! even though the holder already closed it. When other unit tests in the lib test binary fork real
//! processes concurrently (hostname / sh / ip / wg / ping), "re-acquire right after release" is
//! inherently unreliable — exactly why the lock semantics tests must live in a separate binary with no concurrent forks (see the header of `tests/instance_lock_semantics.rs`).
//!
//! This file **must own its own test binary**: the sentinel's own fork would copy lock fds held
//! by other concurrent tests in the same binary; mixed into `instance_lock_semantics.rs`, it
//! would turn that group of "must be deterministically green" tests probabilistically red again.

#![cfg(target_os = "linux")]

use std::time::Duration;

use meshlet_agent::instance_lock::try_acquire;

#[test]
fn forked_fd_copy_keeps_the_lock_alive_until_exec() {
    let state_dir = std::env::temp_dir().join(format!(
        "meshlet-agent-instance-lock-fork-window-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&state_dir).unwrap();
    let first = try_acquire(&state_dir).expect("first acquire");

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        // Child: deliberately stall 3s before exec — the fd table copy (lock fd included) is still open.
        std::thread::sleep(Duration::from_secs(3));
        unsafe {
            libc::execl(
                c"/bin/true".as_ptr(),
                c"true".as_ptr(),
                std::ptr::null::<libc::c_char>(),
            )
        };
        unsafe { libc::_exit(127) };
    }
    // Parent: wait until the child is surely inside the pre-exec window, then close the parent's
    // only lock fd. (Margin ~2.9s: under extreme CI load this must not turn probabilistically red.)
    std::thread::sleep(Duration::from_millis(100));
    drop(first);
    let during = try_acquire(&state_dir);
    assert!(
        during.is_err(),
        "while a pre-exec fd copy is alive, the lock must still be considered held"
    );
    // After the child execs /bin/true (CLOEXEC closes the copy) and exits, the lock must be acquirable.
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(status == 0, "child must exit cleanly (status {status})");
    let _released = try_acquire(&state_dir).expect("acquire succeeds after the child execs");
}
