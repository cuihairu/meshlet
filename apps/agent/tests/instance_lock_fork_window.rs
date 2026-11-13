//! 机制级哨兵：fork 的 fd 副本让 flock 活过持有者的 close，直到 exec。
//!
//! 这是 2026-11-13 instance_lock 单测 flake 的根因机制（strace 现场取证 +
//! C 复现双证实），落成可执行的回归证明：`fork()` 复制整张 fd 表（含
//! `O_CLOEXEC` 的持锁 fd），副本到 exec **成功**才关——窗口期内锁在内核
//! 眼里仍被占，哪怕持有者已经 close 了它。库测试二进制里其它单测并发 fork
//! 真进程时（hostname / sh / ip / wg / ping），「释放后立刻重拿」本来就不
//! 可靠——这正是锁语义测试必须住在无并发 fork 的独立二进制里的原因
//! （见 `tests/instance_lock_semantics.rs` 头注释）。
//!
//! 本文件**必须独占一个测试二进制**：哨兵自身的 fork 会复制本二进制里
//! 其它并发测试可能持有的锁 fd，混进 `instance_lock_semantics.rs` 会把
//! 那组「必须确定性绿」的测试重新变成概率红。

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
        // 子进程：故意停在 exec 前 3s——fd 表副本（含持锁 fd）还开着。
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
    // 父侧等到子进程确定处于 pre-exec 窗口内，再 close 唯一的父侧持锁 fd。
    // （窗口余量 ~2.9s：CI 极端负载下也不许把「窗口内必须拿不到」变成概率红。）
    std::thread::sleep(Duration::from_millis(100));
    drop(first);
    let during = try_acquire(&state_dir);
    assert!(
        during.is_err(),
        "while a pre-exec fd copy is alive, the lock must still be considered held"
    );
    // 子进程 exec /bin/true（CLOEXEC 关掉副本）并退出后，锁必须可拿。
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(status == 0, "child must exit cleanly (status {status})");
    let _released = try_acquire(&state_dir).expect("acquire succeeds after the child execs");
}
