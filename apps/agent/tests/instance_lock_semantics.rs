//! 单实例锁的库级语义（双路互斥 / 跨 state_dir 不冲突 / 释放后可重拿）。
//!
//! 这组测试**必须住在独立集成测试二进制里**，不能搬回
//! `src/instance_lock.rs` 的 `#[cfg(test)] mod tests`——2026-11-13 flake
//! 根因（strace 现场取证 + C 机制复现双证实）：flock 挂在打开的文件描述
//! （OFD）上，`fork()` 复制整张 fd 表（含持锁 fd），`O_CLOEXEC` 到 exec
//! **成功**才关。库测试二进制里其它单测并发 fork 真进程（hostname / sh /
//! ip / wg / ping，strace 实测一轮 1773 次 execve），子进程 exec 前的
//! PATH 徒步窗口（一串 ENOENT，每次都不关）会让锁活过测试线程的
//! `drop(first)`=close——「释放后重拿」微秒级窗口被毫秒级 fork 窗口
//! 偶发跨越（实测 ~5%）。本二进制只有这几个测试、零并发 fork，竞态
//! 结构上不存在。
//!
//! 相关：机制级哨兵（fork 的 fd 副本让锁活过 close 直到 exec）在
//! `tests/instance_lock_fork_window.rs`（独立二进制，见其头注释）；真双
//! 进程互斥（真实 meshlet-agent 进程被拒/释放后可启动）在
//! `tests/instance_lock.rs`。

use std::path::{Path, PathBuf};

use meshlet_agent::instance_lock::{lock_path, try_acquire};

/// 每测试独立目录，避免并行测试之间互相踩锁。
fn scratch_state_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "meshlet-agent-instance-lock-{tag}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 双路互斥。flock / LockFileEx 的锁挂在**打开的文件描述或句柄**上，不是
/// 挂在进程上，所以两次独立 `open` 就是两个「进程」：第二路必须被 OS 拒绝，
/// 互斥不靠代码自觉。锁释放后再拿必须成功（句柄关闭即归还）。
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

/// 不同 `state_dir` 是不同设备身份：两路必须都能拿到锁（互斥只约束同设备）。
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
