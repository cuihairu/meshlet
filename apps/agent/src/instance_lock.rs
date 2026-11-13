//! Agent 单实例守卫：`state_dir` 锚定的活动库锁。
//!
//! 背景（2026-11-12 imac 实锤）：计划任务与残留测试进程让 3 个 meshlet-agent
//! 并存，互相踢掉同一个 `device_id` 的握手，`/dev/tcp` 到 server 的 ESTABLISHED
//! 恒为 0；服务端那侧的在线判定又依赖 agent 自报的心跳（§13.5 无独立在线源），
//! 互踩的进程数只长在本机，server 完全无感知。互斥必须在 OS 层做：**谁先启动
//! 谁持有，后来者明确报错退出**——宁可启动失败，也不与先到实例抢同一个设备身份。
//!
//! 机制（对齐 [`meshlet_server`](../../../../apps/server/src/instance_lock.rs)
//! 的口径）：agent 启动即对 `<state_dir>/agent.lock` 拿排他锁并持有到退出
//! （[`File::try_lock`]，unix 为 flock、windows 为 LockFileEx，OS 级、进程
//! 崩溃时由 OS 自动释放）。同 `state_dir` 即同一账本、同一设备身份，才是冲突；
//! 不同 `state_dir`（不同设备）互不干涉——这是刻意的。
//!
//! 已知边界（如实记录）：锁是 advisory，只约束同样走本机制的 meshlet-agent
//! 进程；拿同一凭证但写不同 `state_dir` 的两份配置绕得过它——那一类属于配置
//! 错误，由服务端的设备身份判定兜底。锁文件只承载锁，不含任何数据。
//!
//! fork 窗口（2026-11-13 flake 根因，strace 现场 + C 复现双证实）：flock 挂
//! 在打开的文件描述（OFD）上，`fork()` 复制 fd 表（含持锁 fd），`O_CLOEXEC`
//! 到 exec **成功**才关——子进程停在 exec 前的窗口里，锁活过持有者的 close
//! （乃至持有进程的退出）。对本产品影响为毫秒级窗口（agent 的 ping/wg 子进程
//! exec 极快、重启间隔远大于窗口）；对**测试**是实打实的坑——锁语义测试必须
//! 住在无并发 fork 的独立集成测试二进制
//! （`tests/instance_lock_semantics.rs` / `tests/instance_lock_fork_window.rs`），
//! 不能搬回本文件的 `#[cfg(test)]`（库测试二进制里其它单测并发 fork 真进程，
//! 实测一轮 1773 次 execve，「释放后重拿」微秒窗口被偶发跨越，~5% 概率红）。

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// 已持有的实例锁；Drop 即释放（关闭句柄，OS 归还锁）。
#[must_use = "the lock is released as soon as the guard is dropped"]
pub struct InstanceLock {
    holder: Option<File>,
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        // 拿走并关闭句柄即释放锁（OS 归还）；进程崩溃时 OS 同样自动释放。
        drop(self.holder.take());
    }
}

/// 本实例的锁文件路径：`<state_dir>/agent.lock`。
pub fn lock_path(state_dir: &Path) -> PathBuf {
    state_dir.join("agent.lock")
}

/// 非阻塞地拿 agent 实例锁。
///
/// `Err(WouldBlock)` 表示锁被占（多半是另一个 meshlet-agent 在跑）；其余
/// `Err` 是锁文件本身打不开——同样拒绝：无法证明没有别的实例在跑时，宁可不
/// 启动（与 server 恢复守卫的口径一致，见 backup 的 `BackupError::Locked`）。
pub fn try_acquire(state_dir: &Path) -> io::Result<InstanceLock> {
    // 启动早于 bootstrap 的目录创建：锁是进程落下的第一个东西，先保证目录在。
    std::fs::create_dir_all(state_dir)?;
    let file = File::options()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path(state_dir))?;
    file.try_lock()?;
    Ok(InstanceLock { holder: Some(file) })
}
