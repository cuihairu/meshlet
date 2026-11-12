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

#[cfg(test)]
mod tests {
    use super::*;

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
            io::ErrorKind::WouldBlock,
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
}
