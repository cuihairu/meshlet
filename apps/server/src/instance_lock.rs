//! 单实例守卫（§17.4）：活动库锁，让 `restore` 能识别「meshlet-server 在跑」。
//!
//! 背景（R-07 验收实录缺陷）：运行中恢复会把新库改名覆盖活动路径，而服务仍
//! 握着旧 inode——此后每次写入（包括一次 HTTP 201 的 token 铸造）都落进脱链
//! 文件，永不落盘，`systemctl` 全程 `active`。原先恢复前的 `BEGIN EXCLUSIVE`
//! 探测拦不住这个场景：WAL 下空闲服务不持写事务，探测照样成功。
//!
//! 机制：服务进程启动即对 `<database>.lock` 拿排他锁并持有到退出
//! （[`File::try_lock`]，unix 为 flock、windows 为 LockFileEx，OS 级、进程
//! 崩溃自动释放）；恢复命令在触碰任何文件**之前**尝试拿同一把锁，拿不到就
//! 整体拒绝——先停服务，再恢复。恢复自身拿锁到结束，恢复期间启动的服务会
//! 得到明确失败而不是半恢复状态。
//!
//! 已知边界（如实记录）：锁是 advisory，只约束同样走本机制的 meshlet 进程；
//! 外来进程直接持有 SQLite 连接不经过它——那一类仍由恢复前的
//! `BEGIN EXCLUSIVE` 兜底。锁文件只承载锁，不含任何数据。

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// 已持有的实例锁；Drop 即释放（关闭句柄，OS 归还锁）。
#[must_use = "the lock is released as soon as the guard is dropped"]
pub struct InstanceLock {
    holder: Option<File>,
}

impl InstanceLock {
    /// 无文件可锁（如 `:memory:` 库）时的空锁：跨进程互斥退化为不可检测，
    /// 与「内存库没有离线恢复场景」一致。
    fn none() -> Self {
        Self { holder: None }
    }
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        // 拿走并关闭句柄即释放锁（OS 归还）；进程崩溃时 OS 同样自动释放。
        drop(self.holder.take());
    }
}

/// 活动库对应的锁文件路径：`<database>.lock`。
pub fn lock_path(database: &Path) -> PathBuf {
    let mut name = database.as_os_str().to_os_string();
    name.push(".lock");
    PathBuf::from(name)
}

/// 非阻塞地拿活动库锁。
///
/// `Err` 表示锁被占（多半是 meshlet-server 在跑），或锁文件本身打不开——
/// 打不开同样拒绝：无法证明没有服务在跑时，宁可不恢复。
pub fn try_acquire(database: &Path) -> io::Result<InstanceLock> {
    let text = database.to_string_lossy();
    if database.as_os_str().is_empty() || text.contains(":memory:") {
        return Ok(InstanceLock::none());
    }
    let file = File::options()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path(database))?;
    file.try_lock()?;
    Ok(InstanceLock { holder: Some(file) })
}
