//! Single-instance guard (§17.4): the active-database lock, letting `restore` detect that "meshlet-server is running".
//!
//! Background (an R-07 acceptance real-world defect): a mid-run restore renames the new database over the active path while the service still
//! holds the old inode — from then on every write (including the token minting of an HTTP 201) goes into an unlinked
//! file and never reaches disk, and `systemctl` stays `active` throughout. The `BEGIN EXCLUSIVE`
//! probe performed before the restore did not catch this scenario: under WAL an idle service holds no write transaction, so the probe succeeds.
//!
//! Mechanism: on startup the service process takes an exclusive lock on `<database>.lock` and holds it until exit
//! ([`File::try_lock`]: flock on unix, LockFileEx on windows — OS-level, auto-released on process
//! crash); the restore command attempts to take that same lock **before** touching any file, and refuses the whole operation when it cannot —
//! stop the service first, then restore. The restore holds the lock until it finishes, and a service started during the restore fails
//! explicitly rather than ending up half-restored.
//!
//! Known limits (recorded honestly): the lock is advisory and only binds meshlet processes that go through this mechanism;
//! foreign processes holding SQLite connections directly bypass it — that class is still covered by the pre-restore
//! `BEGIN EXCLUSIVE` fallback. The lock file carries the lock only, no data.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// A held instance lock; dropped when the guard is dropped (closing the handle, the OS returns the lock).
#[must_use = "the lock is released as soon as the guard is dropped"]
pub struct InstanceLock {
    holder: Option<File>,
}

impl InstanceLock {
    /// A null lock for when there is no file to lock (e.g. a `:memory:` database): cross-process mutual exclusion degrades to undetectable,
    /// consistent with "an in-memory database has no offline restore scenario".
    fn none() -> Self {
        Self { holder: None }
    }
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        // Taking and closing the handle releases the lock (the OS returns it); the OS also auto-releases on a process crash.
        drop(self.holder.take());
    }
}

/// Lock-file path for the active database: `<database>.lock`.
pub fn lock_path(database: &Path) -> PathBuf {
    let mut name = database.as_os_str().to_os_string();
    name.push(".lock");
    PathBuf::from(name)
}

/// Take the active-database lock without blocking.
///
/// `Err` means the lock is held (most likely meshlet-server is running) or the lock file itself cannot be opened —
/// unopenable is also a refusal: when nothing proves no service is running, prefer not restoring.
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
