//! Agent single-instance guard: an active-library lock anchored on `state_dir`.
//!
//! Background (pinned down on the imac 2026-11-12): scheduled tasks and leftover test processes let 3
//! meshlet-agents coexist, kicking each other's handshakes for the same `device_id`, with the
//! `/dev/tcp` ESTABLISHED count to the server permanently at 0; the server's online verdict in turn
//! depends on the agent's self-reported heartbeat (§13.5, no independent online source), so the
//! stomping process count only exists on the machine and the server is entirely unaware. The mutual
//! exclusion must be done at the OS layer: **whoever starts first holds it, later arrivals exit with a
//! clear error** - better to fail startup than to fight the earlier instance over the same device identity.
//!
//! Mechanism (aligned with the [`meshlet_server`](../../../../apps/server/src/instance_lock.rs)
//! approach): at startup the agent takes an exclusive lock on `<state_dir>/agent.lock` and holds it until
//! exit ([`File::try_lock`], flock on unix, LockFileEx on windows - OS-level, and released automatically
//! by the OS if the process crashes). The same `state_dir` means the same ledger and the same device
//! identity, and only that is a conflict; different `state_dir`s (different devices) do not interfere -
//! this is deliberate.
//!
//! Known boundary (recorded honestly): the lock is advisory and only constrains meshlet-agent processes
//! that also go through this mechanism; two configurations sharing the same credential but writing
//! different `state_dir`s can get around it - that class is a configuration error, backstopped by the
//! server's device-identity verdict. The lock file only carries the lock, never any data.
//!
//! The fork window (root cause of the 2026-11-13 flake, confirmed both by an on-the-spot strace and a C
//! reproduction): flock hangs on the open file description (OFD), `fork()` copies the fd table (including
//! the lock-holding fd), and `O_CLOEXEC` only closes at a **successful** exec - a child sitting in the
//! window before exec keeps the lock alive past the holder's close (and even past the holder process's
//! exit). For this product the effect is a millisecond-scale window (the agent's ping/wg child processes
//! exec very quickly and restart intervals far exceed the window); for **tests** it is a real pitfall -
//! lock-semantics tests must live in separate integration-test binaries free of concurrent forks
//! (`tests/instance_lock_semantics.rs` / `tests/instance_lock_fork_window.rs`), and must not be moved back
//! into this file's `#[cfg(test)]` (in the library test binary, other unit tests fork real processes
//! concurrently - one round measured 1773 execve calls, and the microsecond "re-acquire after release"
//! window is occasionally straddled, with a ~5% chance of going red).

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// A held instance lock; dropping releases it (the handle closes and the OS returns the lock).
#[must_use = "the lock is released as soon as the guard is dropped"]
pub struct InstanceLock {
    holder: Option<File>,
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        // Taking and closing the handle releases the lock (the OS returns it); on a process crash the OS releases it the same way.
        drop(self.holder.take());
    }
}

/// This instance's lock-file path: `<state_dir>/agent.lock`.
pub fn lock_path(state_dir: &Path) -> PathBuf {
    state_dir.join("agent.lock")
}

/// Take the agent instance lock without blocking.
///
/// `Err(WouldBlock)` means the lock is held (most likely another meshlet-agent is running); any other
/// `Err` is the lock file itself failing to open - also a refusal: when we cannot prove no other instance
/// is running, better not to start (matching the server recovery guard's approach, see backup's `BackupError::Locked`).
pub fn try_acquire(state_dir: &Path) -> io::Result<InstanceLock> {
    // Startup runs before bootstrap creates the directory: the lock is the first thing the process puts down, so ensure the directory exists first.
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
