//! Mesh state persistence and startup rebuild ([archive §17.3](../../docs/review/chatgpt-2026-10-13.md))
//! and consistent backup/restore ([archive §17.4](../../docs/review/chatgpt-2026-10-13.md)).
//!
//! Request path: `MeshState` remains the single source of truth (`service.rs`);
//! after each change completes inside the lock, the handler mirrors the **new
//! rows** into SQLite (this module's `insert_*`/`update_*`/`delete_*`). A
//! persistence failure → the request gets a 500 ("no commit to DB, no
//! pass-through", the same discipline as the audit's "no trail, no
//! pass-through"); the write order between memory and DB is serialized by the
//! `AppState::persist` mutex (change + persist in the same critical section),
//! so no concurrent interleaving can let an old row overwrite a new one.
//!
//! Startup path ([`load`]):
//! 1. Load networks/devices/lan_routes/invitations/config_revisions/`mesh_meta`
//!    (route_seq) from the DB and rebuild `MeshState` — IPAM keeps every
//!    allocated address (including revoked devices), and revision sequences and
//!    hashes are replayed verbatim;
//! 2. **Interrupt convergence (§10.3)**: a revision stuck at `applying` has an
//!    unknowable result, so it always lands as `failed` plus interrupt
//!    diagnostics, written back to the DB (never pretending to have succeeded);
//!    `rollback_pending` stays retryable; already `applied` revisions do not
//!    replay the backend;
//! 3. presence evidence timestamps are restored to their original DB values —
//!    a restart **never fabricates** being online (§12.4): the judgment happens
//!    at read time, and without fresh evidence the state is
//!    `offline`/`tunnel_only`.
//!
//! Backup/restore (§17.4): [`backup_to`] uses `VACUUM INTO` to produce a single
//! self-consistent local snapshot (consistency is guaranteed by the SQLite
//! snapshot itself); [`restore_from_backup`] validates → renames atomically →
//! leaves a trail → reuses [`load`] to rebuild, with semantics identical to a
//! normal startup.
//!
//! Client (agent) side restart recovery lands together with the dataplane
//! backend (pull the desired config and reapply it); this module first pins
//! down "a server restart does not lose desired state".

use super::shared::MeshStatePersistedView;
use super::tasks::load;
use sqlx::sqlite::SqliteConnection;
use sqlx::{ConnectOptions, Executor, SqlitePool};
use std::path::{Path, PathBuf};
use std::str::FromStr as _;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Consistent backup and restore (archive §17.4)
// ---------------------------------------------------------------------------

const LEGACY_REQUIRED_TABLES: [&str; 16] = [
    "agent_tokens",
    "alias_mappings",
    "audit_events",
    "bootstrap_tokens",
    "config_revisions",
    "device_keys",
    "device_registrations",
    "devices",
    "diagnostics_runs",
    "invitations",
    "lan_routes",
    "mesh_meta",
    "networks",
    "sessions",
    "users",
    "api_tokens",
];

/// Backup/restore error (§17.4: reject explicitly, never leave a half-restored state).
#[derive(Debug)]
pub enum BackupError {
    /// The backup target file already exists (existing backups are never overwritten).
    TargetExists(String),
    /// The source is not a database or its content is corrupt (quick_check/open failure).
    Corrupt(String),
    /// The database is valid but missing tables (incomplete backup, restore refused).
    IncompleteSchema {
        missing: Vec<String>,
    },
    /// The live database is in use (meshlet-server must be stopped before restore).
    Locked(String),
    Io(std::io::Error),
    Db(sqlx::Error),
}

impl std::fmt::Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TargetExists(path) => write!(f, "backup target already exists: {path}"),
            Self::Corrupt(why) => write!(f, "backup file is not a usable database: {why}"),
            Self::IncompleteSchema { missing } => {
                write!(
                    f,
                    "backup is missing required tables: {}",
                    missing.join(", ")
                )
            }
            Self::Locked(why) => {
                write!(
                    f,
                    "database is locked ({why}); stop meshlet-server before restore"
                )
            }
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Db(e) => write!(f, "db: {e}"),
        }
    }
}

impl std::error::Error for BackupError {}

impl From<sqlx::Error> for BackupError {
    fn from(e: sqlx::Error) -> Self {
        let text = e.to_string();
        // SQLite "database is locked / busy" → advise stopping the server before restoring.
        if text.contains("locked") || text.contains("busy") {
            return Self::Locked(text);
        }
        Self::Db(e)
    }
}

impl From<std::io::Error> for BackupError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Report of one backup (path + byte count + a content summary **read back from
/// the backup file itself** — which incidentally proves the backup file opens
/// standalone and has a complete schema).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupReport {
    pub path: String,
    pub bytes: u64,
    pub view: MeshStatePersistedView,
}

/// Validate a backup file: open it standalone read-only + `quick_check` + all
/// required tables present, returning the content summary.
///
/// Any step that fails is rejected as [`BackupError::Corrupt`] /
/// [`BackupError::IncompleteSchema`] — a corrupt or incomplete backup never
/// enters the restore flow. The read-only connection must be released by RAII
/// drop (a pool-style close releases SQLite file handles lazily, which on
/// Windows would block the restore copy).
pub async fn validate_backup(path: &Path) -> Result<MeshStatePersistedView, BackupError> {
    let mut connection =
        sqlx::sqlite::SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))?
            .read_only(true)
            .connect()
            .await
            .map_err(|e| BackupError::Corrupt(e.to_string()))?;

    // Move the validation result out of the connection's scope first, then drop
    // it explicitly, so no file handle is left on the backup or staging file
    // before `copy`/`rename`.
    let result = validate_on(&mut connection).await.map_err(|e| match e {
        e @ BackupError::IncompleteSchema { .. } => e,
        e => BackupError::Corrupt(e.to_string()),
    });
    drop(connection);
    result
}

async fn validate_on(pool: &mut SqliteConnection) -> Result<MeshStatePersistedView, BackupError> {
    let check: Vec<String> = sqlx::query_scalar("PRAGMA quick_check")
        .fetch_all(&mut *pool)
        .await?;
    if check.iter().any(|r| r != "ok") {
        return Err(BackupError::Corrupt(check.join("; ")));
    }

    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
         AND name NOT LIKE '_sqlx_%'",
    )
    .fetch_all(&mut *pool)
    .await?;
    let base_missing: Vec<String> = LEGACY_REQUIRED_TABLES
        .iter()
        .filter(|t| !tables.iter().any(|have| have == **t))
        .map(|t| t.to_string())
        .collect();
    if !base_missing.is_empty() {
        return Err(BackupError::IncompleteSchema {
            missing: base_missing,
        });
    }
    let has_migration_history: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='_sqlx_migrations')",
    )
    .fetch_one(&mut *pool)
    .await?;
    if !has_migration_history {
        return Err(BackupError::IncompleteSchema {
            missing: vec!["_sqlx_migrations".into()],
        });
    }
    let latest: Option<i64> =
        sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations WHERE success=1")
            .fetch_one(&mut *pool)
            .await?;
    let mut required = LEGACY_REQUIRED_TABLES.to_vec();
    if latest.is_some_and(|v| v >= 9) {
        required.extend(["hub_deployments", "device_apply_receipts"]);
    }
    if latest.is_some_and(|v| v >= 10) {
        required.extend(["segments", "segment_grants"]);
    }
    let missing: Vec<String> = required
        .iter()
        .filter(|t| !tables.iter().any(|have| have == *t))
        .map(|t| t.to_string())
        .collect();
    if !missing.is_empty() {
        return Err(BackupError::IncompleteSchema { missing });
    }

    let has_segments = tables.iter().any(|table| table == "segments");
    let has_publish = tables.iter().any(|table| table == "publish_forwards");
    Ok(MeshStatePersistedView {
        networks: count_on(&mut *pool, "networks").await?,
        devices: count_on(&mut *pool, "devices").await?,
        registrations: count_on(&mut *pool, "device_registrations").await?,
        routes: count_on(&mut *pool, "lan_routes").await?,
        aliases: count_on(&mut *pool, "alias_mappings").await?,
        segments: if has_segments {
            count_on(&mut *pool, "segments").await?
        } else {
            0
        },
        segment_grants: if has_segments {
            count_on(&mut *pool, "segment_grants").await?
        } else {
            0
        },
        invites: count_on(&mut *pool, "invitations").await?,
        publishes: if has_publish {
            count_on(&mut *pool, "publish_forwards").await?
                + count_on(&mut *pool, "publish_http_routes").await?
                + count_on(&mut *pool, "publish_probes").await?
                + count_on(&mut *pool, "publish_dns_records").await?
        } else {
            0
        },
        revisions: count_on(&mut *pool, "config_revisions").await?,
    })
}

async fn count_on<'e, E>(pool: E, table: &str) -> Result<usize, BackupError>
where
    E: Executor<'e, Database = sqlx::Sqlite> + 'e,
{
    // Callers use fixed schema table names, never user input.
    let n: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(pool)
        .await?;
    Ok(usize::try_from(n).unwrap_or(0))
}

/// Produce a unique filename under the backup directory (millisecond timestamp; sorting equals time order).
fn backup_filename(now: chrono::DateTime<chrono::Utc>) -> String {
    format!("meshlet-backup-{}.db", now.format("%Y%m%dT%H%M%S%3fZ"))
}

/// Write a consistent backup into `dir` (SQLite `VACUUM INTO` online backup
/// semantics).
///
/// - The backup is a **single self-consistent snapshot** (guaranteed by the
///   SQLite read transaction under WAL) and can be opened standalone;
/// - Refuse if the target file already exists (never silently overwrite an
///   existing backup);
/// - The backup file contains sensitive material such as password hashes, so
///   permissions are tightened (0600) as soon as it hits disk.
///
/// Consistency comes from the SQLite snapshot itself and is independent of the
/// `AppState::persist` mutex.
pub async fn backup_to(pool: &SqlitePool, dir: &Path) -> Result<BackupReport, BackupError> {
    tokio::fs::create_dir_all(dir).await?;
    let path = dir.join(backup_filename(chrono::Utc::now()));
    if path.exists() {
        return Err(BackupError::TargetExists(path.display().to_string()));
    }
    sqlx::query("VACUUM INTO ?")
        .bind(path.display().to_string())
        .execute(pool)
        .await?;
    restrict_permissions(&path);
    let bytes = tokio::fs::metadata(&path).await?.len();
    let view = validate_backup(&path).await?;
    Ok(BackupReport {
        path: path.display().to_string(),
        bytes,
        view,
    })
}

/// Tighten permissions as soon as the backup lands on disk (unix); other platforms keep the system default.
fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Who the restored database should belong to.
///
/// The `restore` subcommand usually runs as root while the service runs as an
/// unprivileged user (the shipped unit sets `User=meshlet`); without fixing
/// ownership, the restored database is owned by root, and the service fails at
/// startup with `unable to open database file` and crash-loops. Priority: the
/// existing live database being replaced (in-place restore, the common case),
/// then the data directory itself (the first restore into an empty directory).
#[cfg(unix)]
pub(super) fn resolve_restored_database_owner(
    database: &Path,
    prior_owner: Option<(u32, u32)>,
) -> Option<(u32, u32)> {
    use std::os::unix::fs::MetadataExt as _;
    prior_owner.or_else(|| {
        database
            .parent()
            .and_then(|dir| dir.metadata().ok())
            .map(|m| (m.uid(), m.gid()))
    })
}

/// Set the restored database back to the service user's ownership. This must be
/// called **after** the rename (before it, the file being read is still the old
/// database); when not running as root, chown necessarily fails with EPERM, and
/// the file already belongs to the current user, so it is ignored.
#[cfg(unix)]
fn apply_restored_database_owner(database: &Path, prior_owner: Option<(u32, u32)>) {
    if let Some((uid, gid)) = resolve_restored_database_owner(database, prior_owner) {
        let _ = std::os::unix::fs::chown(database, Some(uid), Some(gid));
    }
}

/// Back up once and leave a trail (the `system.backup` audit event). Shared by
/// the endpoint (actor = the operator) and the scheduled job (actor = None);
/// an audit failure means the backup fails (the audit lives in the same database
/// as the business data, §16.5).
pub async fn backup_once(
    pool: &SqlitePool,
    dir: &Path,
    actor: Option<&str>,
) -> Result<BackupReport, BackupError> {
    let report = backup_to(pool, dir).await?;
    crate::audit::AuditStore::new(pool.clone())
        .record(
            actor,
            "system.backup",
            "server",
            Some(&report.path),
            Some(serde_json::json!({
                "bytes": report.bytes,
                "networks": report.view.networks,
                "devices": report.view.devices,
                "routes": report.view.routes,
                "invites": report.view.invites,
                "revisions": report.view.revisions,
            })),
        )
        .await?;
    Ok(report)
}

/// Report of one restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    pub source: String,
    pub database: String,
    pub summary: MeshStatePersistedView,
    /// Revisions converged by §10.3 interrupt handling (applying → failed), as (network_id, revision).
    pub interrupted: Vec<(String, u64)>,
}

/// Restore the live database from a backup file (archive §17.4).
///
/// Flow (any step that fails leaves the live database untouched — **never leave
/// a half-restored state**):
/// 1. Instance lock ([`crate::instance_lock`]): refuse outright if
///    meshlet-server is running — under WAL an idle service holds no write
///    transaction, so step 4's `BEGIN EXCLUSIVE` cannot stop the data-loss path
///    where the old inode keeps accepting writes after the rename (a real case
///    from the 2026-10-24 acceptance run);
/// 2. Validate the backup ([`validate_backup`]: standalone open + quick_check +
///    required tables present);
/// 3. Refuse a backup with a sidecar non-empty WAL (copying only the main file
///    would silently lose committed transactions);
/// 4. The live database must be exclusively lockable (otherwise advise stopping
///    meshlet-server first; foreign SQLite connections beyond the advisory lock
///    are caught by this step);
/// 5. Backup → temp file → revalidate → atomic rename; clear the stale
///    `-wal`/`-shm` before replacing;
/// 6. Open the restored database and leave a `system.restore` audit event;
/// 7. Reuse §17.3 [`load`] to rebuild + converge (applying → failed,
///    rollback_pending kept, applied not replayed — exactly the same path as a
///    normal startup, no weaker than today).
pub async fn restore_from_backup(
    backup: &Path,
    database: &Path,
    thresholds: meshlet_domain::PresenceThresholds,
) -> Result<RestoreReport, BackupError> {
    // Instance lock guard: refuse both when it cannot be acquired (the server is
    // running) and when it cannot be opened (we cannot prove no server is
    // running). The lock is held until the function returns, so a server started
    // during the restore gets a clear failure instead of a half-restore.
    let _instance_guard = match crate::instance_lock::try_acquire(database) {
        Ok(lock) => lock,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            return Err(BackupError::Locked(format!(
                "lock {} is held (meshlet-server is running); stop meshlet-server before restore",
                crate::instance_lock::lock_path(database).display(),
            )));
        }
        Err(error) => {
            return Err(BackupError::Locked(format!(
                "cannot verify the live database is unused ({}: {error}); stop meshlet-server before restore",
                crate::instance_lock::lock_path(database).display(),
            )));
        }
    };
    let view = validate_backup(backup).await?;

    // The backup carries a sidecar **non-empty** WAL (someone wrote to the
    // backup file and did not checkpoint) — copying only the main file would
    // silently lose committed transactions, so refuse explicitly: re-take the
    // backup or checkpoint first. A zero-byte WAL (after a TRUNCATE checkpoint)
    // contains no frames and is harmless to let through.
    let wal = PathBuf::from(format!("{}-wal", backup.display()));
    if wal.metadata().map(|m| m.len() > 0).unwrap_or(false) {
        return Err(BackupError::Corrupt(
            "backup has an unsettled write-ahead log (backup-wal has frames); re-take the backup before restoring"
                .into(),
        ));
    }

    // If the live database exists, require that it can be exclusively locked
    // (best-effort guard: with the server running, ordinary writes are most
    // likely visible immediately under WAL).
    if database.exists() {
        let options = sqlx::sqlite::SqliteConnectOptions::from_str(&format!(
            "sqlite:{}",
            database.display()
        ))?
        .create_if_missing(false);
        let mut connection = options.connect().await?;
        match sqlx::query("BEGIN EXCLUSIVE")
            .execute(&mut connection)
            .await
        {
            Ok(_) => {
                let _ = sqlx::query("COMMIT").execute(&mut connection).await;
            }
            Err(error) => return Err(BackupError::from(error)),
        }
        drop(connection);
    }

    // Copy to a temp file and revalidate (a corrupt copy is refused too), then
    // rename atomically. First note the existing live database's ownership: the
    // service runs as a dedicated user while restore usually runs as root.
    #[cfg(unix)]
    let prior_owner = database.metadata().ok().map(|m| {
        use std::os::unix::fs::MetadataExt as _;
        (m.uid(), m.gid())
    });

    let tmp = database.with_extension("restore-tmp");
    let _ = tokio::fs::remove_file(&tmp).await;
    copy_with_windows_busy_retry(backup, &tmp).await?;
    restrict_permissions(&tmp);
    validate_backup(&tmp).await?;

    // Upgrade and validate in staging; a failed migration must not replace the live DB.
    let pool = crate::store::connect(&format!("sqlite:{}", tmp.display())).await?;
    crate::audit::AuditStore::new(pool.clone())
        .record(
            None,
            "system.restore",
            "server",
            Some(&database.display().to_string()),
            Some(serde_json::json!({
                "source": backup.display().to_string(),
                "networks": view.networks,
                "devices": view.devices,
                "routes": view.routes,
                "invites": view.invites,
                "revisions": view.revisions,
            })),
        )
        .await?;
    let boot = load(&pool, thresholds).await?;
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&pool)
        .await?;
    pool.close().await;
    validate_backup(&tmp).await?;
    // Clear two kinds of sidecar files before the rename: the existing live
    // database's `-wal`/`-shm` (belonging to the old database) and the staging
    // file's own — leftovers after the pool closes are dangling garbage in the
    // database.
    for base in [tmp.as_path(), database] {
        for suffix in ["-wal", "-shm"] {
            let _ =
                tokio::fs::remove_file(PathBuf::from(format!("{}{suffix}", base.display()))).await;
        }
    }
    rename_with_windows_busy_retry(&tmp, database).await?;
    sync_parent_dir(database);
    // Restore usually runs as root while the service runs as a dedicated user: without giving ownership back, the service cannot open the database once it starts.
    #[cfg(unix)]
    apply_restored_database_owner(database, prior_owner);

    Ok(RestoreReport {
        source: backup.display().to_string(),
        database: database.display().to_string(),
        summary: boot.summary,
        interrupted: boot.interrupted,
    })
}

/// fsync the parent directory (unix) so the rename reaches disk; failures are ignored (best-effort).
fn sync_parent_dir(database: &Path) {
    #[cfg(unix)]
    {
        if let Some(parent) = database.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }
    #[cfg(not(unix))]
    let _ = database;
}

/// On Windows, after SQLite closes its handles the OS may still briefly block
/// exclusive file access. Retry only the transient "another process has the
/// file in use" class of failure; other IO errors are returned as-is.
async fn copy_with_windows_busy_retry(from: &Path, to: &Path) -> Result<(), BackupError> {
    let mut attempt = 1u32;
    loop {
        match tokio::fs::copy(from, to).await {
            Ok(_) => return Ok(()),
            Err(error) if error.raw_os_error() == Some(32) && attempt < 10 => {
                tokio::time::sleep(Duration::from_millis((25 * attempt) as u64)).await;
                attempt += 1;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// Same as above: the atomic rename can also fail briefly if the staging file
/// handle has not been released yet.
async fn rename_with_windows_busy_retry(from: &Path, to: &Path) -> Result<(), BackupError> {
    let mut attempt = 1u32;
    loop {
        match tokio::fs::rename(from, to).await {
            Ok(_) => return Ok(()),
            Err(error) if error.raw_os_error() == Some(32) && attempt < 10 => {
                tokio::time::sleep(Duration::from_millis((25 * attempt) as u64)).await;
                attempt += 1;
            }
            Err(error) => return Err(error.into()),
        }
    }
}
