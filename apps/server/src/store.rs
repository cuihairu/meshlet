//! SQLx/SQLite persistence (the Phase 1 "core entity migrations" item).
//!
//! Migration files are embedded at compile time (`migrations/`) and applied on connect.
//!
//! Connection-pool policy (performance baselines: docs/architecture/performance.md):
//! - `:memory:`: **always 1 connection** — each connection is an independent in-memory database; multiple connections = multiple databases;
//! - file database: WAL + `synchronous=NORMAL` + `busy_timeout`, 4 connections — read concurrency
//!   (WAL reads and writes do not block each other), while writes remain serialized by SQLite (sufficient for a single-process control plane, ADR-002).
//!   WAL comes with `-wal`/`-shm` sidecar files, reclaimed at checkpoint.

use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};

/// Connection count for a file database: the read-concurrency ceiling (writes are always serialized, so raising it does not help write throughput).
const FILE_DB_MAX_CONNECTIONS: u32 = 4;

/// Migrations embedded at compile time (relative to the crate manifest directory).
pub const MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// Open the database and apply all migrations. `url` such as `sqlite:/var/lib/meshlet/meshlet.db`.
pub async fn connect(url: &str) -> Result<SqlitePool, sqlx::Error> {
    use std::str::FromStr as _;
    let in_memory = url.contains(":memory:");
    // First startup on a fresh host must be able to create the database file (sqlx defaults to create_if_missing=false,
    // and without this switch it reports SQLITE_CANTOPEN); an in-memory database has no such need.
    let options = sqlx::sqlite::SqliteConnectOptions::from_str(url)?.create_if_missing(!in_memory);
    let pool = SqlitePoolOptions::new()
        .max_connections(if in_memory {
            1
        } else {
            FILE_DB_MAX_CONNECTIONS
        })
        .after_connect(move |conn, _meta| {
            Box::pin(async move {
                // `execute` consumes the executor by value: pass a fresh reborrow each time; do not bind and hold it.
                sqlx::query("PRAGMA foreign_keys = ON")
                    .execute(&mut *conn)
                    .await?;
                if !in_memory {
                    // WAL: reads do not block reads/writes; NORMAL: a power loss loses at most the latest transaction, never corrupts the database.
                    sqlx::query("PRAGMA journal_mode = WAL")
                        .execute(&mut *conn)
                        .await?;
                    sqlx::query("PRAGMA synchronous = NORMAL")
                        .execute(&mut *conn)
                        .await?;
                    sqlx::query("PRAGMA busy_timeout = 5000")
                        .execute(&mut *conn)
                        .await?;
                }
                Ok(())
            })
        })
        .connect_with(options)
        .await?;
    if let Err(error) = MIGRATIONS.run(&pool).await {
        // Release file handles before returning, including on Windows where a
        // dropped pool can otherwise keep a failed restore's staging file open.
        pool.close().await;
        return Err(error.into());
    }
    Ok(pool)
}
