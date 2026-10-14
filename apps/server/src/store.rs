//! SQLx/SQLite 持久化（Phase 1「核心实体 migrations」条目）。
//!
//! Migration 文件在编译期嵌入（`migrations/`）；连接时应用。
//!
//! 连接池策略（性能基准见 docs/architecture/performance.md）：
//! - `:memory:`：**恒 1 连接**——每个连接是独立的内存库，多连接 = 多个库；
//! - 文件库：WAL + `synchronous=NORMAL` + `busy_timeout`，4 连接——读并发
//!   （WAL 读写不互斥），写仍由 SQLite 串行（单进程控制平面足够，ADR-002）。
//!   WAL 会伴随 `-wal`/`-shm` 文件，随检查点回收。

use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};

/// 文件库连接数：读并发上限（写始终串行，加大无益于写吞吐）。
const FILE_DB_MAX_CONNECTIONS: u32 = 4;

/// 编译期嵌入的 migration 集合（相对 crate manifest 目录）。
pub const MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// 打开数据库并应用全部 migration。`url` 如 `sqlite:/var/lib/meshlet/meshlet.db`。
pub async fn connect(url: &str) -> Result<SqlitePool, sqlx::Error> {
    use std::str::FromStr as _;
    let in_memory = url.contains(":memory:");
    // 首次启动在全新主机上必须能建库文件（sqlx 默认 create_if_missing=false，
    // 不开这个开关会报 SQLITE_CANTOPEN）；内存库无此需求。
    let options = sqlx::sqlite::SqliteConnectOptions::from_str(url)?.create_if_missing(!in_memory);
    let pool = SqlitePoolOptions::new()
        .max_connections(if in_memory {
            1
        } else {
            FILE_DB_MAX_CONNECTIONS
        })
        .after_connect(move |conn, _meta| {
            Box::pin(async move {
                // `execute` 按值消费 executor：每次传新的重借用，勿绑定持有。
                sqlx::query("PRAGMA foreign_keys = ON")
                    .execute(&mut *conn)
                    .await?;
                if !in_memory {
                    // WAL：读不阻塞读/写；NORMAL：断电最多丢最近事务，不损坏库。
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
    MIGRATIONS.run(&pool).await?;
    Ok(pool)
}
