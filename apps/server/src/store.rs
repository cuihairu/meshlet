//! SQLx/SQLite 持久化（Phase 1「核心实体 migrations」条目）。
//!
//! Migration 文件在编译期嵌入（`migrations/001_init.sql`）；连接时应用。
//! 单连接池：SQLite 写入本身串行，单进程控制平面足够（ADR-002）。

use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};

/// 编译期嵌入的 migration 集合（相对 crate manifest 目录）。
pub const MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// 打开数据库并应用全部 migration。`url` 如 `sqlite:/var/lib/meshlet/meshlet.db`。
pub async fn connect(url: &str) -> Result<SqlitePool, sqlx::Error> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                sqlx::query("PRAGMA foreign_keys = ON")
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .connect(url)
        .await?;
    MIGRATIONS.run(&pool).await?;
    Ok(pool)
}
