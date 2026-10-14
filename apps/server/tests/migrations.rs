//! 集成测试：SQLite migrations（Phase 1「核心实体 migrations」条目）。
use sqlx::Error::Database;
use sqlx::Row;

async fn db() -> sqlx::SqlitePool {
    meshlet_server::store::connect("sqlite::memory:")
        .await
        .unwrap()
}

async fn tables(pool: &sqlx::SqlitePool) -> Vec<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT name FROM sqlite_master
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_sqlx_%'
         ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn table_sql(pool: &sqlx::SqlitePool) -> String {
    let mut out = String::new();
    for t in tables(pool).await {
        let sql: String =
            sqlx::query_scalar("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?")
                .bind(&t)
                .fetch_one(pool)
                .await
                .unwrap();
        out.push_str(&format!("{t}: {sql}\n"));
    }
    out
}

async fn columns(pool: &sqlx::SqlitePool, table: &str) -> Vec<String> {
    sqlx::query(&format!("PRAGMA table_info({table})"))
        .fetch_all(pool)
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get::<String, _>(1))
        .collect()
}

#[tokio::test]
async fn migrations_create_all_core_tables() {
    let pool = db().await;
    let got = tables(&pool).await;
    for expected in [
        "agent_tokens",
        "alias_mappings",
        "audit_events",
        "config_revisions",
        "device_keys",
        "devices",
        "invitations",
        "lan_routes",
        "networks",
        "sessions",
        "users",
    ] {
        assert!(
            got.contains(&expected.to_string()),
            "missing table {expected}"
        );
    }
}

#[tokio::test]
async fn schema_stores_no_private_key_material() {
    // ADR-010 / §11.2：私钥不出客户端，schema 层不存在私钥列。
    let pool = db().await;
    let all = table_sql(&pool).await;
    assert!(
        !all.contains("private"),
        "schema must not contain private key columns: {all}"
    );
    assert!(!all.contains("secret"));
    assert!(!all.contains("seed"));

    let device_cols = columns(&pool, "devices").await;
    assert!(device_cols.contains(&"public_key".to_string()));
    assert!(
        !device_cols.contains(&"fingerprint".to_string()),
        "fingerprint lives on device_keys, not devices"
    );
    let key_cols = columns(&pool, "device_keys").await;
    assert!(key_cols.contains(&"public_key".to_string()));
    assert!(key_cols.contains(&"fingerprint".to_string()));
}

#[tokio::test]
async fn invitations_store_digest_only() {
    let pool = db().await;
    let cols = columns(&pool, "invitations").await;
    assert!(cols.contains(&"token_hash".to_string()), "{cols:?}");
    assert!(
        !cols.contains(&"token".to_string()) && !cols.contains(&"invite_token".to_string()),
        "invitations must not store the raw token"
    );

    sqlx::query(
        "INSERT INTO networks (id, name, overlay_cidr, created_at, updated_at)
         VALUES ('net-1', 'n', '10.240.0.0/16', 't', 't')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO invitations (id, network_id, token_hash, max_uses, used_count, created_at)
         VALUES ('inv-1', 'net-1', 'h1', 1, 0, 't')",
    )
    .execute(&pool)
    .await
    .unwrap();
    // token_hash 唯一。
    assert!(matches!(
        sqlx::query(
            "INSERT INTO invitations (id, network_id, token_hash, max_uses, used_count, created_at)
             VALUES ('inv-2', 'net-1', 'h1', 1, 0, 't')"
        )
        .execute(&pool)
        .await,
        Err(Database(e)) if e.is_unique_violation()
    ));
}

#[tokio::test]
async fn devices_enforce_unique_name_and_virtual_ip() {
    let pool = db().await;
    sqlx::query(
        "INSERT INTO networks (id, name, overlay_cidr, created_at, updated_at)
         VALUES ('net-1', 'n', '10.240.0.0/16', 't', 't')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO devices (id, network_id, name, virtual_ipv4, public_key, platform, status, created_at)
         VALUES ('dev-1', 'net-1', 'laptop', '10.240.0.2', 'pub-1', 'linux', 'active', 't')",
    )
    .execute(&pool)
    .await
    .unwrap();

    // 同网络内设备名唯一。
    assert!(matches!(
        sqlx::query(
            "INSERT INTO devices (id, network_id, name, virtual_ipv4, public_key, platform, status, created_at)
             VALUES ('dev-2', 'net-1', 'laptop', '10.240.0.3', 'pub-2', 'linux', 'active', 't')"
        )
        .execute(&pool)
        .await,
        Err(Database(e)) if e.is_unique_violation()
    ));
    // 同网络内虚拟 IP 唯一。
    assert!(matches!(
        sqlx::query(
            "INSERT INTO devices (id, network_id, name, virtual_ipv4, public_key, platform, status, created_at)
             VALUES ('dev-3', 'net-1', 'phone', '10.240.0.2', 'pub-3', 'linux', 'active', 't')"
        )
        .execute(&pool)
        .await,
        Err(Database(e)) if e.is_unique_violation()
    ));
    // 其他网络可以复用同名。
    sqlx::query(
        "INSERT INTO networks (id, name, overlay_cidr, created_at, updated_at)
         VALUES ('net-2', 'm', '10.241.0.0/16', 't', 't')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO devices (id, network_id, name, virtual_ipv4, public_key, platform, status, created_at)
         VALUES ('dev-4', 'net-2', 'laptop', '10.241.0.2', 'pub-4', 'linux', 'active', 't')",
    )
    .execute(&pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn foreign_keys_reject_orphan_device() {
    let pool = db().await;
    assert!(matches!(
        sqlx::query(
            "INSERT INTO devices (id, network_id, name, virtual_ipv4, public_key, platform, status, created_at)
             VALUES ('dev-1', 'nope', 'x', '10.240.0.2', 'pub-1', 'linux', 'active', 't')"
        )
        .execute(&pool)
        .await,
        Err(Database(e)) if e.is_foreign_key_violation()
    ));
}

#[tokio::test]
async fn sessions_store_digest_only_with_unique_hash() {
    let pool = db().await;
    let cols = columns(&pool, "sessions").await;
    assert!(cols.contains(&"token_hash".to_string()), "{cols:?}");
    assert!(
        !cols.contains(&"token".to_string()) && !cols.contains(&"session_token".to_string()),
        "sessions must not store the raw token"
    );

    sqlx::query(
        "INSERT INTO users (id, email, password_hash, created_at)
         VALUES ('u-1', 'a@b.c', 'h', 't')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, created_at, expires_at)
         VALUES ('th-1', 'u-1', 't', 't2')",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at)
             VALUES ('th-1', 'u-1', 't', 't2')"
        )
        .execute(&pool)
        .await,
        Err(Database(e)) if e.is_unique_violation()
    ));
}

#[tokio::test]
async fn config_revisions_are_keyed_by_network_and_revision() {
    let pool = db().await;
    sqlx::query(
        "INSERT INTO networks (id, name, overlay_cidr, created_at, updated_at)
         VALUES ('net-1', 'n', '10.240.0.0/16', 't', 't')",
    )
    .execute(&pool)
    .await
    .unwrap();
    let insert = |revision: i64| {
        sqlx::query(
            "INSERT INTO config_revisions (network_id, revision, desired_config_hash, created_at)
             VALUES ('net-1', ?, 'h', 't')",
        )
        .bind(revision)
        .execute(&pool)
    };
    insert(1).await.unwrap();
    insert(2).await.unwrap();
    assert!(matches!(
        insert(1).await,
        Err(Database(e)) if e.is_unique_violation()
    ));
}

#[tokio::test]
async fn agent_tokens_store_digest_only_with_unique_hash() {
    let pool = db().await;
    let cols = columns(&pool, "agent_tokens").await;
    assert!(cols.contains(&"token_hash".to_string()), "{cols:?}");
    assert!(
        !cols.contains(&"token".to_string()) && !cols.contains(&"agent_token".to_string()),
        "agent_tokens must not store the raw token"
    );

    sqlx::query(
        "INSERT INTO networks (id, name, overlay_cidr, created_at, updated_at)
         VALUES ('net-1', 'n', '10.240.0.0/16', 't', 't')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO devices (id, network_id, name, virtual_ipv4, public_key, platform, status, created_at)
         VALUES ('dev-1', 'net-1', 'laptop', '10.240.0.2', 'pub-1', 'linux', 'active', 't')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO agent_tokens (token_hash, device_id, created_at)
         VALUES ('ath-1', 'dev-1', 't')",
    )
    .execute(&pool)
    .await
    .unwrap();
    // token_hash 唯一。
    assert!(matches!(
        sqlx::query(
            "INSERT INTO agent_tokens (token_hash, device_id, created_at)
             VALUES ('ath-1', 'dev-1', 't')"
        )
        .execute(&pool)
        .await,
        Err(Database(e)) if e.is_unique_violation()
    ));
}

#[tokio::test]
async fn devices_carry_presence_evidence_timestamps() {
    let pool = db().await;
    let cols = columns(&pool, "devices").await;
    assert!(cols.contains(&"last_handshake_at".to_string()), "{cols:?}");
    assert!(cols.contains(&"last_report_at".to_string()), "{cols:?}");
}

#[tokio::test]
async fn migrations_are_idempotent_across_reopens() {
    // 迁移必须可重复应用（重启不破坏库）。
    let pool = db().await;
    meshlet_server::store::MIGRATIONS.run(&pool).await.unwrap();
    assert_eq!(tables(&pool).await.len(), 11);
}
