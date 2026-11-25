//! Integration test: SQLite migrations (the Phase 1 "core entity migrations" item).
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
        "api_tokens",
        "alias_mappings",
        "audit_events",
        "config_revisions",
        "device_keys",
        "devices",
        "diagnostics_runs",
        "invitations",
        "lan_routes",
        "networks",
        "sessions",
        "segment_grants",
        "segments",
        "tasks",
        "users",
    ] {
        assert!(
            got.contains(&expected.to_string()),
            "missing table {expected}"
        );
    }
}

#[tokio::test]
async fn segment_default_migration_repairs_missing_rows_and_assignments() {
    let pool = db().await;
    sqlx::query(
        "INSERT INTO networks (id, name, overlay_cidr, created_at, updated_at)
         VALUES ('net-legacy', 'legacy', '10.240.0.0/16', 't', 't')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO devices (id, network_id, name, virtual_ipv4, public_key, platform, status, created_at)
         VALUES ('dev-legacy', 'net-legacy', 'legacy-device', '10.240.0.2', 'pub', 'linux', 'revoked', 't')",
    )
    .execute(&pool)
    .await
    .unwrap();

    // Model a pre-default row left by the earlier migration path, then apply
    // 011 directly to verify both missing defaults and non-active devices.
    let migration = include_str!("../../../migrations/011_segment_defaults.sql");
    sqlx::raw_sql(migration).execute(&pool).await.unwrap();
    let segment: (String, String, String) =
        sqlx::query_as("SELECT id, name, cidr FROM segments WHERE network_id = 'net-legacy'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        segment,
        (
            "seg-net-legacy".into(),
            "default".into(),
            "10.240.0.0/16".into()
        )
    );
    let assigned: String =
        sqlx::query_scalar("SELECT segment_id FROM devices WHERE id = 'dev-legacy'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(assigned, "seg-net-legacy");
}

#[tokio::test]
async fn schema_stores_no_private_key_material() {
    // ADR-010 / §11.2: private keys never leave the client, so no private key column exists at the schema level.
    //
    // Exemption: `users.totp_secret` (014_user_totp). RFC 6238 requires the server to hold the TOTP
    // shared key to verify codes -- this is a **symmetric** shared key, a different class from the
    // WireGuard **asymmetric private key** that ADR-010 targets; the private-key/seed checks stay strict, and
    // `secret` columns are now checked table by table, column by column (only totp_secret is allowed, it is not a blanket pass for all secret columns).
    let pool = db().await;
    let all = table_sql(&pool).await;
    assert!(
        !all.contains("private"),
        "schema must not contain private key columns: {all}"
    );
    assert!(!all.contains("seed"));
    const SECRET_EXEMPT: [&str; 1] = ["totp_secret"];
    for table in tables(&pool).await {
        for col in columns(&pool, &table).await {
            assert!(
                !col.contains("secret") || SECRET_EXEMPT.contains(&col.as_str()),
                "unexpected secret column {table}.{col}"
            );
        }
    }

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
    // token_hash is unique.
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

    // Device names are unique within a network.
    assert!(matches!(
        sqlx::query(
            "INSERT INTO devices (id, network_id, name, virtual_ipv4, public_key, platform, status, created_at)
             VALUES ('dev-2', 'net-1', 'laptop', '10.240.0.3', 'pub-2', 'linux', 'active', 't')"
        )
        .execute(&pool)
        .await,
        Err(Database(e)) if e.is_unique_violation()
    ));
    // Virtual IPs are unique within a network.
    assert!(matches!(
        sqlx::query(
            "INSERT INTO devices (id, network_id, name, virtual_ipv4, public_key, platform, status, created_at)
             VALUES ('dev-3', 'net-1', 'phone', '10.240.0.2', 'pub-3', 'linux', 'active', 't')"
        )
        .execute(&pool)
        .await,
        Err(Database(e)) if e.is_unique_violation()
    ));
    // Another network may reuse the same name.
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
    // token_hash is unique.
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
async fn users_carry_totp_columns() {
    // 014_user_totp: `users.totp_secret` (base32, held only by the server) and
    // `users.totp_enabled` (0/1, login requires the second step once enabled).
    let pool = db().await;
    let cols = columns(&pool, "users").await;
    assert!(cols.contains(&"totp_secret".to_string()), "{cols:?}");
    assert!(cols.contains(&"totp_enabled".to_string()), "{cols:?}");
}

#[tokio::test]
async fn migrations_are_idempotent_across_reopens() {
    // Migrations must be re-appliable (a restart must not corrupt the db).
    let pool = db().await;
    meshlet_server::store::MIGRATIONS.run(&pool).await.unwrap();
    // 005 adds mesh_meta (monotonic counters like route_seq, §17.3); 006 adds
    // diagnostics_runs (§12.7 diagnostics snapshots); 008 adds bootstrap_tokens +
    // device_registrations (device bootstrap registration, Pending stays out of devices); 012 adds
    // the four publish object kinds + the probe health mirror (R-06); 015 adds tasks (MT-002 task channel);
    // 016 only adds columns to tasks (confirmed_at/rejected_at/parent_task_id), no new table.
    let tables = tables(&pool).await;
    assert_eq!(tables.len(), 26);
    assert!(tables.contains(&"mesh_meta".to_string()), "{tables:?}");
    assert!(tables.contains(&"tasks".to_string()), "{tables:?}");
    assert!(
        tables.contains(&"diagnostics_runs".to_string()),
        "{tables:?}"
    );
    assert!(
        tables.contains(&"bootstrap_tokens".to_string()),
        "{tables:?}"
    );
    assert!(
        tables.contains(&"device_registrations".to_string()),
        "{tables:?}"
    );
    assert!(
        tables.contains(&"publish_forwards".to_string()),
        "{tables:?}"
    );
    assert!(
        tables.contains(&"publish_probe_reports".to_string()),
        "{tables:?}"
    );
}

#[tokio::test]
async fn migration_017_adds_labels_and_task_required_labels_columns() {
    // 017 only adds columns, no new table: devices.labels (node labels, routing basis) and
    // tasks.required_labels (label constraints on task payloads, kept in the payload across restarts).
    let pool = db().await;
    let device_cols = columns(&pool, "devices").await;
    assert!(
        device_cols.contains(&"labels".to_string()),
        "devices must have labels column: {device_cols:?}"
    );
    let task_cols = columns(&pool, "tasks").await;
    assert!(
        task_cols.contains(&"required_labels".to_string()),
        "tasks must have required_labels column: {task_cols:?}"
    );
}

#[tokio::test]
async fn api_tokens_store_digest_only_with_scopes() {
    let pool = db().await;
    let cols = columns(&pool, "api_tokens").await;
    assert_eq!(
        cols,
        vec![
            "id",
            "token_hash",
            "user_id",
            "name",
            "scopes",
            "created_at",
            "last_used_at",
            "revoked_at"
        ]
    );
    // No raw token column: only the digest is stored, the raw token is returned exactly once in the creation response.
    assert!(
        !cols.contains(&"token".to_string()) && !cols.contains(&"raw_token".to_string()),
        "api_tokens must not store the raw token: {cols:?}"
    );

    sqlx::query(
        "INSERT INTO users (id, email, password_hash, created_at)
                 VALUES ('u-1', 'a@b.c', 'x', 't')",
    )
    .execute(&pool)
    .await
    .unwrap();
    async fn insert(pool: &sqlx::SqlitePool, id: &str, hash: &str, scopes: &str) {
        sqlx::query(
            "INSERT INTO api_tokens (id, token_hash, user_id, name, scopes, created_at)
                     VALUES (?, ?, 'u-1', 'n', ?, 't')",
        )
        .bind(id)
        .bind(hash)
        .bind(scopes)
        .execute(pool)
        .await
        .unwrap();
    }
    insert(&pool, "tok-1", "at-1", "read").await;
    // token_hash is unique (even with a different id).
    assert!(matches!(
        sqlx::query("INSERT INTO api_tokens (id, token_hash, user_id, name, scopes, created_at)
                     VALUES ('tok-2', 'at-1', 'u-1', 'n', 'write', 't')")
            .execute(&pool)
            .await,
        Err(Database(e)) if e.is_unique_violation()
    ));
    // id is unique.
    assert!(matches!(
        sqlx::query("INSERT INTO api_tokens (id, token_hash, user_id, name, scopes, created_at)
                     VALUES ('tok-1', 'at-2', 'u-1', 'n', 'read', 't')")
            .execute(&pool)
            .await,
        Err(Database(e)) if e.is_unique_violation()
    ));
    // The revoked state is carried by revoked_at (so it can be revoked).
    sqlx::query("UPDATE api_tokens SET revoked_at = 't2' WHERE id = 'tok-1'")
        .execute(&pool)
        .await
        .unwrap();
    let row: Option<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT revoked_at, last_used_at FROM api_tokens WHERE id = 'tok-1'")
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert_eq!(row.unwrap(), (Some("t2".into()), None));
}
