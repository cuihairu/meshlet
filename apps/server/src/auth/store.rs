use meshlet_domain::auth::{Session, User};
use meshlet_domain::{token_hash, Timestamp, UserId};
use sqlx::SqlitePool;

// ---------------------------------------------------------------------------
// 存储
// ---------------------------------------------------------------------------

/// 用户/会话存储（SQLite，migrations 001/002）。
#[derive(Clone)]
pub struct AuthStore {
    pool: SqlitePool,
}

/// 查询到的用户行（含哈希；仅在登录路径内部使用，不序列化出站）。
pub struct UserRecord {
    pub id: UserId,
    pub email: String,
    pub password_hash: String,
    /// TOTP base32 密钥；`None` = 未发起绑定。
    pub totp_secret: Option<String>,
    /// TOTP 已激活（登录需第二步校验）。
    pub totp_enabled: bool,
}

impl AuthStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// 池句柄（克隆后供审计存储与其他 store 共用同一库）。
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn user_count(&self) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await
    }

    pub async fn insert_first_user(&self, user: &User) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("INSERT INTO users(id,email,password_hash,created_at) SELECT ?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM users)")
            .bind(&user.id.0).bind(&user.email).bind(&user.password_hash).bind(&user.created_at).execute(&self.pool).await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn insert_user(&self, user: &User) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO users (id, email, password_hash, created_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(&user.id.0)
        .bind(&user.email)
        .bind(&user.password_hash)
        .bind(user.created_at.as_str())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn find_user_by_email(&self, email: &str) -> Result<Option<UserRecord>, sqlx::Error> {
        Self::find_user_by(
            &self.pool,
            "SELECT id, email, password_hash, totp_secret, totp_enabled FROM users WHERE email = ?",
            email,
        )
        .await
    }

    pub async fn find_user_by_id(&self, id: &UserId) -> Result<Option<UserRecord>, sqlx::Error> {
        Self::find_user_by(
            &self.pool,
            "SELECT id, email, password_hash, totp_secret, totp_enabled FROM users WHERE id = ?",
            &id.0,
        )
        .await
    }

    async fn find_user_by(
        pool: &SqlitePool,
        sql: &'static str,
        key: &str,
    ) -> Result<Option<UserRecord>, sqlx::Error> {
        let row = sqlx::query_as::<_, (String, String, String, Option<String>, i64)>(sql)
            .bind(key)
            .fetch_optional(pool)
            .await?;
        Ok(row.map(
            |(id, email, password_hash, totp_secret, totp_enabled)| UserRecord {
                id: UserId(id),
                email,
                password_hash,
                totp_secret,
                totp_enabled: totp_enabled != 0,
            },
        ))
    }

    /// 写入/清除 TOTP 密钥（`None` = 清除并关停）。
    pub async fn set_totp_secret(
        &self,
        id: &UserId,
        secret: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET totp_secret = ? WHERE id = ?")
            .bind(secret)
            .bind(&id.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 激活/关停 TOTP 登录第二步。
    pub async fn set_totp_enabled(&self, id: &UserId, enabled: bool) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET totp_enabled = ? WHERE id = ?")
            .bind(if enabled { 1i64 } else { 0i64 })
            .bind(&id.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn insert_session(&self, session: &Session) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(&session.token_hash)
        .bind(&session.user_id.0)
        .bind(session.created_at.as_str())
        .bind(session.expires_at.as_str())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 校验会话：存在、未撤销、未过期 → 用户 ID。
    pub async fn validate_session(
        &self,
        raw_token: &str,
        now: &Timestamp,
    ) -> Result<Option<UserId>, sqlx::Error> {
        let row = sqlx::query_as::<_, (String, String, Option<String>)>(
            "SELECT user_id, expires_at, revoked_at FROM sessions WHERE token_hash = ?",
        )
        .bind(token_hash(raw_token))
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some((user_id, expires_at, revoked_at)) => {
                if revoked_at.is_none() && expires_at.as_str() > now.as_str() {
                    Ok(Some(UserId(user_id)))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    pub async fn revoke_session(&self, raw_token: &str, at: &Timestamp) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE sessions SET revoked_at = ? WHERE token_hash = ?")
            .bind(at.as_str())
            .bind(token_hash(raw_token))
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
