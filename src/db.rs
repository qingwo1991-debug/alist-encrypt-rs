use sqlx::MySqlPool;

use crate::config::TimeoutProfile;
use crate::migrate::run_bootstrap_sql;

#[derive(Clone)]
pub struct Db {
    pool: MySqlPool,
}

impl Db {
    pub async fn connect(mysql_dsn: &str, auto_migrate: bool) -> Result<Self, sqlx::Error> {
        let pool = MySqlPool::connect(mysql_dsn).await?;
        if auto_migrate {
            let sql = include_str!("../migrations/001_init.sql");
            run_bootstrap_sql(&pool, sql).await?;
        }
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &MySqlPool {
        &self.pool
    }

    pub async fn load_timeout_profile(
        &self,
        tenant_id: &str,
        iface_name: &str,
    ) -> Result<Option<TimeoutProfile>, sqlx::Error> {
        let row: Option<(i32, i32, i32, i32)> = sqlx::query_as(
            r#"
            SELECT connect_ms, ttfb_ms, read_idle_ms, total_ms
            FROM timeout_profiles
            WHERE tenant_id = ? AND iface_name = ? AND enabled = 1
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(iface_name)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(
            |(connect_ms, ttfb_ms, read_idle_ms, total_ms)| TimeoutProfile {
                connect_ms: connect_ms as u64,
                ttfb_ms: ttfb_ms as u64,
                read_idle_ms: read_idle_ms as u64,
                total_ms: total_ms as u64,
            },
        ))
    }

    pub async fn ping(&self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    pub async fn upsert_timeout_profile(
        &self,
        tenant_id: &str,
        iface_name: &str,
        profile: TimeoutProfile,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO timeout_profiles (tenant_id, iface_name, connect_ms, ttfb_ms, read_idle_ms, total_ms, enabled)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            ON DUPLICATE KEY UPDATE
              connect_ms = VALUES(connect_ms),
              ttfb_ms = VALUES(ttfb_ms),
              read_idle_ms = VALUES(read_idle_ms),
              total_ms = VALUES(total_ms),
              enabled = 1
            "#,
        )
        .bind(tenant_id)
        .bind(iface_name)
        .bind(profile.connect_ms as i32)
        .bind(profile.ttfb_ms as i32)
        .bind(profile.read_idle_ms as i32)
        .bind(profile.total_ms as i32)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_runtime_kv(&self, key: &str) -> Result<Option<String>, sqlx::Error> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT JSON_UNQUOTE(v) FROM runtime_kv WHERE k = ? LIMIT 1")
                .bind(key)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(v,)| v))
    }

    pub async fn get_runtime_kv_json_text(&self, key: &str) -> Result<Option<String>, sqlx::Error> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT CAST(v AS CHAR) FROM runtime_kv WHERE k = ? LIMIT 1")
                .bind(key)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(v,)| v))
    }

    pub async fn set_runtime_kv_json(
        &self,
        key: &str,
        json_value: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO runtime_kv (k, v)
            VALUES (?, CAST(? AS JSON))
            ON DUPLICATE KEY UPDATE
              v = VALUES(v)
            "#,
        )
        .bind(key)
        .bind(json_value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn insert_audit_log(
        &self,
        tenant_id: &str,
        request_id: &str,
        trace_id: &str,
        actor: &str,
        action: &str,
        target: &str,
        payload_json: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO audit_logs (tenant_id, request_id, trace_id, actor, action, target, payload)
            VALUES (?, ?, ?, ?, ?, ?, CAST(? AS JSON))
            "#,
        )
        .bind(tenant_id)
        .bind(request_id)
        .bind(trace_id)
        .bind(actor)
        .bind(action)
        .bind(target)
        .bind(payload_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_file_meta_size(
        &self,
        tenant_id: &str,
        file_path: &str,
    ) -> Result<Option<u64>, sqlx::Error> {
        let row: Option<(i64,)> = sqlx::query_as(
            r#"
            SELECT file_size
            FROM file_meta_cache
            WHERE tenant_id = ? AND file_path = ?
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(file_path)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(v,)| v as u64))
    }

    pub async fn upsert_file_meta(
        &self,
        tenant_id: &str,
        file_path: &str,
        file_size: u64,
        enc_mode: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO file_meta_cache (tenant_id, file_path, file_size, enc_mode, hit_count)
            VALUES (?, ?, ?, ?, 1)
            ON DUPLICATE KEY UPDATE
              file_size = VALUES(file_size),
              enc_mode = VALUES(enc_mode),
              hit_count = hit_count + 1
            "#,
        )
        .bind(tenant_id)
        .bind(file_path)
        .bind(file_size as i64)
        .bind(enc_mode)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_stale_file_meta_paths(
        &self,
        stale_seconds: u64,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, sqlx::Error> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            r#"
            SELECT file_path, file_size
            FROM file_meta_cache
            WHERE TIMESTAMPDIFF(SECOND, updated_at, NOW()) >= ?
            ORDER BY hit_count DESC, updated_at ASC
            LIMIT ?
            "#,
        )
        .bind(stale_seconds as i64)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(p, s)| (p, if s < 0 { 0 } else { s as u64 }))
            .collect())
    }

    pub async fn record_strategy_result(
        &self,
        tenant_id: &str,
        cloud_drive_name: &str,
        strategy_name: &str,
        success: bool,
    ) -> Result<(), sqlx::Error> {
        let (succ, fail) = if success {
            (1_i64, 0_i64)
        } else {
            (0_i64, 1_i64)
        };
        sqlx::query(
            r#"
            INSERT INTO cloud_strategy_stats (tenant_id, cloud_drive_name, strategy_name, success_count, fail_count)
            VALUES (?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
              success_count = success_count + VALUES(success_count),
              fail_count = fail_count + VALUES(fail_count)
            "#,
        )
        .bind(tenant_id)
        .bind(cloud_drive_name)
        .bind(strategy_name)
        .bind(succ)
        .bind(fail)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn best_strategy(
        &self,
        tenant_id: &str,
        cloud_drive_name: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        let row: Option<(String,)> = sqlx::query_as(
            r#"
            SELECT strategy_name
            FROM cloud_strategy_stats
            WHERE tenant_id = ? AND cloud_drive_name = ?
            ORDER BY (success_count - fail_count) DESC, success_count DESC, updated_at DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(cloud_drive_name)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(v,)| v))
    }
}
