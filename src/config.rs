use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TimeoutProfile {
    pub connect_ms: u64,
    pub ttfb_ms: u64,
    pub read_idle_ms: u64,
    pub total_ms: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum InterfaceClass {
    Control,
    Metadata,
    SmallTransfer,
    LargeStream,
}

impl InterfaceClass {
    pub fn profile(self) -> TimeoutProfile {
        match self {
            InterfaceClass::Control => TimeoutProfile {
                connect_ms: 300,
                ttfb_ms: 1200,
                read_idle_ms: 2000,
                total_ms: 5000,
            },
            InterfaceClass::Metadata => TimeoutProfile {
                connect_ms: 300,
                ttfb_ms: 2000,
                read_idle_ms: 4000,
                total_ms: 12000,
            },
            InterfaceClass::SmallTransfer => TimeoutProfile {
                connect_ms: 300,
                ttfb_ms: 1500,
                read_idle_ms: 4000,
                total_ms: 20000,
            },
            InterfaceClass::LargeStream => TimeoutProfile {
                connect_ms: 300,
                ttfb_ms: 2500,
                read_idle_ms: 15000,
                total_ms: 0,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeSettings {
    pub upstream_http2_only: bool,
    pub upstream_http2_adaptive_window: bool,
    pub upstream_http2_keepalive_interval_secs: u64,
    pub upstream_http2_keepalive_timeout_secs: u64,
    pub upstream_pool_max_idle_per_host: usize,
    pub upstream_pool_idle_timeout_secs: u64,
    pub upstream_connect_timeout_ms: u64,
    pub upstream_request_timeout_ms: u64,
    pub upstream_tcp_nodelay: bool,
    pub admin_raw_filename_logging_default: bool,
    pub max_request_body_bytes: usize,
    pub max_response_body_bytes: usize,
    pub metadata_prefetch_enabled: bool,
    pub metadata_prefetch_interval_secs: u64,
    pub metadata_prefetch_stale_secs: u64,
    pub metadata_prefetch_batch: usize,
    pub qos_high_priority_concurrency: usize,
    pub qos_low_priority_concurrency: usize,
    pub strategy_learning_enabled: bool,
    pub strategy_learning_rollout_percent: u8,
    pub circuit_breaker_fail_threshold: u32,
    pub circuit_breaker_cooldown_secs: u64,
}

impl Default for RuntimeSettings {
    fn default() -> Self {
        Self {
            upstream_http2_only: false,
            upstream_http2_adaptive_window: true,
            upstream_http2_keepalive_interval_secs: 15,
            upstream_http2_keepalive_timeout_secs: 20,
            upstream_pool_max_idle_per_host: 128,
            upstream_pool_idle_timeout_secs: 90,
            upstream_connect_timeout_ms: 300,
            upstream_request_timeout_ms: 60000,
            upstream_tcp_nodelay: true,
            admin_raw_filename_logging_default: false,
            max_request_body_bytes: 1024 * 1024 * 64,
            max_response_body_bytes: 1024 * 1024 * 128,
            metadata_prefetch_enabled: true,
            metadata_prefetch_interval_secs: 180,
            metadata_prefetch_stale_secs: 600,
            metadata_prefetch_batch: 64,
            qos_high_priority_concurrency: 256,
            qos_low_priority_concurrency: 64,
            strategy_learning_enabled: true,
            strategy_learning_rollout_percent: 100,
            circuit_breaker_fail_threshold: 8,
            circuit_breaker_cooldown_secs: 30,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub listen_addr: String,
    pub upstream_base_url: String,
    pub mysql_dsn: String,
    pub auto_migrate: bool,
    pub admin_token: Option<String>,
    pub admin_username: Option<String>,
    pub admin_password: Option<String>,
    pub admin_cookie_secure_mode: AdminCookieSecureMode,
    pub admin_session_ttl_secs: u64,
    pub admin_captcha_ttl_secs: u64,
    pub runtime: RuntimeSettings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminCookieSecureMode {
    Auto,
    Always,
    Off,
}

impl AppConfig {
    pub fn from_env() -> Self {
        let listen_addr =
            std::env::var("RUST_PROXY_ADDR").unwrap_or_else(|_| "0.0.0.0:5345".to_string());
        let upstream_base_url = std::env::var("UPSTREAM_BASE_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:5244".to_string());

        let mysql_host = std::env::var("MYSQL_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let mysql_port = std::env::var("MYSQL_PORT").unwrap_or_else(|_| "3306".to_string());
        let mysql_db = std::env::var("MYSQL_DB").unwrap_or_else(|_| "alist_encrypt".to_string());
        let mysql_user =
            std::env::var("MYSQL_USER").unwrap_or_else(|_| "alist_encrypt".to_string());
        let mysql_password =
            std::env::var("MYSQL_PASSWORD").unwrap_or_else(|_| "change_me".to_string());

        let mysql_dsn = format!(
            "mysql://{}:{}@{}:{}/{}",
            mysql_user, mysql_password, mysql_host, mysql_port, mysql_db
        );

        let auto_migrate = std::env::var("AUTO_MIGRATE")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);
        let admin_token = std::env::var("ADMIN_TOKEN").ok();
        let admin_username = std::env::var("ADMIN_USERNAME").ok();
        let admin_password = std::env::var("ADMIN_PASSWORD").ok();
        let admin_cookie_secure_mode = std::env::var("ADMIN_COOKIE_SECURE_MODE")
            .ok()
            .and_then(|v| parse_cookie_secure_mode(&v))
            .unwrap_or_else(|| {
                if env_bool("ADMIN_COOKIE_SECURE", false) {
                    AdminCookieSecureMode::Always
                } else {
                    AdminCookieSecureMode::Off
                }
            });
        let admin_session_ttl_secs = env_u64("ADMIN_SESSION_TTL_SECS", 60 * 60 * 12);
        let admin_captcha_ttl_secs = env_u64("ADMIN_CAPTCHA_TTL_SECS", 60 * 2);

        let mut runtime = RuntimeSettings::default();
        runtime.upstream_http2_only = env_bool("UPSTREAM_HTTP2_ONLY", runtime.upstream_http2_only);
        runtime.upstream_http2_adaptive_window = env_bool(
            "UPSTREAM_HTTP2_ADAPTIVE_WINDOW",
            runtime.upstream_http2_adaptive_window,
        );
        runtime.upstream_http2_keepalive_interval_secs = env_u64(
            "UPSTREAM_HTTP2_KEEPALIVE_INTERVAL_SECS",
            runtime.upstream_http2_keepalive_interval_secs,
        );
        runtime.upstream_http2_keepalive_timeout_secs = env_u64(
            "UPSTREAM_HTTP2_KEEPALIVE_TIMEOUT_SECS",
            runtime.upstream_http2_keepalive_timeout_secs,
        );
        runtime.upstream_pool_max_idle_per_host = env_usize(
            "UPSTREAM_POOL_MAX_IDLE_PER_HOST",
            runtime.upstream_pool_max_idle_per_host,
        );
        runtime.upstream_pool_idle_timeout_secs = env_u64(
            "UPSTREAM_POOL_IDLE_TIMEOUT_SECS",
            runtime.upstream_pool_idle_timeout_secs,
        );
        runtime.upstream_connect_timeout_ms = env_u64(
            "UPSTREAM_CONNECT_TIMEOUT_MS",
            runtime.upstream_connect_timeout_ms,
        );
        runtime.upstream_request_timeout_ms = env_u64(
            "UPSTREAM_REQUEST_TIMEOUT_MS",
            runtime.upstream_request_timeout_ms,
        );
        runtime.upstream_tcp_nodelay =
            env_bool("UPSTREAM_TCP_NODELAY", runtime.upstream_tcp_nodelay);
        runtime.admin_raw_filename_logging_default = env_bool(
            "LOG_RAW_FILENAME_DEFAULT",
            runtime.admin_raw_filename_logging_default,
        );
        runtime.max_request_body_bytes =
            env_usize("MAX_REQUEST_BODY_BYTES", runtime.max_request_body_bytes);
        runtime.max_response_body_bytes =
            env_usize("MAX_RESPONSE_BODY_BYTES", runtime.max_response_body_bytes);
        runtime.metadata_prefetch_enabled = env_bool(
            "METADATA_PREFETCH_ENABLED",
            runtime.metadata_prefetch_enabled,
        );
        runtime.metadata_prefetch_interval_secs = env_u64(
            "METADATA_PREFETCH_INTERVAL_SECS",
            runtime.metadata_prefetch_interval_secs,
        );
        runtime.metadata_prefetch_stale_secs = env_u64(
            "METADATA_PREFETCH_STALE_SECS",
            runtime.metadata_prefetch_stale_secs,
        );
        runtime.metadata_prefetch_batch =
            env_usize("METADATA_PREFETCH_BATCH", runtime.metadata_prefetch_batch);
        runtime.qos_high_priority_concurrency = env_usize(
            "QOS_HIGH_PRIORITY_CONCURRENCY",
            runtime.qos_high_priority_concurrency,
        );
        runtime.qos_low_priority_concurrency = env_usize(
            "QOS_LOW_PRIORITY_CONCURRENCY",
            runtime.qos_low_priority_concurrency,
        );
        runtime.strategy_learning_enabled = env_bool(
            "STRATEGY_LEARNING_ENABLED",
            runtime.strategy_learning_enabled,
        );
        runtime.strategy_learning_rollout_percent = env_u64(
            "STRATEGY_LEARNING_ROLLOUT_PERCENT",
            runtime.strategy_learning_rollout_percent as u64,
        )
        .min(100) as u8;
        runtime.circuit_breaker_fail_threshold = env_u64(
            "CIRCUIT_BREAKER_FAIL_THRESHOLD",
            runtime.circuit_breaker_fail_threshold as u64,
        ) as u32;
        runtime.circuit_breaker_cooldown_secs = env_u64(
            "CIRCUIT_BREAKER_COOLDOWN_SECS",
            runtime.circuit_breaker_cooldown_secs,
        );

        Self {
            listen_addr,
            upstream_base_url,
            mysql_dsn,
            auto_migrate,
            admin_token,
            admin_username,
            admin_password,
            admin_cookie_secure_mode,
            admin_session_ttl_secs,
            admin_captcha_ttl_secs,
            runtime,
        }
    }

    pub fn password_login_enabled(&self) -> bool {
        self.admin_username.is_some() && self.admin_password.is_some()
    }
}

fn parse_cookie_secure_mode(v: &str) -> Option<AdminCookieSecureMode> {
    match v.trim().to_ascii_lowercase().as_str() {
        "auto" => Some(AdminCookieSecureMode::Auto),
        "always" | "true" | "on" => Some(AdminCookieSecureMode::Always),
        "off" | "false" => Some(AdminCookieSecureMode::Off),
        _ => None,
    }
}

fn env_bool(k: &str, d: bool) -> bool {
    std::env::var(k)
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(d)
}

fn env_u64(k: &str, d: u64) -> u64 {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(d)
}

fn env_usize(k: &str, d: usize) -> usize {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(d)
}
