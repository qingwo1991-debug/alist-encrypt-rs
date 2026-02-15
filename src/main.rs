use std::{collections::HashMap, sync::Arc};

use alist_encrypt_rs::{
    config::{AppConfig, RuntimeSettings},
    db::Db,
    meta_prefetch, metrics, routes,
    state::{AdminCredentials, AppState},
    upstream::build_upstream_client,
};
use tokio::{net::TcpListener, sync::RwLock};
use tracing::{info, warn};

#[tokio::main]
async fn main() {
    let _ = dotenvy::from_filename("config/app.env");
    alist_encrypt_rs::logging::init_logging();

    let cfg = AppConfig::from_env();
    let db = match Db::connect(&cfg.mysql_dsn, cfg.auto_migrate).await {
        Ok(db) => Some(db),
        Err(e) => {
            warn!(event = "db_connect_failed", message = %e);
            None
        }
    };

    let runtime = load_runtime_settings(db.as_ref(), cfg.runtime.clone()).await;
    let admin_credentials = load_admin_credentials(db.as_ref(), &cfg).await;
    let upstream = build_upstream_client(&runtime).expect("failed to create upstream client");

    let state = AppState {
        cfg: cfg.clone(),
        db,
        upstream: Arc::new(RwLock::new(upstream)),
        runtime: Arc::new(RwLock::new(runtime.clone())),
        metrics: Arc::new(metrics::MetricsRegistry::default()),
        qos_high: Arc::new(tokio::sync::Semaphore::new(
            runtime.qos_high_priority_concurrency.max(1),
        )),
        qos_low: Arc::new(tokio::sync::Semaphore::new(
            runtime.qos_low_priority_concurrency.max(1),
        )),
        breaker_state: Arc::new(RwLock::new(HashMap::new())),
        admin_sessions: Arc::new(RwLock::new(HashMap::new())),
        captcha_store: Arc::new(RwLock::new(HashMap::new())),
        admin_credentials: Arc::new(RwLock::new(admin_credentials)),
    };
    meta_prefetch::spawn_meta_prefetch_worker(state.clone());

    let listener = TcpListener::bind(&cfg.listen_addr)
        .await
        .expect("failed to bind listener");

    let app = routes::app_router(state);
    info!(
        event = "boot",
        message = "alist-encrypt-rs started",
        listen = %cfg.listen_addr,
        upstream = %cfg.upstream_base_url,
        h2_only = runtime.upstream_http2_only,
        h2_adaptive = runtime.upstream_http2_adaptive_window,
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

async fn load_runtime_settings(db: Option<&Db>, fallback: RuntimeSettings) -> RuntimeSettings {
    let Some(db) = db else {
        return fallback;
    };
    match db.get_runtime_kv_json_text("runtime.settings").await {
        Ok(Some(text)) => serde_json::from_str::<RuntimeSettings>(&text).unwrap_or(fallback),
        Ok(None) => fallback,
        Err(_) => fallback,
    }
}

async fn load_admin_credentials(db: Option<&Db>, cfg: &AppConfig) -> Option<AdminCredentials> {
    if let Some(db) = db {
        let username = db
            .get_runtime_kv("admin.auth.username")
            .await
            .ok()
            .flatten();
        let password = db
            .get_runtime_kv("admin.auth.password")
            .await
            .ok()
            .flatten();
        if let (Some(username), Some(password)) = (username, password) {
            if !username.trim().is_empty() && !password.is_empty() {
                return Some(AdminCredentials { username, password });
            }
        }
    }

    match (cfg.admin_username.clone(), cfg.admin_password.clone()) {
        (Some(username), Some(password)) if !username.trim().is_empty() && !password.is_empty() => {
            Some(AdminCredentials { username, password })
        }
        _ => None,
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C signal handler");
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        sigterm.recv().await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
