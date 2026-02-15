use reqwest::Client;
use std::{collections::HashMap, sync::Arc, time::Instant};
use tokio::sync::{RwLock, Semaphore};

use crate::{
    config::{AppConfig, RuntimeSettings},
    db::Db,
    metrics::MetricsRegistry,
};

#[derive(Clone)]
pub struct AppState {
    pub cfg: AppConfig,
    pub db: Option<Db>,
    pub upstream: Arc<RwLock<Client>>,
    pub runtime: Arc<RwLock<RuntimeSettings>>,
    pub metrics: Arc<MetricsRegistry>,
    pub qos_high: Arc<Semaphore>,
    pub qos_low: Arc<Semaphore>,
    pub breaker_state: Arc<RwLock<HashMap<String, BreakerState>>>,
    pub admin_sessions: Arc<RwLock<HashMap<String, AdminSession>>>,
    pub captcha_store: Arc<RwLock<HashMap<String, CaptchaEntry>>>,
    pub admin_credentials: Arc<RwLock<Option<AdminCredentials>>>,
}

#[derive(Debug, Clone)]
pub struct BreakerState {
    pub fail_streak: u32,
    pub open_until: Option<Instant>,
}

impl BreakerState {
    pub fn closed() -> Self {
        Self {
            fail_streak: 0,
            open_until: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AdminSession {
    pub username: String,
    pub expires_at: Instant,
}

#[derive(Debug, Clone)]
pub struct CaptchaEntry {
    pub answer: String,
    pub expires_at: Instant,
}

#[derive(Debug, Clone)]
pub struct AdminCredentials {
    pub username: String,
    pub password: String,
}
