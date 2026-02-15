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
