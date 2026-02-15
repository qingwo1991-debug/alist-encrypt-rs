use std::time::Duration;

use reqwest::Client;
use tokio::time::interval;
use tracing::{info, warn};

use crate::state::AppState;

pub fn spawn_meta_prefetch_worker(state: AppState) {
    tokio::spawn(async move {
        loop {
            let cfg = state.runtime.read().await.clone();
            if !cfg.metadata_prefetch_enabled {
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }

            let mut ticker = interval(Duration::from_secs(cfg.metadata_prefetch_interval_secs));
            ticker.tick().await;
            ticker.tick().await;

            if let Err(e) = run_one_cycle(
                &state,
                cfg.metadata_prefetch_stale_secs,
                cfg.metadata_prefetch_batch,
            )
            .await
            {
                warn!(event = "meta_prefetch_cycle_failed", message = %e);
            }
        }
    });
}

pub async fn run_one_cycle(
    state: &AppState,
    stale_secs: u64,
    batch: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(db) = &state.db else {
        return Ok(());
    };

    let targets = db.list_stale_file_meta_paths(stale_secs, batch).await?;
    if targets.is_empty() {
        return Ok(());
    }

    let client = state.upstream.read().await.clone();
    let tenant = "default";
    for (path, old_size) in targets {
        if let Ok(Some(size)) = prefetch_size(&client, &state.cfg.upstream_base_url, &path).await {
            db.upsert_file_meta(tenant, &path, size, None).await?;
            if size != old_size {
                info!(event = "meta_prefetch_updated", file_path = %path, old_size = old_size, new_size = size);
            }
        }
    }

    Ok(())
}

async fn prefetch_size(
    client: &Client,
    upstream_base_url: &str,
    file_path: &str,
) -> Result<Option<u64>, reqwest::Error> {
    let url = format!("{}{}", upstream_base_url.trim_end_matches('/'), file_path);
    let resp = client.head(&url).send().await?;
    if !resp.status().is_success() {
        return Ok(None);
    }
    let size = resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    Ok(size)
}
