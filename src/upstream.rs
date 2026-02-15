use std::time::Duration;

use reqwest::Client;

use crate::config::RuntimeSettings;

pub fn build_upstream_client(settings: &RuntimeSettings) -> Result<Client, reqwest::Error> {
    let mut b = Client::builder()
        .pool_max_idle_per_host(settings.upstream_pool_max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(
            settings.upstream_pool_idle_timeout_secs,
        ))
        .tcp_keepalive(Duration::from_secs(60))
        .connect_timeout(Duration::from_millis(settings.upstream_connect_timeout_ms))
        .timeout(Duration::from_millis(settings.upstream_request_timeout_ms))
        .tcp_nodelay(settings.upstream_tcp_nodelay)
        .http2_adaptive_window(settings.upstream_http2_adaptive_window)
        .http2_keep_alive_interval(Duration::from_secs(
            settings.upstream_http2_keepalive_interval_secs,
        ))
        .http2_keep_alive_timeout(Duration::from_secs(
            settings.upstream_http2_keepalive_timeout_secs,
        ))
        .http2_keep_alive_while_idle(true);

    if settings.upstream_http2_only {
        b = b.http2_prior_knowledge();
    }

    b.build()
}
