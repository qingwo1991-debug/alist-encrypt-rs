use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, Method, Request, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use futures_util::TryStreamExt;
use reqwest::Client;
use thiserror::Error;
use tokio::time::{timeout, Duration};
use tracing::{error, info, warn};

use crate::{
    config::TimeoutProfile,
    context::ProxyRequestMeta,
    crypto_core::{apply_crypto, CryptoMode},
    filename_codec::decode_path_segment,
    state::AppState,
    webdav,
};

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("timeout({stage}, {budget_ms}ms)")]
    Timeout { stage: &'static str, budget_ms: u64 },
    #[error("upstream request failed: {0}")]
    Upstream(#[from] reqwest::Error),
}

pub async fn proxy_dav(
    State(state): State<AppState>,
    Path(path): Path<String>,
    req: Request<Body>,
) -> Response {
    proxy_with_prefix(state, "/dav", &path, req).await
}

pub async fn proxy_download(
    State(state): State<AppState>,
    Path(path): Path<String>,
    req: Request<Body>,
) -> Response {
    proxy_with_prefix(state, "/d", &path, req).await
}

pub async fn proxy_play(
    State(state): State<AppState>,
    Path(path): Path<String>,
    req: Request<Body>,
) -> Response {
    proxy_with_prefix(state, "/p", &path, req).await
}

async fn proxy_with_prefix(
    state: AppState,
    prefix: &str,
    path: &str,
    req: Request<Body>,
) -> Response {
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();
    let upstream_url = format!("{}{}{}{}", state.cfg.upstream_base_url, prefix, "/", path);
    let upstream_url = format!("{}{}", upstream_url.trim_end_matches('/'), query);

    let meta = req.extensions().get::<ProxyRequestMeta>().cloned();
    let timeout_profile = meta
        .as_ref()
        .map(|m| m.timeout_profile)
        .unwrap_or(TimeoutProfile {
            connect_ms: 300,
            ttfb_ms: 1500,
            read_idle_ms: 4000,
            total_ms: 20000,
        });

    let client = state.upstream.read().await.clone();
    let runtime = state.runtime.read().await.clone();
    if let Some(resp) = check_breaker_open(&state, &req.headers(), &runtime).await {
        return resp;
    }

    let is_high_priority = prefix == "/d" || prefix == "/p";
    let _permit = if is_high_priority {
        state.qos_high.acquire().await.ok()
    } else {
        state.qos_low.acquire().await.ok()
    };

    match forward_req(
        &state,
        &client,
        upstream_url,
        req,
        timeout_profile,
        meta.as_ref(),
        prefix,
        runtime.max_request_body_bytes,
        runtime.max_response_body_bytes,
    )
    .await
    {
        Ok(resp) => resp,
        Err(e) => {
            let msg = e.to_string();
            if let Some(meta) = meta {
                error!(
                    event = "proxy_error",
                    message = %msg,
                    request_id = %meta.request_id,
                    trace_id = %meta.trace_id,
                    iface_name = %meta.iface_name,
                );
            } else {
                error!(event = "proxy_error", message = %msg);
            }
            match &e {
                ProxyError::Timeout { .. } => state.metrics.inc_timeouts(),
                ProxyError::Upstream(_) => state.metrics.inc_errors(),
            }
            match e {
                ProxyError::Timeout { stage, budget_ms } => (
                    StatusCode::GATEWAY_TIMEOUT,
                    axum::Json(serde_json::json!({
                        "code": 504,
                        "message": format!("timeout({}, {}ms)", stage, budget_ms),
                    })),
                )
                    .into_response(),
                ProxyError::Upstream(err) => (
                    StatusCode::BAD_GATEWAY,
                    axum::Json(serde_json::json!({
                        "code": 502,
                        "message": "proxy failed",
                        "detail": err.to_string()
                    })),
                )
                    .into_response(),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn forward_req(
    state: &AppState,
    client: &Client,
    target_url: String,
    req: Request<Body>,
    timeout_profile: TimeoutProfile,
    meta: Option<&ProxyRequestMeta>,
    prefix: &str,
    max_request_body_bytes: usize,
    max_response_body_bytes: usize,
) -> Result<Response, ProxyError> {
    let (parts, body) = req.into_parts();
    let method = parts.method;
    let headers = parts.headers;
    let mut crypto_cfg = parse_crypto_headers(&headers);
    infer_crypto_cfg_from_strategy(state, &headers, &mut crypto_cfg).await;
    hydrate_crypto_cfg_from_meta_cache(state, &headers, &mut crypto_cfg).await;

    let body_bytes = axum::body::to_bytes(body, max_request_body_bytes)
        .await
        .unwrap_or_default();
    let req_body_size = body_bytes.len() as u64;
    state.metrics.add_bytes_in(req_body_size);
    let mut req_body = body_bytes.to_vec();
    if let Some(cfg) = &crypto_cfg {
        if cfg.encrypt_request {
            apply_crypto(
                cfg.mode,
                &cfg.password,
                cfg.size_salt,
                &mut req_body,
                cfg.offset,
            );
        }
    }

    let mut rb = client.request(method_to_reqwest(&method), &target_url);
    rb = copy_headers_to_reqwest(rb, &headers);

    info!(event = "upstream_forward", method = %method, url = %target_url);

    let send_budget = timeout_profile.ttfb_ms.max(timeout_profile.connect_ms);
    let upstream = timeout(Duration::from_millis(send_budget), rb.body(req_body).send())
        .await
        .map_err(|_| ProxyError::Timeout {
            stage: "ttfb",
            budget_ms: send_budget,
        })??;

    let status = upstream.status();
    update_breaker_state(state, &headers, status.is_success()).await;
    record_strategy_result(state, &headers, &crypto_cfg, status.is_success()).await;
    let resp_headers = upstream.headers().clone();
    maybe_cache_file_meta(state, &headers, &resp_headers, &crypto_cfg).await;

    // PROPFIND XML rewrite needs full body parse.
    if prefix == "/dav"
        && method.as_str().eq_ignore_ascii_case("PROPFIND")
        && resp_headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("xml"))
            .unwrap_or(true)
    {
        let mut resp_bytes = timeout(
            Duration::from_millis(timeout_profile.read_idle_ms),
            upstream.bytes(),
        )
        .await
        .map_err(|_| ProxyError::Timeout {
            stage: "read_idle",
            budget_ms: timeout_profile.read_idle_ms,
        })??;

        let rewritten = webdav::rewrite_propfind_displayname(&resp_bytes, |name| {
            let decoded = decode_path_segment(name);
            if decoded.is_empty() {
                name.to_string()
            } else {
                decoded
            }
        });
        resp_bytes = rewritten.into();

        if let Some(cfg) = &crypto_cfg {
            if cfg.decrypt_response {
                let mut dec = resp_bytes.to_vec();
                apply_crypto(cfg.mode, &cfg.password, cfg.size_salt, &mut dec, cfg.offset);
                resp_bytes = dec.into();
            }
        }

        if resp_bytes.len() > max_response_body_bytes {
            return Err(ProxyError::Timeout {
                stage: "response_limit",
                budget_ms: max_response_body_bytes as u64,
            });
        }

        if let Some(meta) = meta {
            info!(
                event = "upstream_response",
                request_id = %meta.request_id,
                trace_id = %meta.trace_id,
                status = status.as_u16(),
            );
        }
        state.metrics.add_bytes_out(resp_bytes.len() as u64);

        let mut response = Response::builder().status(status);
        for (name, val) in &resp_headers {
            response = response.header(name, val);
        }
        return Ok(response.body(Body::from(resp_bytes)).unwrap_or_else(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, "response build failed").into_response()
        }));
    }

    // Stream response for playback and large files to reduce memory footprint.
    let stream_offset = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
        crypto_cfg.as_ref().map(|c| c.offset).unwrap_or(0),
    ));
    let crypto_for_stream = crypto_cfg.clone();
    let stream = upstream
        .bytes_stream()
        .map_err(std::io::Error::other)
        .and_then(move |chunk| {
            let crypto_for_stream = crypto_for_stream.clone();
            let stream_offset = stream_offset.clone();
            async move {
                if chunk.len() > max_response_body_bytes {
                    return Err(std::io::Error::other("response chunk over limit"));
                }
                let offset = stream_offset
                    .fetch_add(chunk.len() as u64, std::sync::atomic::Ordering::Relaxed);
                if let Some(cfg) = crypto_for_stream {
                    if cfg.decrypt_response {
                        let mut dec = chunk.to_vec();
                        apply_crypto(cfg.mode, &cfg.password, cfg.size_salt, &mut dec, offset);
                        return Ok(Bytes::from(dec));
                    }
                }
                Ok(chunk)
            }
        });

    if let Some(meta) = meta {
        info!(
            event = "upstream_response_streaming",
            request_id = %meta.request_id,
            trace_id = %meta.trace_id,
            status = status.as_u16(),
        );
    }

    let mut response = Response::builder().status(status);
    for (name, val) in &resp_headers {
        response = response.header(name, val);
    }

    Ok(response
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, "response build failed").into_response()
        }))
}

async fn maybe_cache_file_meta(
    state: &AppState,
    req_headers: &HeaderMap,
    resp_headers: &HeaderMap,
    cfg: &Option<CryptoHeaderConfig>,
) {
    let Some(db) = &state.db else {
        return;
    };
    let tenant = req_headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("default");
    let path = req_headers
        .get("x-file-path")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if path.is_empty() {
        return;
    }

    let size = resp_headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    if size == 0 {
        return;
    }

    let enc_mode = cfg.as_ref().map(|c| match c.mode {
        CryptoMode::AesCtr => "aesctr",
        CryptoMode::Rc4 => "rc4",
    });
    if let Err(e) = db.upsert_file_meta(tenant, path, size, enc_mode).await {
        warn!(event = "file_meta_cache_upsert_failed", message = %e);
    }
}

async fn hydrate_crypto_cfg_from_meta_cache(
    state: &AppState,
    headers: &HeaderMap,
    cfg: &mut Option<CryptoHeaderConfig>,
) {
    let Some(cfg_ref) = cfg.as_mut() else {
        return;
    };
    if cfg_ref.size_salt > 0 {
        return;
    }
    let Some(db) = &state.db else {
        return;
    };
    let tenant = headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("default");
    let path = headers
        .get("x-file-path")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if path.is_empty() {
        return;
    }
    match db.get_file_meta_size(tenant, path).await {
        Ok(Some(size)) => cfg_ref.size_salt = size,
        Ok(None) => {}
        Err(e) => warn!(event = "file_meta_cache_get_failed", message = %e),
    }
}

fn copy_headers_to_reqwest(
    mut rb: reqwest::RequestBuilder,
    headers: &HeaderMap,
) -> reqwest::RequestBuilder {
    for (name, value) in headers {
        if name.as_str().eq_ignore_ascii_case("host") {
            continue;
        }
        rb = rb.header(name, value);
    }
    rb
}

fn method_to_reqwest(method: &Method) -> reqwest::Method {
    reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET)
}

#[derive(Clone)]
struct CryptoHeaderConfig {
    mode: CryptoMode,
    password: String,
    size_salt: u64,
    offset: u64,
    encrypt_request: bool,
    decrypt_response: bool,
}

fn parse_crypto_headers(headers: &HeaderMap) -> Option<CryptoHeaderConfig> {
    let mode = headers
        .get("x-enc-mode")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| match v.to_ascii_lowercase().as_str() {
            "aesctr" => Some(CryptoMode::AesCtr),
            "rc4" => Some(CryptoMode::Rc4),
            _ => None,
        })?;
    let password = headers
        .get("x-enc-password")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if password.is_empty() {
        return None;
    }
    let size_salt = headers
        .get("x-file-size")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let offset = headers
        .get("x-enc-offset")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .or_else(|| {
            headers
                .get("range")
                .and_then(|v| v.to_str().ok())
                .and_then(parse_range_start)
        })
        .unwrap_or(0);
    let encrypt_request = headers
        .get("x-enc-request")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let decrypt_response = headers
        .get("x-dec-response")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    Some(CryptoHeaderConfig {
        mode,
        password,
        size_salt,
        offset,
        encrypt_request,
        decrypt_response,
    })
}

fn parse_range_start(range_header: &str) -> Option<u64> {
    let s = range_header.strip_prefix("bytes=")?;
    let first = s.split('-').next()?;
    first.parse::<u64>().ok()
}

async fn infer_crypto_cfg_from_strategy(
    state: &AppState,
    headers: &HeaderMap,
    cfg: &mut Option<CryptoHeaderConfig>,
) {
    if cfg.is_some() {
        return;
    }
    let Some(db) = &state.db else {
        return;
    };
    let runtime = state.runtime.read().await.clone();
    if !runtime.strategy_learning_enabled {
        return;
    }
    let sample = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(stable_percent_0_99)
        .unwrap_or(0);
    if sample >= runtime.strategy_learning_rollout_percent as u64 {
        return;
    }
    let password = headers
        .get("x-enc-password")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if password.is_empty() {
        return;
    }
    let tenant = headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("default");
    let drive = headers
        .get("x-cloud-drive-name")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if drive.is_empty() {
        return;
    }
    let strategy = match db.best_strategy(tenant, drive).await {
        Ok(v) => v,
        Err(_) => None,
    };
    let mode = match strategy.as_deref() {
        Some("aesctr") => Some(CryptoMode::AesCtr),
        Some("rc4") => Some(CryptoMode::Rc4),
        _ => None,
    };
    let Some(mode) = mode else {
        return;
    };
    let size_salt = headers
        .get("x-file-size")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let offset = headers
        .get("x-enc-offset")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .or_else(|| {
            headers
                .get("range")
                .and_then(|v| v.to_str().ok())
                .and_then(parse_range_start)
        })
        .unwrap_or(0);
    *cfg = Some(CryptoHeaderConfig {
        mode,
        password,
        size_salt,
        offset,
        encrypt_request: headers
            .get("x-enc-request")
            .and_then(|v| v.to_str().ok())
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
        decrypt_response: true,
    });
}

fn stable_percent_0_99(s: &str) -> u64 {
    let mut h: u64 = 1469598103934665603;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h % 100
}

async fn record_strategy_result(
    state: &AppState,
    headers: &HeaderMap,
    cfg: &Option<CryptoHeaderConfig>,
    success: bool,
) {
    let Some(cfg) = cfg else {
        return;
    };
    let Some(db) = &state.db else {
        return;
    };
    let tenant = headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("default");
    let drive = headers
        .get("x-cloud-drive-name")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if drive.is_empty() {
        return;
    }
    let strategy_name = match cfg.mode {
        CryptoMode::AesCtr => "aesctr",
        CryptoMode::Rc4 => "rc4",
    };
    if let Err(e) = db
        .record_strategy_result(tenant, drive, strategy_name, success)
        .await
    {
        warn!(event = "strategy_record_failed", message = %e);
    }
}

async fn update_breaker_state(state: &AppState, headers: &HeaderMap, success: bool) {
    let drive = headers
        .get("x-cloud-drive-name")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if drive.is_empty() {
        return;
    }
    let runtime = state.runtime.read().await.clone();
    let mut guard = state.breaker_state.write().await;
    let entry = guard
        .entry(drive.to_string())
        .or_insert_with(crate::state::BreakerState::closed);
    if success {
        entry.fail_streak = 0;
        entry.open_until = None;
        return;
    }
    entry.fail_streak = entry.fail_streak.saturating_add(1);
    if entry.fail_streak >= runtime.circuit_breaker_fail_threshold {
        entry.open_until = Some(
            std::time::Instant::now() + Duration::from_secs(runtime.circuit_breaker_cooldown_secs),
        );
        entry.fail_streak = 0;
    }
}

async fn check_breaker_open(
    state: &AppState,
    headers: &HeaderMap,
    runtime: &crate::config::RuntimeSettings,
) -> Option<Response> {
    let drive = headers
        .get("x-cloud-drive-name")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if drive.is_empty() {
        return None;
    }
    let now = std::time::Instant::now();
    let guard = state.breaker_state.read().await;
    if let Some(bs) = guard.get(drive) {
        if let Some(until) = bs.open_until {
            if until > now {
                return Some(
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        axum::Json(serde_json::json!({
                            "code": 503,
                            "message": format!("circuit open for drive {}, retry later", drive)
                        })),
                    )
                        .into_response(),
                );
            }
        }
    }
    drop(guard);
    let _ = runtime; // keep for future runtime-based overrides
    None
}
