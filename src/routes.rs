use axum::{
    extract::{MatchedPath, Request, State},
    http::{header::AUTHORIZATION, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde_json::{json, Value};
use tokio::time::{timeout, Duration, Instant};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    admin_ui,
    context::{ProxyRequestMeta, RequestContext},
    control, proxy,
    state::AppState,
    timeouts,
};

pub fn app_router(state: AppState) -> Router {
    let admin_router = Router::new()
        .route("/ping", get(admin_ping))
        .route(
            "/runtime-settings",
            get(control::get_runtime_settings).put(control::put_runtime_settings),
        )
        .route(
            "/timeout-profiles/:iface_name",
            get(control::get_timeout_profile).put(control::put_timeout_profile),
        )
        .route(
            "/logging-policy",
            get(control::get_logging_policy).put(control::put_logging_policy),
        )
        .route("/codec/encode", post(control::encode_filename))
        .route("/codec/decode", post(control::decode_filename))
        .route("/meta/prefetch-now", post(control::post_meta_prefetch_now))
        .route(
            "/strategy/recommend/:cloud_drive_name",
            get(control::get_strategy_recommendation),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            admin_auth_middleware,
        ));

    Router::new()
        .route("/healthz", get(healthz))
        .route("/admin", get(admin_ui::admin_page))
        .route("/metrics", get(metrics))
        .route("/readyz", get(readyz))
        .nest("/v2/admin", admin_router)
        .route("/dav/*path", axum::routing::any(proxy::proxy_dav))
        .route("/d/*path", axum::routing::any(proxy::proxy_download))
        .route("/p/*path", axum::routing::any(proxy::proxy_play))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            observability_middleware,
        ))
        .with_state(state)
}

async fn admin_auth_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let Some(token) = state.cfg.admin_token.as_ref() else {
        return next.run(req).await;
    };

    let auth = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let expected = format!("Bearer {}", token);
    if auth != expected {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "code": 401,
                "message": "unauthorized"
            })),
        )
            .into_response();
    }
    next.run(req).await
}

async fn healthz() -> Json<Value> {
    Json(json!({"status":"ok"}))
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let body = state.metrics.render_prometheus().await;
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
}

async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    match &state.db {
        Some(db) => match db.ping().await {
            Ok(()) => (StatusCode::OK, Json(json!({"status":"ready"}))).into_response(),
            Err(e) => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"status":"not_ready","reason":e.to_string()})),
            )
                .into_response(),
        },
        None => (
            StatusCode::OK,
            Json(json!({"status":"ready","db":"disabled"})),
        )
            .into_response(),
    }
}

async fn admin_ping() -> Json<Value> {
    Json(json!({"ok": true, "scope":"control"}))
}

async fn observability_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    let request_id = Uuid::new_v4().to_string();
    let trace_id = Uuid::new_v4().to_string();
    let span_id = Uuid::new_v4().to_string();

    let mut req = req;
    let method = req.method().clone();
    let headers = req.headers().clone();
    let path_template = req
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("unknown")
        .to_string();

    let iface_name = infer_iface_name(&method, &path_template);
    let mut timeout_profile = timeouts::default_profile(&path_template);
    let tenant = headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("default");
    let mut allow_raw_filename = state
        .runtime
        .read()
        .await
        .admin_raw_filename_logging_default;
    if let Some(db) = &state.db {
        match db.load_timeout_profile(tenant, &iface_name).await {
            Ok(Some(db_profile)) => timeout_profile = db_profile,
            Ok(None) => {}
            Err(e) => {
                warn!(event = "load_timeout_profile_failed", message = %e, iface_name = %iface_name)
            }
        }
        match db.get_runtime_kv("log_policy.raw_filename_enabled").await {
            Ok(Some(v)) => allow_raw_filename = v == "true",
            Ok(None) => {}
            Err(e) => warn!(event = "load_log_policy_failed", message = %e),
        };
    }

    let mut ctx = RequestContext::new(
        request_id.clone(),
        trace_id.clone(),
        span_id,
        iface_name,
        method.as_str().to_string(),
        path_template,
        timeout_profile,
    );

    enrich_from_headers(&headers, &mut ctx, allow_raw_filename);
    req.extensions_mut().insert(ProxyRequestMeta {
        request_id: ctx.request_id.clone(),
        trace_id: ctx.trace_id.clone(),
        iface_name: ctx.iface_name.clone(),
        timeout_profile: ctx.timeout_profile,
    });

    log_event("request_start", &ctx, None, None, None);
    log_event("upstream_start", &ctx, None, None, None);
    state.metrics.inc_requests();
    state.metrics.inc_iface(&ctx.iface_name).await;

    let total_budget = timeout_profile.total_ms;
    let mut response = if total_budget > 0 {
        match timeout(Duration::from_millis(total_budget), next.run(req)).await {
            Ok(resp) => resp,
            Err(_) => {
                let elapsed = start.elapsed().as_millis() as u64;
                log_timeout("total", &ctx, timeout_profile.total_ms, elapsed);
                state.metrics.inc_timeouts();
                return timeout_response(&ctx, elapsed, StatusCode::GATEWAY_TIMEOUT);
            }
        }
    } else {
        next.run(req).await
    };

    let status = response.status();
    let elapsed = start.elapsed().as_millis() as u64;
    log_event(
        "upstream_first_byte",
        &ctx,
        Some(status),
        Some(elapsed),
        None,
    );
    log_event("response_commit", &ctx, Some(status), Some(elapsed), None);
    log_event(
        "request_end",
        &ctx,
        Some(status),
        Some(elapsed),
        Some(Utc::now().timestamp_millis()),
    );
    attach_response_observability_headers(&mut response, &ctx, elapsed);

    response
}

fn infer_iface_name(method: &Method, path: &str) -> String {
    format!("{} {}", method, path)
}

fn enrich_from_headers(headers: &HeaderMap, ctx: &mut RequestContext, allow_raw_filename: bool) {
    if let Some(v) = headers
        .get("x-cloud-provider")
        .and_then(|v| v.to_str().ok())
    {
        ctx.cloud_provider = Some(v.to_string());
    }
    if let Some(v) = headers
        .get("x-cloud-drive-name")
        .and_then(|v| v.to_str().ok())
    {
        ctx.cloud_drive_name = Some(v.to_string());
    }
    if allow_raw_filename {
        if let Some(v) = headers.get("x-file-name-raw").and_then(|v| v.to_str().ok()) {
            ctx.file.file_name_raw = Some(v.to_string());
        }
    }
    if let Some(v) = headers.get("x-file-name-enc").and_then(|v| v.to_str().ok()) {
        ctx.file.file_name_enc = Some(v.to_string());
    }
    if let Some(v) = headers.get("x-file-path-raw").and_then(|v| v.to_str().ok()) {
        ctx.file.file_path_raw = Some(v.to_string());
    }
    if let Some(v) = headers.get("x-enc-type").and_then(|v| v.to_str().ok()) {
        ctx.file.enc_type = Some(v.to_string());
    }
    if let Some(v) = headers.get("range").and_then(|v| v.to_str().ok()) {
        let r = v.strip_prefix("bytes=").unwrap_or(v);
        let mut parts = r.splitn(2, '-');
        ctx.file.range_start = parts.next().and_then(|s| s.parse::<u64>().ok());
        ctx.file.range_end = parts
            .next()
            .and_then(|s| (!s.is_empty()).then_some(s))
            .and_then(|s| s.parse::<u64>().ok());
    }
}

fn attach_response_observability_headers(
    resp: &mut Response,
    ctx: &RequestContext,
    latency_ms: u64,
) {
    let headers = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&ctx.request_id) {
        headers.insert("x-request-id", v);
    }
    if let Ok(v) = HeaderValue::from_str(&ctx.trace_id) {
        headers.insert("x-trace-id", v);
    }
    if let Ok(v) = HeaderValue::from_str(&latency_ms.to_string()) {
        headers.insert("x-latency-ms", v);
    }
}

fn timeout_response(ctx: &RequestContext, elapsed_ms: u64, status: StatusCode) -> Response {
    let body = Json(json!({
        "code": status.as_u16(),
        "message": "upstream timeout",
        "request_id": ctx.request_id,
        "trace_id": ctx.trace_id,
        "elapsed_ms": elapsed_ms,
    }));

    (status, body).into_response()
}

fn log_event(
    event: &str,
    ctx: &RequestContext,
    status: Option<StatusCode>,
    latency_ms: Option<u64>,
    end_ts_unix_ms: Option<i64>,
) {
    info!(
        event = event,
        ts_unix_ms = ctx.ts_unix_ms,
        ts_rfc3339 = %ctx.ts_rfc3339,
        end_ts_unix_ms = end_ts_unix_ms.unwrap_or(0),
        request_id = %ctx.request_id,
        trace_id = %ctx.trace_id,
        span_id = %ctx.span_id,
        process_name = %ctx.process_name,
        pid = ctx.pid,
        iface_name = %ctx.iface_name,
        method = %ctx.method,
        path_template = %ctx.path_template,
        status = status.map(|s| s.as_u16()).unwrap_or(0),
        latency_ms = latency_ms.unwrap_or(0),
        cloud_provider = ctx.cloud_provider.as_deref().unwrap_or(""),
        cloud_drive_name = ctx.cloud_drive_name.as_deref().unwrap_or(""),
        file_name_raw = ctx.file.file_name_raw.as_deref().unwrap_or(""),
        file_name_enc = ctx.file.file_name_enc.as_deref().unwrap_or(""),
        enc_type = ctx.file.enc_type.as_deref().unwrap_or(""),
        timeout_connect_ms = ctx.timeout_profile.connect_ms,
        timeout_ttfb_ms = ctx.timeout_profile.ttfb_ms,
        timeout_read_idle_ms = ctx.timeout_profile.read_idle_ms,
        timeout_total_ms = ctx.timeout_profile.total_ms,
    );
}

fn log_timeout(stage: &str, ctx: &RequestContext, budget_ms: u64, actual_ms: u64) {
    error!(
        event = "timeout",
        timeout_stage = stage,
        timeout_budget_ms = budget_ms,
        timeout_actual_ms = actual_ms,
        message = format!("timeout({}, {}ms)", stage, budget_ms),
        request_id = %ctx.request_id,
        trace_id = %ctx.trace_id,
        iface_name = %ctx.iface_name,
        method = %ctx.method,
        path_template = %ctx.path_template,
        cloud_drive_name = ctx.cloud_drive_name.as_deref().unwrap_or(""),
        file_name_raw = ctx.file.file_name_raw.as_deref().unwrap_or(""),
        file_name_enc = ctx.file.file_name_enc.as_deref().unwrap_or(""),
    );
}
