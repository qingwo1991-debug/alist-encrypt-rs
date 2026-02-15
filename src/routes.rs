use axum::{
    extract::{MatchedPath, Request, State},
    http::{
        header::{AUTHORIZATION, COOKIE, LOCATION, SET_COOKIE},
        HeaderMap, HeaderValue, Method, StatusCode,
    },
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use rand::{thread_rng, Rng};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Instant;
use tokio::time::{sleep, timeout, Duration};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    admin_ui,
    config::AdminCookieSecureMode,
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
        .route(
            "/admin",
            get(admin_ui::admin_page).route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                admin_page_auth_middleware,
            )),
        )
        .route("/login", get(admin_ui::login_page))
        .route("/metrics", get(metrics))
        .route("/readyz", get(readyz))
        .route("/v2/auth/captcha", get(auth_captcha))
        .route("/v2/auth/login", post(auth_login))
        .route("/v2/auth/logout", post(auth_logout))
        .route(
            "/v2/auth/change-credentials",
            post(auth_change_credentials).route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                admin_auth_middleware,
            )),
        )
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
    let auth_required = state.cfg.admin_token.is_some() || password_login_enabled(&state).await;
    if !auth_required {
        return next.run(req).await;
    }
    if !is_admin_authorized(req.headers(), &state).await {
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

async fn admin_page_auth_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    if !password_login_enabled(&state).await {
        return next.run(req).await;
    }
    if is_admin_authorized(req.headers(), &state).await {
        return next.run(req).await;
    }
    (StatusCode::FOUND, [(LOCATION, "/login")]).into_response()
}

async fn is_admin_authorized(headers: &HeaderMap, state: &AppState) -> bool {
    if let Some(token) = state.cfg.admin_token.as_ref() {
        let auth = headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let expected = format!("Bearer {}", token);
        if auth == expected {
            return true;
        }
    }

    if !password_login_enabled(state).await {
        return false;
    }

    let Some(session_id) = cookie_value(headers, "ae_admin_session") else {
        return false;
    };

    let now = Instant::now();
    let mut sessions = state.admin_sessions.write().await;
    sessions.retain(|_, v| v.expires_at > now);
    if let Some(session) = sessions.get(&session_id) {
        let _ = &session.username;
        return session.expires_at > now;
    }
    false
}

async fn password_login_enabled(state: &AppState) -> bool {
    state.admin_credentials.read().await.is_some()
}

fn cookie_value(headers: &HeaderMap, key: &str) -> Option<String> {
    let raw = headers.get(COOKIE)?.to_str().ok()?;
    raw.split(';').map(str::trim).find_map(|pair| {
        let mut parts = pair.splitn(2, '=');
        let k = parts.next()?;
        let v = parts.next()?;
        if k == key {
            Some(v.to_string())
        } else {
            None
        }
    })
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
    captcha_id: String,
    captcha_code: String,
}

#[derive(Debug, Deserialize)]
struct ChangeCredentialsRequest {
    current_password: String,
    new_username: String,
    new_password: String,
    captcha_id: String,
    captcha_code: String,
}

async fn auth_captcha(State(state): State<AppState>) -> impl IntoResponse {
    if !password_login_enabled(&state).await {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"code": 400, "message": "password login disabled"})),
        );
    }

    let captcha_id = Uuid::new_v4().to_string();
    let code = {
        let mut rng = thread_rng();
        format!("{:06}", rng.gen_range(0..1_000_000))
    };
    let svg = render_captcha_svg(&code);
    let now = Instant::now();
    let ttl = Duration::from_secs(state.cfg.admin_captcha_ttl_secs.max(30));

    let mut store = state.captcha_store.write().await;
    store.retain(|_, v| v.expires_at > now);
    store.insert(
        captcha_id.clone(),
        crate::state::CaptchaEntry {
            answer: code,
            expires_at: now + ttl,
        },
    );

    (
        StatusCode::OK,
        Json(json!({
            "code": 0,
            "data": {
                "captcha_id": captcha_id,
                "svg": svg,
                "expires_in_secs": ttl.as_secs()
            }
        })),
    )
}

async fn auth_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> Response {
    if !password_login_enabled(&state).await {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"code": 400, "message": "password login disabled"})),
        )
            .into_response();
    }

    if !consume_captcha(
        &state,
        payload.captcha_id.trim(),
        payload.captcha_code.trim(),
    )
    .await
    {
        sleep(Duration::from_millis(300)).await;
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"code": 401, "message": "invalid captcha"})),
        )
            .into_response();
    }

    let creds = state.admin_credentials.read().await.clone();
    let (username_ok, password_ok) = match creds {
        Some(c) => (
            c.username == payload.username.trim(),
            c.password == payload.password.as_str(),
        ),
        None => (false, false),
    };
    if !(username_ok && password_ok) {
        sleep(Duration::from_millis(300)).await;
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"code": 401, "message": "invalid credentials"})),
        )
            .into_response();
    }

    let session_id = random_session_id();
    let session_ttl = state.cfg.admin_session_ttl_secs.max(300);
    let now = Instant::now();
    let mut sessions = state.admin_sessions.write().await;
    sessions.retain(|_, v| v.expires_at > now);
    sessions.insert(
        session_id.clone(),
        crate::state::AdminSession {
            username: payload.username,
            expires_at: now + Duration::from_secs(session_ttl),
        },
    );

    let cookie = build_session_cookie(
        &session_id,
        session_ttl,
        cookie_should_be_secure(state.cfg.admin_cookie_secure_mode, &headers),
        false,
    );
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        headers.insert(SET_COOKIE, v);
    }

    (
        StatusCode::OK,
        headers,
        Json(json!({"code": 0, "message": "ok"})),
    )
        .into_response()
}

async fn auth_logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(session_id) = cookie_value(&headers, "ae_admin_session") {
        let mut sessions = state.admin_sessions.write().await;
        sessions.remove(&session_id);
    }
    let cookie = build_session_cookie(
        "",
        0,
        cookie_should_be_secure(state.cfg.admin_cookie_secure_mode, &headers),
        true,
    );
    let mut out_headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        out_headers.insert(SET_COOKIE, v);
    }
    (
        StatusCode::OK,
        out_headers,
        Json(json!({"code": 0, "message": "logged out"})),
    )
        .into_response()
}

async fn auth_change_credentials(
    State(state): State<AppState>,
    Json(payload): Json<ChangeCredentialsRequest>,
) -> Response {
    if !password_login_enabled(&state).await {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"code": 400, "message": "password login disabled"})),
        )
            .into_response();
    }

    let new_username = payload.new_username.trim();
    if new_username.is_empty() || payload.new_password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"code": 400, "message": "username/password cannot be empty"})),
        )
            .into_response();
    }

    if !consume_captcha(
        &state,
        payload.captcha_id.trim(),
        payload.captcha_code.trim(),
    )
    .await
    {
        sleep(Duration::from_millis(300)).await;
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"code": 401, "message": "invalid captcha"})),
        )
            .into_response();
    }

    {
        let creds = state.admin_credentials.read().await;
        let Some(current) = creds.as_ref() else {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"code": 400, "message": "password login disabled"})),
            )
                .into_response();
        };
        if current.password != payload.current_password {
            sleep(Duration::from_millis(300)).await;
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"code": 401, "message": "current password invalid"})),
            )
                .into_response();
        }
    }

    {
        let mut creds = state.admin_credentials.write().await;
        *creds = Some(crate::state::AdminCredentials {
            username: new_username.to_string(),
            password: payload.new_password.clone(),
        });
    }

    if let Some(db) = &state.db {
        if let Err(e) = db
            .set_runtime_kv_json("admin.auth.username", &format!("\"{}\"", new_username))
            .await
        {
            warn!(event = "save_admin_username_failed", message = %e);
        }
        if let Err(e) = db
            .set_runtime_kv_json(
                "admin.auth.password",
                &format!("\"{}\"", payload.new_password),
            )
            .await
        {
            warn!(event = "save_admin_password_failed", message = %e);
        }
    }

    (
        StatusCode::OK,
        Json(json!({"code": 0, "message": "credentials updated"})),
    )
        .into_response()
}

async fn consume_captcha(state: &AppState, captcha_id: &str, captcha_code: &str) -> bool {
    let now = Instant::now();
    let mut store = state.captcha_store.write().await;
    store.retain(|_, v| v.expires_at > now);
    match store.remove(captcha_id) {
        Some(v) => v.expires_at > now && v.answer == captcha_code,
        None => false,
    }
}

fn random_session_id() -> String {
    let mut rng = thread_rng();
    let mut buf = String::with_capacity(48);
    for _ in 0..48 {
        let n: u8 = rng.gen_range(0..16);
        buf.push(char::from_digit(n as u32, 16).unwrap_or('0'));
    }
    buf
}

fn build_session_cookie(session_id: &str, max_age_secs: u64, secure: bool, clear: bool) -> String {
    let mut cookie = if clear {
        "ae_admin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0".to_string()
    } else {
        format!(
            "ae_admin_session={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
            session_id, max_age_secs
        )
    };
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

fn cookie_should_be_secure(mode: AdminCookieSecureMode, headers: &HeaderMap) -> bool {
    match mode {
        AdminCookieSecureMode::Always => true,
        AdminCookieSecureMode::Off => false,
        AdminCookieSecureMode::Auto => request_looks_https(headers),
    }
}

fn request_looks_https(headers: &HeaderMap) -> bool {
    let proto_https = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                v.split(',')
                    .next()
                    .map(|s| s.trim().eq_ignore_ascii_case("https"))
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    };
    if proto_https("x-forwarded-proto")
        || proto_https("x-forwarded-protocol")
        || proto_https("x-url-scheme")
    {
        return true;
    }
    headers
        .get("cf-visitor")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("\"scheme\":\"https\""))
        .unwrap_or(false)
}

fn render_captcha_svg(code: &str) -> String {
    let mut rng = thread_rng();
    let mut noise = String::new();
    for _ in 0..6 {
        let x1: i32 = rng.gen_range(0..160);
        let y1: i32 = rng.gen_range(0..60);
        let x2: i32 = rng.gen_range(0..160);
        let y2: i32 = rng.gen_range(0..60);
        noise.push_str(&format!(
            "<line x1='{x1}' y1='{y1}' x2='{x2}' y2='{y2}' stroke='#9ca3af' stroke-width='1' />"
        ));
    }

    format!(
        "<svg xmlns='http://www.w3.org/2000/svg' width='160' height='60' viewBox='0 0 160 60'>\
<rect width='160' height='60' fill='#f3f4f6' rx='8'/>\
{noise}\
<text x='18' y='40' font-size='30' font-family='monospace' fill='#111827' letter-spacing='4'>{code}</text>\
</svg>"
    )
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
