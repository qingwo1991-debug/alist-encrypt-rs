use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    config::{RuntimeSettings, TimeoutProfile},
    filename_codec::{decode_path_segment, encode_path_segment},
    state::AppState,
    upstream::build_upstream_client,
};

#[derive(Debug, Deserialize)]
pub struct TimeoutProfileUpdate {
    pub tenant_id: String,
    pub connect_ms: u64,
    pub ttfb_ms: u64,
    pub read_idle_ms: u64,
    pub total_ms: u64,
}

#[derive(Debug, Deserialize)]
pub struct LoggingPolicyUpdate {
    pub tenant_id: String,
    pub raw_filename_enabled: bool,
}

#[derive(Debug, Serialize)]
struct ApiResp<T: Serialize> {
    code: u16,
    message: String,
    data: T,
}

#[derive(Debug, Deserialize)]
pub struct CodecPayload {
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct RuntimeSettingsUpdate {
    pub tenant_id: Option<String>,
    pub settings: RuntimeSettings,
}

#[derive(Debug, Deserialize)]
pub struct MetaPrefetchNowReq {
    pub stale_secs: Option<u64>,
    pub batch: Option<usize>,
}

pub async fn get_timeout_profile(
    State(state): State<AppState>,
    Path(iface_name): Path<String>,
) -> impl IntoResponse {
    let Some(db) = &state.db else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiResp {
                code: 503,
                message: "db unavailable".to_string(),
                data: serde_json::json!({}),
            }),
        )
            .into_response();
    };

    match db.load_timeout_profile("default", &iface_name).await {
        Ok(Some(profile)) => (
            StatusCode::OK,
            Json(ApiResp {
                code: 200,
                message: "ok".to_string(),
                data: serde_json::json!(profile),
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiResp {
                code: 404,
                message: "not found".to_string(),
                data: serde_json::json!({}),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResp {
                code: 500,
                message: e.to_string(),
                data: serde_json::json!({}),
            }),
        )
            .into_response(),
    }
}

pub async fn put_timeout_profile(
    State(state): State<AppState>,
    Path(iface_name): Path<String>,
    Json(payload): Json<TimeoutProfileUpdate>,
) -> impl IntoResponse {
    let Some(db) = &state.db else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiResp {
                code: 503,
                message: "db unavailable".to_string(),
                data: serde_json::json!({}),
            }),
        )
            .into_response();
    };

    let profile = TimeoutProfile {
        connect_ms: payload.connect_ms,
        ttfb_ms: payload.ttfb_ms,
        read_idle_ms: payload.read_idle_ms,
        total_ms: payload.total_ms,
    };

    match db
        .upsert_timeout_profile(&payload.tenant_id, &iface_name, profile)
        .await
    {
        Ok(_) => {
            let payload_json = serde_json::json!({
                "iface_name": iface_name,
                "tenant_id": payload.tenant_id,
                "profile": profile
            });
            audit_if_possible(
                state,
                &payload.tenant_id,
                "system",
                "put_timeout_profile",
                &iface_name,
                payload_json,
            )
            .await;
            (
                StatusCode::OK,
                Json(ApiResp {
                    code: 200,
                    message: "saved".to_string(),
                    data: serde_json::json!({
                        "iface_name": iface_name,
                        "tenant_id": payload.tenant_id,
                        "profile": profile
                    }),
                }),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResp {
                code: 500,
                message: e.to_string(),
                data: serde_json::json!({}),
            }),
        )
            .into_response(),
    }
}

pub async fn get_logging_policy(State(state): State<AppState>) -> impl IntoResponse {
    let runtime = state.runtime.read().await;
    (
        StatusCode::OK,
        Json(ApiResp {
            code: 200,
            message: "ok".to_string(),
            data: serde_json::json!({
                "raw_filename_enabled": runtime.admin_raw_filename_logging_default
            }),
        }),
    )
}

pub async fn put_logging_policy(
    State(state): State<AppState>,
    Json(payload): Json<LoggingPolicyUpdate>,
) -> impl IntoResponse {
    if let Some(db) = &state.db {
        let key = "log_policy.raw_filename_enabled";
        let value = if payload.raw_filename_enabled {
            "true"
        } else {
            "false"
        };
        if let Err(e) = db.set_runtime_kv_json(key, &format!("\"{}\"", value)).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResp {
                    code: 500,
                    message: e.to_string(),
                    data: serde_json::json!({}),
                }),
            )
                .into_response();
        }
    }

    {
        let mut rt = state.runtime.write().await;
        rt.admin_raw_filename_logging_default = payload.raw_filename_enabled;
    }

    let payload_json = serde_json::json!({
        "tenant_id": payload.tenant_id,
        "raw_filename_enabled": payload.raw_filename_enabled
    });
    audit_if_possible(
        state,
        &payload.tenant_id,
        "system",
        "put_logging_policy",
        "log_policy.raw_filename_enabled",
        payload_json,
    )
    .await;

    (
        StatusCode::OK,
        Json(ApiResp {
            code: 200,
            message: "saved".to_string(),
            data: serde_json::json!({
                "tenant_id": payload.tenant_id,
                "raw_filename_enabled": payload.raw_filename_enabled
            }),
        }),
    )
        .into_response()
}

pub async fn get_runtime_settings(State(state): State<AppState>) -> impl IntoResponse {
    let rt = state.runtime.read().await.clone();
    (
        StatusCode::OK,
        Json(ApiResp {
            code: 200,
            message: "ok".to_string(),
            data: serde_json::json!(rt),
        }),
    )
}

pub async fn put_runtime_settings(
    State(state): State<AppState>,
    Json(payload): Json<RuntimeSettingsUpdate>,
) -> impl IntoResponse {
    let tenant_id = payload
        .tenant_id
        .clone()
        .unwrap_or_else(|| "default".to_string());

    if let Some(db) = &state.db {
        if let Err(e) = db
            .set_runtime_kv_json(
                "runtime.settings",
                &serde_json::to_string(&payload.settings).unwrap_or_else(|_| "{}".to_string()),
            )
            .await
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResp {
                    code: 500,
                    message: e.to_string(),
                    data: serde_json::json!({}),
                }),
            )
                .into_response();
        }
    }

    let new_client = match build_upstream_client(&payload.settings) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResp {
                    code: 400,
                    message: format!("invalid runtime settings: {e}"),
                    data: serde_json::json!({}),
                }),
            )
                .into_response();
        }
    };

    {
        let mut runtime_guard = state.runtime.write().await;
        *runtime_guard = payload.settings.clone();
    }
    {
        let mut upstream_guard = state.upstream.write().await;
        *upstream_guard = new_client;
    }

    let payload_json = serde_json::json!({
        "tenant_id": tenant_id,
        "settings": payload.settings
    });
    audit_if_possible(
        state,
        &tenant_id,
        "system",
        "put_runtime_settings",
        "runtime.settings",
        payload_json,
    )
    .await;

    (
        StatusCode::OK,
        Json(ApiResp {
            code: 200,
            message: "saved_and_applied".to_string(),
            data: serde_json::json!({ "ok": true }),
        }),
    )
        .into_response()
}

pub async fn post_meta_prefetch_now(
    State(state): State<AppState>,
    Json(payload): Json<MetaPrefetchNowReq>,
) -> impl IntoResponse {
    let stale_secs = payload.stale_secs.unwrap_or(0);
    let batch = payload.batch.unwrap_or(32);
    match crate::meta_prefetch::run_one_cycle(&state, stale_secs, batch).await {
        Ok(()) => (
            StatusCode::OK,
            Json(ApiResp {
                code: 200,
                message: "prefetch_done".to_string(),
                data: serde_json::json!({ "stale_secs": stale_secs, "batch": batch }),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResp {
                code: 500,
                message: e.to_string(),
                data: serde_json::json!({}),
            }),
        )
            .into_response(),
    }
}

pub async fn get_strategy_recommendation(
    State(state): State<AppState>,
    Path(cloud_drive_name): Path<String>,
) -> impl IntoResponse {
    let Some(db) = &state.db else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiResp {
                code: 503,
                message: "db unavailable".to_string(),
                data: serde_json::json!({}),
            }),
        )
            .into_response();
    };
    match db.best_strategy("default", &cloud_drive_name).await {
        Ok(Some(name)) => (
            StatusCode::OK,
            Json(ApiResp {
                code: 200,
                message: "ok".to_string(),
                data: serde_json::json!({ "cloud_drive_name": cloud_drive_name, "best_strategy": name }),
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::OK,
            Json(ApiResp {
                code: 200,
                message: "no_data".to_string(),
                data: serde_json::json!({ "cloud_drive_name": cloud_drive_name }),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResp {
                code: 500,
                message: e.to_string(),
                data: serde_json::json!({}),
            }),
        )
            .into_response(),
    }
}

pub async fn encode_filename(Json(payload): Json<CodecPayload>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(ApiResp {
            code: 200,
            message: "ok".to_string(),
            data: serde_json::json!({
                "encoded": encode_path_segment(&payload.value)
            }),
        }),
    )
}

pub async fn decode_filename(Json(payload): Json<CodecPayload>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(ApiResp {
            code: 200,
            message: "ok".to_string(),
            data: serde_json::json!({
                "decoded": decode_path_segment(&payload.value)
            }),
        }),
    )
}

async fn audit_if_possible(
    state: AppState,
    tenant_id: &str,
    actor: &str,
    action: &str,
    target: &str,
    payload_json: serde_json::Value,
) {
    if let Some(db) = &state.db {
        let request_id = "control-plane";
        let trace_id = "control-plane";
        if let Err(e) = db
            .insert_audit_log(
                tenant_id,
                request_id,
                trace_id,
                actor,
                action,
                target,
                &payload_json.to_string(),
            )
            .await
        {
            warn!(event = "audit_log_failed", message = %e, action = action, target = target);
        }
    }
}
