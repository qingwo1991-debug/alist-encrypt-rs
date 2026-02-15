use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::config::TimeoutProfile;

#[derive(Debug, Clone, Serialize)]
pub struct FileContext {
    pub file_path_raw: Option<String>,
    pub file_name_raw: Option<String>,
    pub file_name_enc: Option<String>,
    pub enc_type: Option<String>,
    pub range_start: Option<u64>,
    pub range_end: Option<u64>,
    pub file_size: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestContext {
    pub ts_unix_ms: i64,
    pub ts_rfc3339: DateTime<Utc>,
    pub request_id: String,
    pub trace_id: String,
    pub span_id: String,
    pub process_name: String,
    pub pid: u32,
    pub iface_name: String,
    pub method: String,
    pub path_template: String,
    pub cloud_provider: Option<String>,
    pub cloud_drive_name: Option<String>,
    pub timeout_profile: TimeoutProfile,
    pub file: FileContext,
}

#[derive(Debug, Clone)]
pub struct ProxyRequestMeta {
    pub request_id: String,
    pub trace_id: String,
    pub iface_name: String,
    pub timeout_profile: TimeoutProfile,
}

impl RequestContext {
    pub fn new(
        request_id: String,
        trace_id: String,
        span_id: String,
        iface_name: String,
        method: String,
        path_template: String,
        timeout_profile: TimeoutProfile,
    ) -> Self {
        let now = Utc::now();
        Self {
            ts_unix_ms: now.timestamp_millis(),
            ts_rfc3339: now,
            request_id,
            trace_id,
            span_id,
            process_name: env!("CARGO_PKG_NAME").to_string(),
            pid: std::process::id(),
            iface_name,
            method,
            path_template,
            cloud_provider: None,
            cloud_drive_name: None,
            timeout_profile,
            file: FileContext {
                file_path_raw: None,
                file_name_raw: None,
                file_name_enc: None,
                enc_type: None,
                range_start: None,
                range_end: None,
                file_size: None,
            },
        }
    }
}
