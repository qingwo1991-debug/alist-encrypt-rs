use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
};

use tokio::sync::RwLock;

#[derive(Default)]
pub struct MetricsRegistry {
    pub requests_total: AtomicU64,
    pub request_errors_total: AtomicU64,
    pub request_timeouts_total: AtomicU64,
    pub bytes_upstream_in_total: AtomicU64,
    pub bytes_upstream_out_total: AtomicU64,
    by_iface: RwLock<HashMap<String, u64>>,
}

impl MetricsRegistry {
    pub fn inc_requests(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_errors(&self) {
        self.request_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_timeouts(&self) {
        self.request_timeouts_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_bytes_in(&self, v: u64) {
        self.bytes_upstream_in_total.fetch_add(v, Ordering::Relaxed);
    }

    pub fn add_bytes_out(&self, v: u64) {
        self.bytes_upstream_out_total
            .fetch_add(v, Ordering::Relaxed);
    }

    pub async fn inc_iface(&self, iface: &str) {
        let mut m = self.by_iface.write().await;
        *m.entry(iface.to_string()).or_insert(0) += 1;
    }

    pub async fn render_prometheus(&self) -> String {
        let iface_snapshot = self.by_iface.read().await.clone();
        let mut lines = vec![
            "# TYPE alist_encrypt_requests_total counter".to_string(),
            format!(
                "alist_encrypt_requests_total {}",
                self.requests_total.load(Ordering::Relaxed)
            ),
            "# TYPE alist_encrypt_request_errors_total counter".to_string(),
            format!(
                "alist_encrypt_request_errors_total {}",
                self.request_errors_total.load(Ordering::Relaxed)
            ),
            "# TYPE alist_encrypt_request_timeouts_total counter".to_string(),
            format!(
                "alist_encrypt_request_timeouts_total {}",
                self.request_timeouts_total.load(Ordering::Relaxed)
            ),
            "# TYPE alist_encrypt_upstream_bytes_in_total counter".to_string(),
            format!(
                "alist_encrypt_upstream_bytes_in_total {}",
                self.bytes_upstream_in_total.load(Ordering::Relaxed)
            ),
            "# TYPE alist_encrypt_upstream_bytes_out_total counter".to_string(),
            format!(
                "alist_encrypt_upstream_bytes_out_total {}",
                self.bytes_upstream_out_total.load(Ordering::Relaxed)
            ),
        ];

        lines.push("# TYPE alist_encrypt_iface_requests_total counter".to_string());
        for (iface, v) in iface_snapshot {
            lines.push(format!(
                "alist_encrypt_iface_requests_total{{iface=\"{}\"}} {}",
                escape_label(&iface),
                v
            ));
        }

        lines.join("\n") + "\n"
    }
}

fn escape_label(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"")
}
