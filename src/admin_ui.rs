use axum::response::{Html, IntoResponse};

pub async fn admin_page() -> impl IntoResponse {
    Html(include_str!("../web/admin.html"))
}
