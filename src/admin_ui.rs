use axum::response::{Html, IntoResponse};

pub async fn admin_page() -> impl IntoResponse {
    Html(include_str!("../web/admin.html"))
}

pub async fn login_page() -> impl IntoResponse {
    Html(include_str!("../web/login.html"))
}
