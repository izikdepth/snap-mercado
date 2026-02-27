use crate::api::signup;
use axum::{Router, routing::get, routing::post};
use tower_http::cors::{Any, CorsLayer};

#[derive(Clone)]
pub struct AppState {
    pub database_name: String,
}

pub fn routes(state: AppState) -> Router<AppState> {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_credentials(false);

    Router::new()
        .route("/signup", post(signup::signup_request))
        .route("/confirm", get(signup::confirm_email))
        .layer(cors)
        .with_state(state)
}
