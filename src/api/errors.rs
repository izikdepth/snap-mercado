use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use derive_more::Display;

#[derive(Clone, Debug, Display)]
pub enum AuthError {
    #[display(fmt = "Authentication error: {}", message)]
    Authentication {
        message: String,
    },
    #[display(fmt = "Signup error: {}", message)]
    Signup {
        message: String,
    },
    #[display(fmt = "Password reset error: {}", message)]
    PasswordReset {
        message: String,
    },
    Network(String),
    HttpError(u16), // status code for HTTP errors

    #[display(fmt = "Invalid Data: {}", message)]
    InvalidData {
        message: String,
    },
    #[display(fmt = "Token creation error: {}", message)]
    TokenCreation {
        message: String,
    },

    #[display(fmt = "Invalid token error: {}", message)]
    InvalidToken {
        message: String,
    },
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = match &self {
            AuthError::Authentication { .. } => StatusCode::UNAUTHORIZED,
            AuthError::Signup { .. } => StatusCode::BAD_REQUEST,
            AuthError::PasswordReset { .. } => StatusCode::BAD_REQUEST,
            AuthError::Network(_) => StatusCode::SERVICE_UNAVAILABLE,
            AuthError::HttpError(code) => {
                StatusCode::from_u16(*code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
            }
            AuthError::InvalidData { .. } => StatusCode::BAD_REQUEST,
            AuthError::TokenCreation { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::InvalidToken { .. } => StatusCode::UNAUTHORIZED,
        };

        (status, self.to_string()).into_response()
    }
}

impl From<sqlite::Error> for AuthError {
    fn from(e: sqlite::Error) -> Self {
        AuthError::Signup {
            message: format!("Database error: {}", e),
        }
    }
}

impl From<jsonwebtoken::errors::Error> for AuthError {
    fn from(value: jsonwebtoken::errors::Error) -> Self {
        AuthError::TokenCreation {
            message: format!("JWT Token error: {}", value),
        }
    }
}
