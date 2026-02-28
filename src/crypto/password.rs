use crate::api::{errors::AuthError, routes::AppState};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use axum::extract::State;
use sqlite::{Connection, OpenFlags};

// this function is used to hash passwords
pub async fn hash_password(password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| AuthError::HashFailed {
            message: "password hash failed".to_string(),
        })?
        .to_string();
    Ok(hash)
}

// this function is used to compare and verify password hashes
pub async fn verify_password(
    State(state): State<AppState>,
    user_id: &str,
    password: &str,
) -> Result<bool, AuthError> {
    // connect to db
    let conn = Connection::open_with_flags(
        &state.database_name,
        OpenFlags::new().with_create().with_read_write(),
    )?;

    // get password hash from db
    let mut stmt = conn
        .prepare("SELECT password FROM users WHERE user_id = ?")
        .map_err(|_| AuthError::UserNotFound {
            message: "User not found in the system".to_string(),
        })?;

    stmt.bind((1, user_id))
        .map_err(|_| AuthError::UserNotFound {
            message: "User not found in the system".to_string(),
        })?;

    let hash: String = match stmt.next() {
        Ok(sqlite::State::Row) => {
            stmt.read::<String, _>(0)
                .map_err(|_| AuthError::UserNotFound {
                    message: "User not found in the system".to_string(),
                })?
        }
        _ => {
            return Err(AuthError::UserNotFound {
                message: "User not found in the system".to_string(),
            });
        }
    };

    let parsed_hash = PasswordHash::new(&hash).map_err(|_| AuthError::HashFailed {
        message: "failed to parse hash".to_string(),
    })?;

    // compare hashes to verify
    let matches = Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok();

    Ok(matches)
}
