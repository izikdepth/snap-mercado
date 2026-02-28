use crate::api::{AuthError, routes::AppState};
use crate::crypto::password::hash_password;
use axum::response::IntoResponse;
use axum::response::Redirect;
use axum::{Json, extract::Query, extract::State};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use dotenv::dotenv;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use lettre::message::{Message, header};
use serde::{Deserialize, Serialize};
use sqlite::{Connection, OpenFlags};
use std::env;
use uuid::Uuid;

/// This struct holds the vars expected in a signup request
#[derive(Serialize, Deserialize)]
pub struct RegistrationRequest {
    pub username: String,
    pub email: String,
}

#[derive(Deserialize)]
pub struct UrlExtraction {
    pub token: String,
}

#[derive(Deserialize)]
pub struct ConfirmationClaim {
    pub email: String,
    pub username: String,
    pub exp: i64,
}

/// takes appdata, registration request (email, username)  and returns an ok response or authentication error.
#[axum::debug_handler]
pub async fn signup_request(
    State(state): State<AppState>,
    Json(r): Json<RegistrationRequest>,
) -> std::result::Result<(), AuthError> {
    // open a connection to the sqlite3 database
    let db_path = &state.database_name;

    let conn =
        Connection::open_with_flags(db_path, OpenFlags::new().with_create().with_read_write())?;

    // check for empty fields (username and email)
    let empty_fields: Vec<String> = [("username", &r.username), ("email", &r.email)]
        .iter()
        .filter(|(_, value)| value.trim().is_empty())
        .map(|(field, _)| field.to_string())
        .collect();

    if !empty_fields.is_empty() {
        return Err(AuthError::InvalidData {
            message: format!(
                "The following fields cannot be empty: {}",
                empty_fields.join(", ")
            ),
        });
    }

    // check if username or email already exists
    {
        let mut stmt =
            conn.prepare("SELECT username, email FROM users WHERE username = ? OR email = ?")?;

        stmt.bind((1, r.username.as_str()))?;

        stmt.bind((2, r.email.as_str()))?;

        let mut already_exists: Vec<String> = Vec::new();

        if let Ok(sqlite::State::Row) = stmt.next() {
            let db_username: String = stmt.read::<String, _>("username").unwrap_or_default();
            let db_email: String = stmt.read::<String, _>("email").unwrap_or_default();

            if db_username == r.username {
                already_exists.push("username".to_string());
            }
            if db_email == r.email {
                already_exists.push("email".to_string());
            }
        }

        if !already_exists.is_empty() {
            return Err(AuthError::Signup {
                message: format!("Username or email already exists."),
            });
        }
    }

    // send confirmation email
    send_confirmation_email(&r).await?;

    Ok(())
}

// this function creates and sends a confirmation email to a user with an expiry of 30 minutes.
async fn send_confirmation_email(r: &RegistrationRequest) -> std::result::Result<(), AuthError> {
    dotenv().ok();

    let secret_key = env::var("JWT_SECRET").expect("JWT_SECRET is not set");
    let encoding_key = EncodingKey::from_secret(secret_key.as_ref());

    // encode the email and username into a jwt token with an expiry of 30 mins
    let token = encode(
        &Header::default(),
        &serde_json::json!({
            "email": &r.email,
            "username": &r.username,
            "exp": chrono::Utc::now().timestamp() + 1800, // 30 min expiry
        }),
        &encoding_key,
    )?;

    // form confirmation link with link + encoded token
    let confirmation_url = format!(
        "{}/confirm?token={}",
        env::var("MARKET_URL").expect("MARKET_URL is not set"),
        token
    );

    // load mailbox from env
    let mbox = env::var("MBOX").expect("MBOX is not set");

    // format email message in plaintext
    let email = Message::builder()
        .from(mbox.parse().unwrap())
        .to(r.email.parse().unwrap())
        .subject("Confirm your email address")
        .header(header::ContentType::TEXT_PLAIN)
        .body(format!(
            "Hi {},\n\nPlease confirm your email by clicking the link below:\n{}\n\nThis link expires in 15 minutes.\n\n 
            SnapCoin",
            r.username, confirmation_url
        ))
        .unwrap();

    // TODO: implement mail sending logic
    // log to prevent warning
    println!("email : {:#?}", email);

    Ok(())
}

// this function extracts the token from the url params,
// validates the token, create a user id and save it to the db with the username and email.
pub async fn confirm_email(
    Query(params): Query<UrlExtraction>,
    State(state): State<AppState>,
) -> std::result::Result<(CookieJar, Redirect), AuthError> {
    dotenv().ok();

    // use the jwt secret key used to encode the token to decode it for confirmation
    let secret_key = env::var("JWT_SECRET").expect("JWT_SECRET is not set");
    let decoding_key = DecodingKey::from_secret(secret_key.as_ref());

    // extract the confirmation token from the confirmation url
    let token_param = params.token;

    // validate token expiry time
    let mut validation = Validation::default();
    validation.validate_exp = true;
    validation.leeway = 60; //allow 60 seconds clock skew

    // decode token
    let decoded =
        decode::<ConfirmationClaim>(&token_param, &decoding_key, &&validation).map_err(|_| {
            AuthError::InvalidToken {
                message: "failed to decode token".to_string(),
            }
        })?;

    let claims = decoded.claims;

    let username = claims.username;
    let email = claims.email;

    if username.is_empty() {
        return Err(AuthError::InvalidToken {
            message: "Username is missing".to_string(),
        });
    }

    if email.is_empty() {
        return Err(AuthError::InvalidToken {
            message: "Email is missing".to_string(),
        });
    }

    // open a connection to the sqlite3 database
    let db_path = &state.database_name;

    let conn =
        Connection::open_with_flags(db_path, OpenFlags::new().with_create().with_read_write())?;

    // create a user id for the user
    let user_id = Uuid::new_v4();

    // insert the user into the db
    {
        let mut stmt = conn.prepare("INSERT INTO users (id, username, email) VALUES (?, ?, ?)")?;
        stmt.bind((1, user_id.to_string().as_str()))?;
        stmt.bind((2, username.as_str()))?;
        stmt.bind((3, email.as_str()))?;

        stmt.next()?;
    }

    // set cookie after successful confirmation
    let mut jar = CookieJar::new();
    jar = jar.add(Cookie::new("user_id", user_id.to_string()));
    Ok((jar, Redirect::to("/create-password")))
}

// this function allows the user to create a password, hashes it and stores it in a db
#[axum::debug_handler]
pub async fn create_password(
    jar: CookieJar,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AuthError> {
    use inquire::Password;

    let user_id = jar
        .get("user_id")
        .ok_or(AuthError::SessionError {
            message: "user_id not found".to_string(),
        })?
        .value()
        .to_string();

    // prompt for password with confirmation
    let pwd = Password::new("Enter your password:")
        .with_custom_confirmation_message("Confirm your password:")
        .with_custom_confirmation_error_message("The passwords don't match.")
        .prompt()?;

    // Open DB connection
    let db_path = &state.database_name;
    let conn =
        Connection::open_with_flags(db_path, OpenFlags::new().with_create().with_read_write())?;

    // Hash and update
    let hash = hash_password(&pwd).await?;

    let mut stmt = conn.prepare("UPDATE users SET password_hash = ?1 WHERE user_id = ?2")?;

    stmt.bind((1, hash.as_str()))?;
    stmt.bind((2, user_id.as_str()))?;

    stmt.next()?;

    // remove cookie after use
    let jar = jar.remove(Cookie::from("user_id"));
    Ok((jar, "Password updated"))
}
