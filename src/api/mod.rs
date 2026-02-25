// db implementation contains logic that initializes a database by creating creating tables and setting up schema
pub mod db;

// All api errors
pub mod errors;

// http routes
pub mod routes;

// contains logic for the entire signup process
pub mod signup;

use crate::api::errors::AuthError;
