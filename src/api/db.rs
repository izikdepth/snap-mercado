use sqlite::{Connection, OpenFlags};

pub fn initialize_database(db_path: &str) -> Result<(), sqlite::Error> {
    let conn =
        Connection::open_with_flags(db_path, OpenFlags::new().with_create().with_read_write())?;

    // create the users table if it doesn't exist
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        client_ip TEXT NOT NULL,
        user_id TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP  
    )",
    )?;

    Ok(())
}
