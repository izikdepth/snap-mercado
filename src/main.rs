use snap_mercado::api::db::initialize_database;
use snap_mercado::api::routes::AppState;
use snap_mercado::api::routes::routes;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    // initialize the database
    if let Err(e) = initialize_database("snap-mercado.db") {
        eprintln!("Failed to initialize database: {}", e);
        return;
    }

    let state = AppState {
        database_name: "snap-mercado.db".to_string(),
    };

    let app = routes(state.clone()).with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await.unwrap();

    println!("Server running on http://localhost:8000");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();

    // clean up temporary users in the database every hour
    tokio::spawn(async {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_mins(10)).await;
            // open a database connection
            let conn = match sqlite::Connection::open("snap-mercado.db") {
                Ok(conn) => conn,
                Err(_) => continue,
            };

            let _ = conn.execute("DELETE FROM users WHERE created_at < datetime('now', '-1 hour')");
        }
    });
}
