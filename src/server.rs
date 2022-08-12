use crate::grpc::server as grpc_server;
use crate::http::server as http_server;
use crate::hybrid_server::hybrid as hybrid_server;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::sync::Arc;
use std::time::Duration;

pub type DbPool = Arc<PgPool>;

pub async fn start() -> anyhow::Result<()> {
    let db_url = std::env::var("DATABASE_URL").expect("Missing DATABASE_URL");

    let db_max_conn: u32 = std::env::var("DB_MAX_CONN")
        .unwrap_or_else(|_| "10".to_string())
        .parse()
        .unwrap();
    let db_min_conn: u32 = std::env::var("DB_MIN_CONN")
        .unwrap_or_else(|_| "2".to_string())
        .parse()
        .unwrap();

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let bind_ip = std::env::var("BIND_IP").unwrap_or_else(|_| "0.0.0.0".to_string());
    let addr = format!("{}:{}", bind_ip, port);

    let db = Arc::new(
        PgPoolOptions::new()
            .max_connections(db_max_conn)
            .min_connections(db_min_conn)
            .max_lifetime(Some(Duration::from_secs(60 * 60 * 24)))
            .idle_timeout(Some(Duration::from_secs(60 * 2)))
            .connect(&db_url)
            .await
            .expect("Could not create db connection pool."),
    );

    let rest = http_server(db.clone()).await;
    let grpc = grpc_server(db).await;
    let hybrid = hybrid_server(rest, grpc);

    Ok(axum::Server::bind(&addr.parse()?).serve(hybrid).await?)
}
