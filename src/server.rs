use crate::auth::key_provider::KeyProvider;
use crate::grpc::server as grpc_server;
use crate::http::server as http_server;
use crate::hybrid_server::hybrid as hybrid_server;
use crate::models;
use diesel::{ConnectionError, ConnectionResult};
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::AsyncPgConnection;
use futures_util::future::BoxFuture;
use futures_util::FutureExt;
use std::time::Duration;

pub async fn start() -> anyhow::Result<()> {
    let db_url = KeyProvider::get_var("DATABASE_URL")?.to_string();
    let db_max_conn: u32 = std::env::var("DB_MAX_CONN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    let db_min_conn: u32 = std::env::var("DB_MIN_CONN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let bind_ip = std::env::var("BIND_IP").unwrap_or_else(|_| "0.0.0.0".to_string());
    let addr = format!("{bind_ip}:{port}");

    // let config = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&db_url);
    let mgr = AsyncDieselConnectionManager::<AsyncPgConnection>::new_with_setup(
        db_url,
        establish_connection,
    );
    let pool = Pool::builder()
        .max_size(db_max_conn)
        .min_idle(Some(db_min_conn))
        .max_lifetime(Some(Duration::from_secs(60 * 60 * 24)))
        .idle_timeout(Some(Duration::from_secs(60 * 2)))
        .build(mgr)
        .await?;

    let db = models::DbPool::new(pool);

    let rest = http_server(db.clone()).await.into_make_service();
    let grpc = grpc_server(db).await.into_service();
    let hybrid = hybrid_server(rest, grpc);

    Ok(axum::Server::bind(&addr.parse()?).serve(hybrid).await?)
}

fn establish_connection(config: &str) -> BoxFuture<ConnectionResult<AsyncPgConnection>> {
    dbg!(config);
    let fut = async {
        use openssl::ssl::{SslConnector, SslMethod};
        let builder = SslConnector::builder(SslMethod::tls())
            .map_err(|e| ConnectionError::BadConnection(e.to_string()))?;
        let tls = postgres_openssl::MakeTlsConnector::new(builder.build());
        let (client, conn) = tokio_postgres::connect(config, tls)
            .await
            .map_err(|e| ConnectionError::BadConnection(e.to_string()))?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::error!("Database connection: {e}");
            }
        });
        AsyncPgConnection::try_from(client).await
    };
    fut.boxed()
}

// fn root_certs() -> rustls::RootCertStore {
//     let mut roots = rustls::RootCertStore::empty();
//     let certs = rustls_native_certs::load_native_certs().expect("Certs not loadable!");
//     let certs: Vec<_> = certs.into_iter().map(|cert| cert.0).collect();
//     roots.add_parsable_certificates(&certs);
//     roots
// }
