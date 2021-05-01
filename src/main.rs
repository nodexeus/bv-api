use actix_web::{
    delete, get, middleware, post, put, web, App, HttpResponse, HttpServer, Responder,
};
use models::*;
use serde::Deserialize;
use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;

mod models;

type DbPool = web::Data<PgPool>;

#[derive(Deserialize)]
struct QueryParams {
    token: Option<String>,
}

#[actix_web::main]
async fn main() -> anyhow::Result<(), std::io::Error> {
    dotenv::dotenv().ok();
    env_logger::init();

    let db_url = std::env::var("DATABASE_URL").expect("Missing DATABASE_URL");
    let db_max_conn = std::env::var("DB_MAX_CONN")
        .unwrap_or("10".to_string())
        .parse()
        .unwrap();
    let port = std::env::var("PORT").unwrap_or("8080".to_string());
    let bind_ip = std::env::var("BIND_IP").unwrap_or("0.0.0.0".to_string());
    let addr = format!("{}:{}", bind_ip, port);

    let db_pool = PgPoolOptions::new()
        .max_connections(db_max_conn)
        .connect(&db_url)
        .await
        .expect("Could not create db connection pool.");

    HttpServer::new(move || {
        App::new()
            .data(db_pool.clone())
            .wrap(middleware::Logger::default())
            .service(add_host)
            .service(update_host)
            .service(list_hosts)
            .service(delete_host)
    })
    .bind(&addr)?
    .run()
    .await
}

#[get("/hosts")]
async fn list_hosts(db_pool: DbPool, params: web::Query<QueryParams>) -> impl Responder {
    if let Some(token) = params.token.clone() {
        let result = Host::find_by_token(&token, db_pool.get_ref()).await;
        match result {
            Ok(host) => HttpResponse::Ok().json(host),
            Err(e) => HttpResponse::BadRequest().json(e.to_string()),
        }
    } else {
        let result = models::Host::find_all(db_pool.get_ref()).await;
        match result {
            Ok(hosts) => HttpResponse::Ok().json(hosts),
            Err(e) => HttpResponse::BadRequest().json(e.to_string()),
        }
    }
}

#[get("/hosts/{host_id}")]
async fn get_host(db_pool: DbPool, id: web::Path<Uuid>) -> impl Responder {
    let id = id.into_inner();
    let result = models::Host::find_by_id(id, db_pool.get_ref()).await;
    match result {
        Ok(host) => HttpResponse::Ok().json(host),
        Err(e) => HttpResponse::NotFound().json(e.to_string()),
    }
}

#[post("/hosts")]
async fn add_host(db_pool: DbPool, host: web::Json<HostRequest>) -> impl Responder {
    let mut host = host.into_inner();
    host.token = Uuid::new_v4().to_string();
    let result = Host::create(host, db_pool.get_ref()).await;
    match result {
        Ok(host) => HttpResponse::Ok().json(host),
        Err(e) => {
            dbg!(&e);
            HttpResponse::BadRequest().json(e.to_string())
        }
    }
}

#[put("/host/{id}")]
async fn update_host(
    db_pool: DbPool,
    id: web::Path<Uuid>,
    host: web::Json<HostRequest>,
) -> impl Responder {
    let host = host.into_inner();
    let result = Host::update(id.into_inner(), host, db_pool.get_ref()).await;
    match result {
        Ok(host) => HttpResponse::Ok().json(host),
        Err(e) => HttpResponse::BadRequest().json(e.to_string()),
    }
}

#[delete("/hosts/{id}")]
async fn delete_host(db_pool: DbPool, id: web::Path<Uuid>) -> impl Responder {
    let result = Host::delete(id.into_inner(), db_pool.get_ref()).await;
    match result {
        Ok(rows) if rows > 0 => {
            HttpResponse::Ok().json(format!("Successfully deleted {} record(s).", rows))
        }
        _ => HttpResponse::BadRequest().json("Host not found."),
    }
}

//login

//add host
//add validator
//update validator

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;
    use sqlx::postgres::{PgPool, PgPoolOptions};

    #[actix_rt::test]
    async fn it_shoud_add_host() {
        let db_pool = setup().await;

        let mut app = test::init_service(
            App::new()
                .data(db_pool.clone())
                .wrap(middleware::Logger::default())
                .service(add_host),
        )
        .await;

        // Insert a host
        let req = test::TestRequest::post()
            .uri("/hosts")
            .set_json(&models::HostRequest {
                name: "Test user 1".to_string(),
                version: Some("0.1.0".to_string()),
                location: Some("Virgina".to_string()),
                ip_addr: "192.168.1.2".parse().expect("Couldn't parse ip address"),
                val_ip_addr_start: "192.168.0.2".parse().expect("Couldn't parse ip address"),
                val_count: 1,
                token: "1234".to_string(),
                status: models::ConnectionStatus::Online,
            })
            .to_request();

        let resp: models::Host = test::read_response_json(&mut app, req).await;

        assert_eq!(resp.name, "Test user 1");
        assert!(resp.validators.is_some());
        assert_eq!(resp.validators.unwrap().len(), 1);

        // Delete new host from table
        let res = models::Host::delete(resp.id, &db_pool).await;
        assert_eq!(1, res.unwrap());
    }

    #[actix_rt::test]
    async fn it_shoud_get_host() {
        let db_pool = setup().await;

        let mut app = test::init_service(
            App::new()
                .data(db_pool.clone())
                .wrap(middleware::Logger::default())
                .service(get_host),
        )
        .await;

        let host = Host::find_by_token("123", &db_pool)
            .await
            .expect("Could not read test host from db.");

        // Get a host
        let req = test::TestRequest::get()
            .uri(&format!("/hosts/{}", host.id))
            .to_request();

        let resp: models::Host = test::read_response_json(&mut app, req).await;

        assert_eq!(resp.name, "Test user");
    }

    #[actix_rt::test]
    async fn it_shoud_get_host_by_token() {
        let db_pool = setup().await;

        let mut app = test::init_service(
            App::new()
                .data(db_pool.clone())
                .wrap(middleware::Logger::default())
                .service(list_hosts),
        )
        .await;

        let host = Host::find_by_token("123", &db_pool)
            .await
            .expect("Could not read test host from db.");

        // Get a host
        let req = test::TestRequest::get()
            .uri(&format!("/hosts?token={}", host.token))
            .to_request();

        let resp: models::Host = test::read_response_json(&mut app, req).await;

        assert_eq!(resp.name, "Test user");
    }

    async fn setup() -> PgPool {
        dotenv::dotenv().ok();

        let db_url = std::env::var("DATABASE_URL").expect("Missing DATABASE_URL");
        let db_max_conn = std::env::var("DB_MAX_CONN")
            .unwrap_or("10".to_string())
            .parse()
            .unwrap();

        let pool = PgPoolOptions::new()
            .max_connections(db_max_conn)
            .connect(&db_url)
            .await
            .expect("Could not create db connection pool.");

        reset_db(&pool.clone()).await;

        pool
    }

    async fn reset_db(pool: &PgPool) {
        sqlx::query("DELETE FROM rewards")
            .execute(pool)
            .await
            .expect("Error deleting rewards");
        sqlx::query("DELETE FROM validators")
            .execute(pool)
            .await
            .expect("Error deleting validators");
        sqlx::query("DELETE FROM hosts")
            .execute(pool)
            .await
            .expect("Error deleting hosts");
        sqlx::query("DELETE FROM users")
            .execute(pool)
            .await
            .expect("Error deleting users");

        let host = HostRequest {
            name: "Test user".to_string(),
            version: Some("0.1.0".to_string()),
            location: Some("Virgina".to_string()),
            ip_addr: "192.168.1.1".parse().expect("Couldn't parse ip address"),
            val_ip_addr_start: "192.168.0.1".parse().expect("Couldn't parse ip address"),
            val_count: 1,
            token: "123".to_string(),
            status: models::ConnectionStatus::Online,
        };

        Host::create(host, &pool)
            .await
            .expect("Could not create test host in db.");
    }
}
