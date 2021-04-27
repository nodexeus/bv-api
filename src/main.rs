use actix_web::{get, middleware, post, web, App, HttpResponse, HttpServer, Responder};
use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;

mod db;
mod models;

type DbPool = web::Data<PgPool>;

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
    })
    .bind(&addr)?
    .run()
    .await
}

#[get("/hosts/{host_id}")]
async fn get_host(db_pool: DbPool, host_id: web::Path<Uuid>) -> impl Responder {
    let host_id = host_id.into_inner();
    let result = models::Host::find_by_id(host_id, db_pool.get_ref()).await;
    match result {
        Ok(host) => HttpResponse::Ok().json(host),
        _ => HttpResponse::NotFound().body("host not found"),
    }
}

#[post("/hosts")]
async fn add_host(_pool: DbPool, _form: web::Json<models::NewHost>) -> impl Responder {
    //TODO
    HttpResponse::InternalServerError().finish()
}

//login

//add host
//add validator
//update validator

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;

    #[actix_rt::test]
    async fn user_routes() {
        std::env::set_var("RUST_LOG", "actix_web=debug");
        env_logger::init();
        dotenv::dotenv().ok();

        let db_url = std::env::var("DATABASE_URL").expect("Missing DATABASE_URL");
        let db_max_conn = std::env::var("DB_MAX_CONN")
            .unwrap_or("10".to_string())
            .parse()
            .unwrap();

        let db_pool = PgPoolOptions::new()
            .max_connections(db_max_conn)
            .connect(&db_url)
            .await
            .expect("Could not create db connection pool.");

        let mut app = test::init_service(
            App::new()
                .data(db_pool.clone())
                .wrap(middleware::Logger::default())
                .service(get_host)
                .service(add_host),
        )
        .await;

        // Insert a host
        let req = test::TestRequest::post()
            .uri("/hosts")
            .set_json(&models::NewHost {
                name: "Test user".to_owned(),
            })
            .to_request();

        let resp: models::Host = test::read_response_json(&mut app, req).await;

        assert_eq!(resp.name, "Test user");

        // Get a host
        let req = test::TestRequest::get()
            .uri(&format!("/hosts/{}", resp.id))
            .to_request();

        let resp: models::Host = test::read_response_json(&mut app, req).await;

        assert_eq!(resp.name, "Test user");

        // Delete new host from table
    }
}
