use actix_web::{get, middleware, post, web, App, Error, HttpResponse, HttpServer, Responder};

#[macro_use]
extern crate diesel;

use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use uuid::Uuid;

mod db;
mod models;
mod schema;

type DbPool = web::Data<r2d2::Pool<ConnectionManager<PgConnection>>>;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    env_logger::init();

    let db_url = std::env::var("DATABASE_URL").expect("Missing DATABASE_URL");
    let port = std::env::var("PORT").unwrap_or("8080".to_string());
    let bind_ip = std::env::var("BIND_IP").unwrap_or("0.0.0.0".to_string());
    let addr = format!("{}:{}", bind_ip, port);

    let db = ConnectionManager::<PgConnection>::new(db_url);
    let pool = r2d2::Pool::builder()
        .build(db)
        .expect("Failed to create db pool.");

    HttpServer::new(move || {
        App::new()
            .data(pool.clone())
            .wrap(middleware::Logger::default())
            .service(add_host)
    })
    .bind(&addr)?
    .run()
    .await
}

#[get("/hosts/{host_id}")]
async fn get_host(pool: DbPool, host_id: web::Path<Uuid>) -> Result<HttpResponse, Error> {
    let host_id = host_id.into_inner();
    let db = pool.get().expect("couldn't get a db connection from pool");

    let host = web::block(move || db::find_host_by_id(host_id, &db))
        .await
        .map_err(|e| {
            eprintln!("{}", e);
            HttpResponse::InternalServerError().finish()
        })?;

    if let Some(host) = host {
        Ok(HttpResponse::Ok().json(host))
    } else {
        let res = HttpResponse::NotFound().body(format!("No user found with id: {}", host_id));
        Ok(res)
    }
}

#[post("/hosts")]
async fn add_host(pool: DbPool, form: web::Json<models::NewHost>) -> Result<HttpResponse, Error> {
    let db = pool.get().expect("couldn't get db connection from pool");

    let host = web::block(move || db::insert_host(&form.name, &db))
        .await
        .map_err(|e| {
            eprintln!("{}", e);
            HttpResponse::InternalServerError().finish()
        })?;

    Ok(HttpResponse::Ok().json(host))
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

        let db = std::env::var("DATABASE_URL").expect("DATABASE_URL");
        let manager = ConnectionManager::<PgConnection>::new(db);
        let pool = r2d2::Pool::builder()
            .build(manager)
            .expect("Failed to create pool.");

        let mut app = test::init_service(
            App::new()
                .data(pool.clone())
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
        use crate::schema::hosts::dsl::*;
        diesel::delete(hosts.filter(id.eq(resp.id)))
            .execute(&pool.get().expect("couldn't get db connection from pool"))
            .expect("couldn't delete test user from table");
    }
}
