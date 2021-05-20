use crate::errors;
use crate::models::*;
use actix_cors::Cors;
use actix_web::{delete, get, middleware, post, put, web, App, HttpResponse, HttpServer};
use serde::Deserialize;
use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;

type ApiResponse = errors::Result<HttpResponse>;

type DbPool = web::Data<PgPool>;

#[derive(Deserialize)]
struct QueryParams {
    token: Option<String>,
}

pub async fn start() -> anyhow::Result<()> {
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

    Ok(HttpServer::new(move || {
        let cors = Cors::permissive().supports_credentials();

        App::new()
            .data(db_pool.clone())
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .service(add_host)
            .service(get_host)
            .service(get_host_by_token)
            .service(update_host)
            .service(update_host_status)
            .service(list_hosts)
            .service(delete_host)
            .service(list_validators)
            .service(list_validators_by_user)
            .service(get_validator)
            .service(update_validator_status)
            .service(update_validator_identity)
            .service(get_command)
            .service(list_commands)
            .service(list_pending_commands)
            .service(create_command)
            .service(update_command_response)
            .service(delete_command)
            .service(login)
            .service(create_user)
    })
    .bind(&addr)?
    .run()
    .await?)
}

#[post("/login")]
async fn login(db_pool: DbPool, login: web::Json<UserLoginRequest>) -> ApiResponse {
    let user = User::login(login.into_inner(), db_pool.get_ref()).await?;
    Ok(HttpResponse::Ok().json(user))
}

#[post("/users")]
async fn create_user(db_pool: DbPool, user: web::Json<UserRequest>) -> ApiResponse {
    let user = User::create(user.into_inner(), db_pool.as_ref()).await?;
    Ok(HttpResponse::Ok().json(user))
}
// Can pass ?token= to get a host by token
#[get("/hosts")]
async fn list_hosts(db_pool: DbPool, params: web::Query<QueryParams>) -> ApiResponse {
    if let Some(token) = params.token.clone() {
        let host = Host::find_by_token(&token, db_pool.get_ref()).await?;
        Ok(HttpResponse::Ok().json(host))
    } else {
        let host = Host::find_all(db_pool.get_ref()).await?;
        Ok(HttpResponse::Ok().json(host))
    }
}

#[get("/hosts/token/{token}")]
async fn get_host_by_token(db_pool: DbPool, token: web::Path<String>) -> ApiResponse {
    let host = Host::find_by_token(&token.into_inner(), db_pool.get_ref()).await?;
    Ok(HttpResponse::Ok().json(host))
}

#[get("/hosts/{id}")]
async fn get_host(db_pool: DbPool, id: web::Path<Uuid>) -> ApiResponse {
    let id = id.into_inner();
    let host = Host::find_by_id(id, db_pool.get_ref()).await?;
    Ok(HttpResponse::Ok().json(host))
}

#[post("/hosts")]
async fn add_host(db_pool: DbPool, host: web::Json<HostCreateRequest>) -> ApiResponse {
    let host = host.into_inner().into();

    let host = Host::create(host, db_pool.get_ref()).await?;
    Ok(HttpResponse::Ok().json(host))
}

#[put("/hosts/{id}")]
async fn update_host(
    db_pool: DbPool,
    id: web::Path<Uuid>,
    host: web::Json<HostRequest>,
) -> ApiResponse {
    let host = Host::update(id.into_inner(), host.into_inner(), db_pool.get_ref()).await?;
    Ok(HttpResponse::Ok().json(host))
}

#[put("/hosts/{id}/status")]
async fn update_host_status(
    db_pool: DbPool,
    id: web::Path<Uuid>,
    host: web::Json<HostStatusRequest>,
) -> ApiResponse {
    let host = Host::update_status(id.into_inner(), host.into_inner(), db_pool.get_ref()).await?;
    Ok(HttpResponse::Ok().json(host))
}

#[delete("/hosts/{id}")]
async fn delete_host(db_pool: DbPool, id: web::Path<Uuid>) -> ApiResponse {
    let rows = Host::delete(id.into_inner(), db_pool.get_ref()).await?;
    Ok(HttpResponse::Ok().json(format!("Successfully deleted {} record(s).", rows)))
}

#[get("/validators")]
async fn list_validators(db_pool: DbPool) -> ApiResponse {
    let validators = Validator::find_all(db_pool.get_ref()).await?;
    Ok(HttpResponse::Ok().json(validators))
}

#[get("/users/{id}/validators")]
async fn list_validators_by_user(db_pool: DbPool, id: web::Path<Uuid>) -> ApiResponse {
    let validators = Validator::find_all_by_user(id.into_inner(), db_pool.get_ref()).await?;
    Ok(HttpResponse::Ok().json(validators))
}

#[get("/validators/{id}")]
async fn get_validator(db_pool: DbPool, id: web::Path<Uuid>) -> ApiResponse {
    let validator = Validator::find_by_id(id.into_inner(), db_pool.get_ref()).await?;
    Ok(HttpResponse::Ok().json(validator))
}

#[put("/validators/{id}/status")]
async fn update_validator_status(
    db_pool: DbPool,
    id: web::Path<Uuid>,
    validator: web::Json<ValidatorStatusRequest>,
) -> ApiResponse {
    let validator =
        Validator::update_status(id.into_inner(), validator.into_inner(), db_pool.as_ref()).await?;
    Ok(HttpResponse::Ok().json(validator))
}

#[put("/validators/{id}/identity")]
async fn update_validator_identity(
    db_pool: DbPool,
    id: web::Path<Uuid>,
    validator: web::Json<ValidatorIdentityRequest>,
) -> ApiResponse {
    let validator =
        Validator::update_identity(id.into_inner(), validator.into_inner(), db_pool.as_ref())
            .await?;
    Ok(HttpResponse::Ok().json(validator))
}

#[get("/commands/{id}")]
async fn get_command(db_pool: DbPool, id: web::Path<Uuid>) -> ApiResponse {
    let command = Command::find_by_id(id.into_inner(), db_pool.as_ref()).await?;
    Ok(HttpResponse::Ok().json(command))
}

#[get("/hosts/(host_id}/commands")]
async fn list_commands(db_pool: DbPool, host_id: web::Path<Uuid>) -> ApiResponse {
    let commands = Command::find_all_by_host(host_id.into_inner(), db_pool.as_ref()).await?;
    Ok(HttpResponse::Ok().json(commands))
}

#[get("/hosts/(host_id}/commands/pending")]
async fn list_pending_commands(db_pool: DbPool, host_id: web::Path<Uuid>) -> ApiResponse {
    let commands = Command::find_pending_by_host(host_id.into_inner(), db_pool.as_ref()).await?;
    Ok(HttpResponse::Ok().json(commands))
}

#[post("/hosts/{host_id}/commands")]
async fn create_command(
    db_pool: DbPool,
    host_id: web::Path<Uuid>,
    command: web::Json<CommandRequest>,
) -> ApiResponse {
    let command =
        Command::create(host_id.into_inner(), command.into_inner(), db_pool.as_ref()).await?;
    Ok(HttpResponse::Ok().json(command))
}

#[put("/commands/{id}/response")]
async fn update_command_response(
    db_pool: DbPool,
    id: web::Path<Uuid>,
    response: web::Json<CommandResponseRequest>,
) -> ApiResponse {
    let command =
        Command::update_response(id.into_inner(), response.into_inner(), db_pool.as_ref()).await?;
    Ok(HttpResponse::Ok().json(command))
}

#[delete("/command/{id}")]
async fn delete_command(db_pool: DbPool, id: web::Path<Uuid>) -> ApiResponse {
    let result = Command::delete(id.into_inner(), db_pool.get_ref()).await?;
    Ok(HttpResponse::Ok().json(format!("Successfully deleted {} record(s).", result)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;
    use sqlx::postgres::{PgPool, PgPoolOptions};

    #[actix_rt::test]
    async fn it_should_create_and_login_user() {
        let db_pool = setup().await;
        let mut app = test::init_service(
            App::new()
                .data(db_pool.clone())
                .wrap(middleware::Logger::default())
                .service(login)
                .service(create_user),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/users")
            .set_json(&UserRequest {
                email: "chris@here.com".to_string(),
                password: "password".to_string(),
                password_confirm: "password".to_string(),
            })
            .to_request();

        #[derive(Debug, Clone, Deserialize)]
        pub struct UserTest {
            pub id: Uuid,
            pub email: String,
        }

        let resp: UserTest = test::read_response_json(&mut app, req).await;
        assert_eq!(resp.email, "chris@here.com");

        let req = test::TestRequest::post()
            .uri("/login")
            .set_json(&UserLoginRequest {
                email: "chris@here.com".to_string(),
                password: "password".to_string(),
            })
            .to_request();

        let resp: UserTest = test::read_response_json(&mut app, req).await;
        assert_eq!(resp.email, "chris@here.com");
    }

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
            .set_json(&HostRequest {
                name: "Test user 1".to_string(),
                version: Some("0.1.0".to_string()),
                location: Some("Virgina".to_string()),
                ip_addr: "192.168.1.2".parse().expect("Couldn't parse ip address"),
                val_ip_addrs: "192.168.0.3, 192.168.0.4".to_string(),
                token: "1234".to_string(),
                status: ConnectionStatus::Online,
            })
            .to_request();

        let resp: Host = test::read_response_json(&mut app, req).await;

        assert_eq!(resp.name, "Test user 1");
        assert!(resp.validators.is_some());
        assert_eq!(resp.validators.unwrap().len(), 2);

        // Delete new host from table
        let res = Host::delete(resp.id, &db_pool).await;
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

        let host = get_test_host(db_pool.clone()).await;

        // Get a host
        let req = test::TestRequest::get()
            .uri(&format!("/hosts/{}", host.id))
            .to_request();

        let resp: Host = test::read_response_json(&mut app, req).await;

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

        // Get a host by token
        let req = test::TestRequest::get()
            .uri(&format!("/hosts?token={}", host.token))
            .to_request();

        let resp: Host = test::read_response_json(&mut app, req).await;

        assert_eq!(resp.name, "Test user");
    }

    #[actix_rt::test]
    async fn it_shoud_update_validator_status() {
        let db_pool = setup().await;

        let mut app = test::init_service(
            App::new()
                .data(db_pool.clone())
                .wrap(middleware::Logger::default())
                .service(update_validator_status),
        )
        .await;

        let host = get_test_host(db_pool.clone()).await;

        let path = format!(
            "/validators/{}/status",
            host.validators.unwrap().first().unwrap().id
        );

        let req = test::TestRequest::put()
            .uri(&path)
            .set_json(&ValidatorStatusRequest {
                version: Some("1.0".to_string()),
                stake_status: StakeStatus::Available,
                status: ValidatorStatus::Provisioning,
                score: 1000000,
            })
            .to_request();

        let resp: Validator = test::read_response_json(&mut app, req).await;

        assert_eq!(resp.host_id, host.id);
        assert_eq!(resp.score, 1000000);
    }

    #[actix_rt::test]
    async fn it_shoud_update_validator_identity() {
        let db_pool = setup().await;

        let mut app = test::init_service(
            App::new()
                .data(db_pool.clone())
                .wrap(middleware::Logger::default())
                .service(update_validator_identity),
        )
        .await;

        let host = get_test_host(db_pool.clone()).await;
        let validators = host.validators.expect("missing validators");
        let validator = &validators.first().expect("missing validator");

        let path = format!("/validators/{}/identity", validator.id);

        let req = test::TestRequest::put()
            .uri(&path)
            .set_json(&ValidatorIdentityRequest {
                version: Some("48".to_string()),
                address: Some("Z729x5EeguKsNZbqBJYCh9p7wVg35RybQjNoqxQcx9u81k2jpY".to_string()),
                swarm_key: Some("EN1VKTRg_ym6SlR83y7dWtc0_uDJG380znHFcWeTy2ztBIPxqD93D__U3JK5mrrFjvcDtPtGLbwwRRGp2rr8YfAnQ_OL7S5pSOINHLIxgEqtz00wn8T74A9d9anlTOb-BHM=".to_string()),
            })
            .to_request();

        let resp: Validator = test::read_response_json(&mut app, req).await;

        assert_eq!(resp.id, validator.id);
        assert_eq!(resp.version, Some("48".to_string()));
    }

    #[actix_rt::test]
    async fn it_shoud_create_command() {
        let db_pool = setup().await;

        let mut app = test::init_service(
            App::new()
                .data(db_pool.clone())
                .wrap(middleware::Logger::default())
                .service(create_command),
        )
        .await;

        let host = get_test_host(db_pool.clone()).await;

        let path = format!("/hosts/{}/commands", host.id);

        let req = test::TestRequest::post()
            .uri(&path)
            .set_json(&CommandRequest {
                cmd: HostCmd::RestartJail,
                sub_cmd: Some("blue_angel".to_string()),
            })
            .to_request();

        let resp: Command = test::read_response_json(&mut app, req).await;

        assert_eq!(resp.host_id, host.id);
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
            ip_addr: "192.168.1.1".to_string(),
            val_ip_addrs: "192.168.0.1, 192.168.0.2".to_string(),
            token: "123".to_string(),
            status: ConnectionStatus::Online,
        };

        Host::create(host, &pool)
            .await
            .expect("Could not create test host in db.");
    }

    async fn get_test_host(db_pool: PgPool) -> Host {
        Host::find_by_token("123", &db_pool)
            .await
            .expect("Could not read test host from db.")
    }
}
