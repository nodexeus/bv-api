use actix_web::{http::StatusCode, middleware, test, App};
use api::models::*;
use api::server::*;
use serde::Deserialize;
use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;

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
        pub token: Option<String>,
        pub refresh: Option<String>,
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
    assert!(resp.token.is_some());
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
            block_height: Some(192),
            stake_status: StakeStatus::Available,
            status: ValidatorStatus::Provisioning,
            tenure_penalty: 1.0,
            dkg_penalty: 1.0,
            performance_penalty: 1.0,
            total_penalty: 1.0,
        })
        .to_request();

    let resp: Validator = test::read_response_json(&mut app, req).await;

    assert_eq!(resp.host_id, host.id);
    assert_eq!(resp.tenure_penalty, 1.0);
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
