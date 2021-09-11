use actix_web::{middleware, test, App};
use api::models::*;
use api::server::*;
use chrono::Utc;
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
async fn it_should_add_host() {
    let db_pool = setup().await;

    let mut app = test::init_service(
        App::new()
            .data(db_pool.clone())
            .wrap(middleware::Logger::default())
            .service(create_host)
            .service(login),
    )
    .await;

    let admin_user = get_admin_user(&db_pool).await;

    // Insert a host
    let req = test::TestRequest::post()
        .uri("/hosts")
        .append_header(auth_header_for_user(&admin_user))
        .set_json(&HostRequest {
            name: "Test user 1".to_string(),
            version: Some("0.1.0".to_string()),
            location: Some("Virgina".to_string()),
            ip_addr: "192.168.8.2".parse().expect("Couldn't parse ip address"),
            val_ip_addrs: "192.168.8.3, 192.168.8.4".to_string(),
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
async fn it_should_get_host() {
    let db_pool = setup().await;

    let mut app = test::init_service(
        App::new()
            .data(db_pool.clone())
            .wrap(middleware::Logger::default())
            .service(get_host),
    )
    .await;

    let host = get_test_host(db_pool.clone()).await;
    let admin_user = get_admin_user(&db_pool).await;

    // Get a host
    let req = test::TestRequest::get()
        .uri(&format!("/hosts/{}", host.id))
        .append_header(auth_header_for_user(&admin_user))
        .to_request();

    let resp: Host = test::read_response_json(&mut app, req).await;

    assert_eq!(resp.name, "Test user");
}

#[actix_rt::test]
async fn it_should_get_host_by_token() {
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

    let admin_user = get_admin_user(&db_pool).await;

    // Get a host by token
    let req = test::TestRequest::get()
        .uri(&format!("/hosts?token={}", host.token))
        .append_header(auth_header_for_user(&admin_user))
        .to_request();

    let resp: Host = test::read_response_json(&mut app, req).await;

    assert_eq!(resp.name, "Test user");
}

#[actix_rt::test]
async fn it_should_update_validator_status() {
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
        .append_header(auth_header_for_token(&host.token))
        .set_json(&ValidatorStatusRequest {
            version: Some("1.0".to_string()),
            block_height: Some(192),
            status: ValidatorStatus::Provisioning,
        })
        .to_request();

    let resp: Validator = test::read_response_json(&mut app, req).await;

    assert_eq!(resp.host_id, host.id);
}

#[actix_rt::test]
async fn it_should_update_validator_penalty() {
    let db_pool = setup().await;

    let mut app = test::init_service(
        App::new()
            .data(db_pool.clone())
            .wrap(middleware::Logger::default())
            .service(update_validator_penalty),
    )
    .await;

    let host = get_test_host(db_pool.clone()).await;

    let path = format!(
        "/validators/{}/penalty",
        host.validators.unwrap().first().unwrap().id
    );

    let req = test::TestRequest::put()
        .uri(&path)
        .append_header(auth_header_for_service())
        .set_json(&ValidatorPenaltyRequest {
            tenure_penalty: 1.5,
            dkg_penalty: 2.5,
            performance_penalty: 3.5,
            total_penalty: 7.5,
        })
        .to_request();

    let resp: Validator = test::read_response_json(&mut app, req).await;

    assert_eq!(resp.tenure_penalty, 1.5);
    assert_eq!(resp.dkg_penalty, 2.5);
    assert_eq!(resp.performance_penalty, 3.5);
    assert_eq!(resp.total_penalty, 7.5);
}

#[actix_rt::test]
async fn it_should_update_validator_identity() {
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
        .append_header(auth_header_for_token(&host.token))
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
async fn it_should_create_command() {
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

#[actix_rt::test]
async fn it_should_stake_one_validator() {
    let db_pool = setup().await;

    let mut app = test::init_service(
        App::new()
            .data(db_pool.clone())
            .wrap(middleware::Logger::default())
            .service(stake_validator),
    )
    .await;

    let login_req = UserLoginRequest {
        email: "test@here.com".into(),
        password: "abc12345".into(),
    };

    let user = User::login(login_req, &db_pool)
        .await
        .expect("could not login test user");

    let path = format!("/users/{}/validators", user.id);

    let stake_req = ValidatorStakeRequest { count: 2 };

    let req = test::TestRequest::post()
        .uri(&path)
        .append_header(auth_header_for_user(&user))
        .set_json(&stake_req)
        .to_request();

    let validators: Vec<Validator> = test::read_response_json(&mut app, req).await;
    validators.iter().for_each(|v| {
        assert_eq!(v.stake_status, StakeStatus::Staking);
        assert!(v.staking_height.is_some());
    })
}

#[actix_rt::test]
async fn it_should_migrate_one_validator() {
    let db_pool = setup().await;

    let mut app = test::init_service(
        App::new()
            .data(db_pool.clone())
            .wrap(middleware::Logger::default())
            .service(migrate_validator),
    )
    .await;

    let admin = get_admin_user(&db_pool).await;

    let host = get_test_host(db_pool.clone()).await;
    let validators = host.validators.expect("host to have validators");
    let validator = &validators.first().expect("validators to have at least one");

    let path = format!("/validators/{}/migrate", validator.id);

    let req = test::TestRequest::post()
        .uri(&path)
        .append_header(auth_header_for_user(&admin))
        .to_request();

    let new_validator: Validator = test::read_response_json(&mut app, req).await;

    let new_host = Host::find_by_token("1234", &db_pool)
        .await
        .expect("host to be returned.");

    assert_ne!(host.id, new_validator.host_id);
    assert_eq!(new_validator.host_id, new_host.id);
    assert_eq!(new_validator.address, validator.address);
    assert_eq!(new_validator.address_name, validator.address_name);
    assert_eq!(new_validator.owner_address, validator.owner_address);
    assert_eq!(new_validator.user_id, validator.user_id);
    assert_eq!(new_validator.swarm_key, validator.swarm_key);
    assert_eq!(new_validator.stake_status, validator.stake_status);
    assert_eq!(new_validator.status, ValidatorStatus::Migrating);

    let old_validator = Validator::find_by_id(validator.id, &db_pool)
        .await
        .expect("the old validator to be returned");
    assert_eq!(old_validator.status, ValidatorStatus::Stopped);
    assert_eq!(old_validator.stake_status, StakeStatus::Disabled);
}

#[actix_rt::test]
async fn it_should_put_block_height_as_service() {
    let db_pool = setup().await;

    let app = test::init_service(
        App::new()
            .data(db_pool.clone())
            .wrap(middleware::Logger::default())
            .service(update_block_info),
    )
    .await;

    let ir = InfoRequest {
        block_height: 100,
        oracle_price: 10,
    };

    let req = test::TestRequest::put()
        .uri("/block_info")
        .append_header(auth_header_for_service())
        .set_json(&ir)
        .to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), 200);
}

#[actix_rt::test]
async fn it_should_list_validators_staking_as_service() {
    let db_pool = setup().await;

    let app = test::init_service(
        App::new()
            .data(db_pool.clone())
            .wrap(middleware::Logger::default())
            .service(list_validators_staking),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/validators/staking")
        .append_header(auth_header_for_service())
        .to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), 200);
}

#[actix_rt::test]
async fn it_should_list_validators_that_need_attention() {
    let db_pool = setup().await;

    let app = test::init_service(
        App::new()
            .data(db_pool.clone())
            .wrap(middleware::Logger::default())
            .service(list_validators_attention),
    )
    .await;

    let admin_user = get_admin_user(&db_pool).await;

    let req = test::TestRequest::get()
        .uri("/validators/needs_attention")
        .append_header(auth_header_for_user(&admin_user))
        .to_request();

    //let resp: Host = test::read_response_json(&mut app, req).await;

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), 200);
}

#[actix_rt::test]
async fn it_should_get_qr_code() {
    let db_pool = setup().await;

    let app = test::init_service(
        App::new()
            .data(db_pool.clone())
            .wrap(middleware::Logger::default())
            .service(get_qr),
    )
    .await;

    let u = User::find_by_email("test@here.com", &db_pool)
        .await
        .expect("Could not fetch test user.");

    let us = User::find_summary_by_user(&db_pool, u.id)
        .await
        .expect("fetch user summary");

    assert_eq!(us.balance(), 1000000000);

    let _inv = Invoice::find_all_by_user(&db_pool, &u.id)
        .await
        .expect("it to get bill")
        .first()
        .expect("should have at least 1 bill")
        .clone();

    let url = format!("/qr/{}", u.id);

    let req = test::TestRequest::get().uri(&url).to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), 200);
}

#[actix_rt::test]
async fn it_should_create_rewards() {
    let db_pool = setup().await;

    let mut app = test::init_service(
        App::new()
            .data(db_pool.clone())
            .wrap(middleware::Logger::default())
            .service(create_rewards)
            .service(get_reward_summary),
    )
    .await;

    let login_req = UserLoginRequest {
        email: "test@here.com".into(),
        password: "abc12345".into(),
    };

    let user = User::login(login_req, &db_pool)
        .await
        .expect("could not login test user");

    let validator = Validator::find_all(&db_pool)
        .await
        .expect("could not get list of validators")
        .first()
        .expect("could not get first validator")
        .to_owned();

    let mut rewards: Vec<RewardRequest> = Vec::new();
    rewards.push(RewardRequest {
        block: 1,
        hash: "1".into(),
        txn_time: Utc::now(),
        validator_id: validator.id,
        user_id: Some(user.id),
        account: "1".into(),
        validator: "1".into(),
        amount: 5000,
    });
    rewards.push(RewardRequest {
        block: 1,
        hash: "2".into(),
        txn_time: Utc::now(),
        validator_id: validator.id,
        user_id: Some(user.id),
        account: "1".into(),
        validator: "1".into(),
        amount: 10000,
    });
    rewards.push(RewardRequest {
        block: 1,
        hash: "1".into(),
        txn_time: Utc::now(),
        validator_id: validator.id,
        user_id: Some(user.id),
        account: "1".into(),
        validator: "1".into(),
        amount: 5000,
    });

    let req = test::TestRequest::post()
        .uri("/rewards")
        .append_header(auth_header_for_service())
        .set_json(&rewards)
        .to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), 200);

    let path = format!("/users/{}/rewards/summary", user.id);
    let req = test::TestRequest::get()
        .uri(&path)
        .append_header(auth_header_for_user(&user))
        .to_request();

    let summary: RewardSummary = test::read_response_json(&mut app, req).await;

    assert_eq!(summary.total, 15000);
    assert_eq!(summary.last_30, 15000)
}

#[actix_rt::test]
async fn it_should_create_payments() {
    let db_pool = setup().await;

    let app = test::init_service(
        App::new()
            .data(db_pool.clone())
            .wrap(middleware::Logger::default())
            .service(create_payments),
    )
    .await;

    let login_req = UserLoginRequest {
        email: "test@here.com".into(),
        password: "abc12345".into(),
    };

    let user = User::login(login_req, &db_pool)
        .await
        .expect("could not login test user");

    let mut payments: Vec<Payment> = Vec::new();
    payments.push(Payment {
        block: 1,
        hash: "1".into(),
        user_id: user.id,
        payer: "123".into(),
        payee: "124".into(),
        amount: 5000,
        oracle_price: 1000,
        created_at: None,
    });

    let req = test::TestRequest::post()
        .uri("/payments")
        .append_header(auth_header_for_service())
        .set_json(&payments)
        .to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), 200);
}

#[actix_rt::test]
async fn it_should_list_invoices() {
    let db_pool = setup().await;

    let app = test::init_service(
        App::new()
            .data(db_pool.clone())
            .wrap(middleware::Logger::default())
            .service(create_rewards)
            .service(list_invoices),
    )
    .await;

    let login_req = UserLoginRequest {
        email: "test@here.com".into(),
        password: "abc12345".into(),
    };

    let user = User::login(login_req, &db_pool)
        .await
        .expect("could not login test user");

    let path = format!("/users/{}/invoices", user.id);
    let req = test::TestRequest::get()
        .uri(&path)
        .append_header(auth_header_for_user(&user))
        .to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), 200);
}

async fn setup() -> PgPool {
    dotenv::dotenv().ok();

    let db_url = std::env::var("DATABASE_URL").expect("Missing DATABASE_URL");
    if db_url.contains("digitalocean") {
        panic!("Attempting to use production db?");
    }
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
    sqlx::query("DELETE FROM payments")
        .execute(pool)
        .await
        .expect("Error deleting payments");
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
    sqlx::query("DELETE FROM info")
        .execute(pool)
        .await
        .expect("Error deleting info");
    sqlx::query("DELETE FROM invoices")
        .execute(pool)
        .await
        .expect("Error deleting invoices");
    sqlx::query("INSERT INTO info (block_height) VALUES (99)")
        .execute(pool)
        .await
        .expect("could not update info in test setup");

    let user = UserRequest {
        email: "test@here.com".into(),
        password: "abc12345".into(),
        password_confirm: "abc12345".into(),
    };

    let user = User::create(user, pool)
        .await
        .expect("Could not create test user in db.");

    sqlx::query(
        "UPDATE users set pay_address = '123456', staking_quota = 3 where email = 'test@here.com'",
    )
    .execute(pool)
    .await
    .expect("could not set user's pay address for user test user in sql");

    sqlx::query("INSERT INTO invoices (user_id, earnings, fee_bps, validators_count, amount, starts_at, ends_at, is_paid) values ($1, 99, 200, 1, 1000000000, now(), now(), false)")
        .bind(user.id)
        .execute(pool)
            .await
            .expect("could insert test invoice into db");

    let user = UserRequest {
        email: "admin@here.com".into(),
        password: "abc12345".into(),
        password_confirm: "abc12345".into(),
    };

    User::create(user, pool)
        .await
        .expect("Could not create test user in db.");

    sqlx::query("UPDATE users set role = 'admin' where email = 'admin@here.com'")
        .execute(pool)
        .await
        .expect("could not set admin to admin test user in sql");

    let host = HostRequest {
        name: "Test user".into(),
        version: Some("0.1.0".into()),
        location: Some("Virgina".into()),
        ip_addr: "192.168.1.1".into(),
        val_ip_addrs: "192.168.0.1, 192.168.0.2, 192.168.0.3, 192.168.0.4, 192.168.0.5".into(),
        token: "123".into(),
        status: ConnectionStatus::Online,
    };

    Host::create(host, &pool)
        .await
        .expect("Could not create test host in db.");

    let host = Host::find_by_token("123", pool)
        .await
        .expect("Could not fetch test host in db.");

    let status = ValidatorStatusRequest {
        version: None,
        block_height: None,
        status: ValidatorStatus::Synced,
    };

    for v in host.validators.expect("No validators.") {
        let _ = Validator::update_status(v.id, status.clone(), pool)
            .await
            .expect("Error updating validator status in db during setup.");
        let _ = Validator::update_stake_status(v.id, StakeStatus::Available, pool)
            .await
            .expect("Error updating validator stake status in db during setup.");
    }

    let host = HostRequest {
        name: "Test Host2".into(),
        version: Some("0.1.0".into()),
        location: Some("Ohio".into()),
        ip_addr: "192.168.2.1".into(),
        val_ip_addrs: "192.168.3.1, 192.168.3.2, 192.168.3.3, 192.168.3.4, 192.168.3.5".into(),
        token: "1234".into(),
        status: ConnectionStatus::Online,
    };

    Host::create(host, &pool)
        .await
        .expect("Could not create test host in db.");

    let host = Host::find_by_token("1234", pool)
        .await
        .expect("Could not fetch test host in db.");

    let status = ValidatorStatusRequest {
        version: None,
        block_height: None,
        status: ValidatorStatus::Synced,
    };

    for v in host.validators.expect("No validators.") {
        let _ = Validator::update_status(v.id, status.clone(), pool)
            .await
            .expect("Error updating validator status in db during setup.");
        let _ = Validator::update_stake_status(v.id, StakeStatus::Available, pool)
            .await
            .expect("Error updating validator stake status in db during setup.");
    }
}

async fn get_test_host(db_pool: PgPool) -> Host {
    Host::find_by_token("123", &db_pool)
        .await
        .expect("Could not read test host from db.")
}

async fn get_admin_user(db_pool: &PgPool) -> User {
    User::find_by_email("admin@here.com", &db_pool)
        .await
        .expect("Could not get admin test user from db.")
        .set_jwt()
        .expect("Could not set JWT.")
}

fn auth_header_for_user(user: &User) -> (String, String) {
    let token = user.token.clone().unwrap_or("".to_string());
    auth_header_for_token(&token)
}

fn auth_header_for_service() -> (String, String) {
    let token = std::env::var("API_SERVICE_SECRET").expect("Missing API_SERVICE_SECRET");
    auth_header_for_token(&token)
}

fn auth_header_for_token(token: &str) -> (String, String) {
    let bearer = format!("Bearer {}", token);
    ("Authorization".to_string(), bearer)
}
