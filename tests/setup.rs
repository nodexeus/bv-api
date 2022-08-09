use api::models::validator::{StakeStatus, Validator, ValidatorStatus, ValidatorStatusRequest};
use api::models::Blockchain;
use api::models::{ConnectionStatus, Host, HostRequest};
use api::models::{User, UserRequest};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

pub async fn setup() -> PgPool {
    dotenv::dotenv().ok();

    let db_url = std::env::var("DATABASE_URL").expect("Missing DATABASE_URL");
    if db_url.contains("digitalocean") {
        panic!("Attempting to use production db?");
    }
    let db_max_conn = std::env::var("DB_MAX_CONN")
        .unwrap_or_else(|_| "10".to_string())
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

pub async fn reset_db(pool: &PgPool) {
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
    sqlx::query("DELETE FROM tokens")
        .execute(pool)
        .await
        .expect("Error deleting tokens");
    sqlx::query("DELETE FROM hosts")
        .execute(pool)
        .await
        .expect("Error deleting hosts");
    sqlx::query("DELETE FROM users")
        .execute(pool)
        .await
        .expect("Error deleting users");
    sqlx::query("DELETE FROM orgs")
        .execute(pool)
        .await
        .expect("Error deleting orgs");
    sqlx::query("DELETE FROM info")
        .execute(pool)
        .await
        .expect("Error deleting info");
    sqlx::query("DELETE FROM invoices")
        .execute(pool)
        .await
        .expect("Error deleting invoices");
    sqlx::query("DELETE FROM blockchains")
        .execute(pool)
        .await
        .expect("Error deleting blockchains");
    sqlx::query("DELETE FROM host_provisions")
        .execute(pool)
        .await
        .expect("Error deleting host_provisions");
    sqlx::query("INSERT INTO info (block_height) VALUES (99)")
        .execute(pool)
        .await
        .expect("could not update info in test setup");
    sqlx::query("INSERT INTO blockchains (name,status) values ('Helium', 'production')")
        .execute(pool)
        .await
        .expect("Error inserting blockchains");
    sqlx::query("DELETE FROM broadcast_filters")
        .execute(pool)
        .await
        .expect("Error deleting broadcast_filters");

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

    let host = HostRequest {
        org_id: None,
        name: "Host-1".into(),
        version: Some("0.1.0".into()),
        location: Some("Virgina".into()),
        cpu_count: None,
        mem_size: None,
        disk_size: None,
        os: None,
        os_version: None,
        ip_addr: "192.168.1.1".into(),
        val_ip_addrs: Some(
            "192.168.0.1, 192.168.0.2, 192.168.0.3, 192.168.0.4, 192.168.0.5".into(),
        ),
        status: ConnectionStatus::Online,
    };

    let host = Host::create(host, pool)
        .await
        .expect("Could not create test host in db.");

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
        org_id: None,
        name: "Host-2".into(),
        version: Some("0.1.0".into()),
        location: Some("Ohio".into()),
        cpu_count: None,
        mem_size: None,
        disk_size: None,
        os: None,
        os_version: None,
        ip_addr: "192.168.2.1".into(),
        val_ip_addrs: Some(
            "192.168.3.1, 192.168.3.2, 192.168.3.3, 192.168.3.4, 192.168.3.5".into(),
        ),
        status: ConnectionStatus::Online,
    };

    let host = Host::create(host, pool)
        .await
        .expect("Could not create test host in db.");

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

pub async fn get_test_host(db: &PgPool) -> Host {
    sqlx::query("select h.*, t.token, t.role from hosts h right join tokens t on h.id = t.host_id where name = 'Host-1'")
        .map(Host::from)
        .fetch_one(db)
        .await
        .unwrap()
}

pub async fn get_admin_user(db: &PgPool) -> User {
    User::find_by_email("admin@here.com", db)
        .await
        .expect("Could not get admin test user from db.")
}

#[allow(dead_code)]
pub async fn get_blockchain(db: &PgPool) -> Blockchain {
    let chains = Blockchain::find_all(db)
        .await
        .expect("To have at least one blockchain");
    chains
        .first()
        .expect("To have a test blockchain")
        .to_owned()
}
