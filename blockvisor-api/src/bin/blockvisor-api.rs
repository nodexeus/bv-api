use anyhow::{Context as _, Result, anyhow};
use diesel::{Connection, PgConnection};
use diesel_migrations::MigrationHarness;
use tracing::info;

use blockvisor_api::config::{Config, Context};
use blockvisor_api::database::{self, Database, MIGRATIONS, Pool};
use blockvisor_api::server;

#[tokio::main]
async fn main() -> Result<()> {
    let context = Context::new().await?;
    context.log.init()?;

    run_migrations(&context.config)?;
    setup_rbac(&context.pool).await?;

    info!("Starting server...");
    server::start(context.clone()).await?;

    context.log.shutdown()?;

    Ok(())
}

fn run_migrations(config: &Config) -> Result<()> {
    PgConnection::establish(config.database.url.as_str())
        .context("failed to establish db connection")?
        .run_pending_migrations(MIGRATIONS)
        .map(|_versions| ())
        .map_err(|err| anyhow!("failed to run db migrations: {err}"))
}

async fn setup_rbac(pool: &Pool) -> Result<()> {
    let mut conn = pool.conn().await?;
    database::create_roles_and_perms(&mut conn)
        .await
        .map_err(Into::into)
}
