use anyhow::{anyhow, Context as _, Result};
use diesel::{Connection, PgConnection};
use diesel_migrations::MigrationHarness;
use opentelemetry::global;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use tracing::info;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use blockvisor_api::config::{Config, Context};
use blockvisor_api::database::{self, Database, Pool, MIGRATIONS};
use blockvisor_api::server;

#[tokio::main]
async fn main() -> Result<()> {
    let context = Context::new().await?;
    let log = context.log.clone();
    let filter = context.config.log.filter()?;

    global::set_meter_provider(log.meter.clone());
    global::set_tracer_provider(log.tracer.clone());

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .with(OpenTelemetryTracingBridge::new(&log.logger))
        .init();

    run_migrations(&context.config)?;
    setup_rbac(&context.pool).await?;

    info!("Starting server...");
    server::start(context).await?;

    global::shutdown_tracer_provider();
    log.tracer.shutdown()?;
    log.meter.shutdown()?;
    log.logger.shutdown()?;

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
