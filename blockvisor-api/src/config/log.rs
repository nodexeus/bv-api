use std::sync::{Arc, OnceLock};
use std::time::Duration;

use displaydoc::Display;
use opentelemetry::KeyValue;
use opentelemetry_otlp::{LogExporter, MetricExporter, SpanExporter, WithExportConfig};
use opentelemetry_sdk::logs::LoggerProvider;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::runtime::Tokio;
use opentelemetry_sdk::trace::{self, TracerProvider};
use opentelemetry_sdk::Resource;
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;
use serde::Deserialize;
use strum::{EnumString, IntoStaticStr};
use thiserror::Error;
use tracing_subscriber::EnvFilter;
use url::Url;

use super::provider::{self, Provider};
use super::HumanTime;

const SERVICE_NAME_DEV: &str = "blockvisor-api-dev";
const SERVICE_NAME_STAGING: &str = "blockvisor-api-staging";
const SERVICE_NAME_PRODUCTION: &str = "blockvisor-api-production";

const LOG_ENVIRONMENT_VAR: &str = "LOG_ENVIRONMENT";
const LOG_ENVIRONMENT_ENTRY: &str = "log.environment";
const LOG_FILTER_VAR: &str = "LOG_FILTER";
const LOG_FILTER_ENTRY: &str = "log.filter";
const LOG_FILTER_DEFAULT: &str = "info";

const OPENTELEMETRY_ENDPOINT_VAR: &str = "OPENTELEMETRY_ENDPOINT";
const OPENTELEMETRY_ENDPOINT_ENTRY: &str = "log.opentelemetry.endpoint";
const OPENTELEMETRY_EXPORT_INTERVAL_VAR: &str = "OPENTELEMETRY_EXPORT_INTERVAL";
const OPENTELEMETRY_EXPORT_INTERVAL_ENTRY: &str = "log.opentelemetry.export_interval";
const OPENTELEMETRY_EXPORT_INTERVAL_DEFAULT: Duration = Duration::from_secs(5);

static INIT_LOG: OnceLock<Arc<Log>> = OnceLock::new();

#[derive(Debug, Display, Error)]
pub enum Error {
    /// Failed to parse log directive: {0}
    Directive(tracing_subscriber::filter::ParseError),
    /// Failed to parse OpentelemetryConfig: {0}
    Opentelemetry(#[from] OpentelemetryError),
    /// Failed to parse {LOG_ENVIRONMENT_ENTRY:?}: {0}
    ParseEnvironment(provider::Error),
    /// Failed to parse {LOG_FILTER_ENTRY:?}: {0}
    ParseFilter(provider::Error),
}

#[derive(Clone, Copy, Debug, Deserialize, EnumString, IntoStaticStr)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum Environment {
    Dev,
    Staging,
    Production,
}

pub struct Log {
    pub logger: LoggerProvider,
    pub meter: SdkMeterProvider,
    pub tracer: TracerProvider,
}

impl Log {
    pub fn new(config: &Config) -> Arc<Self> {
        let log = INIT_LOG.get_or_init(|| {
            let resource = Resource::new(vec![KeyValue::new(SERVICE_NAME, config.service_name())]);

            let log_exporter = LogExporter::builder()
                .with_tonic()
                .with_endpoint(config.opentelemetry.endpoint.clone())
                .build()
                .expect("log exporter");
            let logger = LoggerProvider::builder()
                .with_resource(resource.clone())
                .with_batch_exporter(log_exporter, Tokio)
                .build();

            let metric_exporter = MetricExporter::builder()
                .with_tonic()
                .with_endpoint(config.opentelemetry.endpoint.clone())
                .build()
                .expect("metric exporter");
            let reader = PeriodicReader::builder(metric_exporter, Tokio)
                .with_interval(*config.opentelemetry.export_interval)
                .build();
            let meter = SdkMeterProvider::builder()
                .with_resource(resource.clone())
                .with_reader(reader)
                .build();

            let span_exporter = SpanExporter::builder()
                .with_tonic()
                .with_endpoint(config.opentelemetry.endpoint.clone())
                .build()
                .expect("span exporter");
            let trace_config = trace::Config::default().with_resource(resource);
            let tracer = TracerProvider::builder()
                .with_config(trace_config)
                .with_batch_exporter(span_exporter, Tokio)
                .build();

            Arc::new(Log {
                logger,
                meter,
                tracer,
            })
        });

        log.clone()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub environment: Environment,
    pub filter: String,
    pub opentelemetry: OpentelemetryConfig,
}

impl Config {
    pub const fn service_name(&self) -> &'static str {
        match self.environment {
            Environment::Dev => SERVICE_NAME_DEV,
            Environment::Staging => SERVICE_NAME_STAGING,
            Environment::Production => SERVICE_NAME_PRODUCTION,
        }
    }

    pub fn filter(&self) -> Result<EnvFilter, Error> {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(self.filter.clone()))
            .add_directive("hyper=error".parse().map_err(Error::Directive)?)
            .add_directive("tonic=error".parse().map_err(Error::Directive)?)
            .add_directive("reqwest=error".parse().map_err(Error::Directive)?);

        Ok(filter)
    }
}

impl TryFrom<&Provider> for Config {
    type Error = Error;

    fn try_from(provider: &Provider) -> Result<Self, Self::Error> {
        let environment = provider
            .read(LOG_ENVIRONMENT_VAR, LOG_ENVIRONMENT_ENTRY)
            .map_err(Error::ParseEnvironment)?;
        let filter = provider
            .read_or(LOG_FILTER_DEFAULT, LOG_FILTER_VAR, LOG_FILTER_ENTRY)
            .map_err(Error::ParseFilter)?;

        Ok(Config {
            environment,
            filter,
            opentelemetry: provider.try_into()?,
        })
    }
}

#[derive(Debug, Display, Error)]
pub enum OpentelemetryError {
    /// Failed to parse {OPENTELEMETRY_ENDPOINT_ENTRY:?}: {0}
    ParseEndpoint(provider::Error),
    /// Failed to parse {OPENTELEMETRY_EXPORT_INTERVAL_ENTRY:?}: {0}
    ParseExportInterval(provider::Error),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpentelemetryConfig {
    pub endpoint: Url,
    pub export_interval: HumanTime,
}

impl TryFrom<&Provider> for OpentelemetryConfig {
    type Error = Error;

    fn try_from(provider: &Provider) -> Result<Self, Self::Error> {
        let endpoint = provider
            .read(OPENTELEMETRY_ENDPOINT_VAR, OPENTELEMETRY_ENDPOINT_ENTRY)
            .map_err(OpentelemetryError::ParseEndpoint)?;
        let export_interval = provider
            .read_or(
                OPENTELEMETRY_EXPORT_INTERVAL_DEFAULT,
                OPENTELEMETRY_EXPORT_INTERVAL_VAR,
                OPENTELEMETRY_EXPORT_INTERVAL_ENTRY,
            )
            .map_err(OpentelemetryError::ParseExportInterval)?;

        Ok(OpentelemetryConfig {
            endpoint,
            export_interval,
        })
    }
}

#[cfg(any(test, feature = "integration-test"))]
pub fn test_log(filter: EnvFilter) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    tracing_subscriber::Registry::default()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_error::ErrorLayer::default())
        .init();
}

#[cfg(any(test, feature = "integration-test"))]
pub fn test_debug() {
    let filter = EnvFilter::default()
        .add_directive("debug".parse().unwrap())
        .add_directive("blockvisor_api::config::provider=info".parse().unwrap())
        .add_directive("h2=info".parse().unwrap())
        .add_directive("tokio_postgres=info".parse().unwrap())
        .add_directive("tower_http=off".parse().unwrap());

    test_log(filter);
}
