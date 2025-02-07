use displaydoc::Display;
use serde::Deserialize;
use thiserror::Error;

use super::provider::{self, Provider};
use super::Redacted;

const CLOUDFLARE_CERT_KEY_VAR: &str = "CLOUDFLARE_CERT_KEY";
const CLOUDFLARE_CERT_KEY_ENTRY: &str = "secret.cloudflare_cert_key";
const GRAFANA_LOKI_KEY_VAR: &str = "GRAFANA_LOKI_KEY";
const GRAFANA_LOKI_KEY_ENTRY: &str = "secret.grafana_loki_key";
const GRAFANA_PROMETHEUS_KEY_VAR: &str = "GRAFANA_PROMETHEUS_KEY";
const GRAFANA_PROMETHEUS_KEY_ENTRY: &str = "secret.grafana_prometheus_key";

#[derive(Debug, Display, Error)]
pub enum Error {
    /// Failed to parse {CLOUDFLARE_CERT_KEY_ENTRY:?}: {0}
    CloudflareCertKey(provider::Error),
    /// Failed to parse {GRAFANA_LOKI_KEY_ENTRY:?}: {0}
    GrafanaLokiKey(provider::Error),
    /// Failed to parse {GRAFANA_PROMETHEUS_KEY_ENTRY:?}: {0}
    GrafanaPrometheusKey(provider::Error),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub cloudflare_cert_key: Redacted<String>,
    pub grafana_loki_key: Redacted<String>,
    pub grafana_prometheus_key: Redacted<String>,
}

impl TryFrom<&Provider> for Config {
    type Error = Error;

    fn try_from(provider: &Provider) -> Result<Self, Self::Error> {
        let cloudflare_cert_key = provider
            .read(CLOUDFLARE_CERT_KEY_VAR, CLOUDFLARE_CERT_KEY_ENTRY)
            .map_err(Error::CloudflareCertKey)?;
        let grafana_loki_key = provider
            .read(GRAFANA_LOKI_KEY_VAR, GRAFANA_LOKI_KEY_ENTRY)
            .map_err(Error::GrafanaLokiKey)?;
        let grafana_prometheus_key = provider
            .read(GRAFANA_PROMETHEUS_KEY_VAR, GRAFANA_PROMETHEUS_KEY_ENTRY)
            .map_err(Error::GrafanaPrometheusKey)?;

        Ok(Config {
            cloudflare_cert_key,
            grafana_loki_key,
            grafana_prometheus_key,
        })
    }
}
