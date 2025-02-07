use displaydoc::Display;
use serde::Deserialize;
use thiserror::Error;

use super::provider::{self, Provider};
use super::Redacted;

const CLOUDFLARE_CERT_KEY_VAR: &str = "CLOUDFLARE_CERT_KEY";
const CLOUDFLARE_CERT_KEY_ENTRY: &str = "secret.cloudflare_cert_key";
const GRAFANA_PROMETHEUS_KEY_VAR: &str = "GRAFANA_PROMETHEUS_KEY";
const GRAFANA_PROMETHEUS_KEY_ENTRY: &str = "secret.grafana_prometheus_key";
const GRAFANA_BASIC_AUTH_KEY_VAR: &str = "GRAFANA_BASIC_AUTH_KEY";
const GRAFANA_BASIC_AUTH_KEY_ENTRY: &str = "secret.grafana_basic_auth_key";

#[derive(Debug, Display, Error)]
pub enum Error {
    /// Failed to parse {CLOUDFLARE_CERT_KEY_ENTRY:?}: {0}
    CloudflareCertKey(provider::Error),
    /// Failed to parse {GRAFANA_PROMETHEUS_KEY_ENTRY:?}: {0}
    GrafanaPrometheusKey(provider::Error),
    /// Failed to parse {GRAFANA_BASIC_AUTH_KEY_ENTRY:?}: {0}
    GrafanaBasicAuthKey(provider::Error),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub cloudflare_cert_key: Redacted<String>,
    pub grafana_prometheus_key: Redacted<String>,
    pub grafana_basic_auth_key: Redacted<String>,
}

impl TryFrom<&Provider> for Config {
    type Error = Error;

    fn try_from(provider: &Provider) -> Result<Self, Self::Error> {
        let cloudflare_cert_key = provider
            .read(CLOUDFLARE_CERT_KEY_VAR, CLOUDFLARE_CERT_KEY_ENTRY)
            .map_err(Error::CloudflareCertKey)?;
        let grafana_prometheus_key = provider
            .read(GRAFANA_PROMETHEUS_KEY_VAR, GRAFANA_PROMETHEUS_KEY_ENTRY)
            .map_err(Error::GrafanaPrometheusKey)?;
        let grafana_basic_auth_key = provider
            .read(GRAFANA_BASIC_AUTH_KEY_VAR, GRAFANA_BASIC_AUTH_KEY_ENTRY)
            .map_err(Error::GrafanaBasicAuthKey)?;

        Ok(Config {
            cloudflare_cert_key,
            grafana_prometheus_key,
            grafana_basic_auth_key,
        })
    }
}
