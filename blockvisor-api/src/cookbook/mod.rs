pub mod client;
pub mod image;
pub mod manifest;
pub mod script;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use aws_sdk_s3::config::{Credentials, Region};
use displaydoc::Display;
use rhai::Engine;
use semver::Version;
use thiserror::Error;
use tracing::warn;

use crate::config::cookbook::{BucketConfig, Config};
use crate::grpc::api;
use crate::models::node::{NodeType, NodeVersion};

use self::client::Client;
use self::image::Image;
use self::manifest::DownloadManifest;
use self::script::BlockchainMetadata;

pub const RHAI_FILE_NAME: &str = "babel.rhai";
pub const BABEL_IMAGE_NAME: &str = "blockjoy.gz";
pub const KERNEL_NAME: &str = "kernel.gz";
pub const BUNDLE_NAME: &str = "bvd-bundle.tgz";

#[derive(Debug, Display, Error)]
pub enum Error {
    /// Cookbook client error: {0}
    Client(#[from] client::Error),
    /// Cookbook image error: {0}
    Image(#[from] image::Error),
    /// No manifest found for `{0:?}` in network {1}.
    NoManifest(Image, String),
    /// No valid manifest found for identifier `{0:?}`, version `{1}`, network `{2}`.
    NoValidManifest(Image, Version, String),
    /// Failed to parse manifest: {0}
    ParseManifest(serde_json::Error),
    /// Failed to parse semantic version from NodeVersion `{0}`: {1}
    ParseVersion(NodeVersion, semver::Error),
    /// Cookbook script error: {0}
    Script(#[from] script::Error),
}

pub struct Cookbook {
    pub bucket: BucketConfig,
    pub prefix: String,
    pub expiration: Duration,
    pub client: Arc<dyn Client>,
    pub engine: Arc<Engine>,
}

impl Cookbook {
    pub fn new<C>(config: &Config, client: C) -> Self
    where
        C: Client + 'static,
    {
        Cookbook {
            bucket: config.bucket.clone(),
            prefix: config.dir_chains_prefix.clone(),
            expiration: *config.presigned_url_expiration,
            client: Arc::new(client),
            engine: Arc::new(Engine::new()),
        }
    }

    /// Instantiate `Cookbook` using the S3 config for storage.
    pub fn new_s3(config: &Config) -> Self {
        let credentials = Credentials::new(
            config.key_id.as_str(),
            config.key.as_str(),
            None,
            None,
            "Custom Provided Credentials",
        );

        let s3_config = aws_sdk_s3::Config::builder()
            .endpoint_url(config.r2_url.to_string())
            .region(Region::new(config.region.clone()))
            .credentials_provider(credentials)
            .build();

        Self::new(config, aws_sdk_s3::Client::from_conf(s3_config))
    }

    fn file_path(&self, image: &Image, file: &str) -> String {
        format!(
            "{prefix}/{protocol}/{node_type}/{node_version}/{file}",
            prefix = self.prefix,
            protocol = image.protocol,
            node_type = image.node_type,
            node_version = image.node_version
        )
    }

    pub async fn read_rhai_file(&self, image: &Image) -> Result<Vec<u8>, Error> {
        self.read_file(image, RHAI_FILE_NAME).await
    }

    pub async fn read_file(&self, image: &Image, file: &str) -> Result<Vec<u8>, Error> {
        let path = self.file_path(image, file);
        Ok(self.client.read_file(&self.bucket.cookbook, &path).await?)
    }

    pub async fn download_url(&self, image: &Image, file: &str) -> Result<String, Error> {
        let path = self.file_path(image, file);
        self.download(&self.bucket.cookbook, &path).await
    }

    pub async fn download_bundle(&self, version: &str) -> Result<String, Error> {
        let path = format!("{version}/{BUNDLE_NAME}");
        self.download(&self.bucket.bundle, &path).await
    }

    pub async fn download_kernel(&self, version: &str) -> Result<String, Error> {
        let path = format!("{version}/{KERNEL_NAME}");
        self.download(&self.bucket.kernel, &path).await
    }

    async fn download(&self, bucket: &str, path: &str) -> Result<String, Error> {
        self.client
            .download_url(bucket, path, self.expiration)
            .await
            .map_err(Into::into)
    }

    /// Retrieve config identifiers from the S3 path structure.
    ///
    /// A bucket listing looks like:
    /// ```text
    /// prefix/eth/validator/0.0.3/data.txt
    /// prefix/eth/validator/0.0.3/babel.rhai
    /// prefix/eth/validator/0.0.6/babel.rhai
    /// ```
    ///
    /// Since we filter by protocol and `NodeType` when listing, we only need to
    /// de-duplicate the results by version for each config identifier.
    pub async fn list(
        &self,
        protocol: &str,
        node_type: NodeType,
    ) -> Result<Vec<api::ConfigIdentifier>, Error> {
        let path = format!("{prefix}/{protocol}/{node_type}", prefix = self.prefix);
        let keys = self.client.list_all(&self.bucket.cookbook, &path).await?;

        let idents: HashMap<String, api::ConfigIdentifier> = keys
            .into_iter()
            .map(|key| {
                api::ConfigIdentifier::from_key(key)
                    .map(|ident| (ident.node_version.clone(), ident))
            })
            .collect::<Result<_, _>>()?;

        Ok(idents.into_values().collect())
    }

    pub async fn list_bundles(&self) -> Result<Vec<api::BundleIdentifier>, Error> {
        let keys = self.client.list_all(&self.bucket.bundle, "").await?;
        let idents = keys
            .iter()
            .filter_map(api::BundleIdentifier::maybe_from_key)
            .collect();

        Ok(idents)
    }

    pub async fn list_kernels(&self) -> Result<Vec<api::KernelIdentifier>, Error> {
        let keys = self.client.list_all(&self.bucket.kernel, "").await?;
        let idents = keys
            .iter()
            .filter_map(api::KernelIdentifier::maybe_from_key)
            .collect();

        Ok(idents)
    }

    pub async fn rhai_metadata(&self, image: &Image) -> Result<BlockchainMetadata, Error> {
        let path = self.file_path(image, RHAI_FILE_NAME);
        let script = self
            .client
            .read_string(&self.bucket.cookbook, &path)
            .await?;

        BlockchainMetadata::from_script(&self.engine, &script, image).map_err(Into::into)
    }

    pub async fn get_download_manifest(
        &self,
        image: &Image,
        network: &str,
    ) -> Result<api::DownloadManifest, Error> {
        let node_version = Version::parse(&image.node_version)
            .map_err(|err| Error::ParseVersion(image.node_version.clone(), err))?;
        let node_versions = self.get_node_versions(image).await?;

        let mut versions = node_versions.iter().rev();
        let mut manifest = loop {
            let Some(version) = versions.next() else {
                return Err(Error::NoManifest(image.clone(), network.into()));
            };

            if *version <= node_version {
                match self.find_valid_manifest(image, version, network).await {
                    Ok(manifest) => break manifest,
                    Err(err) => warn!("Manifest not found: {err:#}"),
                }
            }
        };

        for chunk in &mut manifest.chunks {
            chunk.url = self
                .client
                .download_url(&self.bucket.archive, &chunk.key, self.expiration)
                .await?;
        }

        Ok(manifest.into())
    }

    async fn get_node_versions(&self, image: &Image) -> Result<Vec<Version>, Error> {
        let path = format!("{}/{}/", image.protocol, image.node_type);
        let keys = self.client.list(&self.bucket.archive, &path).await?;

        let mut versions = keys
            .iter()
            .filter_map(|key| last_segment(key).and_then(|segment| Version::parse(segment).ok()))
            .collect::<Vec<_>>();

        versions.sort();
        Ok(versions)
    }

    async fn find_valid_manifest(
        &self,
        image: &Image,
        version: &Version,
        network: &str,
    ) -> Result<DownloadManifest, Error> {
        let data_versions = self.get_data_versions(image, version, network).await?;

        for data_version in data_versions.iter().rev() {
            let path = format!(
                "{protocol}/{node_type}/{version}/{network}/{data_version}/manifest.json",
                protocol = image.protocol,
                node_type = image.node_type
            );

            match self
                .client
                .read_string(&self.bucket.archive, &path)
                .await
                .map_err(Into::into)
                .and_then(|manifest| serde_json::from_str(&manifest).map_err(Error::ParseManifest))
            {
                Ok(manifest) => return Ok(manifest),
                Err(err) => warn!("Invalid manifest at `{path}`: {err:#}"),
            }
        }

        Err(Error::NoValidManifest(
            image.clone(),
            version.clone(),
            network.into(),
        ))
    }

    async fn get_data_versions(
        &self,
        image: &Image,
        version: &Version,
        network: &str,
    ) -> Result<Vec<u64>, Error> {
        let path = format!(
            "{protocol}/{node_type}/{version}/{network}/",
            protocol = image.protocol,
            node_type = image.node_type
        );

        let data_versions = self.client.list(&self.bucket.archive, &path).await?;
        let mut versions: Vec<_> = data_versions
            .into_iter()
            .filter_map(|ver| last_segment(&ver).and_then(|segment| segment.parse::<u64>().ok()))
            .collect();

        versions.sort_unstable();
        Ok(versions)
    }
}

fn last_segment(path: &str) -> Option<&str> {
    path.trim_end_matches('/').rsplit('/').next()
}

#[cfg(any(test, feature = "integration-test"))]
pub mod tests {
    use mockito::ServerGuard;

    use super::*;

    pub struct MockStorage {}

    pub struct TestCookbook {
        mock: ServerGuard,
    }

    impl TestCookbook {
        pub async fn new() -> Self {
            let mock = Self::mock_cookbook_api().await;
            Self { mock }
        }

        pub fn get_cookbook_api(&self) -> Cookbook {
            Cookbook::new(&self.mock_config(), MockStorage {})
        }

        async fn mock_cookbook_api() -> ServerGuard {
            let mut r2_server = mockito::Server::new_async().await;
            r2_server
                .mock("POST", mockito::Matcher::Regex(r"^/*".to_string()))
                .with_status(200)
                .with_body("{\"data\":\"id\"}")
                .create_async()
                .await;
            r2_server
        }

        pub fn mock_config(&self) -> Config {
            Config {
                bucket: BucketConfig {
                    cookbook: "news".to_string(),
                    bundle: "bundles".to_string(),
                    kernel: "oui oui ceci sont les kernles".to_string(),
                    archive: "archive".to_string(),
                },
                dir_chains_prefix: "fake".to_string(),
                r2_url: self.mock.url().parse().unwrap(),
                presigned_url_expiration: "1d".parse().unwrap(),
                region: "eu-west-3".to_string(),
                key_id: "not actually a".parse().unwrap(),
                key: "key".parse().unwrap(),
            }
        }
    }

    pub fn dummy_config() -> Config {
        Config {
            bucket: BucketConfig {
                cookbook: "cookbook".to_string(),
                bundle: "bundle".to_string(),
                kernel: "kernel".to_string(),
                archive: "archive".to_string(),
            },
            dir_chains_prefix: "chains".to_string(),
            r2_url: "https://dummy.url".parse().unwrap(),
            presigned_url_expiration: "1d".parse().unwrap(),
            region: "eu-west-3".to_string(),
            key_id: Default::default(),
            key: Default::default(),
        }
    }

    #[test]
    fn test_config_identifier_from_key() {
        api::ConfigIdentifier::from_key("chains/testing/validator/0.0.1").unwrap();
        api::ConfigIdentifier::from_key("chains/testing/validator/0.0.1/babel.rhai").unwrap();
    }

    #[test]
    fn test_list_bundles() {
        let elems = [
            "/bvd-bundle.tgz",
            "0.0.0/tester.txt",
            "0.1.0/bvd-bundle.tgz",
            "0.10.0/bvd-bundle.tgz",
            "0.7.0/bvd-bundle.tgz",
            "0.9.0/bvd-bundle.tgz",
        ];
        let parsed: Vec<_> = elems
            .iter()
            .flat_map(api::BundleIdentifier::from_key)
            .collect();
        assert_eq!(parsed[0].version, "0.1.0");
        assert_eq!(parsed[1].version, "0.10.0");
        assert_eq!(parsed[2].version, "0.7.0");
        assert_eq!(parsed[3].version, "0.9.0");
    }
}
