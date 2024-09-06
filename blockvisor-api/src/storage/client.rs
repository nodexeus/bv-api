use std::time::Duration;

use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::operation::get_object::GetObjectError;
use aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Error;
use aws_sdk_s3::operation::put_object::PutObjectError;
use aws_sdk_s3::presigning::{PresigningConfig, PresigningConfigError};
use aws_sdk_s3::primitives::ByteStreamError;
use displaydoc::Display;
use thiserror::Error;
use url::Url;

// Max expiry from: https://developers.cloudflare.com/r2/api/s3/presigned-urls/
const MAX_URL_EXPIRY: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[mockall::automock]
#[tonic::async_trait]
pub trait Client: Send + Sync {
    /// List entries in `path` non-recursively.
    async fn list(&self, bucket: &str, path: &str) -> Result<Vec<String>, Error>;

    /// List all entries in `path` recursively.
    async fn list_all(&self, bucket: &str, path: &str) -> Result<Vec<String>, Error>;

    async fn read_key(&self, bucket: &str, key: &str) -> Result<Vec<u8>, Error>;

    async fn write_key(&self, bucket: &str, key: &str, data: Vec<u8>) -> Result<(), Error>;

    async fn download_url(&self, bucket: &str, key: &str, expires: Duration) -> Result<Url, Error>;

    async fn upload_url(&self, bucket: &str, key: &str, expires: Duration) -> Result<Url, Error>;
}

#[derive(Debug, Display, Error)]
pub enum Error {
    /// Failed to create presigned download URL for key `{0}`: {1:?}
    DownloadUrl(String, SdkError<GetObjectError>),
    /// Failed to list path `{0}`: {1:?}
    ListPath(String, SdkError<ListObjectsV2Error>),
    /// Bucket `{0}` does not contain key `{1}`
    MissingKey(String, String),
    /// Failed to parse URL from PresignedRequest: {0}
    ParseRequestUrl(url::ParseError),
    /// Failed to create presigned config: {0}
    PresigningConfig(PresigningConfigError),
    /// Failed to query key `{0}:{1}`: {2}
    QueryKey(String, String, ByteStreamError),
    /// Failed to read key `{0}:{1}`: {2:?}
    ReadKey(String, String, SdkError<GetObjectError>),
    #[cfg(any(test, feature = "integration-test"))]
    /// Unexpected error: {0}
    Unexpected(&'static str),
    /// Failed to create presigned download URL for key `{0}`: {1:?}
    UploadUrl(String, SdkError<PutObjectError>),
    /// Failed to write key `{0}:{1}`: {2:?}
    WriteKey(String, String, SdkError<PutObjectError>),
}

#[tonic::async_trait]
impl Client for aws_sdk_s3::Client {
    async fn list(&self, bucket: &str, path: &str) -> Result<Vec<String>, Error> {
        let path = path.to_lowercase();
        let resp = self
            .list_objects_v2()
            .bucket(bucket)
            .prefix(&path)
            .delimiter('/')
            .send()
            .await
            .map_err(|err| Error::ListPath(path, err))?;

        let files = resp
            .common_prefixes()
            .iter()
            .filter_map(|object| object.prefix().map(ToString::to_string))
            .collect();

        Ok(files)
    }

    async fn list_all(&self, bucket: &str, path: &str) -> Result<Vec<String>, Error> {
        let path = path.to_lowercase();
        let resp = self
            .list_objects_v2()
            .bucket(bucket)
            .prefix(&path)
            .send()
            .await
            .map_err(|err| Error::ListPath(path, err))?;

        let files = resp
            .contents()
            .iter()
            .filter_map(|object| object.key().map(ToString::to_string))
            .collect();

        Ok(files)
    }

    async fn read_key(&self, bucket: &str, key: &str) -> Result<Vec<u8>, Error> {
        let key = key.to_lowercase();
        let response = self
            .get_object()
            .bucket(bucket)
            .key(&key)
            .send()
            .await
            .map_err(|err| match err {
                SdkError::ServiceError(e) if matches!(e.err(), GetObjectError::NoSuchKey(_)) => {
                    Error::MissingKey(bucket.into(), key.clone())
                }
                _ => Error::ReadKey(bucket.into(), key.clone(), err),
            })?;

        response
            .body
            .collect()
            .await
            .map(|bytes| bytes.into_bytes().to_vec())
            .map_err(|err| Error::QueryKey(bucket.into(), key, err))
    }

    async fn write_key(&self, bucket: &str, key: &str, data: Vec<u8>) -> Result<(), Error> {
        let key = key.to_lowercase();
        let _response = self
            .put_object()
            .bucket(bucket)
            .key(&key)
            .body(data.into())
            .send()
            .await
            .map_err(|err| Error::WriteKey(bucket.into(), key.clone(), err))?;

        Ok(())
    }

    async fn download_url(&self, bucket: &str, key: &str, expires: Duration) -> Result<Url, Error> {
        let key = key.to_lowercase();
        let expires = expires.min(MAX_URL_EXPIRY);
        let config = PresigningConfig::expires_in(expires).map_err(Error::PresigningConfig)?;

        self.get_object()
            .bucket(bucket)
            .key(&key)
            .presigned(config)
            .await
            .map_err(|err| Error::DownloadUrl(key, err))
            .and_then(|url| url.uri().parse().map_err(Error::ParseRequestUrl))
    }

    async fn upload_url(&self, bucket: &str, key: &str, expires: Duration) -> Result<Url, Error> {
        let key = key.to_lowercase();
        let expires = expires.min(MAX_URL_EXPIRY);
        let config = PresigningConfig::expires_in(expires).map_err(Error::PresigningConfig)?;

        self.put_object()
            .bucket(bucket)
            .key(&key)
            .presigned(config)
            .await
            .map_err(|err| Error::UploadUrl(key, err))
            .and_then(|url| url.uri().parse().map_err(Error::ParseRequestUrl))
    }
}

#[cfg(test)]
mod tests {
    use mockall::predicate::eq;

    use crate::config::storage::{BucketConfig, Config};
    use crate::model::NodeType;
    use crate::storage::image::ImageId;
    use crate::storage::manifest::ManifestHeader;
    use crate::storage::Storage;

    use super::*;

    fn test_image() -> ImageId {
        ImageId::new("test_chain", NodeType::Node, "1.2.3".to_string().into())
    }

    fn dummy_config() -> Config {
        Config {
            bucket: BucketConfig {
                cookbook: "cookbook".to_string(),
                bundle: "bundle".to_string(),
                kernel: "kernel".to_string(),
                archive: "archive".to_string(),
            },
            storage_url: "https://dummy.url".parse().unwrap(),
            key_id: Default::default(),
            key: Default::default(),
            region: "eu-west-3".to_string(),
            dir_chains_prefix: "chains".to_string(),
            presigned_url_expiration: "1d".parse().unwrap(),
        }
    }

    #[tokio::test]
    async fn test_download_manifest_client_error() {
        let mut client = MockClient::new();
        client
            .expect_list()
            .with(eq("archive"), eq("test_chain/Node/1.2.3/test/"))
            .once()
            .returning(|_, _| Err(Error::Unexpected("some client error")));

        let storage = Storage::new(&dummy_config(), client);
        let node_version = "1.2.3".parse().unwrap();
        let result = storage
            .download_manifest_header(&test_image(), &node_version, "test", None)
            .await;

        assert_eq!(
            result.unwrap_err().to_string(),
            "Storage client error: Unexpected error: some client error",
        );
    }

    #[tokio::test]
    async fn test_download_manifest_no_min_versions() {
        let mut client = MockClient::new();
        client
            .expect_list()
            .with(eq("archive"), eq("test_chain/Node/1.2.3/test/"))
            .once()
            .returning(|_, _| Ok(vec![]));
        client
            .expect_list()
            .with(eq("archive"), eq("test_chain/Node/1.2.3/test/"))
            .once()
            .returning(|_, _| {
                Ok(vec![
                    "test_chain/node/invalid/".to_owned(),
                    "test_chain/node/7.7.7/".to_owned(),
                    "test_chain/node/8.8.8/".to_owned(),
                ])
            });

        let storage = Storage::new(&dummy_config(), client);
        let node_version = "1.2.3".parse().unwrap();
        let result = storage
            .download_manifest_header(&test_image(), &node_version, "test", None)
            .await;
        assert_eq!(result.unwrap_err().to_string(), "No data versions found.");

        let result = storage
            .download_manifest_body(&test_image(), &node_version, "test", None)
            .await;
        assert_eq!(result.unwrap_err().to_string(), "No data versions found.");
    }

    #[tokio::test]
    async fn test_download_manifest_no_data_version() {
        let mut client = MockClient::new();
        client
            .expect_list()
            .with(eq("archive"), eq("test_chain/Node/1.2.3/test/"))
            .once()
            .returning(|_, _| {
                Ok(vec![
                    "test_chain/node/invalid/".to_owned(),
                    "test_chain/node/9.0.1/".to_owned(),
                    "test_chain/node/0.0.1/".to_owned(),
                    "test_chain/node/1.2.3/".to_owned(),
                ])
            });

        let storage = Storage::new(&dummy_config(), client);
        let node_version = "1.2.3".parse().unwrap();
        let result = storage
            .download_manifest_header(&test_image(), &node_version, "test", None)
            .await;
        assert_eq!(result.unwrap_err().to_string(), "No data versions found.");
    }

    #[tokio::test]
    async fn test_download_manifest_invalid_manifest() {
        let mut client = MockClient::new();
        client
            .expect_list()
            .with(eq("archive"), eq("test_chain/Node/1.2.3/test/"))
            .once()
            .returning(|_, _| {
                Ok(vec![
                    "test_chain/node/1.2.3/test/invalid/".to_owned(),
                    "test_chain/node/1.2.3/test/1/".to_owned(),
                    "test_chain/node/1.2.3/test/2/".to_owned(),
                ])
            });
        client
            .expect_read_key()
            .returning(|_, _| Ok(b"invalid manifest content".to_vec()));

        let storage = Storage::new(&dummy_config(), client);
        let node_version = "1.2.3".parse().unwrap();
        let result = storage
            .download_manifest_header(&test_image(), &node_version, "test", None)
            .await;

        assert_eq!(
            result.unwrap_err().to_string(),
            "Failed to parse ManifestHeader: expected value at line 1 column 1"
        );
    }

    #[tokio::test]
    async fn test_download_manifest_ok() {
        let mut client = MockClient::new();
        client
            .expect_list()
            .with(eq("archive"), eq("test_chain/Node/1.2.3/test/"))
            .once()
            .returning(|_, _| Ok(vec!["test_chain/node/1.2.3/test/456/".to_owned()]));
        client
            .expect_read_key()
            .returning(|_, _| Ok(br#"{"total_size": 128,"chunks": 5}"#.to_vec()));

        let expected = ManifestHeader {
            total_size: 128,
            compression: None,
            chunks: 5,
        };

        let storage = Storage::new(&dummy_config(), client);
        let node_version = "1.2.3".parse().unwrap();
        let (manifest, data_version) = storage
            .download_manifest_header(&test_image(), &node_version, "test", None)
            .await
            .unwrap();

        assert_eq!(manifest, expected);
        assert_eq!(data_version, 456);
    }
}
