use std::time::Duration;

use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::operation::get_object::GetObjectError;
use aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Error;
use aws_sdk_s3::operation::put_object::PutObjectError;
use aws_sdk_s3::presigning::{PresigningConfig, PresigningConfigError};
use aws_sdk_s3::primitives::ByteStreamError;
use derive_more::Deref;
use displaydoc::Display;
use thiserror::Error;
use url::Url;

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
    /// Failed to create presigned download URL for key `{0}`: {1:?}
    UploadUrl(String, SdkError<PutObjectError>),
    /// Failed to write key `{0}:{1}`: {2:?}
    WriteKey(String, String, SdkError<PutObjectError>),
}

#[derive(Deref)]
pub struct Client {
    #[deref]
    inner: aws_sdk_s3::Client,
}

impl Client {
    pub const fn new(inner: aws_sdk_s3::Client) -> Self {
        Client { inner }
    }

    pub(super) async fn list(&self, bucket: &str, path: &str) -> Result<Vec<String>, Error> {
        let path = path.to_lowercase();
        let path_clone = path.clone();
        let resp = self
            .list_objects_v2()
            .bucket(bucket)
            .prefix(&path)
            .send()
            .await
            .map_err(|err| Error::ListPath(path_clone, err))?;

        let files = resp
            .contents()
            .iter()
            .filter_map(|object| object.key().map(ToString::to_string))
            .collect();
        tracing::debug!("Listed files for path {}: {:?}", path, files);
        Ok(files)
    }

    pub(super) async fn read_key(&self, bucket: &str, key: &str) -> Result<Vec<u8>, Error> {
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

    pub(super) async fn write_key(
        &self,
        bucket: &str,
        key: &str,
        data: Vec<u8>,
    ) -> Result<(), Error> {
        let key = key.to_lowercase();
        self.put_object()
            .bucket(bucket)
            .key(&key)
            .body(data.into())
            .send()
            .await
            .map(|_resp| ())
            .map_err(|err| Error::WriteKey(bucket.into(), key.clone(), err))
    }

    pub(super) async fn download_url(
        &self,
        bucket: &str,
        key: &str,
        expires: Duration,
    ) -> Result<Url, Error> {
        let key = key.to_lowercase();
        let config = PresigningConfig::expires_in(expires).map_err(Error::PresigningConfig)?;

        self.get_object()
            .bucket(bucket)
            .key(&key)
            .presigned(config)
            .await
            .map_err(|err| Error::DownloadUrl(key, err))
            .and_then(|url| url.uri().parse().map_err(Error::ParseRequestUrl))
    }

    pub(super) async fn upload_url(
        &self,
        bucket: &str,
        key: &str,
        expires: Duration,
    ) -> Result<Url, Error> {
        let key = key.to_lowercase();
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
