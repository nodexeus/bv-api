use diesel_async::scoped_futures::ScopedFutureExt;
use displaydoc::Display;
use thiserror::Error;
use tonic::{Request, Response};
use tracing::error;

use crate::auth::Authorize;
use crate::auth::rbac::CryptPerm;
use crate::auth::resource::Resource;
use crate::database::{ReadConn, Transaction, WriteConn};
use crate::grpc::api::crypt_service_server::CryptService;
use crate::grpc::{Grpc, Metadata, Status, api};
use crate::store::secret::SecretKey;

#[derive(Debug, Display, Error)]
pub enum Error {
    /// Auth check failed: {0}
    Auth(#[from] crate::auth::Error),
    /// Claims check failed: {0}
    Claims(#[from] crate::auth::claims::Error),
    /// Diesel failure: {0}
    Diesel(#[from] diesel::result::Error),
    /// Missing the resource.
    MissingResource,
    /// Claims resource failed: {0}
    Resource(#[from] crate::auth::resource::Error),
    /// Crypt secret failed: {0}
    Secret(#[from] crate::store::secret::Error),
}

impl From<Error> for Status {
    fn from(err: Error) -> Self {
        use Error::*;
        error!("{err}");
        match err {
            Diesel(_) => Status::internal("Internal error."),
            MissingResource => Status::invalid_argument("resource"),
            Auth(err) => err.into(),
            Claims(err) => err.into(),
            Resource(err) => err.into(),
            Secret(err) => err.into(),
        }
    }
}

#[tonic::async_trait]
impl CryptService for Grpc {
    async fn get_secret(
        &self,
        req: Request<api::CryptServiceGetSecretRequest>,
    ) -> Result<Response<api::CryptServiceGetSecretResponse>, tonic::Status> {
        let (meta, _, req) = req.into_parts();
        self.read(|read| get_secret(req, meta.into(), read).scope_boxed())
            .await
    }

    async fn put_secret(
        &self,
        req: Request<api::CryptServicePutSecretRequest>,
    ) -> Result<Response<api::CryptServicePutSecretResponse>, tonic::Status> {
        let (meta, _, req) = req.into_parts();
        self.write(|write| put_secret(req, meta.into(), write).scope_boxed())
            .await
    }
}

async fn get_secret(
    req: api::CryptServiceGetSecretRequest,
    meta: Metadata,
    mut read: ReadConn<'_, '_>,
) -> Result<api::CryptServiceGetSecretResponse, Error> {
    let resource = req.resource.ok_or(Error::MissingResource)?;
    let resource = Resource::try_from(&resource)?;
    let _authz = read.auth_for(&meta, CryptPerm::GetSecret, resource).await?;
    let _id = resource.id_exists(&mut read).await?;

    let key = SecretKey::new(req.key)?;
    let data = read.ctx.secret.get(resource, &key)?;

    Ok(api::CryptServiceGetSecretResponse { value: data })
}

async fn put_secret(
    req: api::CryptServicePutSecretRequest,
    meta: Metadata,
    mut write: WriteConn<'_, '_>,
) -> Result<api::CryptServicePutSecretResponse, Error> {
    let resource = req.resource.ok_or(Error::MissingResource)?;
    let resource = Resource::try_from(&resource)?;
    let _authz = write
        .auth_for(&meta, CryptPerm::PutSecret, resource)
        .await?;
    let _id = resource.id_exists(&mut write).await?;

    let key = SecretKey::new(req.key)?;
    write.ctx.secret.put(resource, &key, &req.value)?;

    Ok(api::CryptServicePutSecretResponse {})
}
