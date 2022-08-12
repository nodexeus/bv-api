mod convert;
mod helpers;
mod host_service;

pub mod blockjoy {
    tonic::include_proto!("blockjoy.api.v1");
}

use crate::auth::middleware::grpc_authorization::AuthorizationService;
use crate::auth::Authorization;
use crate::server::DbPool;
use axum::middleware::AddExtension;
use axum::Extension;
use blockjoy::hosts_server::HostsServer;
use host_service::HostsServiceImpl;
use sqlx::PgPool;
use std::sync::Arc;
use tonic::transport::server::Routes;
use tonic::transport::Server;
use tower_http::auth::{AsyncRequireAuthorization, AsyncRequireAuthorizationLayer};
use tower_http::classify::{GrpcErrorsAsFailures, SharedClassifier};
use tower_http::trace::{Trace, TraceLayer};

pub async fn server(
    db: DbPool,
) -> Trace<
    AddExtension<AsyncRequireAuthorization<Routes, AuthorizationService>, Arc<PgPool>>,
    SharedClassifier<GrpcErrorsAsFailures>,
> {
    let enforcer = Authorization::new().await.unwrap();
    let auth_service = AuthorizationService::new(enforcer);
    let h_service = HostsServiceImpl::new(db.clone());

    Server::builder()
        .layer(TraceLayer::new_for_grpc())
        .layer(Extension(db.clone()))
        .layer(AsyncRequireAuthorizationLayer::new(auth_service))
        .add_service(HostsServer::new(h_service))
        .into_service()
}
