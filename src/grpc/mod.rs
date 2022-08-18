mod convert;
mod helpers;
mod host_service;

#[allow(clippy::derive_partial_eq_without_eq)]
pub mod blockjoy {
    tonic::include_proto!("blockjoy.api.v1");
}

use crate::auth::middleware::authorization::AuthorizationService;
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
use tower_http::classify::{GrpcErrorsAsFailures, SharedClassifier};
use tower_http::trace::{Trace, TraceLayer};

pub async fn server(
    db: DbPool,
) -> Trace<AddExtension<Routes, Arc<PgPool>>, SharedClassifier<GrpcErrorsAsFailures>> {
    let enforcer = Authorization::new().await.unwrap();
    let _auth_service = AuthorizationService::new(enforcer);
    let h_service = HostsServer::new(HostsServiceImpl::new(db.clone()));
    let middleware = tower::ServiceBuilder::new()
        .layer(TraceLayer::new_for_grpc())
        .layer(Extension(db.clone()))
        // TODO: Reimplement authorization layer so it can deal with both, HTTP and gRPC requests
        // .layer(AsyncRequireAuthorizationLayer::new(auth_service))
        .into_inner();

    Server::builder()
        .layer(middleware)
        .add_service(h_service)
        .into_service()
}
