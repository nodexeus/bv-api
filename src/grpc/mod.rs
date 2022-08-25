pub mod command_flow;
pub mod convert;
pub mod helpers;
pub mod host_service;

#[allow(clippy::derive_partial_eq_without_eq)]
pub mod blockjoy {
    tonic::include_proto!("blockjoy.api.v1");
}

use crate::auth::middleware::AuthorizationService;
use crate::auth::{unauthenticated_paths::UnauthenticatedPaths, Authorization};
use crate::grpc::blockjoy::command_flow_server::CommandFlowServer;
use crate::grpc::command_flow::CommandFlowServerImpl;
use crate::server::DbPool;
use axum::Extension;
use blockjoy::hosts_server::HostsServer;
use host_service::HostsServiceImpl;
use sqlx::PgPool;
use std::sync::Arc;
use tonic::transport::server::Router;
use tonic::transport::Server;
use tower::layer::util::{Identity, Stack};
use tower_http::auth::AsyncRequireAuthorizationLayer;
use tower_http::classify::{GrpcErrorsAsFailures, SharedClassifier};
use tower_http::trace::TraceLayer;

pub async fn server(
    db: DbPool,
) -> Router<
    Stack<
        Stack<
            AsyncRequireAuthorizationLayer<AuthorizationService>,
            Stack<
                Extension<UnauthenticatedPaths>,
                Stack<
                    Extension<Arc<PgPool>>,
                    Stack<TraceLayer<SharedClassifier<GrpcErrorsAsFailures>>, Identity>,
                >,
            >,
        >,
        Identity,
    >,
> {
    // Add unauthenticated paths. TODO: Should this reside in some config file?
    let unauthenticated = UnauthenticatedPaths::new(vec!["/blockjoy.api.v1.Hosts/Provision"]);
    let enforcer = Authorization::new().await.unwrap();
    let auth_service = AuthorizationService::new(enforcer);
    let h_service = HostsServer::new(HostsServiceImpl::new(db.clone()));
    let c_service = CommandFlowServer::new(CommandFlowServerImpl::new(db.clone()));
    let middleware = tower::ServiceBuilder::new()
        .layer(TraceLayer::new_for_grpc())
        .layer(Extension(db.clone()))
        .layer(Extension(unauthenticated))
        .layer(AsyncRequireAuthorizationLayer::new(auth_service))
        .into_inner();

    Server::builder()
        .layer(middleware)
        .add_service(h_service)
        .add_service(c_service)
}
