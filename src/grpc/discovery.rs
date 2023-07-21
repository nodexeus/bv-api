use diesel_async::scoped_futures::ScopedFutureExt;

use crate::auth::endpoint::Endpoint;
use crate::database::{ReadConn, Transaction};

use super::api::{self, discovery_service_server};

#[tonic::async_trait]
impl discovery_service_server::DiscoveryService for super::Grpc {
    async fn services(
        &self,
        req: tonic::Request<api::DiscoveryServiceServicesRequest>,
    ) -> super::Resp<api::DiscoveryServiceServicesResponse> {
        self.read(|read| services(req, read).scope_boxed()).await
    }
}

async fn services(
    req: tonic::Request<api::DiscoveryServiceServicesRequest>,
    read: ReadConn<'_, '_>,
) -> super::Result<api::DiscoveryServiceServicesResponse> {
    let ReadConn { conn, ctx } = read;
    let _claims = ctx.claims(&req, Endpoint::DiscoveryServices, conn).await?;

    let response = api::DiscoveryServiceServicesResponse {
        key_service_url: ctx.config.key_service.url.to_string(),
        notification_url: ctx.config.mqtt.notification_url(),
    };

    Ok(tonic::Response::new(response))
}
