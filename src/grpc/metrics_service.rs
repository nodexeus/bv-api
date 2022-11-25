//! The metrics service is the service that relates to the metrics for nodes and hosts that we
//! gather. At some point we may switch to a provisioned metrics service, so for now this service
//! does not store a history of metrics. Rather, it overwrites the metrics that are know for each
//! time new ones are provided. This makes sure that the database doesn't grow overly large.

use crate::grpc::blockjoy::{self, metrics_service_server::MetricsService};
use crate::models;
use crate::server::DbPool;

pub struct MetricsServiceImpl {
    db: DbPool,
}

impl MetricsServiceImpl {
    pub fn new(db: DbPool) -> Self {
        Self { db }
    }
}

#[tonic::async_trait]
impl MetricsService for MetricsServiceImpl {
    /// Update the metrics for the nodes provided in this request. Since this endpoint is called
    /// often (e.g. if we have 10,000 nodes, 36 million times per hour) we take care to perform a
    /// single query for this whole list of metrics that comes in.
    async fn node(
        &self,
        request: tonic::Request<blockjoy::NodeMetricsRequest>,
    ) -> Result<tonic::Response<blockjoy::NodeMetricsResponse>, tonic::Status> {
        let request = request.into_inner();
        let updates = request
            .metrics
            .into_iter()
            .map(|(k, v)| models::NodeSelectiveUpdate::from_api(k, v))
            .collect::<Result<_, _>>()?;
        models::NodeSelectiveUpdate::update_many(updates, &self.db).await?;
        Ok(tonic::Response::new(Default::default()))
    }

    async fn host(
        &self,
        _request: tonic::Request<blockjoy::HostMetricsRequest>,
    ) -> Result<tonic::Response<blockjoy::HostMetricsResponse>, tonic::Status> {
        todo!()
    }
}
