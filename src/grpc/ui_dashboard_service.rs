use super::blockjoy_ui::ResponseMeta;
use crate::grpc::blockjoy_ui::dashboard_service_server::DashboardService;
use crate::grpc::blockjoy_ui::{metric, DashboardMetricsRequest, DashboardMetricsResponse, Metric};
use crate::models::Node;
use crate::server::DbPool;
use tonic::{Request, Response, Status};

pub struct DashboardServiceImpl {
    db: DbPool,
}

impl DashboardServiceImpl {
    pub fn new(db: DbPool) -> Self {
        Self { db }
    }
}

#[tonic::async_trait]
impl DashboardService for DashboardServiceImpl {
    async fn metrics(
        &self,
        request: Request<DashboardMetricsRequest>,
    ) -> Result<Response<DashboardMetricsResponse>, Status> {
        let inner = request.into_inner();
        let mut metrics: Vec<Metric> = Vec::with_capacity(2);

        if let Ok(running_nodes) = Node::running_nodes_count(&self.db).await {
            let running = Metric {
                name: metric::Name::Online.into(),
                value: running_nodes.to_string(),
            };
            metrics.insert(0, running);
        }

        if let Ok(stopped_nodes) = Node::halted_nodes_count(&self.db).await {
            let running = Metric {
                name: metric::Name::Offline.into(),
                value: stopped_nodes.to_string(),
            };
            metrics.insert(1, running);
        }

        let response = DashboardMetricsResponse {
            meta: Some(ResponseMeta::from_meta(inner.meta)),
            metrics,
        };

        Ok(Response::new(response))
    }
}
