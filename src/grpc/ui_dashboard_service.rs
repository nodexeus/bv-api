use crate::grpc::blockjoy_ui::dashboard_service_server::DashboardService;
use crate::grpc::blockjoy_ui::{
    kpi, response_meta, DashboardKpiRequest, DashboardKpiResponse, Kpi, ResponseMeta,
};
use crate::models::Node;
use crate::server::DbPool;
use prost_types::Any;
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
        request: Request<DashboardKpiRequest>,
    ) -> Result<Response<DashboardKpiResponse>, Status> {
        let inner = request.into_inner();
        let response_meta = ResponseMeta {
            status: response_meta::Status::Success.into(),
            origin_request_id: inner.meta.unwrap().id,
            messages: vec![],
            pagination: None,
        };
        let mut values: Vec<Kpi> = Vec::with_capacity(2);

        if let Ok(running_nodes) = Node::running_nodes_count(&self.db).await {
            let value = Any {
                type_url: String::from("int32"),
                value: running_nodes.to_string().into_bytes(),
            };
            let running = Kpi {
                name: kpi::Name::Online.into(),
                value: Some(value),
            };
            values.insert(0, running);
        }

        if let Ok(stopped_nodes) = Node::halted_nodes_count(&self.db).await {
            let value = Any {
                type_url: String::from("int32"),
                value: stopped_nodes.to_string().into_bytes(),
            };
            let running = Kpi {
                name: kpi::Name::Offline.into(),
                value: Some(value),
            };
            values.insert(1, running);
        }

        let response = DashboardKpiResponse {
            meta: Some(response_meta),
            values,
        };

        Ok(Response::new(response))
    }
}
