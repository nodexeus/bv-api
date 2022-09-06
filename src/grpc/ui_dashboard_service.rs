use crate::grpc::blockjoy_ui::dashboard_service_server::DashboardService;
use crate::grpc::blockjoy_ui::{DashboardKpiRequest, DashboardKpiResponse};
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
    async fn kp_is(
        &self,
        _request: Request<DashboardKpiRequest>,
    ) -> Result<Response<DashboardKpiResponse>, Status> {
        todo!()
    }
}
