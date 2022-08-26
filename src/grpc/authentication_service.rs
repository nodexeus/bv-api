use crate::auth::TokenIdentifyable;
use crate::grpc::blockjoy_ui::authentication_service_server::AuthenticationService;
use crate::grpc::blockjoy_ui::{
    response_meta, ApiToken, LoginUserRequest, LoginUserResponse, RefreshTokenRequest,
    RefreshTokenResponse,
};
use crate::grpc::helpers::success_response_meta;
use crate::models::User;
use crate::server::DbPool;
use tonic::{Request, Response, Status};

pub struct AuthenticationServiceImpl {
    db: DbPool,
}

impl AuthenticationServiceImpl {
    pub fn new(db: DbPool) -> Self {
        Self { db }
    }
}

#[tonic::async_trait]
impl AuthenticationService for AuthenticationServiceImpl {
    async fn login(
        &self,
        request: Request<LoginUserRequest>,
    ) -> Result<Response<LoginUserResponse>, Status> {
        let inner = request.into_inner();
        let user = User::login(inner.clone(), &self.db).await?;
        let db_token = user.get_token(&self.db).await?;
        let token = ApiToken {
            value: db_token.token,
        };
        let meta = success_response_meta(
            i32::from(response_meta::Status::Success),
            inner.meta.unwrap().id,
        );
        let response = LoginUserResponse {
            meta: Some(meta),
            token: Some(token),
        };

        Ok(Response::new(response))
    }

    async fn refresh(
        &self,
        _request: Request<RefreshTokenRequest>,
    ) -> Result<Response<RefreshTokenResponse>, Status> {
        Err(Status::unimplemented(""))
    }
}
