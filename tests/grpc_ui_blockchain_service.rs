#[allow(dead_code)]
mod setup;

use api::auth::{JwtToken, TokenType, UserAuthToken};
use api::grpc::blockjoy_ui::blockchain_service_client::BlockchainServiceClient;
use api::grpc::blockjoy_ui::{GetBlockchainRequest, ListBlockchainsRequest, RequestMeta};
use api::models::User;
use setup::setup;
use std::sync::Arc;
use test_macros::*;
use tonic::transport::Channel;
use tonic::{Request, Status};
use uuid::Uuid;

async fn with_auth<T>(inner: T, db: &api::TestDb) -> Request<T> {
    let mut request = Request::new(inner);
    let user = db.admin_user().await;
    let token = UserAuthToken::create_token_for::<User>(&user, TokenType::UserAuth).unwrap();
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64().unwrap())
            .parse()
            .unwrap(),
    );
    request.metadata_mut().insert(
        "cookie",
        format!(
            "refresh={}",
            db.user_refresh_token(*token.id()).encode().unwrap()
        )
        .parse()
        .unwrap(),
    );
    request
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_ok_for_get_existing() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(Uuid::new_v4().to_string()),
        token: None,
        fields: vec![],
        pagination: None,
    };
    let uuid: uuid::Uuid = "1fdbf4c3-ff16-489a-8d3d-87c8620b963c".parse().unwrap();
    let inner = GetBlockchainRequest {
        meta: Some(request_meta),
        id: uuid.to_string(),
    };
    let req = with_auth(inner, &db).await;
    assert_grpc_request! { get, req, tonic::Code::Ok, db, BlockchainServiceClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_not_found_for_get_nonexisting() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(Uuid::new_v4().to_string()),
        token: None,
        fields: vec![],
        pagination: None,
    };
    let uuid: uuid::Uuid = "6a9efd38-0c5a-4ab0-bda2-5f308f850565".parse().unwrap();

    let inner = GetBlockchainRequest {
        meta: Some(request_meta),
        id: uuid.to_string(),
    };
    let req = with_auth(inner, &db).await;
    assert_grpc_request! { get, req, tonic::Code::NotFound, db, BlockchainServiceClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_not_found_for_get_deleted() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(Uuid::new_v4().to_string()),
        token: None,
        fields: vec![],
        pagination: None,
    };
    // TODO
    let uuid: uuid::Uuid = "13f25489-bf9b-4667-9f18-f8caa32fa4a9".parse().unwrap();
    let inner = GetBlockchainRequest {
        meta: Some(request_meta),
        id: uuid.to_string(),
    };
    let req = with_auth(inner, &db).await;
    assert_grpc_request! { get, req, tonic::Code::NotFound, db, BlockchainServiceClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn can_list_blockchains() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(Uuid::new_v4().to_string()),
        token: None,
        fields: vec![],
        pagination: None,
    };
    let inner = ListBlockchainsRequest {
        meta: Some(request_meta),
    };
    let req = with_auth(inner, &db).await;
    assert_grpc_request! { list, req, tonic::Code::Ok, db, BlockchainServiceClient<Channel> };
}
