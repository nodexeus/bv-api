mod setup;

use api::grpc::blockjoy_ui::{self, update_service_client};
use tonic::transport;

type Service = update_service_client::UpdateServiceClient<transport::Channel>;

#[tokio::test]
async fn responds_unauthenticated_with_invalid_token_for_update() {
    let tester = setup::Tester::new().await;
    let req = blockjoy_ui::GetUpdatesRequest {
        meta: Some(tester.meta()),
    };
    let status = tester
        .send_with(Service::updates, req, "some-invalid-token")
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}
