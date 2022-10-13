mod setup;

use api::grpc::blockjoy_ui;
use api::grpc::blockjoy_ui::authentication_service_client::AuthenticationServiceClient;
use tonic::transport::Channel;

type Service = AuthenticationServiceClient<Channel>;

#[tokio::test]
async fn responds_ok_with_valid_credentials_for_login() {
    let tester = setup::Tester::new().await;
    let req = blockjoy_ui::LoginUserRequest {
        meta: Some(tester.meta()),
        email: "admin@here.com".to_string(),
        password: "abc12345".to_string(),
    };
    tester.send(Service::login, req).await.unwrap();
}

#[tokio::test]
async fn responds_error_with_invalid_credentials_for_login() {
    let tester = setup::Tester::new().await;
    let bogus = blockjoy_ui::LoginUserRequest {
        meta: Some(tester.meta()),
        email: "foo@bar.com".to_string(),
        password: "eafe12345".to_string(),
    };
    let status = tester.send(Service::login, bogus).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn responds_ok_with_valid_credentials_for_refresh() {
    let tester = setup::Tester::new().await;
    let meta = tester.meta().with_token(tester.admin_token().await);
    let req = blockjoy_ui::RefreshTokenRequest { meta: Some(meta) };
    tester.send_admin(Service::refresh, req).await.unwrap();
}

#[tokio::test]
async fn responds_unauthenticated_with_invalid_credentials_for_refresh() {
    let tester = setup::Tester::new().await;
    let invalid_token = base64::encode("asdf.asdfasdfasdfasdfasdf.asfasdfasdfasdfaf");
    let token = tester.admin_token().await;
    let meta = tester.meta().with_token(token);
    let req = blockjoy_ui::RefreshTokenRequest { meta: Some(meta) };
    let status = tester
        .send_with(Service::refresh, req, invalid_token)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn responds_ok_with_valid_pwds_for_update_ui_pwd() {
    let tester = setup::Tester::new().await;
    let req = blockjoy_ui::UpdateUiPasswordRequest {
        meta: Some(tester.meta()),
        new_pwd: "hugo-boss".to_string(),
        new_pwd_confirmation: "hugo-boss".to_string(),
        old_pwd: "abc12345".to_string(),
    };
    tester
        .send_admin(Service::update_ui_password, req)
        .await
        .unwrap();
}

#[tokio::test]
async fn responds_unauthenticated_with_invalid_old_pwd_for_update_ui_pwd() {
    let tester = setup::Tester::new().await;
    let req = blockjoy_ui::UpdateUiPasswordRequest {
        meta: Some(tester.meta()),
        new_pwd: "hugo-boss".to_string(),
        new_pwd_confirmation: "hugo-boss".to_string(),
        old_pwd: "some-wrong-pwd".to_string(),
    };
    let status = tester
        .send_admin(Service::update_ui_password, req)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn responds_invalid_argument_with_invalid_pwd_confirmation_for_update_ui_pwd() {
    let tester = setup::Tester::new().await;
    let req = blockjoy_ui::UpdateUiPasswordRequest {
        meta: Some(tester.meta()),
        new_pwd: "hugo-boss".to_string(),
        new_pwd_confirmation: "hugo-employee".to_string(),
        old_pwd: "abc12345".to_string(),
    };
    let status = tester
        .send_admin(Service::update_ui_password, req)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}
