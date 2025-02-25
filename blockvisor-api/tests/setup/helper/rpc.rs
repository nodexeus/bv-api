use blockvisor_api::auth::claims::Claims;
use blockvisor_api::auth::rbac::Perm;
use blockvisor_api::auth::resource::{Resource, UserId};
use blockvisor_api::auth::token::jwt::Jwt;
use blockvisor_api::database::seed;
use blockvisor_api::grpc::{api, common};
use blockvisor_api::model::user::{NewUser, User};

use crate::setup::TestServer;
use crate::setup::helper::traits::SocketRpc;

use super::traits::{ApiKeyService, AuthService};

pub async fn new_seed_user(test: &mut TestServer) -> SeedUser {
    let email = test.rand_email().await;
    let conn = &mut test.conn().await;

    let user = NewUser::new(&email, "Test", &email, seed::LOGIN_PASSWORD).unwrap();
    let created = user.create(conn).await.unwrap();
    let user_id = created.id;
    User::confirm(user_id, conn).await.unwrap();

    let claims = login(test, &email).await;
    let jwt = test.cipher().jwt.encode(&claims).unwrap();

    SeedUser {
        user_id,
        email,
        jwt,
    }
}

pub struct SeedUser {
    pub user_id: UserId,
    #[allow(dead_code)]
    pub email: String,
    pub jwt: Jwt,
}

pub async fn login(test: &TestServer, email: &str) -> Claims {
    let req = api::AuthServiceLoginRequest {
        email: email.to_string(),
        password: seed::LOGIN_PASSWORD.into(),
    };

    let resp = test
        .send_unauthenticated(AuthService::login, req)
        .await
        .unwrap();
    let token = resp.token.into();

    test.cipher().jwt.decode(&token).unwrap()
}

pub async fn new_api_key<P, R>(test: &mut TestServer, jwt: &Jwt, resource: R, perms: &[P]) -> String
where
    P: Into<Perm> + Copy,
    R: Into<Resource>,
{
    let label = &test.rand_string(8).await;
    create_api_key(test, jwt, label, resource, perms)
        .await
        .unwrap()
        .api_key
}

pub async fn create_api_key<P, R>(
    test: &TestServer,
    token: &str,
    label: &str,
    resource: R,
    perms: &[P],
) -> Result<api::ApiKeyServiceCreateResponse, tonic::Status>
where
    P: Into<Perm> + Copy,
    R: Into<Resource>,
{
    let req = api::ApiKeyServiceCreateRequest {
        label: label.to_string(),
        resource: Some(common::Resource::from(resource.into())),
        permissions: perms
            .iter()
            .copied()
            .map(|perm| perm.into().to_string())
            .collect(),
    };

    test.send_with(ApiKeyService::create, req, token).await
}
