use blockvisor_api::auth::rbac::{ApiKeyPerm, NodePerm, OrgPerm, OrgRole, Perm, ProtocolPerm};
use blockvisor_api::auth::resource::{OrgId, Resource};
use blockvisor_api::grpc::api;
use blockvisor_api::model::org::Org;
use tonic::Status;

use crate::setup::TestServer;
use crate::setup::helper::rpc;
use crate::setup::helper::traits::{ApiKeyService, NodeService, OrgService, SocketRpc};

#[tokio::test]
async fn user_can_create_and_list_api_keys() {
    let mut test = TestServer::new().await;
    let perms = &[ApiKeyPerm::List];

    let user1 = rpc::new_seed_user(&mut test).await;
    let user2 = rpc::new_seed_user(&mut test).await;

    // user1.jwt can create keys for user1.user_id
    let label1 = &test.rand_string(8).await;
    let resource1 = Resource::User(user1.user_id);
    let created1 = rpc::create_api_key(&test, &user1.jwt, label1, resource1, perms)
        .await
        .unwrap();
    let token1 = created1.api_key;

    // user1.jwt cannot create keys for user2
    let resource2 = Resource::User(user2.user_id);
    let result = rpc::create_api_key(&test, &user1.jwt, label1, resource2, perms).await;
    assert!(result.is_err());

    // user2.jwt can create keys for user2
    let label2 = &test.rand_string(8).await;
    let created2 = rpc::create_api_key(&test, &user2.jwt, label2, resource2, perms)
        .await
        .unwrap();
    let token2 = created2.api_key;
    assert!(token1 != token2);
    assert!(label1 != label2);

    // token1 can list keys for user1
    let keys1 = list_api_keys(&test, &token1).await.unwrap().api_keys;
    assert_eq!(keys1.len(), 1);
    assert_eq!(&keys1[0].label, label1);
    assert_eq!(keys1[0].created_at.unwrap(), created1.created_at.unwrap());

    // token2 can list keys for user2
    let keys2 = list_api_keys(&test, &token2).await.unwrap().api_keys;
    assert_eq!(keys2.len(), 1);
    assert_eq!(&keys2[0].label, label2);
}

#[tokio::test]
async fn user_can_delete_their_api_key() {
    let mut test = TestServer::new().await;
    let perms: &[Perm] = &[ApiKeyPerm::List.into(), ApiKeyPerm::Delete.into()];

    let user1 = rpc::new_seed_user(&mut test).await;
    let user2 = rpc::new_seed_user(&mut test).await;

    let key1 = rpc::new_api_key(&mut test, &user1.jwt, user1.user_id, perms).await;
    let key2 = rpc::new_api_key(&mut test, &user2.jwt, user2.user_id, perms).await;

    let keys = list_api_keys(&test, &key1).await.unwrap().api_keys;
    let key_id = keys[0].api_key_id.clone();

    // key2.token cannot delete key_id
    assert!(delete(&test, &key2, &key_id).await.is_err());

    // key1.token can delete key_id
    assert!(delete(&test, &key1, &key_id).await.is_ok());

    // key1.token is no longer valid
    assert!(list_api_keys(&test, &key1).await.is_err());
}

#[tokio::test]
async fn user_can_get_org_with_api_key() {
    let mut test = TestServer::new().await;
    let perms: &[Perm] = &[OrgPerm::Get.into()];

    let user1 = rpc::new_seed_user(&mut test).await;
    let user2 = rpc::new_seed_user(&mut test).await;

    // create api keys for both users
    let key1 = rpc::new_api_key(&mut test, &user1.jwt, user1.user_id, perms).await;
    let key2 = rpc::new_api_key(&mut test, &user2.jwt, user2.user_id, perms).await;

    // create a new org with user1 as the owner
    let name = test.rand_string(8).await;
    let req = api::OrgServiceCreateRequest { name: name.clone() };
    let created = test
        .send_with(OrgService::create, req, &user1.jwt)
        .await
        .unwrap();
    let org = created.org.unwrap();
    let org_id: OrgId = org.org_id.parse().unwrap();
    assert_eq!(org.name, name);

    // key1.token can get org_id
    let req = api::OrgServiceGetRequest {
        org_id: org_id.to_string(),
    };
    let result = test.send_with(OrgService::get, req, &key1).await;
    assert!(result.is_ok());

    // key2.token cannot get org_id
    let req = api::OrgServiceGetRequest {
        org_id: org_id.to_string(),
    };
    let result = test.send_with(OrgService::get, req, &key2).await;
    assert!(result.is_err());

    // add user2 as a member
    let conn = &mut test.conn().await;
    Org::add_user(user2.user_id, org_id, OrgRole::Member, conn)
        .await
        .unwrap();

    // key2.token can now get org_id
    let req = api::OrgServiceGetRequest {
        org_id: org_id.to_string(),
    };
    let result = test.send_with(OrgService::get, req, &key2).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn api_key_permissions_are_restricted() {
    let test = TestServer::new().await;

    let jwt = test.member_jwt().await;
    let resource = Resource::User(test.seed().member.id);
    let perms: &[Perm] = &[NodePerm::Get.into(), ProtocolPerm::ViewPublic.into()];
    let api_key = rpc::create_api_key(&test, &jwt, "label", resource, perms)
        .await
        .unwrap()
        .api_key;

    // user key should be able to get node info
    let req = api::NodeServiceGetRequest {
        node_id: test.seed().node.id.to_string(),
    };
    let result = test.send_with(NodeService::get, req, &api_key).await;
    let node = result.unwrap().node.unwrap();
    let node_id = node.node_id;

    // key should not be able to update node
    let req = api::NodeServiceUpdateConfigRequest {
        node_id,
        new_display_name: Some("updated".into()),
        ..Default::default()
    };
    let result = test
        .send_with(NodeService::update_config, req, &api_key)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn create_api_key_must_have_permission() {
    let test = TestServer::new().await;
    let resource = Resource::Org(test.seed().org.id);
    let perms: &[Perm] = &[OrgPerm::Update.into()];

    // member cannot update an org
    let jwt = test.member_jwt().await;
    let result = rpc::create_api_key(&test, &jwt, "label", resource, perms).await;
    assert!(result.is_err());

    // admin can update an org
    let jwt = test.admin_jwt().await;
    let result = rpc::create_api_key(&test, &jwt, "label", resource, perms).await;
    assert!(result.is_ok());
}

async fn list_api_keys(
    test: &TestServer,
    token: &str,
) -> Result<api::ApiKeyServiceListResponse, Status> {
    let req = api::ApiKeyServiceListRequest {};
    test.send_with(ApiKeyService::list, req, token).await
}

async fn delete(
    test: &TestServer,
    token: &str,
    key_id: &str,
) -> Result<api::ApiKeyServiceDeleteResponse, Status> {
    let req = api::ApiKeyServiceDeleteRequest {
        api_key_id: key_id.into(),
    };
    test.send_with(ApiKeyService::delete, req, token).await
}
