#[allow(dead_code)]
mod setup;

use api::auth::TokenIdentifyable;
use api::grpc::blockjoy;
use api::grpc::blockjoy::{
    hosts_client::HostsClient, DeleteHostRequest, HostInfoUpdateRequest, ProvisionHostRequest,
};
use api::models::{Host, HostProvision, HostProvisionRequest, HostSelectiveUpdate};
use setup::setup;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use test_macros::*;
use tonic::transport::Channel;
use tonic::{Request, Status};
use uuid::Uuid;

#[before(call = "setup")]
#[tokio::test]
async fn responds_unauthenticated_without_valid_token_for_info_update() {
    let db = _before_values.await;
    let hosts = Host::find_all(&db.pool).await.unwrap();
    let host = hosts.first().unwrap();
    let b_uuid = host.id.to_string();
    let host_info = blockjoy::HostInfo {
        id: Some(b_uuid.clone()),
        name: Some("tester".into()),
        version: None,
        location: None,
        cpu_count: None,
        mem_size: None,
        disk_size: None,
        os: None,
        os_version: None,
        ip: Some("123.456.789.0".into()),
        ip_gateway: Some("192.168.0.1".into()),
        ip_range_from: Some("192.168.0.10".into()),
        ip_range_to: Some("192.168.0.20".into()),
    };
    let inner = HostInfoUpdateRequest {
        request_id: Some(Uuid::new_v4().to_string()),
        info: Some(host_info),
    };
    let mut request = Request::new(inner);

    request
        .metadata_mut()
        .insert("authorization", "".parse().unwrap());

    assert_grpc_request! { info_update, request, tonic::Code::Unauthenticated, db, HostsClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_unauthenticated_without_token_for_info_update() {
    let db = _before_values.await;
    let hosts = Host::find_all(&db.pool).await.unwrap();
    let host = hosts.first().unwrap();
    let b_uuid = host.id.to_string();

    let host_info = blockjoy::HostInfo {
        id: Some(b_uuid.clone()),
        name: Some("tester".into()),
        version: None,
        location: None,
        cpu_count: None,
        mem_size: None,
        disk_size: None,
        os: None,
        os_version: None,
        ip: Some("123.456.789.0".into()),
        ip_gateway: Some("192.168.0.1".into()),
        ip_range_from: Some("192.168.0.10".into()),
        ip_range_to: Some("192.168.0.20".into()),
    };
    let inner = HostInfoUpdateRequest {
        request_id: Some(Uuid::new_v4().to_string()),
        info: Some(host_info),
    };

    assert_grpc_request! { info_update, Request::new(inner), tonic::Code::Unauthenticated, db, HostsClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_unauthenticated_with_token_for_info_update() {
    let db = _before_values.await;
    let host = db.test_host().await;
    let b_uuid = host.id.to_string();

    let host_info = blockjoy::HostInfo {
        id: Some(b_uuid.clone()),
        name: Some("tester".into()),
        version: None,
        location: None,
        cpu_count: None,
        mem_size: None,
        disk_size: None,
        os: None,
        os_version: None,
        ip: Some("123.456.789.0".into()),
        ip_gateway: Some("192.168.0.1".into()),
        ip_range_from: Some("192.168.0.10".into()),
        ip_range_to: Some("192.168.0.20".into()),
    };
    let inner = HostInfoUpdateRequest {
        request_id: Some(Uuid::new_v4().to_string()),
        info: Some(host_info),
    };
    let mut request = Request::new(inner);

    request
        .metadata_mut()
        .insert("authorization", "923783".parse().unwrap());

    assert_grpc_request! { info_update, request, tonic::Code::Unauthenticated, db, HostsClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_permission_denied_with_token_ownership_for_info_update() {
    let db = _before_values.await;
    let hosts = Host::find_all(&db.pool).await.unwrap();
    let request_token = hosts.first().unwrap().get_token(&db.pool).await.unwrap();
    let resource_host = hosts.last().unwrap();
    let b_uuid = resource_host.id.to_string();
    let host_info = blockjoy::HostInfo {
        id: Some(b_uuid.clone()),
        name: Some("tester".into()),
        version: None,
        location: None,
        cpu_count: None,
        mem_size: None,
        disk_size: None,
        os: None,
        os_version: None,
        ip: Some("123.456.789.0".into()),
        ip_gateway: Some("192.168.0.1".into()),
        ip_range_from: Some("192.168.0.10".into()),
        ip_range_to: Some("192.168.0.20".into()),
    };
    let inner = HostInfoUpdateRequest {
        request_id: Some(Uuid::new_v4().to_string()),
        info: Some(host_info),
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", request_token.to_base64())
            .parse()
            .unwrap(),
    );

    assert_grpc_request! { info_update, request, tonic::Code::PermissionDenied, db, HostsClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_not_found_for_provision() {
    let db = _before_values.await;
    let b_uuid = Uuid::new_v4().to_string();
    let host_info = blockjoy::HostInfo {
        id: Some(b_uuid),
        name: Some("tester".into()),
        version: None,
        location: None,
        cpu_count: None,
        mem_size: None,
        disk_size: None,
        os: None,
        os_version: None,
        ip: Some("123.456.789.0".into()),
        ip_gateway: Some("192.168.0.1".into()),
        ip_range_from: Some("192.168.0.10".into()),
        ip_range_to: Some("192.168.0.20".into()),
    };
    let inner = ProvisionHostRequest {
        request_id: Some(Uuid::new_v4().to_string()),
        otp: "unknown-otp".into(),
        info: Some(host_info),
        status: 0,
    };
    let request = Request::new(inner);

    assert_grpc_request! { provision, request, tonic::Code::NotFound, db, HostsClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_ok_for_provision() -> anyhow::Result<()> {
    let db = _before_values.await;
    let mut tx = db.pool.begin().await.unwrap();
    let org: (Uuid,) = sqlx::query_as("select id from orgs")
        .fetch_one(&mut tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let host_provision_request = HostProvisionRequest {
        org_id: org.0,
        nodes: None,
        ip_gateway: IpAddr::from_str("172.168.0.1").unwrap(),
        ip_range_from: IpAddr::from_str("172.168.0.10").unwrap(),
        ip_range_to: IpAddr::from_str("172.168.0.100").unwrap(),
    };
    let host_provision = HostProvision::create(host_provision_request, &db.pool)
        .await
        .unwrap();
    let host_info = blockjoy::HostInfo {
        id: Some(Uuid::new_v4().to_string()),
        name: Some("tester".into()),
        version: None,
        location: None,
        cpu_count: None,
        mem_size: None,
        disk_size: None,
        os: None,
        os_version: None,
        ip: Some("123.456.789.0".into()),
        ip_gateway: Some("127.18.0.1".into()),
        ip_range_from: Some("127.18.0.10".into()),
        ip_range_to: Some("127.18.0.20".into()),
    };
    let inner = ProvisionHostRequest {
        request_id: Some(Uuid::new_v4().to_string()),
        otp: host_provision.id,
        info: Some(host_info),
        status: 0,
    };
    let request = Request::new(inner);

    assert_grpc_request! { provision, request, tonic::Code::Ok, db, HostsClient<Channel> };

    let host = sqlx::query("SELECT * FROM hosts ORDER BY created_at DESC LIMIT 1")
        .map(|row| Host::try_from(row).unwrap_or_default())
        .fetch_one(&db.pool)
        .await?;

    println!("host name: {}", host.name);

    assert_eq!(host.name.split('_').count(), 4);

    Ok(())
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_ok_for_info_update() {
    let db = _before_values.await;
    let hosts = Host::find_all(&db.pool).await.unwrap();
    let host = hosts.first().unwrap();
    let token = host.get_token(&db.pool).await.unwrap();
    let b_uuid = host.id.to_string();
    let host_info = blockjoy::HostInfo {
        id: Some(b_uuid.clone()),
        name: Some("tester".into()),
        version: None,
        location: None,
        cpu_count: None,
        mem_size: None,
        disk_size: None,
        os: None,
        os_version: None,
        ip: Some("123.456.789.0".into()),
        ip_gateway: Some("192.168.0.1".into()),
        ip_range_from: Some("192.168.0.10".into()),
        ip_range_to: Some("192.168.0.20".into()),
    };
    let inner = HostInfoUpdateRequest {
        request_id: Some(Uuid::new_v4().to_string()),
        info: Some(host_info),
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64()).parse().unwrap(),
    );

    assert_grpc_request! { info_update, request, tonic::Code::Ok, db, HostsClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_ok_for_delete() {
    let db = _before_values.await;
    let hosts = Host::find_all(&db.pool).await.unwrap();
    let host = hosts.first().unwrap();
    let token = host.get_token(&db.pool).await.unwrap();
    let b_uuid = host.id.to_string();
    let inner = DeleteHostRequest {
        request_id: Some(Uuid::new_v4().to_string()),
        host_id: b_uuid,
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64()).parse().unwrap(),
    );

    assert_grpc_request! { delete, request, tonic::Code::Ok, db, HostsClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_unauthenticated_without_valid_token_for_delete() {
    let db = _before_values.await;
    let hosts = Host::find_all(&db.pool).await.unwrap();
    let host = hosts.first().unwrap();
    let b_uuid = host.id.to_string();
    let inner = DeleteHostRequest {
        request_id: Some(Uuid::new_v4().to_string()),
        host_id: b_uuid,
    };

    assert_grpc_request! { delete, Request::new(inner), tonic::Code::Unauthenticated, db, HostsClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_permission_denied_for_delete() {
    let db = _before_values.await;
    let hosts = Host::find_all(&db.pool).await.unwrap();
    let host = hosts.first().unwrap();
    let request_host = hosts.last().unwrap();
    let token = request_host.get_token(&db.pool).await.unwrap();
    let b_uuid = host.id.to_string();
    let inner = DeleteHostRequest {
        request_id: Some(Uuid::new_v4().to_string()),
        host_id: b_uuid,
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64()).parse().unwrap(),
    );

    assert_grpc_request! { delete, request, tonic::Code::PermissionDenied, db, HostsClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn can_update_host_info() -> anyhow::Result<()> {
    let db = _before_values.await;
    let host = db.test_host().await;
    let host_info = blockjoy::HostInfo {
        id: Some(host.id.to_string()),
        name: Some("tester".to_string()),
        version: None,
        location: None,
        cpu_count: None,
        mem_size: None,
        disk_size: None,
        os: None,
        os_version: None,
        ip: None,
        ip_gateway: Some("192.168.0.1".into()),
        ip_range_from: Some("192.168.0.10".into()),
        ip_range_to: Some("192.168.0.20".into()),
    };
    let fields = HostSelectiveUpdate::from(host_info);

    assert_eq!(
        Host::update_all(host.id, fields, &db.pool)
            .await
            .unwrap()
            .name,
        "tester".to_string()
    );

    // Fetch host after update to see if it really worked as expected
    let mut tx = db.pool.begin().await.unwrap();
    let row = sqlx::query(r#"SELECT * from hosts where ID = $1"#)
        .bind(host.id)
        .fetch_one(&mut tx)
        .await;
    tx.commit().await.unwrap();

    match row {
        Ok(row) => {
            let updated_host = Host::try_from(row)?;

            assert_eq!(updated_host.name, "tester".to_string());
            assert!(!updated_host.ip_addr.is_empty())
        }
        Err(e) => panic!("{:?}", e),
    }

    Ok(())
}
