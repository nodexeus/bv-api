#[allow(dead_code)]
mod setup;

use api::auth::TokenIdentifyable;
use api::grpc::blockjoy;
use api::grpc::blockjoy::{hosts_client::HostsClient, HostInfoUpdateRequest, ProvisionHostRequest};
use api::models::{Host, HostProvision, HostProvisionRequest, HostSelectiveUpdate};
use setup::{get_test_host, setup};
use sqlx::PgPool;
use std::convert::TryFrom;
use std::future::Future;
use std::sync::Arc;
use tempfile::NamedTempFile;
use test_macros::*;
use tokio::net::{UnixListener, UnixStream};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Request, Status};
use tower::service_fn;
use uuid::Uuid;

async fn server_and_client_stub(
    db: Arc<PgPool>,
) -> (impl Future<Output = ()>, HostsClient<Channel>) {
    let socket = NamedTempFile::new().unwrap();
    let socket = Arc::new(socket.into_temp_path());
    std::fs::remove_file(&*socket).unwrap();

    let uds = UnixListener::bind(&*socket).unwrap();
    let stream = UnixListenerStream::new(uds);
    let serve_future = async {
        let result = api::grpc::server(db)
            .await
            .serve_with_incoming(stream)
            .await;

        assert!(result.is_ok());
    };

    let socket = Arc::clone(&socket);
    // Connect to the server over a Unix socket
    // The URL will be ignored.
    let channel = Endpoint::try_from("http://any.url")
        .unwrap()
        .connect_with_connector(service_fn(move |_: Uri| {
            let socket = Arc::clone(&socket);
            async move { UnixStream::connect(&*socket).await }
        }))
        .await
        .unwrap();

    let client = HostsClient::new(channel);

    (serve_future, client)
}

macro_rules! assert_grpc_request {
    ($r:expr, $s:expr, $db: expr) => {{
        // db must be defined in the calling fn
        let (serve_future, mut client) = server_and_client_stub($db).await;

        let request_future = async {
            match client.info_update($r).await {
                Ok(response) => {
                    let inner = response.into_inner();
                    println!("response OK: {:?}", inner);
                }
                Err(e) => {
                    let s = Status::from(e);
                    assert_eq!($s, s.code());
                }
            }
        };

        // Wait for completion, when the client request future completes
        tokio::select! {
        _ = serve_future => panic!("server returned first"),
        _ = request_future => (),
        }
    }};

    ($m:tt, $r:expr, $s:expr, $db: expr) => {{
        // db must be defined in the calling fn
        let (serve_future, mut client) = server_and_client_stub($db).await;

        let request_future = async {
            match client.$m($r).await {
                Ok(response) => {
                    let inner = response.into_inner();
                    println!("response OK: {:?}", inner);
                }
                Err(e) => {
                    let s = Status::from(e);
                    assert_eq!($s, s.code());
                }
            }
        };

        // Wait for completion, when the client request future completes
        tokio::select! {
            _ = serve_future => panic!("server returned first"),
            _ = request_future => (),
        }
    }};
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_unauthenticated_without_valid_token_for_info_update() {
    let db = Arc::new(_before_values.await);
    let hosts = Host::find_all(&db).await.unwrap();
    let host = hosts.first().unwrap();
    let b_uuid = blockjoy::Uuid::from(host.id);
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
    };
    let inner = HostInfoUpdateRequest {
        request_id: Some(blockjoy::Uuid::from(Uuid::new_v4())),
        info: Some(host_info),
    };
    let mut request = Request::new(inner);

    request
        .metadata_mut()
        .insert("authorization", "".parse().unwrap());

    assert_grpc_request! { request, tonic::Code::Unauthenticated, db };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_unauthenticated_without_token_for_info_update() {
    let db = Arc::new(_before_values.await);
    let hosts = Host::find_all(&db).await.unwrap();
    let host = hosts.first().unwrap();
    let b_uuid = blockjoy::Uuid::from(host.id);

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
    };
    let inner = HostInfoUpdateRequest {
        request_id: Some(blockjoy::Uuid::from(Uuid::new_v4())),
        info: Some(host_info),
    };

    assert_grpc_request! { Request::new(inner), tonic::Code::Unauthenticated, db };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_unauthenticated_with_token_for_info_update() {
    let db = Arc::new(_before_values.await);
    let host = get_test_host(&db).await;
    let b_uuid = blockjoy::Uuid::from(host.id);

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
    };
    let inner = HostInfoUpdateRequest {
        request_id: Some(blockjoy::Uuid::from(Uuid::new_v4())),
        info: Some(host_info),
    };
    let mut request = Request::new(inner);

    request
        .metadata_mut()
        .insert("authorization", "923783".parse().unwrap());

    assert_grpc_request! { request, tonic::Code::Unauthenticated, db };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_permission_denied_with_token_ownership_for_info_update() {
    let db = Arc::new(_before_values.await);
    let hosts = Host::find_all(&db).await.unwrap();
    let request_token = hosts.first().unwrap().get_token(&db).await.unwrap();
    let resource_host = hosts.last().unwrap();
    let b_uuid = blockjoy::Uuid::from(resource_host.id);
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
    };
    let inner = HostInfoUpdateRequest {
        request_id: Some(blockjoy::Uuid::from(Uuid::new_v4())),
        info: Some(host_info),
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", request_token.to_base64())
            .parse()
            .unwrap(),
    );

    assert_grpc_request! { request, tonic::Code::PermissionDenied, db };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_not_found_for_provision() {
    let db = Arc::new(_before_values.await);
    let b_uuid = blockjoy::Uuid::from(Uuid::new_v4());
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
    };
    let inner = ProvisionHostRequest {
        request_id: Some(blockjoy::Uuid::from(Uuid::new_v4())),
        otp: "unknown-otp".into(),
        info: Some(host_info),
        validator_ips: vec![],
        org_id: None,
        token: "".into(),
        status: 0,
    };
    let request = Request::new(inner);

    assert_grpc_request! { provision, request, tonic::Code::NotFound, db };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_ok_for_provision() {
    let db = Arc::new(_before_values.await);
    let mut tx = db.begin().await.unwrap();
    let org: (Uuid,) = sqlx::query_as("select id from orgs")
        .fetch_one(&mut tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let host_provision_request = HostProvisionRequest {
        org_id: org.0,
        nodes: None,
    };
    let host_provision = HostProvision::create(host_provision_request, &db)
        .await
        .unwrap();
    let host_info = blockjoy::HostInfo {
        id: Some(blockjoy::Uuid::from(Uuid::new_v4())),
        name: Some("tester".into()),
        version: None,
        location: None,
        cpu_count: None,
        mem_size: None,
        disk_size: None,
        os: None,
        os_version: None,
        ip: Some("123.456.789.0".into()),
    };
    let inner = ProvisionHostRequest {
        request_id: Some(blockjoy::Uuid::from(Uuid::new_v4())),
        otp: host_provision.id,
        info: Some(host_info),
        validator_ips: vec![],
        org_id: None,
        token: "".into(),
        status: 0,
    };
    let request = Request::new(inner);

    assert_grpc_request! { provision, request, tonic::Code::Ok, db };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_ok_for_info_update() {
    let db = Arc::new(_before_values.await);
    let hosts = Host::find_all(&db).await.unwrap();
    let host = hosts.first().unwrap();
    let token = host.get_token(&db).await.unwrap();
    let b_uuid = blockjoy::Uuid::from(host.id);
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
    };
    let inner = HostInfoUpdateRequest {
        request_id: Some(blockjoy::Uuid::from(Uuid::new_v4())),
        info: Some(host_info),
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64()).parse().unwrap(),
    );

    assert_grpc_request! { request, tonic::Code::Ok, db };
}

#[before(call = "setup")]
#[tokio::test]
async fn can_update_host_info() {
    let db = Arc::new(_before_values.await);
    let host = get_test_host(&db).await;
    let host_info = blockjoy::HostInfo {
        id: Some(blockjoy::Uuid::from(host.id)),
        name: Some("tester".to_string()),
        version: None,
        location: None,
        cpu_count: None,
        mem_size: None,
        disk_size: None,
        os: None,
        os_version: None,
        ip: None,
    };
    let fields = HostSelectiveUpdate::from(host_info);

    assert_eq!(
        Host::update_all(host.id, fields, &db).await.unwrap().name,
        "tester".to_string()
    );

    // Fetch host after update to see if it really worked as expected
    let mut tx = db.begin().await.unwrap();
    let row = sqlx::query(r#"SELECT * from hosts where ID = $1"#)
        .bind(host.id)
        .fetch_one(&mut tx)
        .await;
    tx.commit().await.unwrap();

    match row {
        Ok(row) => {
            let updated_host = Host::from(row);

            assert_eq!(updated_host.name, "tester".to_string());
            assert!(!updated_host.ip_addr.is_empty())
        }
        Err(e) => panic!("{:?}", e),
    }
}
