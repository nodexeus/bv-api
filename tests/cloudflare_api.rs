mod setup;

use blockvisor_api::config::{Config, Context};
use blockvisor_api::dns::{Cloudflare, Dns};
use blockvisor_api::grpc::{api, api::node_service_client};
use blockvisor_api::models::Node;
use tonic::transport;

type Service = node_service_client::NodeServiceClient<transport::Channel>;

#[tokio::test]
async fn can_create_node_dns() -> anyhow::Result<()> {
    let (ctx, _db) = Context::with_mocked().await.unwrap();

    let name = format!("test_{}", petname::petname(3, "_"));
    let id = ctx.dns.get_node_dns(&name, "127.0.0.1".to_string()).await?;
    assert!(!id.is_empty());

    Ok(())
}

#[tokio::test]
async fn can_create_node_with_dns() -> anyhow::Result<()> {
    let tester = setup::Tester::new().await;
    let mut conn = tester.conn().await;
    let blockchain = tester.blockchain().await;
    let user = tester.user().await;
    let org = tester.org_for(&user).await;
    let req = api::NodeServiceCreateRequest {
        org_id: org.id.to_string(),
        blockchain_id: blockchain.id.to_string(),
        node_type: api::NodeType::Validator.into(),
        properties: vec![],
        version: "3.3.0".to_string(),
        network: "some network".to_string(),
        placement: Some(api::NodePlacement {
            placement: Some(api::node_placement::Placement::HostId(
                tester.host().await.id.to_string(),
            )),
        }),
        allow_ips: vec![],
        deny_ips: vec![],
    };

    let resp = tester.send_admin(Service::create, req).await.unwrap();

    let node_id = resp.node.unwrap().id.parse().unwrap();
    let node = Node::find_by_id(node_id, &mut conn).await.unwrap();
    assert!(!node.dns_record_id.is_empty());

    Ok(())
}

#[tokio::test]
#[ignore]
async fn can_remove_node_dns() -> anyhow::Result<()> {
    let config = Config::new()?;

    let dns = Cloudflare::new(config.cloudflare.clone());
    let id = "b32dfad93146bf7593b258e3064642c0";

    assert!(dns.remove_node_dns(id).await.is_ok());

    Ok(())
}
