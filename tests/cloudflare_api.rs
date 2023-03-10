mod setup;

use api::cloudflare::CloudflareApi;
use axum::http;

#[tokio::test]
async fn can_create_node_dns() -> anyhow::Result<()> {
    let tester = setup::Tester::new().await;
    let mut node = tester.node().await;
    node.name = "stribu-test".to_string();

    let api = CloudflareApi::new()?;

    assert!(api.create_node_dns(node).await?);

    Ok(())
}
