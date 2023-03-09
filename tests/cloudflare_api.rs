mod setup;

use api::cloudflare::CloudflareApi;

#[tokio::test]
async fn can_create_node_dns() -> anyhow::Result<()> {
    let tester = setup::Tester::new().await;
    let node = tester.node().await;
    let api = CloudflareApi::new()?;

    assert!(api.create_node_dns(node).await?);

    Ok(())
}
