mod setup;

use api::cloudflare::CloudflareApi;

#[tokio::test]
async fn can_create_node_dns() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    let api = CloudflareApi::new()?;
    let mut name = String::from("test_");
    name.push_str(petname::petname(3, "_").as_str());
    let id = api.get_node_dns(name).await?;

    assert!(!id.is_empty());

    Ok(())
}

#[tokio::test]
#[ignore]
async fn can_remove_node_dns() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    let api = CloudflareApi::new()?;
    let id = "97c3c61963a3b2b94f9b066deff22185".to_string();

    assert!(api.remove_node_dns(id).await?);

    Ok(())
}
