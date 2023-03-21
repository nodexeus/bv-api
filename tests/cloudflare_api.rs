mod setup;

use api::cloudflare::CloudflareApi;

#[tokio::test]
async fn can_create_node_dns() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    let api = CloudflareApi::new("127.0.0.1".to_string())?;
    let mut name = String::from("test_");
    name.push_str(petname::petname(3, "_").as_str());
    let id = api.get_node_dns(name, "127.0.0.1".to_string()).await?;

    assert!(!id.is_empty());

    Ok(())
}

#[tokio::test]
#[ignore]
async fn can_remove_node_dns() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    let api = CloudflareApi::new("127.0.0.1".to_string())?;
    let id = "b32dfad93146bf7593b258e3064642c0".to_string();

    assert!(api.remove_node_dns(id).await?);

    Ok(())
}
