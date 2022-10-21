mod setup;

use api::models::{IpAddress, IpAddressRangeRequest};
use setup::setup;
use std::net::IpAddr;
use std::str::FromStr;
use test_macros::*;

#[before(call = "setup")]
#[tokio::test]
async fn should_create_ip_range() -> anyhow::Result<()> {
    let db = _before_values.await;
    let host = db.test_host().await;
    let req = IpAddressRangeRequest::try_new(
        IpAddr::from_str("192.129.0.10").unwrap(),
        IpAddr::from_str("192.129.0.20").unwrap(),
        Some(host.id),
    )?;
    let range = IpAddress::create_range(req, &db.pool).await?;

    assert_eq!(range.len(), 11);

    Ok(())
}

#[before(call = "setup")]
#[tokio::test]
async fn should_fail_creating_ip_range() -> anyhow::Result<()> {
    let db = _before_values.await;
    let host = db.test_host().await;
    match IpAddressRangeRequest::try_new(
        IpAddr::from_str("192.129.0.20").unwrap(),
        IpAddr::from_str("192.129.0.10").unwrap(),
        Some(host.id),
    ) {
        Ok(_) => panic!("This should error"),
        Err(_) => println!("all good"),
    }

    Ok(())
}

#[test]
fn should_fail_if_ip_in_range() {
    let ref_ip = IpAddr::from_str("192.168.0.15").unwrap();
    let from_ip = IpAddr::from_str("192.168.0.10").unwrap();
    let to_ip = IpAddr::from_str("192.168.0.10").unwrap();

    assert!(!IpAddress::in_range(ref_ip, from_ip, to_ip));
}
