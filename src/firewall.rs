use crate::grpc::blockjoy::{Direction, NodeFirewallUpdate, Policy, Protocol, Rule};
use crate::grpc::blockjoy_ui::FilteredIpAddr;
use crate::models::Node;
use crate::Error;
use crate::Result as ApiResult;
use anyhow::anyhow;

pub fn create_firewall_rule(denied_or_allowed_ips: &Vec<serde_json::Value>) -> ApiResult<Rule> {
    let mut ips: Vec<String> = vec![];

    for ip in denied_or_allowed_ips {
        let ip = ip
            .as_object()
            .ok_or_else(|| Error::UnexpectedError(anyhow!("Unknown IP object")))?;

        ips.push(String::from(
            ip.get("ip")
                .ok_or_else(|| Error::UnexpectedError(anyhow!("Invalid IP format")))?
                .as_str()
                .unwrap_or_default(),
        ));
    }
    let ips = ips.join(",");

    Ok(Rule {
        name: "".to_string(),
        policy: 0,
        direction: 0,
        protocol: None,
        ips: Some(ips),
        ports: vec![],
    })
}
