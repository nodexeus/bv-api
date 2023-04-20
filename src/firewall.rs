use crate::grpc::api::{Action, Direction, Rule};
use crate::models::Node;
use crate::Error;
use crate::Result as ApiResult;
use anyhow::anyhow;
use std::net::Ipv4Addr;
use std::str::FromStr;

pub fn create_rule_for_node(node: &Node) -> ApiResult<Vec<Rule>> {
    let mut rules: Vec<Rule> = vec![];
    let allow_ips = node
        .allow_ips
        .as_array()
        .ok_or_else(|| Error::UnexpectedError(anyhow!("No allowed IPs defined")))?;
    let deny_ips = node
        .deny_ips
        .as_array()
        .ok_or_else(|| Error::UnexpectedError(anyhow!("No deny IPs defined")))?;

    rules.push(create_firewall_rule(allow_ips, Action::Deny)?);
    rules.push(create_firewall_rule(deny_ips, Action::Allow)?);

    Ok(rules)
}

fn create_firewall_rule(
    // I'll leave the Vec for now, maybe we need it later
    denied_or_allowed_ips: &Vec<serde_json::Value>,
    action: Action,
) -> ApiResult<Rule> {
    let mut final_ip = String::new();

    for ip in denied_or_allowed_ips {
        let ip = ip
            .as_object()
            .ok_or_else(|| Error::UnexpectedError(anyhow!("Unknown IP object")))?;
        let ip = String::from(
            ip.get("ip")
                .ok_or_else(|| Error::UnexpectedError(anyhow!("Invalid IP format")))?
                .as_str()
                .unwrap_or_default(),
        );

        // Validate IP
        if ip.contains('/') {
            final_ip = cidr::Ipv4Cidr::from_str(ip.as_str())?.to_string();
        } else {
            final_ip = Ipv4Addr::from_str(ip.as_str())?.to_string();
        };
    }

    Ok(Rule {
        name: "".to_string(),
        action: action as i32,
        direction: Direction::In as i32,
        protocol: None,
        ips: Some(final_ip),
        ports: vec![],
    })
}
