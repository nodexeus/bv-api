use crate::grpc::api::{Action, Direction, Rule};
use crate::models::Node;
use crate::Error;
use crate::Result as ApiResult;
use anyhow::anyhow;

pub fn create_rule_for_nodes(node: &Node) -> ApiResult<Vec<Rule>> {
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
    denied_or_allowed_ips: &Vec<serde_json::Value>,
    action: Action,
) -> ApiResult<Rule> {
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
        action: action as i32,
        direction: Direction::In as i32,
        protocol: None,
        ips: Some(ips),
        ports: vec![],
    })
}
