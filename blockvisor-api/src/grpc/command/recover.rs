//! This module contains code regarding recovery from failed commands.

use displaydoc::Display;
use thiserror::Error;
use tracing::warn;

use crate::auth::AuthZ;
use crate::auth::resource::{HostId, OrgId};
use crate::database::WriteConn;
use crate::grpc::{Status, api};
use crate::model::command::NewCommand;
use crate::model::node::{LogEvent, NewNodeLog, UpdateNode};
use crate::model::{Command, CommandType, Host, IpAddress, Node, Protocol};

#[derive(Debug, Display, Error)]
pub enum Error {
    /// Failed to create cancelled log: {0}
    CancelledLog(crate::model::node::log::Error),
    /// Command recovery error: {0}
    Command(#[from] crate::model::command::Error),
    /// Command recovery failed to build a new NodeCreate command: {0}
    CreateCommand(Box<crate::grpc::command::Error>),
    /// Recovery of `CreateNode` command has no node id.
    CreateNodeId,
    /// Command recovery dns error: {0}
    Dns(#[from] crate::cloudflare::Error),
    /// Failed to create deployment log: {0}
    DeploymentLog(crate::model::node::log::Error),
    /// Command recovery host error: {0}
    Host(#[from] crate::model::host::Error),
    /// Command recovery ip address: {0}
    IpAddress(#[from] crate::model::ip_address::Error),
    /// Command recovery node error: {0}
    Node(#[from] crate::model::node::Error),
    /// No IP addresses available for host: {0}
    NoIps(HostId),
    /// No recovery visibilitiy of NodeCreate command.
    NoNodeCreate,
    /// No recovery visibilitiy of NodeStart command.
    NoNodeStart,
    /// Command protocol error: {0}
    Protocol(#[from] crate::model::protocol::Error),
    /// Command recovery failed to build a new NodeStart command: {0}
    StartCommand(Box<crate::grpc::command::Error>),
    /// Command recovery failed to update node: {0}
    UpdateNode(crate::model::node::Error),
}

impl From<Error> for Status {
    fn from(err: Error) -> Self {
        use Error::*;
        match err {
            Dns(_) => Status::internal("Internal error."),
            CreateNodeId => Status::invalid_argument("node_id"),
            NoIps(_) => Status::failed_precondition("No host IPs."),
            NoNodeCreate | NoNodeStart => Status::forbidden("Access denied."),
            CancelledLog(err) => err.into(),
            Command(err) => err.into(),
            CreateCommand(err) => (*err).into(),
            DeploymentLog(err) => err.into(),
            Host(err) => err.into(),
            IpAddress(err) => err.into(),
            Node(err) | UpdateNode(err) => err.into(),
            Protocol(err) => err.into(),
            StartCommand(err) => (*err).into(),
        }
    }
}

/// Attempt to recover from a failed `Command`.
pub(super) async fn recover(
    failed: &Command,
    org_id: Option<OrgId>,
    authz: &AuthZ,
    write: &mut WriteConn<'_, '_>,
) -> Result<Vec<api::Command>, Error> {
    match failed.command_type {
        CommandType::NodeCreate => node_create_failed(failed, org_id, authz, write).await,
        _ => Ok(vec![]),
    }
}

/// Recover from a failed node creation.
async fn node_create_failed(
    failed: &Command,
    org_id: Option<OrgId>,
    authz: &AuthZ,
    write: &mut WriteConn<'_, '_>,
) -> Result<Vec<api::Command>, Error> {
    let node_id = failed.node_id.ok_or(Error::CreateNodeId)?;
    let node = Node::by_id(node_id, write).await?;
    Host::remove_node(&node, write).await?;

    // log that creating the node failed.
    let _ = NewNodeLog::from(&node, authz, LogEvent::CreateFailed)
        .create(write)
        .await
        .map_err(Error::DeploymentLog)?;

    if let Err(err) = write.ctx.dns.delete(&node.dns_id).await {
        warn!("Failed to remove node dns for node {}: {err}", node.id);
    }

    // find the next host to assign the node to
    let protocol = Protocol::by_id(node.protocol_id, org_id, authz, write).await?;
    let Some(host) = node.next_host(&protocol, write).await? else {
        return NewNodeLog::from(&node, authz, LogEvent::CreateCancelled)
            .create(write)
            .await
            .map(|_log| vec![])
            .map_err(Error::CancelledLog);
    };

    // update the node to the new host
    let ip = IpAddress::next_for_host(host.id, write)
        .await?
        .ok_or(Error::NoIps(host.id))?;
    let update = UpdateNode {
        org_id: None,
        host_id: Some(host.id),
        display_name: None,
        auto_upgrade: None,
        ip_address: Some(ip.ip),
        ip_gateway: Some(host.ip_gateway),
        note: None,
        tags: None,
        cost: None,
    };
    let node = update
        .apply(node_id, authz, write)
        .await
        .map_err(Error::UpdateNode)?;

    Host::add_node(&node, write).await?;
    write.ctx.dns.create(&node.dns_name, ip.ip.ip()).await?;

    // notify blockvisor to create the new node
    let mut commands = vec![];
    let create_cmd = NewCommand::node(&node, CommandType::NodeCreate)?
        .create(write)
        .await?;
    let create_cmd = api::Command::from(&create_cmd, authz, write)
        .await
        .map_err(|err| Error::CreateCommand(Box::new(err)))?
        .ok_or(Error::NoNodeCreate)?;
    commands.push(create_cmd);

    // and to start it
    let start_cmd = NewCommand::node(&node, CommandType::NodeStart)?
        .create(write)
        .await?;
    let start_cmd = api::Command::from(&start_cmd, authz, write)
        .await
        .map_err(|err| Error::StartCommand(Box::new(err)))?
        .ok_or(Error::NoNodeStart)?;
    commands.push(start_cmd);

    Ok(commands)
}
