use displaydoc::Display;
use thiserror::Error;
use tracing::warn;

use crate::auth::AuthZ;
use crate::auth::resource::NodeId;
use crate::database::WriteConn;
use crate::grpc::{Status, api};
use crate::model::CommandId;
use crate::model::command::{Command, CommandType, NewCommand};
use crate::model::node::{
    LogEvent, NewNodeLog, Node, NodeJobs, NodeState, UpdateNodeMetrics, UpdateNodeState,
};

#[derive(Debug, Display, Error)]
pub enum Error {
    /// Command success model error: {0}
    Command(#[from] crate::model::command::Error),
    /// Command `{0}` failedto delete node `{1}`: {2}
    DeleteNode(CommandId, NodeId, crate::model::node::Error),
    /// Failed to serialize JSON: {0}
    Json(serde_json::Error),
    /// Command `{0}` is missing the `NodeId`.
    MissingNodeId(CommandId),
    /// Failed to write a NodeStart command to MQTT: {0}
    MqttStart(Box<super::Error>),
    /// Command success node error: {0}
    Node(#[from] crate::model::node::Error),
    /// Command success node log error: {0}
    NodeLog(#[from] crate::model::node::log::Error),
    /// No success visibility of NodeStart command.
    NoNodeStart,
}

impl From<Error> for Status {
    fn from(err: Error) -> Self {
        use Error::*;
        match err {
            Json(_) => Status::internal("Internal error."),
            MissingNodeId(_) => Status::invalid_argument("node_id"),
            NoNodeStart => Status::forbidden("Access denied."),
            DeleteNode(_, _, err) => err.into(),
            MqttStart(err) => (*err).into(),
            Command(err) => err.into(),
            Node(err) => err.into(),
            NodeLog(err) => err.into(),
        }
    }
}

/// Confirm success and take additional action after receiving `ExitCode::Ok`.
pub(super) async fn confirm(
    cmd: &Command,
    authz: &AuthZ,
    write: &mut WriteConn<'_, '_>,
) -> Result<(), Error> {
    match cmd.command_type {
        CommandType::NodeCreate => node_created(cmd, authz, write).await,
        CommandType::NodeUpgrade => node_upgraded(cmd, write).await,
        CommandType::NodeDelete => node_deleted(cmd, write).await,
        _ => Ok(()),
    }
}

/// After NodeCreate, write a log and send a start command.
async fn node_created(
    cmd: &Command,
    authz: &AuthZ,
    write: &mut WriteConn<'_, '_>,
) -> Result<(), Error> {
    let node_id = cmd.node_id.ok_or_else(|| Error::MissingNodeId(cmd.id))?;
    let node = Node::by_id(node_id, write).await?;

    NewNodeLog::from(&node, authz, LogEvent::CreateSucceeded)
        .create(write)
        .await?;

    let start_cmd = NewCommand::node(&node, CommandType::NodeStart)?
        .create(write)
        .await?;
    let start_cmd = api::Command::from(&start_cmd, authz, write)
        .await
        .map_err(|err| Error::MqttStart(Box::new(err)))?
        .ok_or(Error::NoNodeStart)?;
    write.mqtt(start_cmd);

    Ok(())
}

/// After NodeUpgrade, clear out any old jobs.
async fn node_upgraded(cmd: &Command, write: &mut WriteConn<'_, '_>) -> Result<(), Error> {
    let node_id = cmd.node_id.ok_or_else(|| Error::MissingNodeId(cmd.id))?;
    let update = UpdateNodeMetrics {
        id: node_id,
        node_state: None,
        protocol_state: None,
        protocol_health: None,
        block_height: None,
        block_age: None,
        consensus: None,
        apr: None,
        jobs: Some(NodeJobs(vec![])),
        jailed: None,
        jailed_reason: None,
        sqd_name: None,
    };
    let _updated = update.apply(write).await?;

    Ok(())
}

/// After NodeDelete, set the node status to deleted.
async fn node_deleted(cmd: &Command, write: &mut WriteConn<'_, '_>) -> Result<(), Error> {
    let node = cmd
        .node(write)
        .await?
        .ok_or_else(|| Error::MissingNodeId(cmd.id))?;
    if node.deleted_at.is_none() {
        // TODO: This should go on a queue for inconsistencies that we register
        warn!("Received a deleted confirmation for a node that is not deleted");
    }

    let update = UpdateNodeState {
        node_state: Some(NodeState::Deleted),
        next_state: Some(None),
        protocol_state: None,
        protocol_health: None,
        p2p_address: None,
    };
    let _ = update.apply(node.id, write).await?;

    Ok(())
}
