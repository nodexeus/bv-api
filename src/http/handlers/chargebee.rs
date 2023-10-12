//! Handler for incoming chargebee events.
//!
//! These are currently only used for follow-up actions after the cancellation
//! of a subscription.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::{post, Router};
use diesel_async::scoped_futures::ScopedFutureExt;
use displaydoc::Display;
use serde::Deserialize;
use serde_enum_str::Deserialize_enum_str;
use thiserror::Error;
use tracing::{debug, error};

use crate::config::Context;
use crate::database::{Transaction, WriteConn};
use crate::grpc::api;
use crate::http::response::{bad_params, failed, not_found, ok_custom};
use crate::models::command::NewCommand;
use crate::models::{Command, CommandType, IpAddress, Node, Subscription};

#[derive(Debug, Display, Error)]
pub enum Error {
    /// Chargebee command: {0}
    Command(#[from] crate::models::command::Error),
    /// Chargebee database error: {0}
    Database(#[from] diesel::result::Error),
    /// Chargebee gRPC command: {0}
    GrpcCommand(#[from] crate::grpc::command::Error),
    /// Chargebee IpAddress: {0}
    IpAddress(#[from] crate::models::ip_address::Error),
    /// Chargebee node: {0}
    Node(#[from] crate::models::node::Error),
    /// Chargebee failed to parse IpAddr: {0}
    ParseIpAddr(std::net::AddrParseError),
    /// Chargebee subscription: {0}
    Subscription(#[from] crate::models::subscription::Error),
}

impl From<Error> for tonic::Status {
    fn from(err: Error) -> Self {
        use Error::*;
        error!("Chargebee webhook: {err:?}");
        match err {
            Command(_) | Database(_) | GrpcCommand(_) | IpAddress(_) | Node(_) | ParseIpAddr(_)
            | Subscription(_) => tonic::Status::internal("Internal error"),
        }
    }
}

pub fn router<S>(context: Arc<Context>) -> Router<S>
where
    S: Clone + Send + Sync,
{
    Router::new()
        .route("/callback/:secret", post(callback))
        .with_state(context)
}

#[derive(Debug, Deserialize)]
struct Callback {
    event: Event,
}

#[derive(Debug, Deserialize)]
struct Event {
    subscription: EventSubscription,
    event_type: EventType,
}

#[derive(Debug, Deserialize)]
struct EventSubscription {
    id: String,
}

#[derive(Debug, Deserialize_enum_str)]
#[serde(rename_all = "snake_case")]
enum EventType {
    SubscriptionCancelled,
    #[serde(other)]
    Other(String),
}

async fn callback(
    State(ctx): State<Arc<Context>>,
    Path(secret): Path<String>,
    body: String,
) -> Response {
    if ctx.config.chargebee.secret != secret {
        error!("Bad chargebee callback secret. Ignoring event.");
        // We return a 404 if the secret is incorrect, so we don't give away
        // that there is a secret in this url that might be brute-forced.
        return not_found();
    }

    // This is temporary, until we get it working end to end
    // I (luuk) will definitely be going into the logs to inspect these values
    dbg!(&body);

    // We only start parsing the json after the secret is verfied so people
    // can't try to discover this endpoint.
    let callback: Callback = match serde_json::from_str(&body) {
        Ok(body) => body,
        Err(err) => {
            error!("Failed to parse chargebee callback body `{body}`: {err:?}");
            return bad_params();
        }
    };

    dbg!(&callback);

    let resp = match callback.event.event_type {
        EventType::SubscriptionCancelled => {
            ctx.write(|c| subscription_cancelled(callback, c).scope_boxed())
                .await
        }
        EventType::Other(event) => {
            debug!("Skipping chargebee callback event: {event}");
            return ok_custom("event ignored");
        }
    };

    resp.map_or_else(|_| failed(), |resp| ok_custom(resp.into_inner()))
}

/// When a subscription is cancelled we delete all the nodes associated with
/// that org.
async fn subscription_cancelled(
    callback: Callback,
    mut write: WriteConn<'_, '_>,
) -> Result<&'static str, Error> {
    let id = callback.event.subscription.id;
    let subscription = Subscription::find_by_external_id(&id, &mut write).await?;
    let nodes = Node::find_by_org(subscription.org_id, &mut write).await?;

    for node in nodes {
        delete_node(&node, &mut write).await?;
    }

    Ok("subscription cancelled")
}

async fn delete_node(node: &Node, write: &mut WriteConn<'_, '_>) -> Result<(), Error> {
    // 1. Delete node, if the node belongs to the current user
    // Key files are deleted automatically because of 'on delete cascade' in tables DDL
    Node::delete(node.id, write).await?;

    let host_id = node.host_id;
    // 2. Do NOT delete reserved IP addresses, but set assigned to false
    let ip_addr = node.ip_addr.parse().map_err(Error::ParseIpAddr)?;
    let ip = IpAddress::find_by_node(ip_addr, write).await?;

    IpAddress::unassign(ip.id, host_id, write).await?;

    // Delete all pending commands for this node: there are not useable anymore
    Command::delete_pending(node.id, write).await?;

    // Send delete node command
    let node_id = node.id.to_string();
    let new_command = NewCommand {
        host_id: node.host_id,
        cmd: CommandType::DeleteNode,
        sub_cmd: Some(&node_id),
        // Note that the `node_id` goes into the `sub_cmd` field, not the node_id field, because the
        // node was just deleted.
        node_id: None,
    };
    let cmd = new_command.create(write).await?;
    let cmd = api::Command::from_model(&cmd, write).await?;

    let deleted = api::NodeMessage::deleted(node, None);

    write.mqtt(cmd);
    write.mqtt(deleted);

    Ok(())
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn can_parse_example_event() {
//         let test_event = "put sample event here once we have one";
//         let _: Callback = serde_json::from_str(test_event).unwrap();
//     }
// }
