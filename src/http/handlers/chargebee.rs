//! Handler meant to deal will the incoming chargebee events. These are currently only used to deal
//! with people canceling their billing and in so doing cancel their blockjoy account.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{post, Router};
use axum::Json;
use diesel_async::scoped_futures::ScopedFutureExt;
use displaydoc::Display;
use hyper::StatusCode;
use thiserror::Error;

use crate::config::Context;
use crate::database::{Transaction, WriteConn};
use crate::grpc::api;
use crate::models::command::NewCommand;
use crate::models::{Command, CommandType, IpAddress, Node, Subscription};

pub fn router<S>(context: Arc<Context>) -> Router<S>
where
    S: Clone + Send + Sync,
{
    Router::new()
        .route("/callback/:secret", post(callback))
        .with_state(context)
}

async fn callback(
    Path(secret): Path<String>,
    State(ctx): State<Arc<Context>>,
    Json(callback): Json<Callback>,
) -> Result<Response, (Response, StatusCode)> {
    if secret != ctx.config.chargebee.secret {
        return Err((Resp::new("not found"), StatusCode::NOT_FOUND));
    }

    let resp = match callback.event.event_type {
        EventType::SubscriptionCancelled => {
            ctx.write(|c| subscription_cancelled(callback, c).scope_boxed())
                .await
        }
        EventType::Other => return Ok(Resp::new("event ignored")),
    };

    resp.map(|resp| Resp::new(resp.into_inner())).map_err(|e| {
        tracing::warn!("{e:?}");
        (Resp::new("error"), StatusCode::INTERNAL_SERVER_ERROR)
    })
}

async fn subscription_cancelled(
    callback: Callback,
    mut write: WriteConn<'_, '_>,
) -> Result<tonic::Response<&'static str>, Error> {
    let subscription =
        Subscription::find_by_external_id(&callback.event.subscription.id, &mut write).await?;
    let nodes = Node::find_by_org(subscription.org_id, &mut write).await?;
    for node in nodes {
        delete_node(&node, &mut write).await?;
    }
    Ok(tonic::Response::new("subscription canceled"))
}

#[derive(serde::Deserialize)]
struct Callback {
    event: Event,
}

#[derive(serde::Deserialize)]
struct Event {
    subscription: EventSubscription,
    event_type: EventType,
}

#[derive(serde::Deserialize)]
struct EventSubscription {
    id: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum EventType {
    SubscriptionCancelled,
    #[serde(other)]
    Other,
}

#[derive(serde::Serialize)]
struct Resp {
    msg: &'static str,
}

impl Resp {
    fn new(msg: &'static str) -> Response {
        Json(Self { msg }).into_response()
    }
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

    let deleted = api::NodeMessage::deleted(&node, None);

    write.mqtt(cmd);
    write.mqtt(deleted);

    Ok(())
}

#[derive(Debug, Display, Error)]
pub enum Error {
    /// Node error: {0}
    Node(#[from] crate::models::node::Error),
    /// Subscription error: {0}
    Subscription(#[from] crate::models::subscription::Error),
    /// IpAddress error: {0}
    IpAddress(#[from] crate::models::ip_address::Error),
    /// Command error: {0}
    Command(#[from] crate::models::command::Error),
    /// Error constructing a gRPC command message: {0}
    CommandGrpc(#[from] crate::grpc::command::Error),
    /// Database error: {0}
    Database(#[from] diesel::result::Error),

    /// Failed to parse IpAddr: {0}
    ParseIpAddr(std::net::AddrParseError),
}

impl From<Error> for tonic::Status {
    fn from(err: Error) -> Self {
        use Error::*;
        tracing::error!("{err}");
        match err {
            Node(_) | Subscription(_) | Database(_) | ParseIpAddr(_) | IpAddress(_)
            | Command(_) | CommandGrpc(_) => tonic::Status::internal("Internal error"),
        }
    }
}
