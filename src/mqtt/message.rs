use derive_more::From;
use displaydoc::Display;
use prost::Message as _;
use thiserror::Error;
use uuid::Uuid;

use crate::database::Conn;
use crate::grpc::api;
use crate::models::{Host, Invitation, Node, Org, User};

#[derive(Debug, Display, Error)]
pub enum Error {
    /// Failed to parse Host: {0}
    Host(Box<crate::Error>),
    /// Failed to parse Invitation from model: {0}
    Invitation(Box<crate::Error>),
    /// Missing `host_id`. This should not happen.
    MissingHostId,
    /// Missing `node_id`. This should not happen.
    MissingNodeId,
    /// Missing `org_id`. This should not happen.
    MissingOrgId,
    /// Failed to parse Node: {0}
    Node(Box<crate::Error>),
    /// Failed to parse User: {0}
    User(Box<crate::Error>),
}

#[derive(From)]
pub enum Message {
    Command(api::Command),
    OrgMessage(api::OrgMessage),
    HostMessage(api::HostMessage),
    NodeMessage(Box<api::NodeMessage>),
}

impl From<api::NodeMessage> for Message {
    fn from(value: api::NodeMessage) -> Self {
        Self::NodeMessage(Box::new(value))
    }
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Message::Command(msg) => msg.encode_to_vec(),
            Message::OrgMessage(msg) => msg.encode_to_vec(),
            Message::HostMessage(msg) => msg.encode_to_vec(),
            Message::NodeMessage(msg) => msg.encode_to_vec(),
        }
    }

    pub fn channels(&self) -> Result<Vec<String>, Error> {
        match self {
            Message::Command(msg) => msg.channels(),
            Message::OrgMessage(msg) => msg.channels(),
            Message::HostMessage(msg) => msg.channels(),
            Message::NodeMessage(msg) => msg.channels(),
        }
    }
}

impl api::Command {
    fn channels(&self) -> Result<Vec<String>, Error> {
        let host_id = self.host_id().ok_or(Error::MissingHostId)?;
        let mut channels = vec![format!("/hosts/{host_id}/commands")];

        if let Some(node_id) = self.node_id() {
            channels.push(format!("/hosts/{host_id}/nodes/{node_id}/commands"));
            channels.push(format!("/nodes/{node_id}/commands"));
        }

        Ok(channels)
    }

    fn host_id(&self) -> Option<&str> {
        match self.command.as_ref()? {
            api::command::Command::Node(cmd) => Some(&cmd.host_id),
            api::command::Command::Host(cmd) => Some(&cmd.host_id),
        }
    }

    fn node_id(&self) -> Option<&str> {
        match self.command.as_ref()? {
            api::command::Command::Node(cmd) => Some(&cmd.node_id),
            api::command::Command::Host(_) => None,
        }
    }
}

impl api::OrgMessage {
    fn channels(&self) -> Result<Vec<String>, Error> {
        let org_id = self.org_id().ok_or(Error::MissingOrgId)?;

        Ok(vec![format!("/orgs/{org_id}")])
    }

    fn org_id(&self) -> Option<Uuid> {
        use api::org_message::Message::*;
        match self.message.as_ref()? {
            Created(api::OrgCreated { org, .. }) => org.as_ref()?.id.parse().ok(),
            Updated(api::OrgUpdated { org, .. }) => org.as_ref()?.id.parse().ok(),
            Deleted(api::OrgDeleted { org_id, .. }) => org_id.parse().ok(),
            InvitationCreated(api::InvitationCreated { org_id, .. }) => org_id.parse().ok(),
            InvitationAccepted(api::InvitationAccepted { org_id, .. }) => org_id.parse().ok(),
            InvitationDeclined(api::InvitationDeclined { org_id, .. }) => org_id.parse().ok(),
        }
    }

    pub fn created(org: api::Org, user: User) -> Self {
        Self {
            message: Some(api::org_message::Message::Created(api::OrgCreated {
                org: Some(org),
                created_by: user.id.to_string(),
                created_by_name: user.name(),
                created_by_email: user.email,
            })),
        }
    }

    pub fn updated(org: api::Org, user: User) -> Self {
        Self {
            message: Some(api::org_message::Message::Updated(api::OrgUpdated {
                org: Some(org),
                updated_by: user.id.to_string(),
                updated_by_name: user.name(),
                updated_by_email: user.email,
            })),
        }
    }

    pub fn deleted(org: Org, user: User) -> Self {
        Self {
            message: Some(api::org_message::Message::Deleted(api::OrgDeleted {
                org_id: org.id.to_string(),
                deleted_by: user.id.to_string(),
                deleted_by_name: user.name(),
                deleted_by_email: user.email,
            })),
        }
    }

    pub async fn invitation_created(
        org: Org,
        invitation: Invitation,
        conn: &mut Conn<'_>,
    ) -> Result<Self, Error> {
        let invitation = api::Invitation::from_model(invitation, conn)
            .await
            .map_err(|err| Error::Invitation(Box::new(err)))?;

        Ok(Self {
            message: Some(api::org_message::Message::InvitationCreated(
                api::InvitationCreated {
                    org_id: org.id.to_string(),
                    invitation: Some(invitation),
                },
            )),
        })
    }

    pub async fn invitation_accepted(
        org: Org,
        invitation: Invitation,
        user: User,
        conn: &mut Conn<'_>,
    ) -> Result<Self, Error> {
        let invitation = api::Invitation::from_model(invitation, conn)
            .await
            .map_err(|err| Error::Invitation(Box::new(err)))?;
        let user = api::User::from_model(user).map_err(|err| Error::User(Box::new(err)))?;

        Ok(Self {
            message: Some(api::org_message::Message::InvitationAccepted(
                api::InvitationAccepted {
                    org_id: org.id.to_string(),
                    invitation: Some(invitation),
                    user: Some(user),
                },
            )),
        })
    }

    pub async fn invitation_declined(
        org: Org,
        invitation: Invitation,
        conn: &mut Conn<'_>,
    ) -> Result<Self, Error> {
        let invitation = api::Invitation::from_model(invitation, conn)
            .await
            .map_err(|err| Error::Invitation(Box::new(err)))?;

        Ok(Self {
            message: Some(api::org_message::Message::InvitationDeclined(
                api::InvitationDeclined {
                    org_id: org.id.to_string(),
                    invitation: Some(invitation),
                },
            )),
        })
    }
}

impl api::HostMessage {
    fn channels(&self) -> Result<Vec<String>, Error> {
        let host_id = self.host_id().ok_or(Error::MissingHostId)?;

        Ok(vec![format!("/hosts/{host_id}")])
    }

    fn host_id(&self) -> Option<Uuid> {
        use api::host_message::Message::*;
        match self.message.as_ref()? {
            Created(api::HostCreated { host, .. }) => host.as_ref()?.id.parse().ok(),
            Updated(api::HostUpdated { host, .. }) => host.as_ref()?.id.parse().ok(),
            Deleted(api::HostDeleted { host_id, .. }) => host_id.parse().ok(),
        }
    }

    pub async fn created(host: Host, user: User, conn: &mut Conn<'_>) -> Result<Self, Error> {
        let host = api::Host::from_model(host, conn)
            .await
            .map_err(|err| Error::Host(Box::new(err)))?;

        Ok(Self {
            message: Some(api::host_message::Message::Created(api::HostCreated {
                host: Some(host),
                created_by: user.id.to_string(),
                created_by_name: user.name(),
                created_by_email: user.email,
            })),
        })
    }

    pub async fn updated(host: Host, user: User, conn: &mut Conn<'_>) -> Result<Self, Error> {
        let host = api::Host::from_model(host, conn)
            .await
            .map_err(|err| Error::Host(Box::new(err)))?;

        Ok(Self {
            message: Some(api::host_message::Message::Updated(api::HostUpdated {
                host: Some(host),
                updated_by: Some(user.id.to_string()),
                updated_by_name: Some(user.name()),
                updated_by_email: Some(user.email),
            })),
        })
    }

    pub async fn updated_many(models: Vec<Host>, conn: &mut Conn<'_>) -> Result<Vec<Self>, Error> {
        api::Host::from_models(models, conn)
            .await
            .map_err(|err| Error::Host(Box::new(err)))?
            .into_iter()
            .map(|host| {
                Ok(Self {
                    message: Some(api::host_message::Message::Updated(api::HostUpdated {
                        host: Some(host),
                        updated_by: None,
                        updated_by_name: None,
                        updated_by_email: None,
                    })),
                })
            })
            .collect()
    }

    pub fn deleted(host: Host, user: User) -> Self {
        Self {
            message: Some(api::host_message::Message::Deleted(api::HostDeleted {
                host_id: host.id.to_string(),
                deleted_by: user.id.to_string(),
                deleted_by_name: user.name(),
                deleted_by_email: user.email,
            })),
        }
    }
}

impl api::NodeMessage {
    fn channels(&self) -> Result<Vec<String>, Error> {
        let org_id = self.org_id().ok_or(Error::MissingOrgId)?;
        let host_id = self.host_id().ok_or(Error::MissingHostId)?;
        let node_id = self.node_id().ok_or(Error::MissingNodeId)?;

        Ok(vec![
            format!("/orgs/{org_id}/nodes"),
            format!("/hosts/{host_id}/nodes"),
            format!("/nodes/{node_id}"),
        ])
    }

    fn node_id(&self) -> Option<Uuid> {
        use api::node_message::Message::*;
        match self.message.as_ref()? {
            Created(api::NodeCreated { node, .. }) => node.as_ref()?.id.parse().ok(),
            Updated(api::NodeUpdated { node, .. }) => node.as_ref()?.id.parse().ok(),
            Deleted(api::NodeDeleted { node_id, .. }) => node_id.parse().ok(),
        }
    }

    fn host_id(&self) -> Option<Uuid> {
        use api::node_message::Message::*;
        match self.message.as_ref()? {
            Created(api::NodeCreated { node, .. }) => node.as_ref()?.host_id.parse().ok(),
            Updated(api::NodeUpdated { node, .. }) => node.as_ref()?.host_id.parse().ok(),
            Deleted(api::NodeDeleted { host_id, .. }) => host_id.parse().ok(),
        }
    }

    fn org_id(&self) -> Option<Uuid> {
        use api::node_message::Message::*;
        match self.message.as_ref()? {
            Created(api::NodeCreated { node, .. }) => node.as_ref()?.org_id.parse().ok(),
            Updated(api::NodeUpdated { node, .. }) => node.as_ref()?.org_id.parse().ok(),
            Deleted(api::NodeDeleted { org_id, .. }) => org_id.parse().ok(),
        }
    }

    pub fn created(node: api::Node, user: User) -> Self {
        Self {
            message: Some(api::node_message::Message::Created(api::NodeCreated {
                node: Some(node),
                created_by: user.id.to_string(),
                created_by_name: user.name(),
                created_by_email: user.email,
            })),
        }
    }

    pub async fn updated(
        node: Node,
        user: Option<User>,
        conn: &mut Conn<'_>,
    ) -> Result<Self, Error> {
        let node = api::Node::from_model(node, conn)
            .await
            .map_err(|err| Error::Node(Box::new(err)))?;

        Ok(Self {
            message: Some(api::node_message::Message::Updated(api::NodeUpdated {
                node: Some(node),
                updated_by: user.as_ref().map(|u| u.id.to_string()),
                updated_by_name: user.as_ref().map(|u| u.name()),
                updated_by_email: user.map(|u| u.email),
            })),
        })
    }

    pub async fn updated_many(models: Vec<Node>, conn: &mut Conn<'_>) -> Result<Vec<Self>, Error> {
        api::Node::from_models(models, conn)
            .await
            .map_err(|err| Error::Node(Box::new(err)))?
            .into_iter()
            .map(|node| {
                Ok(Self {
                    message: Some(api::node_message::Message::Updated(api::NodeUpdated {
                        node: Some(node),
                        updated_by: None,
                        updated_by_name: None,
                        updated_by_email: None,
                    })),
                })
            })
            .collect()
    }

    pub fn deleted(node: Node, user: User) -> Self {
        Self {
            message: Some(api::node_message::Message::Deleted(api::NodeDeleted {
                node_id: node.id.to_string(),
                host_id: node.host_id.to_string(),
                org_id: node.org_id.to_string(),
                deleted_by: user.id.to_string(),
                deleted_by_name: user.name(),
                deleted_by_email: user.email,
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::Context;

    use super::*;

    #[tokio::test]
    async fn test_send_command() {
        let (ctx, db) = Context::with_mocked().await.unwrap();

        let command = db.command().await;
        let mut conn = db.conn().await;

        let command = api::Command::from_model(&command, &mut conn).await.unwrap();
        ctx.notifier.send([command]).await.unwrap();
    }

    #[tokio::test]
    async fn test_send_hosts() {
        let (ctx, db) = Context::with_mocked().await.unwrap();
        let mut conn = db.conn().await;

        let host = db.host().await;
        let user = db.user().await;

        let msg = api::HostMessage::created(host.clone(), user.clone(), &mut conn)
            .await
            .unwrap();
        ctx.notifier.send([msg]).await.unwrap();

        let msg = api::HostMessage::updated(host.clone(), user.clone(), &mut conn)
            .await
            .unwrap();
        ctx.notifier.send([msg]).await.unwrap();

        let msg = api::HostMessage::deleted(host, user);
        ctx.notifier.send([msg]).await.unwrap();
    }

    #[tokio::test]
    async fn test_send_nodes() {
        let (ctx, db) = Context::with_mocked().await.unwrap();
        let mut conn = db.conn().await;

        let node = db.node().await;
        let user = db.user().await;

        let node_model = api::Node::from_model(node.clone(), &mut conn)
            .await
            .unwrap();
        let msg = api::NodeMessage::created(node_model.clone(), user.clone());
        ctx.notifier.send([msg]).await.unwrap();

        let msg = api::NodeMessage::updated(node.clone(), Some(user.clone()), &mut conn)
            .await
            .unwrap();
        ctx.notifier.send([msg]).await.unwrap();

        let msg = api::NodeMessage::deleted(node, user);
        ctx.notifier.send([msg]).await.unwrap();
    }
}
