use std::collections::HashMap;

use displaydoc::Display;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tonic::Status;
use tracing::error;

use crate::database::Conn;
use crate::models::{Host, Node, Org};
use crate::timestamp::SecondsUtc;

use super::endpoint::{Endpoint, Endpoints};
use super::resource::{HostId, NodeId, OrgId, Resource, ResourceEntry, UserId};

#[derive(Debug, Display, Error)]
pub enum Error {
    /// Host does not have permission to access the requested HostId.
    EnsureHost,
    /// Node does not have permission to access the requested NodeId.
    EnsureNode,
    /// Org does not have permission to access the requested OrgId.
    EnsureOrg,
    /// User does not have permission to access the requested UserId.
    EnsureUser,
    /// Expiration time is before issue time.
    ExpiresBeforeIssued,
    /// Failed to lookup permissions for host {0}: {1},
    LookupHost(HostId, Box<crate::Error>),
    /// Failed to lookup permissions for hosts: {0},
    LookupHosts(Box<crate::Error>),
    /// Failed to lookup permissions for node {0}: {1},
    LookupNode(NodeId, Box<crate::Error>),
    /// Failed to lookup permissions for org {0}: {1},
    LookupOrg(OrgId, Box<crate::Error>),
    /// Failed to lookup permissions for user {0}: {1},
    LookupUser(UserId, Box<crate::Error>),
    /// User is not an admin of the org.
    NotOrgAdmin,
}

impl From<Error> for Status {
    fn from(err: Error) -> Self {
        error!("{}: {err}", std::any::type_name::<Error>());

        use Error::*;
        match err {
            EnsureHost | EnsureNode | EnsureOrg | EnsureUser | NotOrgAdmin => {
                Status::permission_denied("Access denied.")
            }
            ExpiresBeforeIssued | LookupHost(..) | LookupHosts(_) | LookupNode(..)
            | LookupOrg(..) | LookupUser(..) => Status::internal("Internal error."),
        }
    }
}

/// A serializable representation of the auth token claims.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    #[serde(flatten)]
    pub resource_entry: ResourceEntry,
    #[serde(flatten)]
    pub expirable: Expirable,
    pub endpoints: Endpoints,
    pub data: HashMap<String, String>,
}

impl Claims {
    pub fn new(resource: Resource, expirable: Expirable, endpoints: Endpoints) -> Self {
        Claims {
            resource_entry: resource.into(),
            expirable,
            endpoints,
            data: Default::default(),
        }
    }

    pub fn with_data(mut self, data: HashMap<String, String>) -> Self {
        self.data = data;
        self
    }

    pub fn from_now<I>(expires: chrono::Duration, resource: Resource, endpoints: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<Endpoint>,
    {
        let expirable = Expirable::from_now(expires);
        let endpoints = endpoints.into_iter().map(Into::into).collect();
        Self::new(resource, expirable, endpoints)
    }

    pub fn user_from_now<I>(expires: chrono::Duration, user_id: UserId, endpoints: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<Endpoint>,
    {
        Self::from_now(expires, Resource::User(user_id), endpoints)
    }

    pub fn resource(&self) -> Resource {
        self.resource_entry.into()
    }

    pub fn expires_at(&self) -> SecondsUtc {
        self.expirable.expires_at
    }

    /// Ensure that `Claims` can access the requested `Resource` as an Org member.
    pub async fn ensure(
        &self,
        resource: Resource,
        conn: &mut Conn<'_>,
    ) -> Result<Ensure<'_>, Error> {
        let claims = match resource {
            Resource::User(id) => self.ensure_user(id).map(Into::into),
            Resource::Org(id) => self.ensure_org(id, false, conn).await.map(Into::into),
            Resource::Host(id) => self.ensure_host(id, false, conn).await.map(Into::into),
            Resource::Node(id) => self.ensure_node(id, false, conn).await.map(Into::into),
        }?;

        Ok(Ensure { resource, claims })
    }

    /// Ensure that `Claims` can access the requested `Resource` as an Org admin.
    pub async fn ensure_admin(
        &self,
        resource: Resource,
        conn: &mut Conn<'_>,
    ) -> Result<Ensure<'_>, Error> {
        let claims = match resource {
            Resource::User(id) => self.ensure_user(id).map(Into::into),
            Resource::Org(id) => self.ensure_org(id, true, conn).await.map(Into::into),
            Resource::Host(id) => self.ensure_host(id, true, conn).await.map(Into::into),
            Resource::Node(id) => self.ensure_node(id, true, conn).await.map(Into::into),
        }?;

        Ok(Ensure { resource, claims })
    }

    /// Ensure that `Claims` can access the requested `UserId`.
    pub fn ensure_user(&self, user_id: UserId) -> Result<UserClaims<'_>, Error> {
        let claims = self;
        match claims.resource() {
            Resource::User(id) if id == user_id => Ok(UserClaims { claims, user_id }),
            _ => Err(Error::EnsureUser),
        }
    }

    /// Ensure that `Claims` can access the requested `OrgId`.
    pub async fn ensure_org(
        &self,
        org_id: OrgId,
        org_admin: bool,
        conn: &mut Conn<'_>,
    ) -> Result<OrgClaims<'_>, Error> {
        let claims = self;
        match claims.resource() {
            Resource::User(user_id) => {
                let has_org = if org_admin {
                    Org::is_admin(user_id, org_id, conn).await
                } else {
                    Org::is_member(user_id, org_id, conn).await
                };

                has_org
                    .map_err(|err| Error::LookupOrg(org_id, Box::new(err)))?
                    .then_some(OrgClaims { claims, org_id })
                    .ok_or(Error::EnsureOrg)
            }

            Resource::Org(id) if id == org_id => Ok(OrgClaims { claims, org_id }),

            _ => Err(Error::EnsureOrg),
        }
    }

    /// Ensure that `Claims` can access the requested `HostId`.
    pub async fn ensure_host(
        &self,
        host_id: HostId,
        org_admin: bool,
        conn: &mut Conn<'_>,
    ) -> Result<HostClaims<'_>, Error> {
        let claims = self;
        match claims.resource() {
            Resource::User(user_id) => {
                let host = Host::find_by_id(host_id, conn)
                    .await
                    .map_err(|err| Error::LookupHost(host_id, Box::new(err)))?;

                let has_org = if org_admin {
                    Org::is_admin(user_id, host.org_id, conn).await
                } else {
                    Org::is_member(user_id, host.org_id, conn).await
                };

                has_org
                    .map_err(|err| Error::LookupOrg(host.org_id, Box::new(err)))?
                    .then_some(HostClaims { claims, host_id })
                    .ok_or(Error::EnsureHost)
            }

            Resource::Org(org_id) => {
                let host = Host::find_by_id(host_id, conn)
                    .await
                    .map_err(|err| Error::LookupHost(host_id, Box::new(err)))?;

                if host.org_id == org_id {
                    Ok(HostClaims { claims, host_id })
                } else {
                    Err(Error::EnsureHost)
                }
            }

            Resource::Host(id) if id == host_id => Ok(HostClaims { claims, host_id }),

            _ => Err(Error::EnsureHost),
        }
    }

    pub async fn ensure_hosts(
        &self,
        host_ids: Vec<HostId>,
        org_admin: bool,
        conn: &mut Conn<'_>,
    ) -> Result<HashMap<HostId, HostClaims<'_>>, Error> {
        let claims = self;
        match claims.resource() {
            Resource::User(user_id) => {
                let hosts = Host::find_by_ids(host_ids, conn)
                    .await
                    .map_err(|err| Error::LookupHosts(Box::new(err)))?;
                let org_ids = hosts.iter().map(|host| host.org_id).collect();

                let belongs_all = if org_admin {
                    Org::is_admin_all(user_id, org_ids, conn).await
                } else {
                    Org::is_member_all(user_id, org_ids, conn).await
                }
                .map_err(|err| Error::LookupHosts(Box::new(err)))?;

                if !belongs_all {
                    return Err(Error::EnsureHost);
                }

                Ok(hosts
                    .into_iter()
                    .map(|host| host.id)
                    .map(|host_id| (host_id, HostClaims { claims, host_id }))
                    .collect())
            }

            Resource::Org(org_id) => {
                let hosts = Host::find_by_ids(host_ids, conn)
                    .await
                    .map_err(|err| Error::LookupHosts(Box::new(err)))?;

                if !hosts.iter().all(|host| host.org_id == org_id) {
                    return Err(Error::EnsureHost);
                }

                Ok(hosts
                    .into_iter()
                    .map(|host| host.id)
                    .map(|host_id| (host_id, HostClaims { claims, host_id }))
                    .collect())
            }

            Resource::Host(host_id) => {
                if !host_ids.iter().all(|id| *id == host_id) {
                    return Err(Error::EnsureHost);
                }

                Ok(host_ids
                    .into_iter()
                    .map(|host_id| (host_id, HostClaims { claims, host_id }))
                    .collect())
            }

            _ => Err(Error::EnsureHost),
        }
    }

    /// Ensure that `Claims` can access the requested `NodeId`.
    pub async fn ensure_node(
        &self,
        node_id: NodeId,
        org_admin: bool,
        conn: &mut Conn<'_>,
    ) -> Result<NodeClaims<'_>, Error> {
        let claims = self;
        match claims.resource() {
            Resource::User(user_id) => {
                let node = Node::find_by_id(node_id, conn)
                    .await
                    .map_err(|err| Error::LookupNode(node_id, Box::new(err)))?;

                let has_org = if org_admin {
                    Org::is_admin(user_id, node.org_id, conn).await
                } else {
                    Org::is_member(user_id, node.org_id, conn).await
                };

                has_org
                    .map_err(|err| Error::LookupOrg(node.org_id, Box::new(err)))?
                    .then_some(NodeClaims { claims, node_id })
                    .ok_or(Error::EnsureNode)
            }

            Resource::Org(org_id) => {
                let node = Node::find_by_id(node_id, conn)
                    .await
                    .map_err(|err| Error::LookupNode(node_id, Box::new(err)))?;

                if node.org_id == org_id {
                    Ok(NodeClaims { claims, node_id })
                } else {
                    Err(Error::EnsureNode)
                }
            }

            Resource::Host(host_id) => {
                let node = Node::find_by_id(node_id, conn)
                    .await
                    .map_err(|err| Error::LookupNode(node_id, Box::new(err)))?;

                if node.host_id == host_id {
                    Ok(NodeClaims { claims, node_id })
                } else {
                    Err(Error::EnsureNode)
                }
            }

            Resource::Node(id) if id == node_id => Ok(NodeClaims { claims, node_id }),

            _ => Err(Error::EnsureNode),
        }
    }
}

pub enum EnsureClaims<'c> {
    User(UserClaims<'c>),
    Org(OrgClaims<'c>),
    Host(HostClaims<'c>),
    Node(NodeClaims<'c>),
}

/// Validated `Claims` for some `Resource`.
pub struct Ensure<'c> {
    claims: EnsureClaims<'c>,
    resource: Resource,
}

impl<'c> Ensure<'c> {
    pub fn resource(&self) -> Resource {
        self.resource
    }

    pub fn user(&self) -> Option<&UserClaims<'c>> {
        if let EnsureClaims::User(claims) = &self.claims {
            Some(claims)
        } else {
            None
        }
    }

    pub fn org(&self) -> Option<&OrgClaims<'c>> {
        if let EnsureClaims::Org(claims) = &self.claims {
            Some(claims)
        } else {
            None
        }
    }

    pub fn host(&self) -> Option<&HostClaims<'c>> {
        if let EnsureClaims::Host(claims) = &self.claims {
            Some(claims)
        } else {
            None
        }
    }

    pub fn node(&self) -> Option<&NodeClaims<'c>> {
        if let EnsureClaims::Node(claims) = &self.claims {
            Some(claims)
        } else {
            None
        }
    }
}

/// Validated `Claims` for some `UserId`.
pub struct UserClaims<'c> {
    user_id: UserId,
    claims: &'c Claims,
}

impl<'c> UserClaims<'c> {
    pub fn user_id(&self) -> UserId {
        self.user_id
    }

    pub fn claims(&self) -> &Claims {
        self.claims
    }

    pub fn resource(&self) -> Resource {
        self.claims.resource()
    }
}

impl<'c> From<UserClaims<'c>> for EnsureClaims<'c> {
    fn from(claims: UserClaims<'c>) -> Self {
        EnsureClaims::User(claims)
    }
}

/// Validated `Claims` for some `OrgId`.
pub struct OrgClaims<'c> {
    org_id: OrgId,
    claims: &'c Claims,
}

impl<'c> OrgClaims<'c> {
    pub fn org_id(&self) -> OrgId {
        self.org_id
    }

    pub fn claims(&self) -> &Claims {
        self.claims
    }

    pub fn resource(&self) -> Resource {
        self.claims.resource()
    }
}

impl<'c> From<OrgClaims<'c>> for EnsureClaims<'c> {
    fn from(claims: OrgClaims<'c>) -> Self {
        EnsureClaims::Org(claims)
    }
}

/// Validated `Claims` for some `HostId`.
pub struct HostClaims<'c> {
    host_id: HostId,
    claims: &'c Claims,
}

impl<'c> HostClaims<'c> {
    pub fn host_id(&self) -> HostId {
        self.host_id
    }

    pub fn claims(&self) -> &Claims {
        self.claims
    }

    pub fn resource(&self) -> Resource {
        self.claims.resource()
    }
}

impl<'c> From<HostClaims<'c>> for EnsureClaims<'c> {
    fn from(claims: HostClaims<'c>) -> Self {
        EnsureClaims::Host(claims)
    }
}

/// Validated `Claims` for some `NodeId`.
pub struct NodeClaims<'c> {
    node_id: NodeId,
    claims: &'c Claims,
}

impl<'c> NodeClaims<'c> {
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    pub fn claims(&self) -> &Claims {
        self.claims
    }

    pub fn resource(&self) -> Resource {
        self.claims.resource()
    }
}

impl<'c> From<NodeClaims<'c>> for EnsureClaims<'c> {
    fn from(claims: NodeClaims<'c>) -> Self {
        EnsureClaims::Node(claims)
    }
}

/// `Expirable` ensures that `issued_at` is not after `expires_at`.
///
/// It also serializes and deserializes with second precision since JWTs don't
/// support nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Expirable {
    #[serde(rename = "iat")]
    pub issued_at: SecondsUtc,
    #[serde(rename = "exp")]
    pub expires_at: SecondsUtc,
}

impl Expirable {
    pub fn new(issued_at: SecondsUtc, expires_at: SecondsUtc) -> Result<Self, Error> {
        if expires_at < issued_at {
            return Err(Error::ExpiresBeforeIssued);
        }

        Ok(Self {
            issued_at,
            expires_at,
        })
    }

    pub fn from_now(expires: chrono::Duration) -> Self {
        let issued_at = SecondsUtc::now();
        let expires_at = issued_at + expires;

        Self {
            issued_at,
            expires_at,
        }
    }

    pub fn duration(&self) -> chrono::Duration {
        self.expires_at - self.issued_at
    }
}

#[cfg(any(test, feature = "integration-test"))]
pub mod tests {
    use super::*;

    pub fn claims_none(user_id: UserId) -> Claims {
        let expires = chrono::Duration::minutes(15);

        Claims {
            resource_entry: ResourceEntry::new_user(user_id),
            expirable: Expirable::from_now(expires),
            endpoints: Endpoints::Multiple(Vec::new()),
            data: HashMap::new(),
        }
    }

    pub fn claims_all(user_id: UserId) -> Claims {
        let expires = chrono::Duration::minutes(15);

        Claims {
            resource_entry: ResourceEntry::new_user(user_id),
            expirable: Expirable::from_now(expires),
            endpoints: Endpoints::Wildcard,
            data: HashMap::new(),
        }
    }
}
