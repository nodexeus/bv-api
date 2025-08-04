pub mod job;
pub use job::{NodeJob, NodeJobProgress, NodeJobStatus, NodeJobs};

pub mod launch;
pub use launch::{HostCount, Launch, RegionCount};

pub mod log;
pub use log::{LogEvent, NewNodeLog, NodeEvent, NodeEventData, NodeLog};

pub mod report;
pub use report::{NewNodeReport, NodeReport};

pub mod scheduler;
pub use scheduler::{NodeScheduler, ResourceAffinity, SimilarNodeAffinity};

pub mod status;
pub use status::{NextState, NodeHealth, NodeState, NodeStatus, ProtocolStatus};

#[cfg(test)]
mod resource_test;

#[cfg(test)]
mod upgrade_functionality_test;

#[cfg(test)]
mod upgrade_test;



use std::collections::{HashMap, HashSet, VecDeque};

use chrono::{DateTime, Utc};
use diesel::dsl::{self, InnerJoinQuerySource};
use diesel::expression::expression_types::NotSelectable;
use diesel::pg::Pg;
use diesel::prelude::*;
use diesel::result::DatabaseErrorKind::UniqueViolation;
use diesel::result::Error::{DatabaseError, NotFound};
use diesel::sql_types::Bool;
use diesel_async::RunQueryDsl;
use displaydoc::Display;
use petname::{Generator, Petnames};
use thiserror::Error;
use tracing::warn;

use crate::auth::AuthZ;
use crate::auth::rbac::{BillingPerm, NodeAdminPerm};
use crate::auth::resource::{HostId, NodeId, OrgId, Resource, ResourceId, ResourceType, UserId};
use crate::database::{Conn, WriteConn};
use crate::grpc::{Status, api};
use crate::model::sql::{self, Amount, Currency, IpNetwork, Period, Tags, Version};
use crate::stripe::api::subscription::SubscriptionItemId;
use crate::util::{SearchOperator, SortOrder};

use super::command::NewCommand;
use super::host::{Host, HostCandidate, HostRequirements};
use super::image::config::{ConfigType, FirewallConfig, NewConfig};
use super::image::property::NewImagePropertyValue;
use super::image::{Config, ConfigId, Image, ImageId, NodeConfig};
use super::protocol::version::{ProtocolVersion, VersionId};
use super::protocol::{Protocol, ProtocolId, VersionKey};
use super::schema::{hosts, nodes, protocol_versions};
use super::{Command, CommandType, IpAddress, Org, Paginate, Region, RegionId};

#[derive(Debug, Display, Error)]
pub enum Error {
    /// Cannot delete node `{0}`, it is already deleted.
    AlreadyDeleted(NodeId),
    /// Node Cloudflare error: {0}
    Cloudflare(#[from] crate::cloudflare::Error),
    /// Node Command error: {0}
    Command(Box<crate::model::command::Error>),
    /// Node image config error: {0}
    Config(#[from] crate::model::image::config::Error),
    /// Failed to create node: {0}
    Create(diesel::result::Error),
    /// Failed to delete node `{0}`: {1}
    Delete(NodeId, diesel::result::Error),
    /// Failed to find deleted node by id `{0}`: {1}
    FindDeletedById(NodeId, diesel::result::Error),
    /// Failed to find node by id `{0}`: {1}
    FindById(NodeId, diesel::result::Error),
    /// Failed to find nodes by ids `{0:?}`: {1}
    FindByIds(HashSet<NodeId>, diesel::result::Error),
    /// Failed to find nodes by version ids `{0:?}`: {1}
    FindByVersionIds(HashSet<VersionId>, diesel::result::Error),
    /// Failed to find host id for possibly deleted node {0}: {1}
    FindDeletedHostId(NodeId, diesel::result::Error),
    /// Failed to find org id for possibly deleted node {0}: {1}
    FindDeletedOrgId(NodeId, diesel::result::Error),
    /// Failed to find host id for node {0}: {1}
    FindHostId(NodeId, diesel::result::Error),
    /// Failed to find nodes by host ids `{0:?}`: {1}
    FindHostIds(HashSet<HostId>, diesel::result::Error),
    /// Failed to find org id for node {0}: {1}
    FindOrgId(NodeId, diesel::result::Error),
    /// Failed to generate node name. This should not happen.
    GenerateName,
    /// Grpc command error: {0}
    Grpc(Box<crate::grpc::command::Error>),
    /// Node host error: {0}
    Host(#[from] crate::model::host::Error),
    /// Host doesn't have enough free CPU: {0}
    HostFreeCpu(HostId),
    /// Host doesn't have enough free disk: {0}
    HostFreeDisk(HostId),
    /// Host has no free IP addresses: {0}
    HostFreeIp(HostId),
    /// Host doesn't have enough free memory: {0}
    HostFreeMem(HostId),
    /// Failed to check if host {0} has nodes: {1}
    HostHasNodes(HostId, diesel::result::Error),
    /// Node image error: {0},
    Image(#[from] crate::model::image::Error),
    /// Node ip address error: {0},
    IpAddress(#[from] crate::model::ip_address::Error),
    /// The stripe `item` for this node doesn't have an associated `price`.
    ItemWithoutPrice,
    /// Node launch error: {0}
    Launch(#[from] Box<self::launch::Error>),
    /// Missing node-admin-transfer permission.
    MissingTransferPerm,
    /// Node log error: {0}
    NodeLog(#[from] self::log::Error),
    /// Failed to find a matching host.
    NoMatchingHost,
    /// No visibility of NodeUpgrade command.
    NoUpgradeCommand,
    /// Node org error: {0}
    Org(#[from] crate::model::org::Error),
    /// Node pagination: {0}
    Paginate(#[from] crate::model::paginate::Error),
    /// The stripe `price` for this node doesn't have an associated `amount`.
    PriceWithoutAmount,
    /// Node protocol error: {0}
    Protocol(#[from] crate::model::protocol::Error),
    /// Node protocol version error: {0}
    ProtocolVersion(#[from] crate::model::protocol::version::Error),
    /// Node region error: {0}
    Region(#[from] crate::model::region::Error),
    /// Node report error: {0}
    Report(#[from] self::report::Error),
    /// Store error for node: {0}
    Store(#[from] crate::store::Error),
    /// Node stripe error: {0}
    Stripe(#[from] crate::stripe::Error),
    /// Failed to update the node config: {0}
    UpdateConfig(diesel::result::Error),
    /// Failed to update the node status: {0}
    UpdateStatus(diesel::result::Error),
    /// Failed to update metrics for node {0}: {1}
    UpdateMetrics(NodeId, diesel::result::Error),
    /// The updated org is the same as the current org.
    UpdateSameOrg,
    /// Failed to upgrade the node: {0}
    Upgrade(diesel::result::Error),
    /// The node is already using the requested image_id.
    UpgradeSameImage,
    /// Failed to parse VM cpu count: {0}
    VmCpu(std::num::TryFromIntError),
    /// Failed to parse VM memory bytes: {0}
    VmMemory(std::num::TryFromIntError),
    /// Failed to parse VM disk bytes: {0}
    VmDisk(std::num::TryFromIntError),
    /// Failed to update host resource counters: {0}
    UpdateHostCounters(diesel::result::Error),
    /// Resource calculation would cause integer overflow
    ResourceOverflow,
    /// Host resource counters would become negative after update
    NegativeHostCounters,
    /// Invalid image configuration: {0}
    InvalidImageConfig(String),
    /// Cannot retrieve old node configuration: {0}
    OldConfigNotFound(crate::model::image::config::Error),
}

impl From<Error> for Status {
    fn from(err: Error) -> Self {
        use Error::*;
        match err {
            Create(DatabaseError(UniqueViolation, _)) => {
                Status::already_exists("Node already exists.")
            }
            Delete(_, NotFound)
            | FindById(_, NotFound)
            | FindByIds(_, NotFound)
            | FindDeletedById(_, NotFound)
            | FindDeletedHostId(_, NotFound)
            | FindDeletedOrgId(_, NotFound)
            | FindHostId(_, NotFound)
            | FindHostIds(_, NotFound)
            | FindOrgId(_, NotFound)
            | FindByVersionIds(_, NotFound) => Status::not_found("Node not found."),
            AlreadyDeleted(_)
            | Cloudflare(_)
            | Create(_)
            | Delete(_, _)
            | FindById(_, _)
            | FindByIds(_, _)
            | FindDeletedById(_, _)
            | FindDeletedHostId(_, _)
            | FindDeletedOrgId(_, _)
            | FindHostId(_, _)
            | FindHostIds(_, _)
            | FindOrgId(_, _)
            | FindByVersionIds(_, _)
            | GenerateName
            | HostHasNodes(_, _)
            | ItemWithoutPrice
            | PriceWithoutAmount
            | Stripe(_)
            | UpdateConfig(_)
            | UpdateMetrics(_, _)
            | UpdateStatus(_)
            | Upgrade(_)
            | UpdateHostCounters(_)
            | VmCpu(_)
            | VmDisk(_)
            | VmMemory(_)
            | OldConfigNotFound(_) => Status::internal("Internal error."),
            HostFreeCpu(_) => Status::failed_precondition("Host has too little available cpu."),
            HostFreeDisk(_) => Status::failed_precondition("Host has too little available memory."),
            HostFreeIp(_) => Status::failed_precondition("Host has too few available IPs."),
            HostFreeMem(_) => Status::failed_precondition("Host has too little available disk."),
            MissingTransferPerm => Status::forbidden("Missing permission."),
            NoMatchingHost => Status::failed_precondition("No matching host."),
            NoUpgradeCommand => Status::forbidden("Access denied."),
            ResourceOverflow => Status::invalid_argument("Resource calculation would cause overflow."),
            NegativeHostCounters => Status::invalid_argument("Host resource counters would become negative."),
            InvalidImageConfig(_) => Status::invalid_argument("Invalid image configuration."),
            UpdateSameOrg => Status::already_exists("new_org_id"),
            UpgradeSameImage => Status::already_exists("image_id"),
            Command(err) => (*err).into(),
            Config(err) => err.into(),
            Grpc(err) => (*err).into(),
            Host(err) => err.into(),
            Image(err) => err.into(),
            IpAddress(err) => err.into(),
            Launch(err) => (*err).into(),
            NodeLog(err) => err.into(),
            Org(err) => err.into(),
            Paginate(err) => err.into(),
            Protocol(err) => err.into(),
            ProtocolVersion(err) => err.into(),
            Region(err) => err.into(),
            Report(err) => err.into(),
            Store(err) => err.into(),
        }
    }
}

#[derive(Clone, Debug, Queryable, AsChangeset, Selectable)]
pub struct Node {
    pub id: NodeId,
    pub node_name: String,
    pub display_name: String,
    pub old_node_id: Option<NodeId>,
    pub org_id: OrgId,
    pub host_id: HostId,
    pub image_id: ImageId,
    pub config_id: ConfigId,
    pub protocol_id: ProtocolId,
    pub protocol_version_id: VersionId,
    pub semantic_version: Version,
    pub auto_upgrade: bool,
    pub node_state: NodeState,
    pub next_state: Option<NextState>,
    pub protocol_state: Option<String>,
    pub protocol_health: Option<NodeHealth>,
    pub jobs: Option<NodeJobs>,
    pub note: Option<String>,
    pub tags: Tags,
    pub ip_address: IpNetwork,
    pub ip_gateway: IpNetwork,
    pub p2p_address: Option<String>,
    pub dns_id: String,
    pub dns_name: String,
    pub dns_url: Option<String>,
    pub cpu_cores: i64,
    pub memory_bytes: i64,
    pub disk_bytes: i64,
    pub block_height: Option<i64>,
    pub block_age: Option<i64>,
    pub consensus: Option<bool>,
    pub scheduler_similarity: Option<SimilarNodeAffinity>,
    pub scheduler_resource: Option<ResourceAffinity>,
    pub scheduler_region_id: Option<RegionId>,
    pub stripe_item_id: Option<SubscriptionItemId>,
    pub created_by_type: ResourceType,
    pub created_by_id: ResourceId,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub cost: Option<Amount>,
    pub apr: Option<f64>,
    pub jailed: Option<bool>,
    pub jailed_reason: Option<String>,
    pub sqd_name: Option<String>,
}

impl Node {
    pub async fn by_id(id: NodeId, conn: &mut Conn<'_>) -> Result<Self, Error> {
        nodes::table
            .find(id)
            .filter(nodes::deleted_at.is_null())
            .get_result(conn)
            .await
            .map_err(|err| Error::FindById(id, err))
    }

    pub async fn deleted_by_id(id: NodeId, conn: &mut Conn<'_>) -> Result<Self, Error> {
        nodes::table
            .find(id)
            .get_result(conn)
            .await
            .map_err(|err| Error::FindDeletedById(id, err))
    }

    pub async fn by_ids(ids: &HashSet<NodeId>, conn: &mut Conn<'_>) -> Result<Vec<Self>, Error> {
        nodes::table
            .filter(nodes::id.eq_any(ids))
            .filter(nodes::deleted_at.is_null())
            .get_results(conn)
            .await
            .map_err(|err| Error::FindByIds(ids.clone(), err))
    }

    pub async fn by_host_ids(
        host_ids: &HashSet<HostId>,
        org_ids: &HashSet<OrgId>,
        conn: &mut Conn<'_>,
    ) -> Result<Vec<Self>, Error> {
        nodes::table
            .filter(nodes::host_id.eq_any(host_ids))
            .filter(nodes::org_id.eq_any(org_ids))
            .filter(nodes::deleted_at.is_null())
            .get_results(conn)
            .await
            .map_err(|err| Error::FindHostIds(host_ids.clone(), err))
    }

    pub async fn by_version_ids(
        version_ids: &HashSet<VersionId>,
        conn: &mut Conn<'_>,
    ) -> Result<Vec<Self>, Error> {
        nodes::table
            .filter(nodes::protocol_version_id.eq_any(version_ids))
            .filter(nodes::deleted_at.is_null())
            .get_results(conn)
            .await
            .map_err(|err| Error::FindByVersionIds(version_ids.clone(), err))
    }

    pub async fn org_id(id: NodeId, conn: &mut Conn<'_>) -> Result<OrgId, Error> {
        nodes::table
            .find(id)
            .filter(nodes::deleted_at.is_null())
            .select(nodes::org_id)
            .get_result(conn)
            .await
            .map_err(|err| Error::FindOrgId(id, err))
    }

    pub async fn deleted_org_id(id: NodeId, conn: &mut Conn<'_>) -> Result<OrgId, Error> {
        nodes::table
            .find(id)
            .select(nodes::org_id)
            .get_result(conn)
            .await
            .map_err(|err| Error::FindDeletedOrgId(id, err))
    }

    pub async fn host_id(id: NodeId, conn: &mut Conn<'_>) -> Result<HostId, Error> {
        nodes::table
            .find(id)
            .filter(nodes::deleted_at.is_null())
            .select(nodes::host_id)
            .get_result(conn)
            .await
            .map_err(|err| Error::FindHostId(id, err))
    }

    pub async fn deleted_host_id(id: NodeId, conn: &mut Conn<'_>) -> Result<HostId, Error> {
        nodes::table
            .find(id)
            .select(nodes::host_id)
            .get_result(conn)
            .await
            .map_err(|err| Error::FindDeletedHostId(id, err))
    }

    pub async fn host_has_nodes(host_id: HostId, conn: &mut Conn<'_>) -> Result<bool, Error> {
        let query = nodes::table
            .filter(nodes::host_id.eq(host_id))
            .filter(nodes::deleted_at.is_null());

        diesel::select(dsl::exists(query))
            .get_result(conn)
            .await
            .map_err(|err| Error::HostHasNodes(host_id, err))
    }

    pub async fn delete(id: NodeId, write: &mut WriteConn<'_, '_>) -> Result<Node, Error> {
        let node = Node::deleted_by_id(id, write).await?;
        if node.deleted_at.is_some() {
            return Err(Error::AlreadyDeleted(node.id));
        }

        Org::remove_node(node.org_id, write).await?;
        Host::remove_node(&node, write).await?;
        Command::delete_node_pending(node.id, write)
            .await
            .map_err(|err| Error::Command(Box::new(err)))?;

        let node: Node = diesel::update(nodes::table.find(id))
            .set((
                nodes::next_state.eq(Some(NextState::Deleting)),
                nodes::deleted_at.eq(Utc::now()),
            ))
            .get_result(write)
            .await
            .map_err(|err| Error::Delete(id, err))?;

        if let Err(err) = write.ctx.dns.delete(&node.dns_id).await {
            warn!("Failed to remove node dns: {err}");
        }

        // FIXME: secrets integration
        /*
            let prefix = format!("node/{id}/secret");
            let secrets = write.ctx.vault.read().await.list_path(&prefix).await?;
            if let Some(names) = secrets {
            for name in names {
            let path = format!("{prefix}/{name}");
            let result = write.ctx.vault.read().await.delete_path(&path).await;
            match result {
            Ok(()) | Err(crate::store::vault::Error::PathNotFound) => (),
            Err(err) => return Err(err.into()),
        }
        }
        }
             */

        if let Some(ref item_id) = node.stripe_item_id {
            if let Some(stripe) = write.ctx.stripe.as_ref() {
                stripe.remove_subscription(item_id).await?;
            }
        }

        Ok(node)
    }

    /// Find the next host to schedule a node on.
    pub async fn next_host(
        &self,
        protocol: &Protocol,
        write: &mut WriteConn<'_, '_>,
    ) -> Result<Option<Host>, Error> {
        let scheduler = self.scheduler(write).await?;
        let requirements = HostRequirements {
            scheduler: &scheduler,
            protocol,
            org_id: Some(self.org_id),
            cpu_cores: self.cpu_cores,
            memory_bytes: self.memory_bytes,
            disk_bytes: self.disk_bytes,
        };
        let candidates = Host::candidates(requirements, Some(2), write).await?;

        let mut counts: HashMap<HostId, usize> = HashMap::new();
        for log in NodeLog::by_node_id(self.id, write).await? {
            if log.event == NodeEvent::CreateStarted {
                *counts.entry(log.host_id).or_insert(0) += 1;
            }
        }

        let host_ids = counts.keys().copied().collect();
        let org_ids = hashset! {};
        let hosts_tried: Vec<_> = Host::by_ids(&host_ids, &org_ids, write)
            .await?
            .into_iter()
            .map(|host @ Host { id, .. }| (host, counts[&id]))
            .collect();

        let best = match (hosts_tried.as_slice(), candidates.len()) {
            // If there are 0 hosts to try, we return None.
            (_, 0) => return Ok(None),
            // If we are on the first host to try we just take the first candidate.
            ([], _) => candidates[0].host.clone(),
            // If we are on the first host to try and we tried once, we try that host again.
            ([(host, 1)], 1) => host.clone(),
            // Now we need at least two candidates, so lets check for that.
            (_, 1) => return Ok(None),
            // If there is 1 host that we tried so far, we can try a new one
            ([_], _) => candidates[1].host.clone(),
            // If we are on the second host to try and we tried once, we try that host again.
            ([_, (host, 1)], _) => host.clone(),
            // Otherwise we exhausted our our options and return None
            (_, _) => return Ok(None),
        };

        Ok(Some(best))
    }

    pub async fn scheduler(&self, conn: &mut Conn<'_>) -> Result<NodeScheduler, Error> {
        Ok(NodeScheduler {
            resource: self.scheduler_resource,
            similarity: self.scheduler_similarity,
            region: self.region(conn).await?,
        })
    }

    pub async fn region(&self, conn: &mut Conn<'_>) -> Result<Option<Region>, Error> {
        let Some(region_id) = self.scheduler_region_id else {
            return Ok(None);
        };

        Region::by_id(region_id, conn)
            .await
            .map(Some)
            .map_err(Error::Region)
    }

    pub fn status(&self) -> NodeStatus {
        NodeStatus {
            state: self.node_state,
            next: self.next_state,
            protocol: match (&self.protocol_state, self.protocol_health) {
                (Some(state), Some(health)) => Some(ProtocolStatus {
                    state: state.clone(),
                    health,
                }),
                _ => None,
            },
        }
    }

    pub async fn report(
        &self,
        created_by: Resource,
        message: String,
        conn: &mut Conn<'_>,
    ) -> Result<NodeReport, Error> {
        let report = NewNodeReport {
            node_id: self.id,
            created_by_type: created_by.typ(),
            created_by_id: created_by.id(),
            message,
        };
        report.create(conn).await.map_err(Error::Report)
    }

    pub async fn notify_auto_upgrades(
        image: &Image,
        version: &ProtocolVersion,
        org_id: Option<OrgId>,
        authz: &AuthZ,
        write: &mut WriteConn<'_, '_>,
    ) -> Result<(), Error> {
        let is_lower_but_compatible = |lower: &semver::Version, than: &semver::Version| {
            lower < than && lower.major == than.major
        };

        let old_versions = ProtocolVersion::by_key(&version.into(), org_id, authz, write)
            .await?
            .into_iter()
            .filter(|pv| is_lower_but_compatible(&pv.semantic_version, &version.semantic_version))
            .map(|version| version.id)
            .collect();
        let old_nodes = Node::by_version_ids(&old_versions, write)
            .await?
            .into_iter()
            .filter(|node| node.auto_upgrade);

        for node in old_nodes {
            node.notify_upgrade(image, version, org_id, authz, write)
                .await?;
        }

        Ok(())
    }

    pub async fn notify_upgrade(
        self,
        image: &Image,
        version: &ProtocolVersion,
        org_id: Option<OrgId>,
        authz: &AuthZ,
        write: &mut WriteConn<'_, '_>,
    ) -> Result<Self, Error> {
        let upgrade = UpgradeNode {
            id: self.id,
            image,
            version,
            org_id,
        };
        let upgraded = upgrade.apply(authz, write).await?;

        let cmd = NewCommand::node(&upgraded, CommandType::NodeUpgrade)
            .map_err(|err| Error::Command(Box::new(err)))?
            .create(write)
            .await
            .map_err(|err| Error::Command(Box::new(err)))?;
        let cmd = api::Command::from(&cmd, authz, write)
            .await
            .map_err(|err| Error::Grpc(Box::new(err)))?
            .ok_or(Error::NoUpgradeCommand)?;
        write.mqtt(cmd);

        Ok(upgraded)
    }

    pub fn created_by(&self) -> Resource {
        Resource::new(self.created_by_type, self.created_by_id)
    }
}

#[derive(Debug, Insertable)]
#[diesel(table_name = nodes)]
pub struct NewNode {
    pub org_id: OrgId,
    pub image_id: ImageId,
    pub config_id: ConfigId,
    pub old_node_id: Option<NodeId>,
    pub protocol_id: ProtocolId,
    pub protocol_version_id: VersionId,
    pub semantic_version: Version,
    pub auto_upgrade: bool,
    pub tags: Tags,
}

impl NewNode {
    pub async fn create(
        &self,
        launch: Launch,
        dns_base: &str,
        authz: &AuthZ,
        write: &mut WriteConn<'_, '_>,
    ) -> Result<Vec<Node>, Error> {
        let config = Config::by_id(self.config_id, write).await?;
        let node_config = config.node_config()?;

        let org = Org::by_id(self.org_id, write).await?;
        let image = Image::by_id(self.image_id, Some(self.org_id), authz, write).await?;
        let version =
            ProtocolVersion::by_id(self.protocol_version_id, Some(self.org_id), authz, write)
                .await?;

        // FIXME: secrets integration
        /*
            let secrets = if let Some(old_id) = self.old_node_id {
            let prefix = format!("node/{old_id}/secret");
            let names = write.ctx.vault.read().await.list_path(&prefix).await?;

            if let Some(names) = names {
            let mut secrets = HashMap::with_capacity(names.len());
            for name in names {
            let path = format!("{prefix}/{name}");
            let result = write.ctx.vault.read().await.get_bytes(&path).await;
            let _ = match result {
            Ok(data) => secrets.insert(name.clone(), data),
            Err(crate::store::vault::Error::PathNotFound) => None,
            Err(err) => return Err(err.into()),
        };
        }
            Some(secrets)
        } else {
            None
        }
        } else {
            None
        };
             */

        launch
            .create(
                self,
                &org,
                &image,
                &version,
                &node_config,
                dns_base,
                None,
                authz,
                write,
            )
            .await
            .map_err(|err| Error::Launch(Box::new(err)))
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_node(
        &self,
        host: &Host,
        org: &Org,
        image: &Image,
        version: &ProtocolVersion,
        node_config: &NodeConfig,
        dns_base: &str,
        _secrets: Option<&HashMap<String, Vec<u8>>>,
        created_by: Resource,
        authz: &AuthZ,
        mut write: &mut WriteConn<'_, '_>,
    ) -> Result<Node, Error> {
        let cpu_cores = i64::try_from(node_config.vm.cpu_cores).map_err(Error::VmCpu)?;
        let memory_bytes = i64::try_from(node_config.vm.memory_bytes).map_err(Error::VmMemory)?;
        let disk_bytes = i64::try_from(node_config.vm.disk_bytes).map_err(Error::VmDisk)?;

        if cpu_cores + host.node_cpu_cores > host.cpu_cores {
            return Err(Error::HostFreeCpu(host.id));
        } else if memory_bytes + host.node_memory_bytes > host.memory_bytes {
            return Err(Error::HostFreeMem(host.id));
        } else if disk_bytes + host.node_disk_bytes > host.disk_bytes {
            return Err(Error::HostFreeDisk(host.id));
        }

        let ip_address = IpAddress::next_for_host(host.id, write)
            .await?
            .ok_or_else(|| Error::HostFreeIp(host.id))?;

        // Users that have the billing-exempt permission or that are launching a node on their own
        // host do not need to be charged.
        let billing_exempt =
            authz.has_perm(BillingPerm::Exempt) || host.org_id == Some(self.org_id);
        let (stripe_item_id, price) = if billing_exempt {
            (None, None)
        } else {
            let region = Region::by_id(host.region_id, write).await?;

            if let Some(sku) = version.sku(&region) {
                if let Some(stripe) = write.ctx.stripe.as_ref() {
                    let item = stripe.add_subscription(org, &sku).await?;
                    let price = item
                        .price
                        .ok_or(Error::ItemWithoutPrice)?
                        .unit_amount
                        .ok_or(Error::PriceWithoutAmount)?;
                    (Some(item.id), Some(price))
                } else {
                    warn!("Stripe not configured, cannot charge for node!");
                    (None, None)
                }
            } else {
                (None, None)
            }
        };
        let cost = price.map(|amount| Amount {
            amount,
            currency: Currency::Usd,
            period: Period::Monthly,
        });

        loop {
            let name = Petnames::small()
                .generate_one(3, "-")
                .ok_or(Error::GenerateName)?;
            let dns_id = write.ctx.dns.create(&name, ip_address.ip.ip()).await?.id;
            let dns_name = if let Some(scheme) = &image.dns_scheme {
                format!("{scheme}://{name}.{dns_base}")
            } else {
                format!("{name}.{dns_base}")
            };

            match diesel::insert_into(nodes::table)
                .values((
                    self,
                    nodes::node_name.eq(&name),
                    nodes::display_name.eq(&name),
                    nodes::host_id.eq(host.id),
                    nodes::node_state.eq(NodeState::Starting),
                    nodes::ip_address.eq(&ip_address.ip),
                    nodes::ip_gateway.eq(&host.ip_gateway),
                    nodes::dns_id.eq(&dns_id),
                    nodes::dns_name.eq(&dns_name),
                    nodes::cpu_cores.eq(cpu_cores),
                    nodes::memory_bytes.eq(memory_bytes),
                    nodes::disk_bytes.eq(disk_bytes),
                    nodes::stripe_item_id.eq(&stripe_item_id),
                    nodes::created_by_type.eq(created_by.typ()),
                    nodes::created_by_id.eq(created_by.id()),
                    nodes::created_at.eq(Utc::now()),
                    nodes::cost.eq(&cost),
                ))
                .get_result::<Node>(&mut write)
                .await
            {
                Ok(node) => {
                    Org::add_node(self.org_id, write).await?;
                    Host::add_node(&node, write).await?;

                    /*
                        if let Some(secrets) = secrets {
                        for (name, data) in secrets {
                        let path = format!("node/{}/secret/{name}", node.id);
                        let _version =
                        write.ctx.vault.read().await.set_bytes(&path, data).await?;
                    }
                    }
                         */

                    return Ok(node);
                }

                Err(err) => {
                    if let Err(err) = write.ctx.dns.delete(&dns_id).await {
                        warn!("Failed to delete DNS record {dns_id}: {err}");
                    }

                    if let DatabaseError(UniqueViolation, ref info) = err {
                        if info.column_name() == Some("name") {
                            warn!("Node name {} already taken. Retrying...", name);
                            continue;
                        }
                    }

                    return Err(Error::Create(err));
                }
            }
        }
    }

    /// Finds the most suitable host to place the node on.
    async fn find_host(
        &self,
        scheduler: &NodeScheduler,
        authz: &AuthZ,
        conn: &mut Conn<'_>,
    ) -> Result<HostCandidate, Error> {
        let config = Config::by_id(self.config_id, conn).await?;
        let node_config = config.node_config()?;
        let protocol = Protocol::by_id(self.protocol_id, Some(self.org_id), authz, conn).await?;

        let requirements = HostRequirements {
            scheduler,
            protocol: &protocol,
            org_id: Some(self.org_id),
            cpu_cores: i64::try_from(node_config.vm.cpu_cores).map_err(Error::VmCpu)?,
            memory_bytes: i64::try_from(node_config.vm.memory_bytes).map_err(Error::VmMemory)?,
            disk_bytes: i64::try_from(node_config.vm.disk_bytes).map_err(Error::VmDisk)?,
        };

        let candidates = Host::candidates(requirements, Some(1), conn).await?;
        candidates.into_iter().next().ok_or(Error::NoMatchingHost)
    }
}

#[derive(Debug, AsChangeset)]
#[diesel(table_name = nodes)]
pub struct UpdateNode<'u> {
    pub org_id: Option<OrgId>,
    pub host_id: Option<HostId>,
    pub display_name: Option<&'u str>,
    pub auto_upgrade: Option<bool>,
    pub ip_address: Option<IpNetwork>,
    pub ip_gateway: Option<IpNetwork>,
    pub note: Option<&'u str>,
    pub tags: Option<Tags>,
    pub cost: Option<Amount>,
}

impl UpdateNode<'_> {
    pub async fn apply(
        self,
        id: NodeId,
        authz: &AuthZ,
        conn: &mut Conn<'_>,
    ) -> Result<Node, Error> {
        let node = Node::by_id(id, conn).await?;

        if let Some(org_id) = self.org_id {
            if org_id == node.org_id {
                return Err(Error::UpdateSameOrg);
            } else if !authz.has_perm(NodeAdminPerm::Transfer) {
                return Err(Error::MissingTransferPerm);
            }

            let event = LogEvent::OrgTransferred(log::OrgTransferred {
                old: node.org_id,
                new: org_id,
            });
            NewNodeLog::from(&node, authz, event).create(conn).await?;
        }

        diesel::update(nodes::table.find(id))
            .set((self, nodes::updated_at.eq(Utc::now())))
            .get_result(conn)
            .await
            .map_err(Error::UpdateConfig)
    }
}

pub struct UpdateNodeConfig {
    pub new_values: Vec<NewImagePropertyValue>,
    pub new_firewall: Option<FirewallConfig>,
}

impl UpdateNodeConfig {
    pub async fn apply(
        self,
        id: NodeId,
        authz: &AuthZ,
        conn: &mut Conn<'_>,
    ) -> Result<Node, Error> {
        let node = Node::by_id(id, conn).await?;
        let config = Config::by_id(node.config_id, conn).await?;
        let image_id = config.image_id;
        let archive_id = config.archive_id;

        let node_config = config.node_config()?;
        let updated_config = node_config
            .update(self.new_values, self.new_firewall, conn)
            .await?;
        let new_config = NewConfig {
            image_id,
            archive_id,
            config_type: ConfigType::Node,
            config: updated_config.into(),
        };
        let config = new_config.create(authz, conn).await?;

        diesel::update(nodes::table.find(id))
            .set((
                nodes::config_id.eq(config.id),
                nodes::updated_at.eq(Utc::now()),
            ))
            .get_result(conn)
            .await
            .map_err(Error::UpdateConfig)
    }
}

#[derive(Debug, AsChangeset)]
#[diesel(table_name = nodes)]
pub struct UpdateNodeState<'u> {
    pub node_state: Option<NodeState>,
    pub next_state: Option<Option<NextState>>,
    pub protocol_state: Option<String>,
    pub protocol_health: Option<NodeHealth>,
    pub p2p_address: Option<&'u str>,
}

impl UpdateNodeState<'_> {
    pub async fn apply(self, id: NodeId, conn: &mut Conn<'_>) -> Result<Node, Error> {
        let row = nodes::table.find(id);
        diesel::update(row)
            .set((self, nodes::updated_at.eq(Utc::now())))
            .get_result(conn)
            .await
            .map_err(Error::UpdateStatus)
    }
}

#[derive(Debug, AsChangeset)]
#[diesel(table_name = nodes)]
pub struct UpdateNodeMetrics {
    pub id: NodeId,
    pub node_state: Option<NodeState>,
    pub protocol_state: Option<String>,
    pub protocol_health: Option<NodeHealth>,
    pub block_height: Option<i64>,
    pub block_age: Option<i64>,
    pub apr: Option<f64>,
    pub consensus: Option<bool>,
    pub jobs: Option<NodeJobs>,
    pub jailed: Option<bool>,
    pub jailed_reason: Option<String>,
    pub sqd_name: Option<String>,
}

impl UpdateNodeMetrics {
    pub async fn apply(&self, conn: &mut Conn<'_>) -> Result<Node, Error> {
        let row = nodes::table
            .find(self.id)
            .filter(nodes::deleted_at.is_null());

        diesel::update(row)
            .set(self)
            .get_result(conn)
            .await
            .map_err(|err| Error::UpdateMetrics(self.id, err))
    }

    pub async fn apply_all(updates: Vec<Self>, conn: &mut Conn<'_>) -> Result<Vec<Node>, Error> {
        let mut results = Vec::with_capacity(updates.len());
        for update in updates {
            match update.apply(conn).await {
                Ok(node) => results.push(node),
                Err(Error::UpdateMetrics(_, NotFound)) => (),
                Err(err) => return Err(err),
            }
        }
        Ok(results)
    }
}

#[derive(Debug)]
pub struct UpgradeNode<'a> {
    pub id: NodeId,
    pub image: &'a Image,
    pub version: &'a ProtocolVersion,
    pub org_id: Option<OrgId>,
}

impl UpgradeNode<'_> {
    /// Extract current resource values from the existing node record
    fn extract_current_resources(&self, node: &Node) -> (i64, i64, i64) {
        (node.cpu_cores, node.memory_bytes, node.disk_bytes)
    }

    /// Calculate new resource requirements from upgraded NodeConfig with safe integer conversion
    fn calculate_new_resources(&self, new_config: &NodeConfig) -> Result<(i64, i64, i64), Error> {
        let cpu_cores = i64::try_from(new_config.vm.cpu_cores).map_err(Error::VmCpu)?;
        let memory_bytes = i64::try_from(new_config.vm.memory_bytes).map_err(Error::VmMemory)?;
        let disk_bytes = i64::try_from(new_config.vm.disk_bytes).map_err(Error::VmDisk)?;
        
        Ok((cpu_cores, memory_bytes, disk_bytes))
    }

    /// Validate image configuration for upgrade compatibility
    fn validate_image_config(&self, new_config: &NodeConfig) -> Result<(), Error> {
        // Validate that resource values are reasonable (not zero or negative)
        if new_config.vm.cpu_cores == 0 {
            return Err(Error::InvalidImageConfig("CPU cores cannot be zero".to_string()));
        }
        
        if new_config.vm.memory_bytes == 0 {
            return Err(Error::InvalidImageConfig("Memory bytes cannot be zero".to_string()));
        }
        
        if new_config.vm.disk_bytes == 0 {
            return Err(Error::InvalidImageConfig("Disk bytes cannot be zero".to_string()));
        }

        // Validate that resource values don't exceed reasonable limits to prevent overflow
        const MAX_REASONABLE_CPU: u64 = 1000; // 1000 cores
        const MAX_REASONABLE_MEMORY: u64 = 1024 * 1024 * 1024 * 1024; // 1TB
        const MAX_REASONABLE_DISK: u64 = 100 * 1024 * 1024 * 1024 * 1024; // 100TB

        if new_config.vm.cpu_cores > MAX_REASONABLE_CPU {
            return Err(Error::InvalidImageConfig(format!(
                "CPU cores {} exceeds reasonable limit of {}",
                new_config.vm.cpu_cores, MAX_REASONABLE_CPU
            )));
        }

        if new_config.vm.memory_bytes > MAX_REASONABLE_MEMORY {
            return Err(Error::InvalidImageConfig(format!(
                "Memory bytes {} exceeds reasonable limit of {}",
                new_config.vm.memory_bytes, MAX_REASONABLE_MEMORY
            )));
        }

        if new_config.vm.disk_bytes > MAX_REASONABLE_DISK {
            return Err(Error::InvalidImageConfig(format!(
                "Disk bytes {} exceeds reasonable limit of {}",
                new_config.vm.disk_bytes, MAX_REASONABLE_DISK
            )));
        }

        Ok(())
    }

    /// Calculate resource differences for host counter updates with overflow protection
    fn calculate_resource_differences(
        &self,
        old_resources: (i64, i64, i64),
        new_resources: (i64, i64, i64),
    ) -> Result<(i64, i64, i64), Error> {
        let (old_cpu, old_memory, old_disk) = old_resources;
        let (new_cpu, new_memory, new_disk) = new_resources;

        // Validate that old resources are non-negative (sanity check)
        if old_cpu < 0 || old_memory < 0 || old_disk < 0 {
            return Err(Error::InvalidImageConfig(
                "Old resource values cannot be negative".to_string()
            ));
        }

        // Validate that new resources are non-negative
        if new_cpu < 0 || new_memory < 0 || new_disk < 0 {
            return Err(Error::InvalidImageConfig(
                "New resource values cannot be negative".to_string()
            ));
        }

        // Check for potential overflow in subtraction
        let cpu_diff = new_cpu.checked_sub(old_cpu).ok_or(Error::ResourceOverflow)?;
        let memory_diff = new_memory.checked_sub(old_memory).ok_or(Error::ResourceOverflow)?;
        let disk_diff = new_disk.checked_sub(old_disk).ok_or(Error::ResourceOverflow)?;

        // Additional validation: check if differences are within reasonable bounds
        const MAX_REASONABLE_DIFF: i64 = i64::MAX / 2; // Half of max to prevent addition overflow later
        
        if cpu_diff.abs() > MAX_REASONABLE_DIFF ||
           memory_diff.abs() > MAX_REASONABLE_DIFF ||
           disk_diff.abs() > MAX_REASONABLE_DIFF {
            return Err(Error::ResourceOverflow);
        }

        Ok((cpu_diff, memory_diff, disk_diff))
    }

    /// Validate that host counter updates won't result in negative values
    async fn validate_host_counter_updates(
        &self,
        host_id: HostId,
        resource_diffs: (i64, i64, i64),
        conn: &mut Conn<'_>,
    ) -> Result<(), Error> {
        use super::schema::hosts;
        
        let (cpu_diff, memory_diff, disk_diff) = resource_diffs;
        
        // Get current host counters
        let host = hosts::table
            .find(host_id)
            .select((hosts::node_cpu_cores, hosts::node_memory_bytes, hosts::node_disk_bytes))
            .get_result::<(i64, i64, i64)>(conn)
            .await
            .map_err(Error::UpdateHostCounters)?;
        
        let (current_cpu, current_memory, current_disk) = host;
        
        // Validate current counters are non-negative (sanity check)
        if current_cpu < 0 || current_memory < 0 || current_disk < 0 {
            return Err(Error::InvalidImageConfig(
                "Host counters are already negative - data inconsistency detected".to_string()
            ));
        }
        
        // Check for overflow in addition before checking for negative values
        let new_cpu = current_cpu.checked_add(cpu_diff).ok_or(Error::ResourceOverflow)?;
        let new_memory = current_memory.checked_add(memory_diff).ok_or(Error::ResourceOverflow)?;
        let new_disk = current_disk.checked_add(disk_diff).ok_or(Error::ResourceOverflow)?;
        
        // Check if any counter would become negative
        if new_cpu < 0 || new_memory < 0 || new_disk < 0 {
            return Err(Error::NegativeHostCounters);
        }
        
        Ok(())
    }

    pub async fn apply(self, authz: &AuthZ, conn: &mut Conn<'_>) -> Result<Node, Error> {
        let node = Node::by_id(self.id, conn).await?;
        let config = Config::by_id(node.config_id, conn)
            .await
            .map_err(Error::OldConfigNotFound)?;

        if self.image.id == config.image_id {
            return Err(Error::UpgradeSameImage);
        }

        // Extract current resource values from existing node record
        let old_resources = self.extract_current_resources(&node);

        // Gracefully handle old config retrieval
        let old_config = config.node_config()
            .map_err(Error::OldConfigNotFound)?;
        
        let new_config = old_config
            .upgrade(self.image.clone(), self.org_id, conn)
            .await?;

        // Validate image configuration before proceeding
        self.validate_image_config(&new_config)?;

        // Calculate new resource requirements from upgraded NodeConfig
        let new_resources = self.calculate_new_resources(&new_config)?;

        // Calculate resource differences for host counter updates
        let resource_diffs = self.calculate_resource_differences(old_resources, new_resources)?;

        // Validate that host counter updates won't result in negative values
        self.validate_host_counter_updates(node.host_id, resource_diffs, conn).await?;

        let new_config = NewConfig {
            image_id: self.image.id,
            archive_id: new_config.image.archive_id,
            config_type: ConfigType::Node,
            config: new_config.into(),
        };
        let config = new_config.create(authz, conn).await?;

        let event = LogEvent::UpgradeStarted(log::UpgradeStarted {
            old: node.image_id,
            new: self.image.id,
        });
        NewNodeLog::from(&node, authz, event).create(conn).await?;

        // Update node record with new resource fields AND metadata
        let (new_cpu, new_memory, new_disk) = new_resources;
        let updated_node = diesel::update(nodes::table.find(self.id))
            .set((
                nodes::image_id.eq(self.image.id),
                nodes::config_id.eq(config.id),
                nodes::protocol_id.eq(self.version.protocol_id),
                nodes::protocol_version_id.eq(self.version.id),
                nodes::semantic_version.eq(&self.version.semantic_version),
                nodes::cpu_cores.eq(new_cpu),
                nodes::memory_bytes.eq(new_memory),
                nodes::disk_bytes.eq(new_disk),
                nodes::next_state.eq(Some(NextState::Upgrading)),
                nodes::updated_at.eq(Utc::now()),
            ))
            .get_result(conn)
            .await
            .map_err(Error::Upgrade)?;

        // Update host resource counters with the resource difference
        let (cpu_diff, memory_diff, disk_diff) = resource_diffs;
        diesel::update(hosts::table.find(node.host_id))
            .set((
                hosts::node_cpu_cores.eq(hosts::node_cpu_cores + cpu_diff),
                hosts::node_memory_bytes.eq(hosts::node_memory_bytes + memory_diff),
                hosts::node_disk_bytes.eq(hosts::node_disk_bytes + disk_diff),
            ))
            .execute(conn)
            .await
            .map_err(Error::UpdateHostCounters)?;

        Ok(updated_node)
    }
}

#[derive(Debug)]
pub struct NodeSearch {
    pub operator: SearchOperator,
    pub id: Option<String>,
    pub node_name: Option<String>,
    pub display_name: Option<String>,
    pub dns_name: Option<String>,
    pub ip: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub enum NodeSort {
    NodeName(SortOrder),
    DnsName(SortOrder),
    DisplayName(SortOrder),
    NodeState(SortOrder),
    NextState(SortOrder),
    ProtocolState(SortOrder),
    ProtocolHealth(SortOrder),
    BlockHeight(SortOrder),
    Apr(SortOrder),
    CreatedAt(SortOrder),
    UpdatedAt(SortOrder),
    Jailed(SortOrder),
    SqdName(SortOrder),
}

impl NodeSort {
    fn into_expr<T>(self) -> Box<dyn BoxableExpression<T, Pg, SqlType = NotSelectable>>
    where
        nodes::node_name: SelectableExpression<T>,
        nodes::dns_name: SelectableExpression<T>,
        nodes::display_name: SelectableExpression<T>,
        nodes::created_at: SelectableExpression<T>,
        nodes::updated_at: SelectableExpression<T>,
        nodes::node_state: SelectableExpression<T>,
        nodes::next_state: SelectableExpression<T>,
        nodes::protocol_state: SelectableExpression<T>,
        nodes::protocol_health: SelectableExpression<T>,
        nodes::block_height: SelectableExpression<T>,
        nodes::apr: SelectableExpression<T>,
        nodes::jailed: SelectableExpression<T>,
        nodes::sqd_name: SelectableExpression<T>,
    {
        use NodeSort::*;
        use SortOrder::*;

        match self {
            NodeName(Asc) => Box::new(nodes::node_name.asc()),
            NodeName(Desc) => Box::new(nodes::node_name.desc()),

            DnsName(Asc) => Box::new(nodes::dns_name.asc()),
            DnsName(Desc) => Box::new(nodes::dns_name.desc()),

            DisplayName(Asc) => Box::new(nodes::display_name.asc()),
            DisplayName(Desc) => Box::new(nodes::display_name.desc()),

            NodeState(Asc) => Box::new(nodes::node_state.asc()),
            NodeState(Desc) => Box::new(nodes::node_state.desc()),

            NextState(Asc) => Box::new(nodes::next_state.asc()),
            NextState(Desc) => Box::new(nodes::next_state.desc()),

            ProtocolState(Asc) => Box::new(nodes::protocol_state.asc()),
            ProtocolState(Desc) => Box::new(nodes::protocol_state.desc()),

            ProtocolHealth(Asc) => Box::new(nodes::protocol_health.asc()),
            ProtocolHealth(Desc) => Box::new(nodes::protocol_health.desc()),

            BlockHeight(Asc) => Box::new(nodes::block_height.asc()),
            BlockHeight(Desc) => Box::new(nodes::block_height.desc()),

            Apr(Asc) => Box::new(nodes::apr.asc()),
            Apr(Desc) => Box::new(nodes::apr.desc()),

            CreatedAt(Asc) => Box::new(nodes::created_at.asc()),
            CreatedAt(Desc) => Box::new(nodes::created_at.desc()),

            UpdatedAt(Asc) => Box::new(nodes::updated_at.asc()),
            UpdatedAt(Desc) => Box::new(nodes::updated_at.desc()),

            Jailed(Asc) => Box::new(nodes::jailed.asc()),
            Jailed(Desc) => Box::new(nodes::jailed.desc()),

            SqdName(Asc) => Box::new(nodes::sqd_name.asc()),
            SqdName(Desc) => Box::new(nodes::sqd_name.desc()),
        }
    }
}

#[derive(Debug)]
pub struct NodeFilter {
    pub protocol_ids: Vec<ProtocolId>,
    pub version_keys: Vec<VersionKey<'static>>,
    pub semantic_versions: Vec<String>,
    pub org_ids: Vec<OrgId>,
    pub host_ids: Vec<HostId>,
    pub user_ids: Vec<UserId>,
    pub ip_addresses: Vec<IpNetwork>,
    pub node_states: Vec<NodeState>,
    pub next_states: Vec<NextState>,
    pub search: Option<NodeSearch>,
    pub sort: VecDeque<NodeSort>,
    pub limit: i64,
    pub offset: i64,
}

impl NodeFilter {
    const DELETED_STATES: &[NodeState] = &[NodeState::Deleting, NodeState::Deleted];

    pub async fn query(mut self, conn: &mut Conn<'_>) -> Result<(Vec<Node>, u64), Error> {
        let mut query = nodes::table
            .inner_join(protocol_versions::table)
            .into_boxed();

        if let Some(search) = self.search {
            query = query.filter(search.into_expression());
        }

        if !self.protocol_ids.is_empty() {
            query = query.filter(nodes::protocol_id.eq_any(self.protocol_ids));
        }

        if !self.version_keys.is_empty() {
            let mut filters: Vec<Box<dyn BoxableExpression<_, _, SqlType = Bool>>> = Vec::new();

            for version_key in self.version_keys {
                let filter = protocol_versions::protocol_key
                    .eq(version_key.protocol_key)
                    .and(protocol_versions::variant_key.eq(version_key.variant_key));
                filters.push(Box::new(filter));
            }

            let combined = filters
                .into_iter()
                .reduce(|acc, item| Box::new(acc.or(item)));
            if let Some(filter) = combined {
                query = query.filter(filter);
            }
        }

        if !self.semantic_versions.is_empty() {
            query = query.filter(nodes::semantic_version.eq_any(self.semantic_versions));
        }

        if !self.org_ids.is_empty() {
            query = query.filter(nodes::org_id.eq_any(self.org_ids));
        }

        if !self.host_ids.is_empty() {
            query = query.filter(nodes::host_id.eq_any(self.host_ids));
        }

        if !self.user_ids.is_empty() {
            query = query.filter(nodes::created_by_id.eq_any(self.user_ids));
        }

        if !self.ip_addresses.is_empty() {
            query = query.filter(nodes::ip_address.eq_any(self.ip_addresses));
        }

        // exclude deleted nodes unless a deleted state is requested.
        if !self
            .node_states
            .iter()
            .any(|s| Self::DELETED_STATES.contains(s))
        {
            query = query.filter(nodes::deleted_at.is_null());
        }

        if !self.node_states.is_empty() {
            query = query.filter(nodes::node_state.eq_any(self.node_states));
        }

        if !self.next_states.is_empty() {
            query = query.filter(nodes::next_state.eq_any(self.next_states));
        }

        if let Some(sort) = self.sort.pop_front() {
            query = query.order_by(sort.into_expr());
        } else {
            query = query.order_by(nodes::created_at.desc());
        }

        while let Some(sort) = self.sort.pop_front() {
            query = query.then_order_by(sort.into_expr());
        }

        query
            .select(Node::as_select())
            .paginate(self.limit, self.offset)?
            .count_results(conn)
            .await
            .map_err(Into::into)
    }
}

type NodesAndVersions = InnerJoinQuerySource<nodes::table, protocol_versions::table>;

impl NodeSearch {
    fn into_expression(self) -> Box<dyn BoxableExpression<NodesAndVersions, Pg, SqlType = Bool>> {
        match self.operator {
            SearchOperator::Or => {
                let mut predicate: Box<
                    dyn BoxableExpression<NodesAndVersions, Pg, SqlType = Bool>,
                > = Box::new(false.into_sql::<Bool>());
                if let Some(id) = self.id {
                    predicate = Box::new(predicate.or(sql::text(nodes::id).like(id)));
                }
                if let Some(name) = self.node_name {
                    predicate = Box::new(predicate.or(sql::lower(nodes::node_name).like(name)));
                }
                if let Some(name) = self.display_name {
                    predicate = Box::new(predicate.or(sql::lower(nodes::display_name).like(name)));
                }
                if let Some(name) = self.dns_name {
                    predicate = Box::new(predicate.or(sql::lower(nodes::dns_name).like(name)));
                }
                if let Some(ip) = self.ip {
                    predicate = Box::new(predicate.or(dsl::abbrev(nodes::ip_address).like(ip)));
                }
                predicate
            }
            SearchOperator::And => {
                let mut predicate: Box<
                    dyn BoxableExpression<NodesAndVersions, Pg, SqlType = Bool>,
                > = Box::new(true.into_sql::<Bool>());
                if let Some(id) = self.id {
                    predicate = Box::new(predicate.and(sql::text(nodes::id).like(id)));
                }
                if let Some(name) = self.node_name {
                    predicate = Box::new(predicate.and(sql::lower(nodes::node_name).like(name)));
                }
                if let Some(name) = self.display_name {
                    predicate = Box::new(predicate.and(sql::lower(nodes::display_name).like(name)));
                }
                if let Some(name) = self.dns_name {
                    predicate = Box::new(predicate.and(sql::lower(nodes::dns_name).like(name)));
                }
                if let Some(ip) = self.ip {
                    predicate = Box::new(predicate.and(dsl::abbrev(nodes::ip_address).like(ip)));
                }
                predicate
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use tokio::sync::mpsc;

    use crate::auth::rbac::access::tests::view_authz;
    use crate::config::Context;

    use super::*;

    #[tokio::test]
    async fn can_filter_nodes() {
        let (ctx, db) = Context::with_mocked().await.unwrap();
        let (meta_tx, _meta_rx) = mpsc::unbounded_channel();
        let (mqtt_tx, _mqtt_rx) = mpsc::unbounded_channel();
        let mut write = WriteConn {
            conn: &mut db.conn().await,
            ctx: &ctx,
            meta_tx,
            mqtt_tx,
        };

        let new_node = NewNode {
            org_id: db.seed.org.id,
            image_id: db.seed.image.id,
            config_id: db.seed.config.id,
            old_node_id: None,
            protocol_id: db.seed.protocol.id,
            protocol_version_id: db.seed.version.id,
            semantic_version: "1.2.3".parse().unwrap(),
            auto_upgrade: false,
            tags: Default::default(),
        };

        let launch = Launch::ByHost(vec![HostCount::one(db.seed.host1.id)]);
        let dns_base = &ctx.config.cloudflare.dns.base;
        let authz = view_authz(db.seed.node.id);
        new_node
            .create(launch, dns_base, &authz, &mut write)
            .await
            .unwrap();

        let filter = NodeFilter {
            protocol_ids: vec![],
            version_keys: vec![VersionKey {
                protocol_key: Cow::Owned(db.seed.version.protocol_key.clone()),
                variant_key: Cow::Owned(db.seed.version.variant_key.clone()),
            }],
            semantic_versions: vec![],
            org_ids: vec![db.seed.org.id],
            host_ids: vec![db.seed.host1.id],
            user_ids: vec![],
            ip_addresses: vec![],
            node_states: vec![NodeState::Running],
            next_states: vec![],
            search: None,
            sort: VecDeque::new(),
            offset: 0,
            limit: 10,
        };

        let (nodes, _count) = filter.query(&mut write).await.unwrap();
        assert_eq!(nodes.len(), 1);
    }

    #[test]
    fn test_resource_tracking_error_types() {
        use crate::grpc::Status;

        // Test UpdateHostCounters error conversion
        let db_error = diesel::result::Error::NotFound;
        let error = Error::UpdateHostCounters(db_error);
        let status: Status = error.into();
        match status {
            Status::Internal(message) => {
                assert_eq!(message, "Internal error.");
            }
            _ => panic!("Expected Internal status"),
        }

        // Test ResourceOverflow error conversion
        let error = Error::ResourceOverflow;
        let status: Status = error.into();
        match status {
            Status::InvalidArgument(message) => {
                assert!(message.contains("overflow"));
            }
            _ => panic!("Expected InvalidArgument status"),
        }

        // Test NegativeHostCounters error conversion
        let error = Error::NegativeHostCounters;
        let status: Status = error.into();
        match status {
            Status::InvalidArgument(message) => {
                assert!(message.contains("negative"));
            }
            _ => panic!("Expected InvalidArgument status"),
        }
    }
}
