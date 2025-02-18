use std::collections::HashMap;

use displaydoc::Display;
use thiserror::Error;
use tracing::warn;

use crate::auth::resource::{HostId, Resource};
use crate::auth::AuthZ;
use crate::database::WriteConn;
use crate::grpc::{common, Status};
use crate::model::image::NodeConfig;
use crate::model::region::RegionId;
use crate::model::{Host, Image, Org, ProtocolVersion, Region};

use super::{NewNode, Node, NodeScheduler, ResourceAffinity, SimilarNodeAffinity};

#[derive(Debug, Display, Error)]
pub enum Error {
    /// Launch host error: {0}
    Host(#[from] crate::model::host::Error),
    /// Launch node error: {0}
    Node(#[from] crate::model::node::Error),
    /// Failed to parse HostId: {0}
    ParseHostId(uuid::Error),
    /// Failed to parse RegionId: {0}
    ParseRegionId(uuid::Error),
    /// Launch region error: {0}
    Region(#[from] crate::model::region::Error),
}

impl From<Error> for Status {
    fn from(err: Error) -> Self {
        use Error::*;
        match err {
            ParseHostId(_) => Status::invalid_argument("host_id"),
            ParseRegionId(_) => Status::invalid_argument("region_id"),
            Host(err) => err.into(),
            Node(err) => err.into(),
            Region(err) => err.into(),
        }
    }
}

pub enum Launch {
    ByHost(Vec<HostCount>),
    ByRegion(Vec<RegionCount>),
}

impl Launch {
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        self,
        node: &NewNode,
        org: &Org,
        image: &Image,
        version: &ProtocolVersion,
        node_config: &NodeConfig,
        dns_base: &str,
        secrets: Option<&HashMap<String, Vec<u8>>>,
        authz: &AuthZ,
        write: &mut WriteConn<'_, '_>,
    ) -> Result<Vec<Node>, Error> {
        let created_by = Resource::from(authz);
        let mut launched = Vec::new();

        match self {
            Launch::ByHost(host_counts) => {
                for count in host_counts {
                    let host = Host::by_id(count.host_id, Some(node.org_id), write).await?;
                    for _ in 0..count.node_count {
                        match node
                            .create_node(
                                &host,
                                org,
                                image,
                                version,
                                node_config,
                                dns_base,
                                secrets,
                                created_by,
                                authz,
                                write,
                            )
                            .await
                        {
                            Ok(node) => launched.push(node),
                            Err(err) => {
                                for node in launched {
                                    if let Err(err) = write.ctx.dns.delete(&node.dns_id).await {
                                        warn!("Failed to delete DNS record {}: {err}", node.dns_id);
                                    }
                                }

                                return Err(Error::Node(err));
                            }
                        }
                    }
                }
            }

            Launch::ByRegion(region_counts) => {
                for count in region_counts {
                    let region = Region::by_id(count.region_id, write).await?;
                    let scheduler = NodeScheduler {
                        resource: count.resource,
                        similarity: count.similarity,
                        region: Some(region),
                    };

                    for _ in 0..count.node_count {
                        let candidate = node.find_host(&scheduler, authz, write).await?;
                        match node
                            .create_node(
                                &candidate.host,
                                org,
                                image,
                                version,
                                node_config,
                                dns_base,
                                secrets,
                                created_by,
                                authz,
                                write,
                            )
                            .await
                        {
                            Ok(node) => launched.push(node),
                            Err(err) => {
                                for node in launched {
                                    if let Err(err) = write.ctx.dns.delete(&node.dns_id).await {
                                        warn!("Failed to delete DNS record {}: {err}", node.dns_id);
                                    }
                                }

                                return Err(Error::Node(err));
                            }
                        }
                    }
                }
            }
        }

        Ok(launched)
    }
}

pub struct HostCount {
    pub host_id: HostId,
    pub node_count: u32,
}

impl HostCount {
    pub const fn one(host_id: HostId) -> Self {
        HostCount {
            host_id,
            node_count: 1,
        }
    }
}

impl TryFrom<&common::HostCount> for HostCount {
    type Error = Error;

    fn try_from(count: &common::HostCount) -> Result<Self, Self::Error> {
        Ok(HostCount {
            host_id: count.host_id.parse().map_err(Error::ParseHostId)?,
            node_count: count.node_count,
        })
    }
}

pub struct RegionCount {
    pub region_id: RegionId,
    pub node_count: u32,
    pub resource: Option<ResourceAffinity>,
    pub similarity: Option<SimilarNodeAffinity>,
}

impl RegionCount {
    pub const fn one(region_id: RegionId) -> Self {
        RegionCount {
            region_id,
            node_count: 1,
            resource: None,
            similarity: None,
        }
    }
}

impl TryFrom<&common::RegionCount> for RegionCount {
    type Error = Error;

    fn try_from(count: &common::RegionCount) -> Result<Self, Self::Error> {
        Ok(RegionCount {
            region_id: count.region_id.parse().map_err(Error::ParseRegionId)?,
            node_count: count.node_count,
            resource: count.resource().into(),
            similarity: count.similarity().into(),
        })
    }
}
