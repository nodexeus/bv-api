use std::collections::{HashMap, HashSet};

use diesel_async::scoped_futures::ScopedFutureExt;
use displaydoc::Display;
use futures_util::future::join_all;
use thiserror::Error;
use tonic::metadata::MetadataMap;
use tonic::{Request, Response, Status};
use tracing::{error, warn};

use crate::auth::rbac::{BlockchainAdminPerm, BlockchainPerm};
use crate::auth::Authorize;
use crate::cookbook::image::Image;
use crate::cookbook::Cookbook;
use crate::database::{Conn, ReadConn, Transaction};
use crate::models::blockchain::{
    Blockchain, BlockchainNodeType, BlockchainNodeTypeId, BlockchainProperty, BlockchainVersion,
    BlockchainVersionId, NodeStats,
};
use crate::models::BlockchainId;
use crate::timestamp::NanosUtc;

use super::api::blockchain_service_server::BlockchainService;
use super::{api, Grpc};

#[derive(Debug, Display, Error)]
pub enum Error {
    /// Auth check failed: {0}
    Auth(#[from] crate::auth::Error),
    /// Blockchain model error: {0}
    Blockchain(#[from] crate::models::blockchain::Error),
    /// Blockchain node type error: {0}
    BlockchainNodeType(#[from] crate::models::blockchain::node_type::Error),
    /// Blockchain version error: {0}
    BlockchainVersion(#[from] crate::models::blockchain::version::Error),
    /// Claims check failed: {0}
    Claims(#[from] crate::auth::claims::Error),
    /// Blockchain failed to get cookbook networks for `{0:?}`: {1}
    CookbookNetworks(Image, crate::cookbook::Error),
    /// Diesel failure: {0}
    Diesel(#[from] diesel::result::Error),
    /// Missing blockchain id. This should not happen.
    MissingId,
    /// Missing `api::Blockchain` model output. This should not happen.
    MissingModel,
    /// Missing blockchain node type. This should not happen.
    MissingNodeType,
    /// Unable to cast node count from i64 to u64: {0}
    NodeCount(std::num::TryFromIntError),
    /// Unable to cast active node count from i64 to u64: {0}
    NodeCountActive(std::num::TryFromIntError),
    /// Unable to cast syncing node count from i64 to u64: {0}
    NodeCountSyncing(std::num::TryFromIntError),
    /// Unable to cast provisioning node count from i64 to u64: {0}
    NodeCountProvisioning(std::num::TryFromIntError),
    /// Unable to cast failed node count from i64 to u64: {0}
    NodeCountFailed(std::num::TryFromIntError),
    /// Failed to parse BlockchainId: {0}
    ParseId(uuid::Error),
    /// Failed to parse OrgId: {0}
    ParseOrgId(uuid::Error),
    /// Blockchain property error: {0}
    Property(#[from] crate::models::blockchain::property::Error),
    /// Unknown NodeType: {0}
    UnknownNodeType(prost::DecodeError),
}

impl From<Error> for Status {
    fn from(err: Error) -> Self {
        use Error::*;
        error!("{err}");
        match err {
            CookbookNetworks(..)
            | Diesel(_)
            | MissingId
            | MissingModel
            | MissingNodeType
            | NodeCount(_)
            | NodeCountActive(_)
            | NodeCountSyncing(_)
            | NodeCountProvisioning(_)
            | NodeCountFailed(_)
            | UnknownNodeType(_) => Status::internal("Internal error."),
            ParseId(_) => Status::invalid_argument("id"),
            ParseOrgId(_) => Status::invalid_argument("org_id"),
            Auth(err) => err.into(),
            Claims(err) => err.into(),
            Blockchain(err) => err.into(),
            BlockchainNodeType(err) => err.into(),
            BlockchainVersion(err) => err.into(),
            Property(err) => err.into(),
        }
    }
}

#[tonic::async_trait]
impl BlockchainService for Grpc {
    async fn get(
        &self,
        req: Request<api::BlockchainServiceGetRequest>,
    ) -> Result<Response<api::BlockchainServiceGetResponse>, Status> {
        let (meta, _, req) = req.into_parts();
        self.read(|read| get(req, meta, read).scope_boxed()).await
    }

    async fn list(
        &self,
        req: Request<api::BlockchainServiceListRequest>,
    ) -> Result<Response<api::BlockchainServiceListResponse>, Status> {
        let (meta, _, req) = req.into_parts();
        self.read(|read| list(req, meta, read).scope_boxed()).await
    }
}

async fn get(
    req: api::BlockchainServiceGetRequest,
    meta: MetadataMap,
    mut read: ReadConn<'_, '_>,
) -> Result<api::BlockchainServiceGetResponse, Error> {
    let id = req.id.parse().map_err(Error::ParseId)?;
    let org_id = req
        .org_id
        .as_deref()
        .map(|id| id.parse().map_err(Error::ParseOrgId))
        .transpose()?;
    if let Some(org_id) = org_id {
        read.auth_or_all(&meta, BlockchainAdminPerm::Get, BlockchainPerm::Get, org_id)
            .await?
    } else {
        read.auth_all(&meta, BlockchainAdminPerm::Get).await?
    };
    let blockchain = Blockchain::find_by_id(id, &mut read).await?;

    let node_types = BlockchainNodeType::by_blockchain_id(blockchain.id, &mut read).await?;
    let node_types: HashMap<_, _> = node_types.into_iter().map(|nt| (nt.id, nt)).collect();

    let versions = BlockchainVersion::by_blockchain_id(blockchain.id, &mut read).await?;
    let version_ids = versions
        .into_iter()
        .map(|version| {
            let node_type = node_types
                .get(&version.blockchain_node_type_id)
                .map(|node_type| node_type.node_type)
                .ok_or(Error::MissingNodeType)?;
            Ok((
                version.id,
                Image::new(&blockchain.name, node_type, version.version.into()),
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let network_futs = version_ids
        .iter()
        .map(|(version_id, image)| cookbook_networks(&read.ctx.cookbook, image, *version_id));

    let mut networks: HashMap<BlockchainVersionId, Vec<api::BlockchainNetwork>> = HashMap::new();
    for result in join_all(network_futs).await {
        match result {
            Ok((version_id, nets)) => {
                networks.entry(version_id).or_default().extend(nets);
            }
            Err(err) => warn!("Failed to get cookbook networks: {err}"),
        }
    }

    let node_stats = Blockchain::node_stats(org_id, &mut read).await?;
    let node_stats = node_stats
        .into_iter()
        .map(|ns| (ns.blockchain_id, ns))
        .collect();

    let blockchain =
        api::Blockchain::from_model(blockchain, &mut networks, Some(&node_stats), &mut read)
            .await?;

    Ok(api::BlockchainServiceGetResponse {
        blockchain: Some(blockchain),
    })
}

async fn list(
    req: api::BlockchainServiceListRequest,
    meta: MetadataMap,
    mut read: ReadConn<'_, '_>,
) -> Result<api::BlockchainServiceListResponse, Error> {
    let org_id = req
        .org_id
        .as_deref()
        .map(|id| id.parse().map_err(Error::ParseOrgId))
        .transpose()?;

    if let Some(org_id) = org_id {
        read.auth_or_all(
            &meta,
            BlockchainAdminPerm::List,
            BlockchainPerm::List,
            org_id,
        )
        .await?
    } else {
        read.auth_all(&meta, BlockchainAdminPerm::List).await?
    };

    // We need to combine info from two seperate sources: the database and cookbook. Since
    // cookbook is slow, the step where we call it is parallelized.

    // We query the necessary blockchains from the database.
    let blockchains = Blockchain::find_all(&mut read).await?;
    let blockchain_ids: HashSet<_> = blockchains.iter().map(|b| b.id).collect();
    let blockchain_map: HashMap<_, _> = blockchains.iter().map(|b| (b.id, b)).collect();

    // Now we need to combine this info with the networks that are stored in the cookbook
    // service. Since we want to do this in parallel, `network_futs` will contain a number of
    // futures that each resolve to a list of networks for that blockchain version.
    let node_types =
        BlockchainNodeType::by_blockchain_ids(blockchain_ids.clone(), &mut read).await?;
    let node_types: HashMap<_, _> = node_types.into_iter().map(|nt| (nt.id, nt)).collect();

    let versions = BlockchainVersion::by_blockchain_ids(blockchain_ids, &mut read).await?;
    let version_ids = versions
        .iter()
        .map(|version| {
            let blockchain = blockchain_map
                .get(&version.blockchain_id)
                .ok_or(Error::MissingId)?;
            let node_type = node_types
                .get(&version.blockchain_node_type_id)
                .ok_or(Error::MissingNodeType)?
                .node_type;
            let image = Image::new(&blockchain.name, node_type, version.version.clone().into());
            Ok((version.id, image))
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let network_futs = version_ids
        .iter()
        .map(|(version_id, image)| cookbook_networks(&read.ctx.cookbook, image, *version_id));

    let mut networks: HashMap<BlockchainVersionId, Vec<api::BlockchainNetwork>> = HashMap::new();
    for result in join_all(network_futs).await {
        match result {
            Ok((version_id, nets)) => {
                networks.entry(version_id).or_default().extend(nets);
            }
            Err(err) => warn!("Failed to get cookbook networks: {err}"),
        }
    }

    let node_stats = Blockchain::node_stats(org_id, &mut read).await?;
    let node_stats = node_stats
        .into_iter()
        .map(|ns| (ns.blockchain_id, ns))
        .collect();

    let blockchains =
        api::Blockchain::from_models(blockchains, &mut networks, Some(&node_stats), &mut read)
            .await?;

    Ok(api::BlockchainServiceListResponse { blockchains })
}

async fn cookbook_networks(
    cookbook: &Cookbook,
    image: &Image,
    version_id: BlockchainVersionId,
) -> Result<(BlockchainVersionId, Vec<api::BlockchainNetwork>), Error> {
    let metadata = cookbook
        .rhai_metadata(image)
        .await
        .map_err(|err| Error::CookbookNetworks(image.clone(), err))?;

    let networks = metadata
        .nets
        .into_iter()
        .map(|(name, network)| api::BlockchainNetwork {
            name,
            url: network.url,
            net_type: api::NetType::from(network.net_type) as i32,
        })
        .collect();

    Ok((version_id, networks))
}

impl api::Blockchain {
    async fn from_models(
        models: Vec<Blockchain>,
        networks: &mut HashMap<BlockchainVersionId, Vec<api::BlockchainNetwork>>,
        node_stats: Option<&HashMap<BlockchainId, NodeStats>>,
        conn: &mut Conn<'_>,
    ) -> Result<Vec<Self>, Error> {
        let ids: HashSet<_> = models.iter().map(|blockchain| blockchain.id).collect();

        let mut node_types: HashMap<_, Vec<_>> = HashMap::new();
        for node_type in BlockchainNodeType::by_blockchain_ids(ids.clone(), conn).await? {
            node_types
                .entry(node_type.blockchain_id)
                .or_default()
                .push(node_type);
        }

        let mut versions: HashMap<_, Vec<_>> = HashMap::new();
        for version in BlockchainVersion::by_blockchain_ids(ids.clone(), conn).await? {
            versions
                .entry(version.blockchain_node_type_id)
                .or_default()
                .push(version);
        }

        let mut properties: HashMap<_, Vec<_>> = HashMap::new();
        for property in BlockchainProperty::by_blockchain_ids(ids, conn).await? {
            properties
                .entry(property.blockchain_version_id)
                .or_default()
                .push(property);
        }

        models
            .into_iter()
            .map(|model| {
                let node_types = node_types.remove(&model.id).unwrap_or_default();
                let node_types = api::BlockchainNodeType::from_models(
                    node_types,
                    &mut versions,
                    networks,
                    &mut properties,
                );

                let stats = node_stats
                    .map(|stats| api::BlockchainStats::from_model(&model, stats))
                    .transpose()?;

                Ok(api::Blockchain {
                    id: model.id.to_string(),
                    name: model.name,
                    description: model.description,
                    project_url: model.project_url,
                    repo_url: model.repo_url,
                    node_types,
                    created_at: Some(NanosUtc::from(model.created_at).into()),
                    updated_at: Some(NanosUtc::from(model.updated_at).into()),
                    stats,
                })
            })
            .collect()
    }

    async fn from_model(
        blockchain: Blockchain,
        networks: &mut HashMap<BlockchainVersionId, Vec<api::BlockchainNetwork>>,
        node_stats: Option<&HashMap<BlockchainId, NodeStats>>,
        conn: &mut Conn<'_>,
    ) -> Result<Self, Error> {
        let mut blockchains = Self::from_models(vec![blockchain], networks, node_stats, conn)
            .await?
            .into_iter();

        match (blockchains.next(), blockchains.next()) {
            (Some(blockchain), None) => Ok(blockchain),
            _ => Err(Error::MissingModel),
        }
    }
}

impl api::BlockchainNodeType {
    fn from_models(
        node_types: Vec<BlockchainNodeType>,
        versions: &mut HashMap<BlockchainNodeTypeId, Vec<BlockchainVersion>>,
        networks: &mut HashMap<BlockchainVersionId, Vec<api::BlockchainNetwork>>,
        properties: &mut HashMap<BlockchainVersionId, Vec<BlockchainProperty>>,
    ) -> Vec<Self> {
        node_types
            .into_iter()
            .map(|node_type| {
                let versions = versions.remove(&node_type.id).unwrap_or_default();
                Self::from_model(node_type, versions, networks, properties)
            })
            .collect()
    }

    fn from_model(
        node_type: BlockchainNodeType,
        versions: Vec<BlockchainVersion>,
        networks: &mut HashMap<BlockchainVersionId, Vec<api::BlockchainNetwork>>,
        properties: &mut HashMap<BlockchainVersionId, Vec<BlockchainProperty>>,
    ) -> Self {
        api::BlockchainNodeType {
            id: node_type.id.to_string(),
            node_type: api::NodeType::from_model(node_type.node_type) as i32,
            versions: api::BlockchainVersion::from_models(versions, networks, properties),
            description: node_type.description,
            created_at: Some(NanosUtc::from(node_type.created_at).into()),
            updated_at: Some(NanosUtc::from(node_type.updated_at).into()),
        }
    }
}

impl api::BlockchainVersion {
    fn from_models(
        models: Vec<BlockchainVersion>,
        networks: &mut HashMap<BlockchainVersionId, Vec<api::BlockchainNetwork>>,
        properties: &mut HashMap<BlockchainVersionId, Vec<BlockchainProperty>>,
    ) -> Vec<Self> {
        models
            .into_iter()
            .map(|model| {
                let networks = networks.remove(&model.id).unwrap_or_else(|| {
                    warn!("No networks for blockchain version `{}`", model.id);
                    vec![]
                });
                let properties = properties.remove(&model.id).unwrap_or_default();

                Self::from_model(model, networks, properties)
            })
            .collect()
    }

    fn from_model(
        version: BlockchainVersion,
        networks: Vec<api::BlockchainNetwork>,
        properties: Vec<BlockchainProperty>,
    ) -> Self {
        api::BlockchainVersion {
            id: version.id.to_string(),
            version: version.version,
            description: version.description,
            created_at: Some(NanosUtc::from(version.created_at).into()),
            updated_at: Some(NanosUtc::from(version.updated_at).into()),
            networks,
            properties: properties
                .into_iter()
                .map(api::BlockchainProperty::from_model)
                .collect(),
        }
    }
}

impl api::BlockchainProperty {
    fn from_model(model: BlockchainProperty) -> Self {
        let mut prop = api::BlockchainProperty {
            name: model.name,
            display_name: model.display_name,
            default: model.default,
            ui_type: 0, // We use the setter to set this field for type-safety
            required: model.required,
        };
        prop.set_ui_type(api::UiType::from(model.ui_type));
        prop
    }
}

impl api::BlockchainStats {
    fn from_model(
        model: &Blockchain,
        node_stats: &HashMap<BlockchainId, NodeStats>,
    ) -> Result<Self, Error> {
        let stats = node_stats.get(&model.id);

        let count = stats.map(|s| s.node_count).unwrap_or_default();
        let active = stats.map(|s| s.node_count_active).unwrap_or_default();
        let syncing = stats.map(|s| s.node_count_syncing).unwrap_or_default();
        let provisioning = stats.map(|s| s.node_count_provisioning).unwrap_or_default();
        let failed = stats.map(|s| s.node_count_failed).unwrap_or_default();

        Ok(api::BlockchainStats {
            node_count: Some(count.try_into().map_err(Error::NodeCount)?),
            node_count_active: Some(active.try_into().map_err(Error::NodeCountActive)?),
            node_count_syncing: Some(syncing.try_into().map_err(Error::NodeCountSyncing)?),
            node_count_provisioning: Some(
                provisioning
                    .try_into()
                    .map_err(Error::NodeCountProvisioning)?,
            ),
            node_count_failed: Some(failed.try_into().map_err(Error::NodeCountFailed)?),
        })
    }
}
