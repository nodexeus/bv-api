use crate::errors::Result as ApiResult;
use crate::grpc::blockjoy::{
    command, node_command, Command as GrpcCommand, CommandMeta, ContainerImage, NodeCommand,
    NodeCreate, NodeDelete, NodeInfoGet, NodeRestart, NodeStop, Uuid as GrpcUuid,
};
use crate::grpc::helpers::{image_url_from_node, pb_current_timestamp};
use crate::models::{Blockchain, Command, HostCmd, Node};
use crate::server::DbPool;

pub async fn db_command_to_grpc_command(cmd: Command, db: &DbPool) -> ApiResult<GrpcCommand> {
    let meta = Some(CommandMeta {
        api_command_id: Some(GrpcUuid::from(cmd.id)),
        created_at: Some(pb_current_timestamp()),
    });
    let mut node_cmd = NodeCommand {
        id: Some(GrpcUuid::from(cmd.resource_id)),
        command: None,
        meta,
    };

    node_cmd.command = match cmd.cmd {
        HostCmd::RestartNode => Some(node_command::Command::Restart(NodeRestart::default())),
        HostCmd::KillNode => {
            tracing::debug!("Using NodeStop for KillNode");
            Some(node_command::Command::Stop(NodeStop::default()))
        }
        HostCmd::ShutdownNode => Some(node_command::Command::Stop(NodeStop::default())),
        HostCmd::UpdateNode => {
            tracing::debug!("Using NodeUpgrade for UpdateNode");
            unimplemented!();
            /*
            // TODO: add image
            Self {
                r#type: Some(command::Type::Node(NodeUpgrade {})),
            }
             */
        }
        HostCmd::MigrateNode => {
            tracing::debug!("Using NodeGenericCommand for MigrateNode");
            unimplemented!();
            /*
            node_cmd.command = Some(node_command::Command::Generic(NodeGenericCommand::default()))
             */
        }
        HostCmd::GetNodeVersion => {
            tracing::debug!("Using NodeInfoGet for GetNodeVersion");
            Some(node_command::Command::InfoGet(NodeInfoGet::default()))
        }
        // The following should be HostCommands
        HostCmd::CreateNode => {
            let node = Node::find_by_id(cmd.resource_id, &db).await?;
            let blockchain = Blockchain::find_by_id(node.blockchain_id, &db).await?;
            let image = ContainerImage {
                url: image_url_from_node(&node, blockchain.name),
            };
            let create_cmd = NodeCreate {
                name: node.name.unwrap_or_default(),
                blockchain: node.blockchain_id.to_string(),
                image: Some(image),
                r#type: node.node_type.to_json()?,
            };

            Some(node_command::Command::Create(create_cmd))
        }
        HostCmd::DeleteNode => Some(node_command::Command::Delete(NodeDelete::default())),
        HostCmd::GetBVSVersion => unimplemented!(),
        HostCmd::UpdateBVS => unimplemented!(),
        HostCmd::RestartBVS => unimplemented!(),
        HostCmd::RemoveBVS => unimplemented!(),
        HostCmd::CreateBVS => unimplemented!(),
        HostCmd::StopBVS => unimplemented!(),
        // TODO: Missing
        // NodeStart, NodeUpgrade
    };

    Ok(GrpcCommand {
        r#type: Some(command::Type::Node(node_cmd)),
    })
}

pub mod from {
    use crate::errors::ApiError;
    use crate::grpc::blockjoy::{self, HostInfo, Uuid as GrpcUuid};
    use crate::grpc::blockjoy_ui::{
        self, node::NodeStatus as GrpcNodeStatus, Host as GrpcHost,
        HostProvision as GrpcHostProvision, Node as GrpcNode, Organization, User as GrpcUiUser,
        Uuid as GrpcUiUuid,
    };
    use crate::grpc::helpers::required;
    use crate::models::{
        self, ConnectionStatus, ContainerStatus, HostProvision, HostRequest, Node, NodeChainStatus,
        NodeCreateRequest, NodeInfo, NodeStakingStatus, NodeSyncStatus, Org, User,
    };
    use crate::models::{Host, HostSelectiveUpdate};
    use anyhow::anyhow;
    use prost_types::Timestamp;
    use serde_json::Value;
    use std::i64;
    use std::str::FromStr;
    use tonic::{Code, Status};
    use uuid::Uuid;

    /// Private function to convert the datetimes from the database into the API representation of
    /// a timestamp.
    fn try_dt_to_ts(datetime: chrono::DateTime<chrono::Utc>) -> Result<Timestamp, ApiError> {
        const NANOS_PER_SEC: i64 = 1_000_000_000;
        let nanos = datetime.timestamp_nanos();
        let timestamp = Timestamp {
            seconds: nanos / NANOS_PER_SEC,
            // This _should_ never fail because 1_000_000_000 fits into an i32, but using `as` was
            // hiding this bug in the first place. Therefore I have left the `try_into` call here.
            nanos: (nanos % NANOS_PER_SEC).try_into()?,
        };
        Ok(timestamp)
    }

    impl FromStr for GrpcUuid {
        type Err = ApiError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            // Assuming 's' is some UUID
            match Uuid::parse_str(s) {
                Ok(_) => Ok(Self { value: s.into() }),
                Err(e) => Err(ApiError::UnexpectedError(anyhow!(e))),
            }
        }
    }

    impl From<HostSelectiveUpdate> for HostInfo {
        fn from(update: HostSelectiveUpdate) -> Self {
            Self {
                id: None,
                name: update.name,
                version: update.version,
                location: update.location,
                cpu_count: update.cpu_count,
                mem_size: update.mem_size,
                disk_size: update.disk_size,
                os: update.os,
                os_version: update.os_version,
                ip: None,
            }
        }
    }

    impl TryFrom<blockjoy_ui::Uuid> for uuid::Uuid {
        type Error = ApiError;

        fn try_from(id: blockjoy_ui::Uuid) -> Result<Self, Self::Error> {
            let id = id
                .value
                .parse()
                .map_err(|e| anyhow!("Could not parse provided uuid: {e:?}"))?;
            Ok(id)
        }
    }

    impl TryFrom<blockjoy::Uuid> for uuid::Uuid {
        type Error = ApiError;

        fn try_from(id: blockjoy::Uuid) -> Result<Self, Self::Error> {
            let id = id
                .value
                .parse()
                .map_err(|e| anyhow!("Could not parse provided uuid: {e:?}"))?;
            Ok(id)
        }
    }

    impl TryFrom<GrpcHost> for HostSelectiveUpdate {
        type Error = ApiError;

        fn try_from(host: GrpcHost) -> Result<Self, Self::Error> {
            let updater = Self {
                org_id: host.org_id.map(uuid::Uuid::try_from).transpose()?,
                name: host.name,
                version: host.version,
                location: host.location,
                cpu_count: host.cpu_count,
                mem_size: host.mem_size,
                disk_size: host.disk_size,
                os: host.os,
                os_version: host.os_version,
                ip_addr: host.ip,
                val_ip_addrs: None,
                status: None,
            };
            Ok(updater)
        }
    }

    impl TryFrom<HostProvision> for GrpcHostProvision {
        type Error = ApiError;

        fn try_from(hp: HostProvision) -> Result<Self, Self::Error> {
            let hp = Self {
                id: Some(hp.id),
                org_id: Some(GrpcUiUuid::from(hp.org_id)),
                host_id: hp.host_id.map(GrpcUiUuid::from),
                created_at: Some(try_dt_to_ts(hp.created_at)?),
                claimed_at: hp.claimed_at.map(try_dt_to_ts).transpose()?,
                install_cmd: hp.install_cmd.map(String::from),
            };
            Ok(hp)
        }
    }

    impl TryFrom<GrpcHost> for HostRequest {
        type Error = ApiError;

        fn try_from(host: GrpcHost) -> Result<Self, Self::Error> {
            let req = Self {
                org_id: host.org_id.map(uuid::Uuid::try_from).transpose()?,
                name: host.name.ok_or_else(required("host.name"))?,
                version: host.version,
                location: host.location,
                cpu_count: host.cpu_count,
                mem_size: host.mem_size,
                disk_size: host.disk_size,
                os: host.os,
                os_version: host.os_version,
                ip_addr: host.ip.ok_or_else(required("host.ip"))?,
                val_ip_addrs: None,
                status: ConnectionStatus::Online,
            };
            Ok(req)
        }
    }

    impl TryFrom<&GrpcUuid> for Uuid {
        type Error = ApiError;

        fn try_from(id: &GrpcUuid) -> Result<Self, Self::Error> {
            let id = Uuid::parse_str(&id.value).map_err(|e| anyhow!("Uuid parsing failed: {e}"))?;
            Ok(id)
        }
    }

    impl From<Uuid> for GrpcUiUuid {
        fn from(id: Uuid) -> Self {
            Self {
                value: id.to_string(),
            }
        }
    }

    impl From<Uuid> for GrpcUuid {
        fn from(id: Uuid) -> Self {
            Self {
                value: id.to_string(),
            }
        }
    }

    impl TryFrom<&GrpcUiUuid> for Uuid {
        type Error = ApiError;

        fn try_from(id: &GrpcUiUuid) -> Result<Self, Self::Error> {
            let id = Uuid::parse_str(&id.value).map_err(|e| anyhow!("Uuid parsing failed: {e}"))?;
            Ok(id)
        }
    }

    impl TryFrom<&User> for GrpcUiUser {
        type Error = ApiError;

        fn try_from(user: &User) -> Result<Self, Self::Error> {
            let user = Self {
                id: Some(GrpcUiUuid::from(user.id)),
                email: Some(user.email.clone()),
                first_name: Some(user.first_name.clone()),
                last_name: Some(user.last_name.clone()),
                created_at: Some(try_dt_to_ts(user.created_at)?),
                updated_at: None,
            };
            Ok(user)
        }
    }

    impl From<ApiError> for Status {
        fn from(e: ApiError) -> Self {
            let msg = format!("{:?}", e);

            match e {
                ApiError::ValidationError(_) => Status::invalid_argument(msg),
                ApiError::NotFoundError(_) => Status::not_found(msg),
                ApiError::DuplicateResource => Status::invalid_argument(msg),
                ApiError::InvalidAuthentication(_) => Status::unauthenticated(msg),
                ApiError::InsufficientPermissionsError => Status::permission_denied(msg),
                _ => Status::internal(msg),
            }
        }
    }

    impl From<Status> for ApiError {
        fn from(status: Status) -> Self {
            let e = anyhow!(format!("{:?}", status));

            match status.code() {
                Code::Unauthenticated => ApiError::InvalidAuthentication(e),
                Code::PermissionDenied => ApiError::InsufficientPermissionsError,
                _ => ApiError::UnexpectedError(e),
            }
        }
    }

    impl TryFrom<User> for GrpcUiUser {
        type Error = ApiError;

        fn try_from(user: User) -> Result<Self, Self::Error> {
            let user = Self {
                id: Some(GrpcUiUuid::from(user.id)),
                email: Some(user.email),
                first_name: Some(user.first_name),
                last_name: Some(user.last_name),
                created_at: Some(try_dt_to_ts(user.created_at)?),
                updated_at: None,
            };
            Ok(user)
        }
    }

    impl TryFrom<Org> for Organization {
        type Error = ApiError;

        fn try_from(org: Org) -> Result<Self, Self::Error> {
            Organization::try_from(&org)
        }
    }

    impl TryFrom<&Org> for Organization {
        type Error = ApiError;

        fn try_from(org: &Org) -> Result<Self, Self::Error> {
            let org = Self {
                id: Some(GrpcUiUuid::from(org.id)),
                name: Some(org.name.clone()),
                personal: Some(org.is_personal),
                member_count: org.member_count,
                created_at: Some(try_dt_to_ts(org.created_at)?),
                updated_at: Some(try_dt_to_ts(org.updated_at)?),
            };
            Ok(org)
        }
    }

    impl TryFrom<Host> for GrpcHost {
        type Error = ApiError;

        fn try_from(host: Host) -> Result<Self, Self::Error> {
            GrpcHost::try_from(&host)
        }
    }

    impl TryFrom<&Host> for GrpcHost {
        type Error = ApiError;

        fn try_from(host: &Host) -> Result<Self, Self::Error> {
            let empty: Vec<Node> = vec![];
            let nodes = host.nodes.as_ref().unwrap_or(&empty);
            let nodes: Result<_, ApiError> = nodes.iter().map(GrpcNode::try_from).collect();

            let grpc_host = Self {
                id: Some(GrpcUiUuid::from(host.id)),
                org_id: host.org_id.map(GrpcUiUuid::from),
                name: Some(host.name.clone()),
                version: host.version.clone().map(String::from),
                location: host.location.clone().map(String::from),
                cpu_count: host.cpu_count.map(i64::from),
                mem_size: host.mem_size.map(i64::from),
                disk_size: host.disk_size.map(i64::from),
                os: host.os.clone().map(String::from),
                os_version: host.os_version.clone().map(String::from),
                ip: Some(host.ip_addr.clone()),
                status: None,
                nodes: nodes?,
                created_at: Some(try_dt_to_ts(host.created_at)?),
            };
            Ok(grpc_host)
        }
    }

    impl TryFrom<Node> for GrpcNode {
        type Error = ApiError;

        fn try_from(node: Node) -> Result<Self, Self::Error> {
            Self::try_from(&node)
        }
    }

    impl TryFrom<&Node> for GrpcNode {
        type Error = ApiError;

        fn try_from(node: &Node) -> Result<Self, Self::Error> {
            let grpc_node = Self {
                id: Some(GrpcUiUuid::from(node.id)),
                org_id: Some(GrpcUiUuid::from(node.org_id)),
                host_id: Some(GrpcUiUuid::from(node.host_id)),
                blockchain_id: Some(GrpcUiUuid::from(node.blockchain_id)),
                name: node.name.clone(),
                // TODO: get node groups
                groups: vec![],
                version: node.version.clone(),
                ip: node.ip_addr.clone(),
                r#type: Some(node.node_type.to_json()?),
                address: node.address.clone(),
                wallet_address: node.wallet_address.clone(),
                block_height: node.block_height.map(i64::from),
                // TODO: Get node data
                node_data: None,
                created_at: Some(try_dt_to_ts(node.created_at)?),
                updated_at: Some(try_dt_to_ts(node.updated_at)?),
                status: Some(GrpcNodeStatus::from(node.chain_status).into()),
            };
            Ok(grpc_node)
        }
    }

    impl TryFrom<&NodeCreateRequest> for GrpcNode {
        type Error = ApiError;

        fn try_from(req: &NodeCreateRequest) -> Result<Self, Self::Error> {
            let r#type = serde_json::to_string(req.node_type.as_ref()).map_err(|e| {
                anyhow!("Could not serialize field `type` of `NodeCreateRequest`: {e:?}")
            })?;
            let node = Self {
                id: None,
                org_id: Some(GrpcUiUuid::from(req.org_id)),
                host_id: Some(GrpcUiUuid::from(req.host_id)),
                blockchain_id: Some(GrpcUiUuid::from(req.blockchain_id)),
                name: Some(petname::petname(3, "_")),
                // TODO
                groups: vec![],
                version: req.version.clone(),
                ip: req.ip_addr.clone(),
                r#type: Some(r#type),
                address: req.address.clone(),
                wallet_address: req.wallet_address.clone(),
                block_height: req.block_height.map(i64::from),
                node_data: None,
                created_at: None,
                updated_at: None,
                status: Some(GrpcNodeStatus::from(req.chain_status).into()),
            };
            Ok(node)
        }
    }

    impl TryFrom<NodeCreateRequest> for GrpcNode {
        type Error = ApiError;

        fn try_from(req: NodeCreateRequest) -> Result<Self, Self::Error> {
            Self::try_from(&req)
        }
    }

    impl TryFrom<GrpcNode> for NodeCreateRequest {
        type Error = ApiError;

        fn try_from(node: GrpcNode) -> Result<Self, Self::Error> {
            let req = Self {
                org_id: node
                    .org_id
                    .ok_or_else(|| ApiError::validation("GrpcNode.org_id is required"))?
                    .try_into()?,
                host_id: node
                    .host_id
                    .ok_or_else(|| ApiError::validation("GrpcNode.host_id is required"))?
                    .try_into()?,
                name: Some(petname::petname(3, "_")),
                groups: Some(node.groups.join(",")),
                version: node.version.map(String::from),
                ip_addr: node.ip.map(String::from),
                blockchain_id: node
                    .blockchain_id
                    .ok_or_else(|| ApiError::validation("GrpcNode.blockchain_id is required"))?
                    .try_into()?,
                node_type: node
                    .r#type
                    .ok_or_else(required("node.type"))?
                    .try_into()
                    .map(sqlx::types::Json)?,
                address: node.address.map(String::from),
                wallet_address: node.wallet_address.map(String::from),
                block_height: node.block_height.map(i64::from),
                node_data: node.node_data.map(Value::from),
                chain_status: node
                    .status
                    .ok_or_else(required("node.status"))?
                    .try_into()?,
                sync_status: NodeSyncStatus::Unknown,
                staking_status: Some(NodeStakingStatus::Unknown),
                container_status: ContainerStatus::Unknown,
            };
            Ok(req)
        }
    }

    impl TryFrom<GrpcNode> for NodeInfo {
        type Error = ApiError;

        fn try_from(node: GrpcNode) -> Result<Self, Self::Error> {
            let node_info = Self {
                version: node.version,
                ip_addr: node.ip,
                block_height: node.block_height,
                node_data: node.node_data.map(Value::from),
                chain_status: node.status.map(|n| n.try_into()).transpose()?,
                sync_status: None,
                staking_status: None,
                container_status: None,
            };
            Ok(node_info)
        }
    }

    impl From<NodeChainStatus> for GrpcNodeStatus {
        fn from(ncs: NodeChainStatus) -> Self {
            match ncs {
                NodeChainStatus::Unknown => GrpcNodeStatus::UndefinedApplicationStatus,
                NodeChainStatus::Broadcasting => GrpcNodeStatus::Broadcasting,
                NodeChainStatus::Cancelled => GrpcNodeStatus::Cancelled,
                // TODO
                NodeChainStatus::Delegating => GrpcNodeStatus::Delegating,
                NodeChainStatus::Delinquent => GrpcNodeStatus::Delinquent,
                NodeChainStatus::Disabled => GrpcNodeStatus::Disabled,
                NodeChainStatus::Earning => GrpcNodeStatus::Earning,
                NodeChainStatus::Elected => GrpcNodeStatus::Elected,
                NodeChainStatus::Electing => GrpcNodeStatus::Electing,
                // TODO Thomas please rename this to exported in the api or to exporting in the database
                NodeChainStatus::Exported => GrpcNodeStatus::Exporting,
                // TODO
                NodeChainStatus::Ingesting => GrpcNodeStatus::Ingesting,
                NodeChainStatus::Mining => GrpcNodeStatus::Mining,
                NodeChainStatus::Minting => GrpcNodeStatus::Minting,
                NodeChainStatus::Processing => GrpcNodeStatus::Processing,
                NodeChainStatus::Relaying => GrpcNodeStatus::Relaying,
                NodeChainStatus::Removed => GrpcNodeStatus::Removed,
                NodeChainStatus::Removing => GrpcNodeStatus::Removing,
            }
        }
    }

    impl TryFrom<models::Blockchain> for blockjoy_ui::Blockchain {
        type Error = ApiError;

        fn try_from(model: models::Blockchain) -> Result<Self, Self::Error> {
            let json = model.supported_node_types.0;
            let json = serde_json::to_string(&json)
                .map_err(|e| anyhow!("Could not serialize supported node types: {e}"))?;

            tracing::info!("sending json: {}", json);

            let blockchain = Self {
                id: Some(model.id.into()),
                name: model.name,
                description: model.description,
                status: model.status as i32,
                project_url: model.project_url,
                repo_url: model.repo_url,
                supports_etl: model.supports_etl,
                supports_node: model.supports_node,
                supports_staking: model.supports_staking,
                supports_broadcast: model.supports_broadcast,
                version: model.version,
                supported_nodes_types: json,
                created_at: Some(try_dt_to_ts(model.created_at)?),
                updated_at: Some(try_dt_to_ts(model.updated_at)?),
            };
            Ok(blockchain)
        }
    }
}

pub mod into {
    use crate::{
        errors::ApiError,
        grpc::{
            blockjoy::{HostInfo, HostInfoUpdateRequest, Uuid as GrpcUuid},
            helpers::required,
        },
    };
    use tonic::Request;

    impl ToString for GrpcUuid {
        fn to_string(&self) -> String {
            self.value.clone()
        }
    }

    pub trait IntoData<R, T> {
        type Error;

        fn into_data(self) -> Result<T, Self::Error>;
    }

    impl IntoData<Request<HostInfoUpdateRequest>, (GrpcUuid, HostInfo)>
        for Request<HostInfoUpdateRequest>
    {
        type Error = ApiError;

        fn into_data(self) -> Result<(GrpcUuid, HostInfo), Self::Error> {
            let inner = self.into_inner();
            let id = inner.request_id.ok_or_else(required("request_id"))?;
            let info = inner.info.ok_or_else(required("info"))?;

            Ok((id, info))
        }
    }
}
