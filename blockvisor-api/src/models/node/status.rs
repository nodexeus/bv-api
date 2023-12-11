use diesel_derive_enum::DbEnum;

use crate::grpc::common;
use crate::models::schema::sql_types;
use crate::util::search::SortIndex;

#[derive(Clone, Copy, Debug, PartialEq, Eq, DbEnum)]
#[ExistingTypePath = "sql_types::EnumNodeStatus"]
pub enum NodeStatus {
    ProvisioningPending,
    Provisioning,
    Broadcasting,
    Cancelled,
    Delegating,
    Delinquent,
    Disabled,
    Earning,
    Electing,
    Elected,
    Exported,
    Ingesting,
    Mining,
    Minting,
    Processing,
    Relaying,
    DeletePending,
    Deleting,
    Deleted,
    UpdatePending,
    Updating,
}

impl From<NodeStatus> for common::NodeStatus {
    fn from(status: NodeStatus) -> Self {
        match status {
            NodeStatus::ProvisioningPending => Self::ProvisioningPending,
            NodeStatus::Provisioning => Self::Provisioning,
            NodeStatus::Broadcasting => Self::Broadcasting,
            NodeStatus::Cancelled => Self::Cancelled,
            NodeStatus::Delegating => Self::Delegating,
            NodeStatus::Delinquent => Self::Delinquent,
            NodeStatus::Disabled => Self::Disabled,
            NodeStatus::Earning => Self::Earning,
            NodeStatus::Electing => Self::Electing,
            NodeStatus::Elected => Self::Elected,
            NodeStatus::Exported => Self::Exported,
            NodeStatus::Ingesting => Self::Ingesting,
            NodeStatus::Mining => Self::Mining,
            NodeStatus::Minting => Self::Minting,
            NodeStatus::Processing => Self::Processing,
            NodeStatus::Relaying => Self::Relaying,
            NodeStatus::DeletePending => Self::DeletePending,
            NodeStatus::Deleting => Self::Deleting,
            NodeStatus::Deleted => Self::Deleted,
            NodeStatus::UpdatePending => Self::UpdatePending,
            NodeStatus::Updating => Self::Updating,
        }
    }
}

impl From<common::NodeStatus> for Option<NodeStatus> {
    fn from(status: common::NodeStatus) -> Self {
        match status {
            common::NodeStatus::Unspecified => None,
            common::NodeStatus::ProvisioningPending => Some(NodeStatus::ProvisioningPending),
            common::NodeStatus::Provisioning => Some(NodeStatus::Provisioning),
            common::NodeStatus::Broadcasting => Some(NodeStatus::Broadcasting),
            common::NodeStatus::Cancelled => Some(NodeStatus::Cancelled),
            common::NodeStatus::Delegating => Some(NodeStatus::Delegating),
            common::NodeStatus::Delinquent => Some(NodeStatus::Delinquent),
            common::NodeStatus::Disabled => Some(NodeStatus::Disabled),
            common::NodeStatus::Earning => Some(NodeStatus::Earning),
            common::NodeStatus::Electing => Some(NodeStatus::Electing),
            common::NodeStatus::Elected => Some(NodeStatus::Elected),
            common::NodeStatus::Exported => Some(NodeStatus::Exported),
            common::NodeStatus::Ingesting => Some(NodeStatus::Ingesting),
            common::NodeStatus::Mining => Some(NodeStatus::Mining),
            common::NodeStatus::Minting => Some(NodeStatus::Minting),
            common::NodeStatus::Processing => Some(NodeStatus::Processing),
            common::NodeStatus::Relaying => Some(NodeStatus::Relaying),
            common::NodeStatus::DeletePending => Some(NodeStatus::DeletePending),
            common::NodeStatus::Deleting => Some(NodeStatus::Deleting),
            common::NodeStatus::Deleted => Some(NodeStatus::Deleted),
            common::NodeStatus::UpdatePending => Some(NodeStatus::UpdatePending),
            common::NodeStatus::Updating => Some(NodeStatus::Updating),
        }
    }
}

impl SortIndex for NodeStatus {
    fn index(&self) -> i32 {
        match self {
            NodeStatus::Broadcasting => 1,
            NodeStatus::Cancelled => 2,
            NodeStatus::Delegating => 3,
            NodeStatus::DeletePending => 4,
            NodeStatus::Deleted => 5,
            NodeStatus::Deleting => 6,
            NodeStatus::Delinquent => 7,
            NodeStatus::Disabled => 8,
            NodeStatus::Earning => 9,
            NodeStatus::Elected => 10,
            NodeStatus::Electing => 11,
            NodeStatus::Exported => 12,
            NodeStatus::Ingesting => 13,
            NodeStatus::Mining => 14,
            NodeStatus::Minting => 15,
            NodeStatus::Processing => 16,
            NodeStatus::Provisioning => 17,
            NodeStatus::ProvisioningPending => 18,
            NodeStatus::Relaying => 19,
            NodeStatus::UpdatePending => 20,
            NodeStatus::Updating => 21,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, DbEnum)]
#[ExistingTypePath = "sql_types::EnumContainerStatus"]
pub enum ContainerStatus {
    Unknown,
    Creating,
    Running,
    Starting,
    Stopping,
    Stopped,
    Upgrading,
    Upgraded,
    Deleting,
    Deleted,
    Installing,
    Snapshotting,
    Failed,
    Busy,
}

impl From<ContainerStatus> for common::ContainerStatus {
    fn from(status: ContainerStatus) -> Self {
        match status {
            ContainerStatus::Unknown => Self::Unspecified,
            ContainerStatus::Creating => Self::Creating,
            ContainerStatus::Running => Self::Running,
            ContainerStatus::Starting => Self::Starting,
            ContainerStatus::Stopping => Self::Stopping,
            ContainerStatus::Stopped => Self::Stopped,
            ContainerStatus::Upgrading => Self::Upgrading,
            ContainerStatus::Upgraded => Self::Upgraded,
            ContainerStatus::Deleting => Self::Deleting,
            ContainerStatus::Deleted => Self::Deleted,
            ContainerStatus::Installing => Self::Installing,
            ContainerStatus::Snapshotting => Self::Snapshotting,
            ContainerStatus::Failed => Self::Failed,
            ContainerStatus::Busy => Self::Busy,
        }
    }
}

impl From<common::ContainerStatus> for ContainerStatus {
    fn from(status: common::ContainerStatus) -> Self {
        match status {
            common::ContainerStatus::Unspecified => ContainerStatus::Unknown,
            common::ContainerStatus::Creating => ContainerStatus::Creating,
            common::ContainerStatus::Running => ContainerStatus::Running,
            common::ContainerStatus::Starting => ContainerStatus::Starting,
            common::ContainerStatus::Stopping => ContainerStatus::Stopping,
            common::ContainerStatus::Stopped => ContainerStatus::Stopped,
            common::ContainerStatus::Upgrading => ContainerStatus::Upgrading,
            common::ContainerStatus::Upgraded => ContainerStatus::Upgraded,
            common::ContainerStatus::Deleting => ContainerStatus::Deleting,
            common::ContainerStatus::Deleted => ContainerStatus::Deleted,
            common::ContainerStatus::Installing => ContainerStatus::Installing,
            common::ContainerStatus::Snapshotting => ContainerStatus::Snapshotting,
            common::ContainerStatus::Failed => ContainerStatus::Failed,
            common::ContainerStatus::Busy => ContainerStatus::Busy,
        }
    }
}

impl SortIndex for ContainerStatus {
    fn index(&self) -> i32 {
        match self {
            ContainerStatus::Busy => 1,
            ContainerStatus::Creating => 2,
            ContainerStatus::Deleted => 3,
            ContainerStatus::Deleting => 4,
            ContainerStatus::Failed => 5,
            ContainerStatus::Installing => 6,
            ContainerStatus::Running => 7,
            ContainerStatus::Snapshotting => 8,
            ContainerStatus::Starting => 9,
            ContainerStatus::Stopped => 10,
            ContainerStatus::Stopping => 11,
            ContainerStatus::Unknown => 12,
            ContainerStatus::Upgraded => 13,
            ContainerStatus::Upgrading => 14,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, DbEnum)]
#[ExistingTypePath = "sql_types::EnumNodeSyncStatus"]
pub enum SyncStatus {
    Unknown,
    Syncing,
    Synced,
}

impl SortIndex for SyncStatus {
    fn index(&self) -> i32 {
        match self {
            SyncStatus::Synced => 1,
            SyncStatus::Syncing => 2,
            SyncStatus::Unknown => 3,
        }
    }
}

impl From<SyncStatus> for common::SyncStatus {
    fn from(status: SyncStatus) -> Self {
        match status {
            SyncStatus::Unknown => Self::Unspecified,
            SyncStatus::Syncing => Self::Syncing,
            SyncStatus::Synced => Self::Synced,
        }
    }
}

impl From<common::SyncStatus> for SyncStatus {
    fn from(status: common::SyncStatus) -> Self {
        match status {
            common::SyncStatus::Unspecified => SyncStatus::Unknown,
            common::SyncStatus::Syncing => SyncStatus::Syncing,
            common::SyncStatus::Synced => SyncStatus::Synced,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, DbEnum)]
#[ExistingTypePath = "sql_types::EnumNodeStakingStatus"]
pub enum StakingStatus {
    Unknown,
    Follower,
    Staked,
    Staking,
    Validating,
    Consensus,
    Unstaked,
}

impl From<StakingStatus> for common::StakingStatus {
    fn from(status: StakingStatus) -> Self {
        match status {
            StakingStatus::Unknown => Self::Unspecified,
            StakingStatus::Follower => Self::Follower,
            StakingStatus::Staked => Self::Staked,
            StakingStatus::Staking => Self::Staking,
            StakingStatus::Validating => Self::Validating,
            StakingStatus::Consensus => Self::Consensus,
            StakingStatus::Unstaked => Self::Unstaked,
        }
    }
}

impl From<common::StakingStatus> for StakingStatus {
    fn from(status: common::StakingStatus) -> StakingStatus {
        match status {
            common::StakingStatus::Unspecified => StakingStatus::Unknown,
            common::StakingStatus::Follower => StakingStatus::Follower,
            common::StakingStatus::Staked => StakingStatus::Staked,
            common::StakingStatus::Staking => StakingStatus::Staking,
            common::StakingStatus::Validating => StakingStatus::Validating,
            common::StakingStatus::Consensus => StakingStatus::Consensus,
            common::StakingStatus::Unstaked => StakingStatus::Unstaked,
        }
    }
}

impl SortIndex for StakingStatus {
    fn index(&self) -> i32 {
        match self {
            StakingStatus::Consensus => 1,
            StakingStatus::Follower => 2,
            StakingStatus::Staked => 3,
            StakingStatus::Staking => 4,
            StakingStatus::Unknown => 5,
            StakingStatus::Unstaked => 6,
            StakingStatus::Validating => 7,
        }
    }
}
