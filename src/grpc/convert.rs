pub mod from {
    use crate::errors::ApiError;
    use crate::grpc::blockjoy::{
        command, node_command, Command as GrpcCommand, CommandMeta, HostInfo, NodeCommand,
        NodeDelete, NodeInfoGet, NodeRestart, NodeStop, Uuid as GrpcUuid,
    };
    use crate::grpc::blockjoy_ui::{
        Host as GrpcHost, Organization, User as GrpcUiUser, Uuid as GrpcUiUuid,
    };
    use crate::grpc::helpers::pb_current_timestamp;
    use crate::models::{Command as DbCommand, HostCmd, Org, User};
    use crate::models::{Host, HostSelectiveUpdate};
    use anyhow::anyhow;
    use prost_types::Timestamp;
    use std::str::FromStr;
    use tonic::{Code, Status};
    use uuid::Uuid;

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

    impl From<GrpcHost> for HostSelectiveUpdate {
        fn from(host: GrpcHost) -> Self {
            Self {
                org_id: host.org_id.map(Uuid::from),
                name: host.name.map(String::from),
                version: host.version.map(String::from),
                location: host.location.map(String::from),
                cpu_count: host.cpu_count.map(i64::from),
                mem_size: host.mem_size.map(i64::from),
                disk_size: host.disk_size.map(i64::from),
                os: host.os.map(String::from),
                os_version: host.os_version.map(String::from),
                ip_addr: host.ip.map(String::from),
                val_ip_addrs: None,
                status: None,
                token_id: None,
            }
        }
    }

    impl From<DbCommand> for GrpcCommand {
        fn from(db_cmd: DbCommand) -> Self {
            let mut node_cmd = NodeCommand::from(db_cmd.cmd);

            // TODO: what should happen, if there's no UUID in the sub_cmd?
            node_cmd.id = Some(db_cmd.sub_cmd.unwrap().parse::<GrpcUuid>().unwrap());

            Self {
                r#type: Some(command::Type::Node(node_cmd)),
            }
        }
    }

    impl From<HostCmd> for NodeCommand {
        fn from(host_cmd: HostCmd) -> Self {
            let meta = Some(CommandMeta {
                // TODO: Use api command ID
                api_command_id: Some(GrpcUuid::from(Uuid::new_v4())),
                created_at: Some(pb_current_timestamp()),
            });
            let mut node_cmd = NodeCommand {
                id: None,
                command: None,
                meta,
            };

            match host_cmd {
                HostCmd::RestartNode => {
                    node_cmd.command = Some(node_command::Command::Restart(NodeRestart::default()))
                }
                HostCmd::KillNode => {
                    tracing::debug!("Using NodeStop for KillNode");
                    node_cmd.command = Some(node_command::Command::Stop(NodeStop::default()))
                }
                HostCmd::ShutdownNode => {
                    node_cmd.command = Some(node_command::Command::Stop(NodeStop::default()))
                }
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
                    node_cmd.command = Some(node_command::Command::InfoGet(NodeInfoGet::default()))
                }
                // The following should be HostCommands
                HostCmd::CreateNode => {
                    unimplemented!();
                }
                HostCmd::DeleteNode => {
                    node_cmd.command = Some(node_command::Command::Delete(NodeDelete::default()))
                }
                HostCmd::GetBVSVersion => unimplemented!(),
                HostCmd::UpdateBVS => unimplemented!(),
                HostCmd::RestartBVS => unimplemented!(),
                HostCmd::RemoveBVS => unimplemented!(),
                // TODO: Missing
                // NodeStart, NodeUpgrade
            }

            node_cmd
        }
    }

    impl From<GrpcUuid> for Uuid {
        fn from(id: GrpcUuid) -> Self {
            Uuid::parse_str(id.value.as_str()).unwrap()
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

    impl From<GrpcUiUuid> for Uuid {
        fn from(id: GrpcUiUuid) -> Self {
            Uuid::parse_str(id.value.as_str()).unwrap()
        }
    }

    impl From<&User> for GrpcUiUser {
        fn from(user: &User) -> Self {
            Self {
                id: Some(GrpcUiUuid::from(user.id)),
                email: Some(user.email.clone()),
                first_name: None,
                last_name: None,
                created_at: Some(Timestamp {
                    seconds: user.created_at.timestamp(),
                    nanos: user.created_at.timestamp_nanos() as i32,
                }),
                updated_at: None,
            }
        }
    }

    impl From<Option<String>> for GrpcUuid {
        fn from(id: Option<String>) -> Self {
            Self { value: id.unwrap() }
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

    impl From<User> for GrpcUiUser {
        fn from(user: User) -> Self {
            Self {
                id: Some(GrpcUiUuid::from(user.id)),
                email: Some(user.email),
                first_name: None,
                last_name: None,
                created_at: Some(Timestamp {
                    seconds: user.created_at.timestamp(),
                    nanos: user.created_at.timestamp_nanos() as i32,
                }),
                updated_at: None,
            }
        }
    }

    impl From<Org> for Organization {
        fn from(org: Org) -> Self {
            Organization::from(&org)
        }
    }

    impl From<&Org> for Organization {
        fn from(org: &Org) -> Self {
            Self {
                id: Some(GrpcUiUuid::from(org.id)),
                name: Some(org.name.clone()),
                personal: Some(org.is_personal),
                member_count: org.member_count,
                created_at: Some(Timestamp {
                    seconds: org.created_at.timestamp(),
                    nanos: org.created_at.timestamp_nanos() as i32,
                }),
                updated_at: Some(Timestamp {
                    seconds: org.updated_at.timestamp(),
                    nanos: org.updated_at.timestamp_nanos() as i32,
                }),
            }
        }
    }

    impl From<Host> for GrpcHost {
        fn from(host: Host) -> Self {
            GrpcHost::from(&host)
        }
    }

    impl From<&Host> for GrpcHost {
        fn from(host: &Host) -> Self {
            Self {
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
                nodes: vec![],
                created_at: Some(Timestamp {
                    seconds: host.created_at.timestamp(),
                    nanos: host.created_at.timestamp_nanos() as i32,
                }),
            }
        }
    }
}

pub mod into {
    use crate::grpc::blockjoy::{HostInfo, HostInfoUpdateRequest, Uuid as GrpcUuid};
    use tonic::Request;

    impl ToString for GrpcUuid {
        fn to_string(&self) -> String {
            self.value.clone()
        }
    }

    pub trait IntoData<R, T> {
        fn into_data(self) -> T;
    }

    impl IntoData<Request<HostInfoUpdateRequest>, (GrpcUuid, HostInfo)>
        for Request<HostInfoUpdateRequest>
    {
        fn into_data(self) -> (GrpcUuid, HostInfo) {
            let inner = self.into_inner();
            let id = inner.request_id.unwrap();
            let info = inner.info.unwrap();

            (id, info)
        }
    }
}
