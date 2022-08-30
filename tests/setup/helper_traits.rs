use api::grpc::blockjoy::hosts_client::HostsClient;
use api::grpc::blockjoy_ui::{
    authentication_service_client::AuthenticationServiceClient,
    user_service_client::UserServiceClient,
};
use tonic::transport::Channel;

pub trait GrpcClient<T> {
    fn create(channel: Channel) -> Self;
}

impl GrpcClient<Channel> for HostsClient<Channel> {
    fn create(channel: Channel) -> Self {
        Self::new(channel)
    }
}

impl GrpcClient<Channel> for AuthenticationServiceClient<Channel> {
    fn create(channel: Channel) -> Self {
        Self::new(channel)
    }
}

impl GrpcClient<Channel> for UserServiceClient<Channel> {
    fn create(channel: Channel) -> Self {
        Self::new(channel)
    }
}
