use api::grpc::blockjoy::hosts_client::HostsClient;
use api::grpc::blockjoy_ui::authentication_service_client::AuthenticationServiceClient;
use api::grpc::blockjoy_ui::organization_service_client::OrganizationServiceClient;
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

impl GrpcClient<Channel> for OrganizationServiceClient<Channel> {
    fn create(channel: Channel) -> Self {
        Self::new(channel)
    }
}
