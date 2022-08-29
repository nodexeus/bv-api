//! Build file generating gRPC stubs

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        // needed for integration tests
        .build_client(true)
        .compile(
            &[
                // Backend API
                "proto/blockjoy/api/v1/command_flow.proto",
                "proto/blockjoy/api/v1/host_service.proto",
                // UI API
                "proto/blockjoy/api/ui_v1/authentication_service.proto",
                "proto/blockjoy/api/ui_v1/billing_service.proto",
                "proto/blockjoy/api/ui_v1/host_provision_service.proto",
                "proto/blockjoy/api/ui_v1/fe_host_service.proto",
                "proto/blockjoy/api/ui_v1/node_service.proto",
                "proto/blockjoy/api/ui_v1/organization_service.proto",
                "proto/blockjoy/api/ui_v1/update_service.proto",
                "proto/blockjoy/api/ui_v1/user_service.proto",
            ],
            &["proto/blockjoy/api/v1", "proto/blockjoy/api/ui_v1"],
        )?;

    Ok(())
}
